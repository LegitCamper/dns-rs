use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::dns::handler::handle_query;
use crate::state::AppState;

/// DNS messages are length-prefixed with a u16, so this is the hard ceiling
/// regardless of transport.
const MAX_MESSAGE_SIZE: usize = 65535;

/// RFC 7858 DNS-over-TLS listener: plain TCP + TLS, with each message framed
/// by a 2-byte big-endian length prefix (the same framing classic DNS-over-TCP
/// uses). A connection may carry multiple pipelined queries.
pub async fn serve(addr: SocketAddr, tls_config: Arc<rustls::ServerConfig>, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind DoT listener on {addr}"))?;
    let acceptor = TlsAcceptor::from(tls_config);
    info!(%addr, "DoT listener ready");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                warn!(error = %err, "failed to accept DoT connection");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(acceptor, tcp, &state).await {
                debug!(%peer, error = %err, "DoT connection ended");
            }
        });
    }
}

async fn handle_connection(acceptor: TlsAcceptor, tcp: TcpStream, state: &AppState) -> Result<()> {
    let mut tls = acceptor.accept(tcp).await.context("TLS handshake failed")?;

    loop {
        let mut len_buf = [0u8; 2];
        if let Err(err) = tls.read_exact(&mut len_buf).await {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(err).context("failed to read message length prefix");
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_MESSAGE_SIZE {
            return Ok(());
        }

        let mut buf = vec![0u8; len];
        tls.read_exact(&mut buf)
            .await
            .context("failed to read DNS query body")?;

        let response = handle_query(state, &buf).await;
        let resp_len =
            u16::try_from(response.len()).context("encoded response too large for DoT framing")?;
        tls.write_all(&resp_len.to_be_bytes()).await?;
        tls.write_all(&response).await?;
        tls.flush().await?;
    }
}
