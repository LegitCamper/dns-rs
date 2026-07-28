use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::dns::handler::handle_query;
use crate::state::AppState;

/// DNS messages are length-prefixed with a u16, so this is the hard ceiling
/// regardless of transport.
const MAX_MESSAGE_SIZE: usize = 65535;

/// RFC 7858 DNS-over-TLS listener: plain TCP + TLS, with each message framed
/// by a 2-byte big-endian length prefix (the same framing classic DNS-over-TCP
/// uses). A connection may carry multiple pipelined queries.
///
/// Stops accepting new connections and returns once `shutdown` is cancelled
/// (used for config-reload restarts); already-accepted connections are left
/// to finish on their own rather than being cut off.
pub async fn serve(
    addr: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    state: Arc<AppState>,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind DoT listener on {addr}"))?;
    let acceptor = TlsAcceptor::from(tls_config);
    info!(%addr, "DoT listener ready");

    loop {
        let (tcp, peer) = tokio::select! {
            () = shutdown.cancelled() => {
                info!(%addr, "DoT listener shutting down");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(err) => {
                    warn!(error = %err, "failed to accept DoT connection");
                    continue;
                }
            },
        };
        // Without this, Nagle's algorithm can hold small DNS responses back
        // waiting to coalesce with more outbound data, adding tens of
        // milliseconds of pure buffering delay per query for no benefit here.
        tcp.set_nodelay(true).ok();
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
        // One write for the length prefix + body, rather than two, so it's a
        // single TCP segment instead of two back-to-back ones.
        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&resp_len.to_be_bytes());
        framed.extend_from_slice(&response);
        tls.write_all(&framed).await?;
        tls.flush().await?;
    }
}
