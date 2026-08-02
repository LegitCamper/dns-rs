use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::dns::handler::handle_query;
use crate::state::AppState;

/// DNS messages are length-prefixed with a u16, so this is the hard ceiling
/// regardless of transport.
const MAX_MESSAGE_SIZE: usize = 65535;

/// Caps how many queries a single DoT connection may have resolving at
/// once. Pipelined queries are processed concurrently (see
/// `handle_connection`), so without a limit a connection that pipelines a
/// large burst could spawn unbounded concurrent upstream fetches; this
/// makes the reader loop itself apply backpressure (stop reading further
/// queries off the socket) once the limit is reached, rather than buffering
/// unboundedly ahead.
const MAX_CONCURRENT_QUERIES_PER_CONNECTION: usize = 32;

/// RFC 7858 DNS-over-TLS listener, 2-byte length-prefixed framing (same as
/// classic DNS-over-TCP); a connection may carry multiple pipelined queries.
/// Stops accepting new connections once `shutdown` fires; already-accepted
/// ones finish on their own.
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
            if let Err(err) = handle_connection(acceptor, tcp, state).await {
                debug!(%peer, error = %err, "DoT connection ended");
            }
        });
    }
}

/// Reads pipelined queries off one connection and resolves them
/// concurrently rather than one at a time: each query is handled in its own
/// task (bounded by `MAX_CONCURRENT_QUERIES_PER_CONNECTION`) so a slow
/// cache-miss earlier in the pipeline doesn't block faster queries behind
/// it. A single writer task serializes the actual socket writes, sending
/// each response as soon as it's ready - responses may therefore complete
/// out of request order, same as any other pipelined DNS-over-TCP
/// implementation; the client matches them back up by message ID.
async fn handle_connection(acceptor: TlsAcceptor, tcp: TcpStream, state: Arc<AppState>) -> Result<()> {
    let tls = acceptor.accept(tcp).await.context("TLS handshake failed")?;
    let (mut read_half, mut write_half) = tokio::io::split(tls);

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_CONCURRENT_QUERIES_PER_CONNECTION);
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_QUERIES_PER_CONNECTION));

    let writer = tokio::spawn(async move {
        while let Some(response) = rx.recv().await {
            let Ok(resp_len) = u16::try_from(response.len()) else {
                // handle_query always encodes a response that fits DoT framing
                // (falling back to a minimal SERVFAIL if it somehow can't);
                // this is just a defensive skip, not an expected path.
                continue;
            };
            // One write for the length prefix + body, rather than two, so
            // it's a single TCP segment instead of two back-to-back ones.
            let mut framed = Vec::with_capacity(2 + response.len());
            framed.extend_from_slice(&resp_len.to_be_bytes());
            framed.extend_from_slice(&response);
            if write_half.write_all(&framed).await.is_err() || write_half.flush().await.is_err() {
                break;
            }
        }
    });

    let result: Result<()> = async {
        loop {
            let mut len_buf = [0u8; 2];
            if let Err(err) = read_half.read_exact(&mut len_buf).await {
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
            read_half.read_exact(&mut buf).await.context("failed to read DNS query body")?;

            let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                return Ok(()); // semaphore only closes if the connection is being torn down
            };
            let state = Arc::clone(&state);
            let tx = tx.clone();
            tokio::spawn(async move {
                let response = handle_query(&state, &buf).await;
                let _ = tx.send(response).await;
                drop(permit);
            });
        }
    }
    .await;

    // Drop our sender so the writer's `rx.recv()` returns `None` (and the
    // writer task ends) once every still-in-flight query task has sent its
    // response and dropped its own clone.
    drop(tx);
    let _ = writer.await;
    result
}
