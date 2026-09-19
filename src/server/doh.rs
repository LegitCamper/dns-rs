use std::net::SocketAddr;
#[cfg(feature = "doh-tls")]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query as AxumQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
#[cfg(feature = "doh-tls")]
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// How long a config-reload shutdown waits for in-flight DoH requests to
/// finish before cutting them off, so a reload can't hang forever on a slow
/// client but still gives well-behaved ones a chance to complete.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// hyper's HTTP/2 "rapid reset" mitigation (RUSTSEC-2024-0003) tears down the
/// whole connection once a client has RST_STREAM'd more than this many
/// requests without the server finishing them first. h2's own default (20)
/// is sized for detecting a deliberate flood, not for a legitimate client
/// under load bailing on a batch of slow-resolving queries — hitting it just
/// converts a handful of individually-slow queries into every other
/// in-flight query on that connection failing too. Raised, not disabled, so
/// real abuse is still caught. Applies to the plaintext listener too: it
/// speaks h2 via prior-knowledge upgrade, not just via ALPN.
const MAX_PENDING_RESET_STREAMS: usize = 200;
/// SETTINGS_MAX_CONCURRENT_STREAMS: h2's default of 200 throttles new stream
/// creation once a single connection has that many DoH queries in flight,
/// which a concurrent test client (or a busy resolver) reaches easily and
/// then queues/times out waiting for a slot.
const MAX_CONCURRENT_STREAMS: u32 = 1000;

use crate::dns::handler::handle_query;
use crate::state::AppState;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

#[derive(Deserialize)]
struct DohGetParams {
    dns: String,
}

fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/dns-query", get(handle_get).post(handle_post))
        .route("/healthz", get(|| async { "ok" }))
        .fallback(get(handle_get).post(handle_post))
        .with_state(state)
}

/// RFC 8484 DNS-over-HTTPS listener on every path except `/healthz`, supporting
/// both the GET form (`?dns=<base64url>`) and POST form (raw wire bytes as body).
/// axum-server negotiates HTTP/1.1 or h2 over ALPN automatically.
#[cfg(feature = "doh-tls")]
pub async fn serve(
    addr: SocketAddr,
    cert: &Path,
    key: &Path,
    state: Arc<AppState>,
    shutdown: CancellationToken,
) -> Result<()> {
    let tls_config = RustlsConfig::from_pem_file(cert, key)
        .await
        .context("failed to load DoH TLS certificate/key")?;

    let app = app(state);

    // axum-server's own handle drives graceful shutdown: once `shutdown` is
    // cancelled (a config-reload restart), stop accepting new connections
    // and give in-flight ones up to GRACEFUL_SHUTDOWN_TIMEOUT to finish.
    let handle = axum_server::Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown.cancelled().await;
            handle.graceful_shutdown(Some(GRACEFUL_SHUTDOWN_TIMEOUT));
        }
    });

    let mut server = axum_server::bind_rustls(addr, tls_config);
    server
        .http_builder()
        .http2()
        .max_pending_accept_reset_streams(Some(MAX_PENDING_RESET_STREAMS))
        .max_concurrent_streams(Some(MAX_CONCURRENT_STREAMS));

    info!(%addr, "DoH listener ready");
    server
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .context("DoH listener failed")?;
    info!(%addr, "DoH listener shut down");
    Ok(())
}

#[cfg(not(feature = "doh-tls"))]
pub async fn serve(
    addr: SocketAddr,
    state: Arc<AppState>,
    shutdown: CancellationToken,
) -> Result<()> {
    let app = app(state);

    let handle = axum_server::Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown.cancelled().await;
            handle.graceful_shutdown(Some(GRACEFUL_SHUTDOWN_TIMEOUT));
        }
    });

    info!(%addr, "DoH listener ready (plaintext HTTP, expects a TLS terminator in front)");
    let mut server = axum_server::bind(addr);
    server
        .http_builder()
        .http2()
        .max_pending_accept_reset_streams(Some(MAX_PENDING_RESET_STREAMS))
        .max_concurrent_streams(Some(MAX_CONCURRENT_STREAMS));
    server
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .context("DoH listener failed")?;
    info!(%addr, "DoH listener shut down");
    Ok(())
}

async fn handle_get(
    State(state): State<Arc<AppState>>,
    AxumQuery(params): AxumQuery<DohGetParams>,
) -> Response {
    match URL_SAFE_NO_PAD.decode(params.dns.as_bytes()) {
        Ok(bytes) => respond(&state, &bytes).await,
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn handle_post(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    respond(&state, &body).await
}

async fn respond(state: &AppState, query_bytes: &[u8]) -> Response {
    let response_bytes = handle_query(state, query_bytes).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)],
        response_bytes,
    )
        .into_response()
}
