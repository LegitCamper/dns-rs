use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query as AxumQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use tracing::info;

use crate::dns::handler::handle_query;
use crate::state::AppState;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

#[derive(Deserialize)]
struct DohGetParams {
    dns: String,
}

/// RFC 8484 DNS-over-HTTPS listener on `/dns-query`, supporting both the GET
/// form (`?dns=<base64url>`) and the POST form (raw wire bytes as the body).
/// axum-server negotiates HTTP/1.1 or h2 over ALPN automatically.
pub async fn serve(addr: SocketAddr, cert: &Path, key: &Path, state: Arc<AppState>) -> Result<()> {
    let tls_config = RustlsConfig::from_pem_file(cert, key)
        .await
        .context("failed to load DoH TLS certificate/key")?;

    let app = Router::new()
        .route("/dns-query", get(handle_get).post(handle_post))
        .with_state(state);

    info!(%addr, "DoH listener ready");
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("DoH listener failed")?;
    Ok(())
}

async fn handle_get(State(state): State<Arc<AppState>>, AxumQuery(params): AxumQuery<DohGetParams>) -> Response {
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
