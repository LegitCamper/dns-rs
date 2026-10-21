use std::net::SocketAddr;
#[cfg(not(feature = "certless"))]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query as AxumQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
#[cfg(not(feature = "certless"))]
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

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
use crate::dns::upstream::{MultiUpstream, Upstream};
use crate::state::AppState;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// CORS for browser-based DoH clients (test pages, JS resolvers). A public
/// resolver has no origin-derived authority and no cookies/auth, so `*` with
/// credentials disallowed leaks nothing a direct fetch couldn't already get.
/// ponytail: fixed `*` rather than a configurable allowlist; swap in a
/// config-driven origin check if this ever grows authenticated endpoints.
const CORS_HEADERS: [(header::HeaderName, &str); 4] = [
    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
    (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"),
    (header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type, accept"),
    (header::ACCESS_CONTROL_MAX_AGE, "86400"),
];

#[derive(Deserialize)]
struct DohGetParams {
    dns: String,
}

fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/dns-query",
            get(handle_get).post(handle_post).options(handle_options),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(handle_ready))
        .fallback(get(handle_get).post(handle_post).options(handle_options))
        .with_state(state)
}

/// RFC 8484 DNS-over-HTTPS listener except `/healthz` and `/readyz`, supporting
/// both the GET form (`?dns=<base64url>`) and POST form (raw wire bytes as body).
/// axum-server negotiates HTTP/1.1 or h2 over ALPN automatically.
#[cfg(not(feature = "certless"))]
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

#[cfg(feature = "certless")]
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

/// Preflight. Answered for any path the query handlers accept, since a
/// browser sends OPTIONS before a POST with `content-type:
/// application/dns-message` (not a CORS-safelisted value).
async fn handle_options() -> Response {
    (StatusCode::NO_CONTENT, CORS_HEADERS).into_response()
}

async fn handle_ready(State(state): State<Arc<AppState>>) -> Response {
    let (status, body) = match check_readiness(&state.upstreams).await {
        Ok(()) => (StatusCode::OK, "ok"),
        Err(err) => {
            warn!(error = %err, "DNS readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready")
        }
    };
    (status, [(header::CACHE_CONTROL, "no-store")], body).into_response()
}

async fn check_readiness<U: Upstream>(upstreams: &MultiUpstream<U>) -> Result<()> {
    let mut probe = Message::query();
    probe.metadata.recursion_desired = true;
    probe.add_query(Query::query(Name::root(), RecordType::NS));
    // Bypass local cache/blocklists so a cached answer cannot hide an outage.
    // resolve_wire applies the normal strategy and a five-second deadline.
    let wire = upstreams.resolve_wire(&probe.to_vec()?).await?;
    let response = Message::from_vec(&wire).context("invalid readiness response")?;
    ensure!(
        response.metadata.message_type == MessageType::Response
            && response.metadata.op_code == probe.metadata.op_code
            && response.metadata.response_code == ResponseCode::NoError
            && !response.metadata.truncation
            && response.queries == probe.queries
            && response.answers.iter().any(|answer| {
                answer.name == Name::root() && matches!(answer.data, RData::NS(_))
            }),
        "readiness probe did not return root NS records"
    );
    Ok(())
}

async fn handle_get(
    State(state): State<Arc<AppState>>,
    AxumQuery(params): AxumQuery<DohGetParams>,
) -> Response {
    match URL_SAFE_NO_PAD.decode(params.dns.as_bytes()) {
        Ok(bytes) => respond(&state, &bytes).await,
        Err(_) => (StatusCode::BAD_REQUEST, CORS_HEADERS).into_response(),
    }
}

async fn handle_post(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    respond(&state, &body).await
}

async fn respond(state: &Arc<AppState>, query_bytes: &[u8]) -> Response {
    let response_bytes = handle_query(state, query_bytes).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)],
        CORS_HEADERS,
        response_bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::upstream::Strategy;
    use hickory_proto::op::OpCode;
    use hickory_proto::rr::{Record, rdata::NS};

    struct ProbeUpstream(Option<Vec<u8>>);

    impl Upstream for ProbeUpstream {
        fn label(&self) -> &str {
            "readiness test"
        }

        async fn resolve(&self, query: &[u8]) -> Result<Vec<u8>> {
            let query = Message::from_vec(query)?;
            assert!(query.metadata.recursion_desired);
            assert_eq!(query.queries, root_answer().queries);
            self.0.clone().context("upstream unavailable")
        }
    }

    fn root_answer() -> Message {
        let mut response = Message::response(0, OpCode::Query);
        response.add_query(Query::query(Name::root(), RecordType::NS));
        response.add_answer(Record::from_rdata(
            Name::root(),
            60,
            RData::NS(NS(Name::from_ascii("a.root-servers.net.").unwrap())),
        ));
        response
    }

    #[tokio::test]
    async fn readiness_accepts_working_fallback() {
        let upstreams = MultiUpstream::new(
            vec![
                ProbeUpstream(None),
                ProbeUpstream(Some(root_answer().to_vec().unwrap())),
            ],
            Strategy::Sequential,
        );
        assert!(check_readiness(&upstreams).await.is_ok());
    }

    #[tokio::test]
    async fn readiness_rejects_failed_or_invalid_answers() {
        let valid = root_answer();
        let mut servfail = valid.clone();
        servfail.metadata.response_code = ResponseCode::ServFail;
        let mut truncated = valid.clone();
        truncated.metadata.truncation = true;
        let mut wrong_question = valid.clone();
        wrong_question.queries[0] = Query::query(Name::root(), RecordType::A);
        let mut no_answer = valid.clone();
        no_answer.answers.clear();
        let mut query = valid;
        query.metadata.message_type = MessageType::Query;

        for wire in [
            None,
            Some(vec![0]),
            Some(servfail.to_vec().unwrap()),
            Some(truncated.to_vec().unwrap()),
            Some(wrong_question.to_vec().unwrap()),
            Some(no_answer.to_vec().unwrap()),
            Some(query.to_vec().unwrap()),
        ] {
            let upstreams = MultiUpstream::new(vec![ProbeUpstream(wire)], Strategy::Sequential);
            assert!(check_readiness(&upstreams).await.is_err());
        }
    }

    #[tokio::test]
    async fn readiness_times_out_when_upstream_hangs() {
        struct HungUpstream;
        impl Upstream for HungUpstream {
            fn label(&self) -> &str {
                "hung readiness test"
            }

            async fn resolve(&self, _: &[u8]) -> Result<Vec<u8>> {
                std::future::pending().await
            }
        }
        let upstreams = MultiUpstream::new(vec![HungUpstream], Strategy::Sequential);
        let result = tokio::time::timeout(Duration::from_secs(6), check_readiness(&upstreams))
            .await
            .expect("readiness must finish before Fly's six-second timeout");
        assert!(result.is_err());
    }

    /// Preflight must carry all four CORS headers, or a browser rejects the
    /// subsequent POST before it is ever sent.
    #[tokio::test]
    async fn options_returns_cors_headers() {
        let response = handle_options().await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        for (name, value) in CORS_HEADERS {
            assert_eq!(
                response.headers().get(&name).map(|v| v.to_str().unwrap()),
                Some(value),
                "missing or wrong {name}"
            );
        }
    }
}
