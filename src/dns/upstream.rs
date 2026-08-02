use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use futures_util::future::select_ok;
use hickory_proto::op::Message;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::config::{UpstreamConfig, UpstreamStrategy};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// A single upstream resolver. Implemented by the real `SingleUpstream` and
/// by network-free test doubles (see `test_support`).
pub trait Upstream: Send + Sync {
    fn label(&self) -> &str;
    fn resolve(&self, query: &Message) -> impl Future<Output = Result<Message>> + Send;
}

/// Persistent, reusable DoT connection to one upstream, avoiding a fresh
/// TCP+TLS handshake per query (RFC 7858). No in-flight multiplexing — a
/// checked-out connection serves exactly one query before returning.
struct DotPool {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    /// At most one idle connection is kept warm for reuse. Concurrent
    /// queries beyond that each dial their own and it's closed (not kept)
    /// on checkin — public DoT resolvers close idle connections quickly
    /// (Cloudflare observed at ~5-10s), so a deeper idle pool barely
    /// improves the steady-state reuse rate and isn't worth the complexity.
    idle: Mutex<Option<TlsStream<TcpStream>>>,
}

impl DotPool {
    fn new(host: String, port: u16, server_name: ServerName<'static>, connector: TlsConnector) -> Self {
        Self {
            host,
            port,
            server_name,
            connector,
            idle: Mutex::new(None),
        }
    }

    /// Returns a connection plus whether it came from the idle slot (vs.
    /// freshly dialed) — a reused one gets a one-shot retry on failure.
    async fn checkout(&self) -> Result<(TlsStream<TcpStream>, bool)> {
        if let Some(conn) = self.idle.lock().unwrap().take() {
            return Ok((conn, true));
        }
        Ok((self.connect().await?, false))
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .with_context(|| format!("failed to connect to {}:{}", self.host, self.port))?;
        tcp.set_nodelay(true).ok();
        self.connector
            .connect(self.server_name.clone(), tcp)
            .await
            .context("TLS handshake with upstream failed")
    }

    /// Parks this connection in the idle slot for the next query, unless
    /// it's already occupied (a concurrent query's connection got there
    /// first), in which case this one is simply dropped/closed.
    fn checkin(&self, conn: TlsStream<TcpStream>) {
        let mut idle = self.idle.lock().unwrap();
        if idle.is_none() {
            *idle = Some(conn);
        }
    }
}

enum Backend {
    // Boxed so a live idle `TlsStream` (stored inline in `DotPool`, not
    // behind its own pointer, now that it's an `Option` rather than a `Vec`)
    // doesn't inflate every `Backend`/`SingleUpstream` value to DotPool's
    // size, including the `Doh` upstreams that don't need it.
    Dot(Box<DotPool>),
    Doh { url: String, http: reqwest::Client },
}

pub struct SingleUpstream {
    label: String,
    backend: Backend,
}

impl Upstream for SingleUpstream {
    fn label(&self) -> &str {
        &self.label
    }

    async fn resolve(&self, query: &Message) -> Result<Message> {
        let mut outgoing = query.clone();
        outgoing.metadata.id = rand::random();
        let wire = outgoing.to_vec().context("failed to encode upstream query")?;

        let response_bytes = match &self.backend {
            Backend::Dot(pool) => query_dot(pool, &wire).await?,
            Backend::Doh { url, http } => query_doh(http, url, &wire).await?,
        };

        let response = Message::from_vec(&response_bytes).context("failed to decode upstream response")?;
        if response.metadata.id != outgoing.metadata.id {
            bail!("upstream response ID mismatch");
        }
        Ok(response)
    }
}

impl<T: Upstream + ?Sized> Upstream for Arc<T> {
    fn label(&self) -> &str {
        (**self).label()
    }

    async fn resolve(&self, query: &Message) -> Result<Message> {
        (**self).resolve(query).await
    }
}

/// How `MultiUpstream` spreads a query across its configured upstreams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Try each upstream in order, falling back on failure or timeout.
    Sequential,
    /// Query every upstream at once, use whichever answers first.
    Race,
}

impl From<UpstreamStrategy> for Strategy {
    fn from(value: UpstreamStrategy) -> Self {
        match value {
            UpstreamStrategy::Sequential => Self::Sequential,
            UpstreamStrategy::Race => Self::Race,
        }
    }
}

/// Generic over `Upstream` so fallback/race selection logic can be tested
/// against fakes with no real network/TLS involved.
pub struct MultiUpstream<U> {
    upstreams: Vec<U>,
    strategy: Strategy,
}

impl<U: Upstream> MultiUpstream<U> {
    pub fn new(upstreams: Vec<U>, strategy: Strategy) -> Self {
        Self { upstreams, strategy }
    }

    /// Each attempt randomizes its own outgoing query ID; the caller's
    /// original ID is restored on the returned message.
    pub async fn resolve(&self, query: &Message) -> Result<Message> {
        let original_id = query.metadata.id;
        let mut response = match self.strategy {
            Strategy::Sequential => self.resolve_sequential(query).await,
            Strategy::Race => self.resolve_race(query).await,
        }?;
        response.metadata.id = original_id;
        Ok(response)
    }

    /// Falling back across N upstreams must not cost N times
    /// `UPSTREAM_TIMEOUT` — a client waiting on this query has its own
    /// timeout, and stacking a full timeout per upstream routinely blew past
    /// it, causing the client to give up and tear down the connection out
    /// from under us mid-response. Bound the whole sequential attempt by a
    /// single deadline instead, splitting it across however many upstreams
    /// there are to try.
    async fn resolve_sequential(&self, query: &Message) -> Result<Message> {
        let mut last_err = None;
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;

        for upstream in &self.upstreams {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                warn!(upstream = upstream.label(), "skipping upstream, overall query deadline already exceeded");
                last_err = Some(anyhow!("timed out querying {}", upstream.label()));
                break;
            }

            match timeout(remaining, upstream.resolve(query)).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(err)) => {
                    warn!(upstream = upstream.label(), error = format!("{err:#}"), "upstream query failed");
                    last_err = Some(err);
                }
                Err(_) => {
                    warn!(upstream = upstream.label(), "upstream query timed out");
                    last_err = Some(anyhow!("timed out querying {}", upstream.label()));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("no upstream resolvers configured")))
    }

    async fn resolve_race(&self, query: &Message) -> Result<Message> {
        if self.upstreams.is_empty() {
            bail!("no upstream resolvers configured");
        }

        let futures = self.upstreams.iter().map(|upstream| {
            let fut = async move {
                match timeout(UPSTREAM_TIMEOUT, upstream.resolve(query)).await {
                    Ok(Ok(response)) => Ok(response),
                    Ok(Err(err)) => {
                        warn!(upstream = upstream.label(), error = format!("{err:#}"), "upstream query failed (race)");
                        Err(err)
                    }
                    Err(_) => {
                        warn!(upstream = upstream.label(), "upstream query timed out (race)");
                        Err(anyhow!("timed out querying {}", upstream.label()))
                    }
                }
            };
            Box::pin(fut) as Pin<Box<dyn Future<Output = Result<Message>> + Send + '_>>
        });

        select_ok(futures).await.map(|(response, _still_running)| response)
    }
}

/// Builds the production upstream pool from parsed config.
pub fn build(configs: &[UpstreamConfig], strategy: UpstreamStrategy) -> Result<MultiUpstream<SingleUpstream>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(tls_config);

    let doh_http = reqwest::Client::builder()
        .user_agent(concat!("dns-rs/", env!("CARGO_PKG_VERSION")))
        .timeout(UPSTREAM_TIMEOUT)
        .build()
        .context("failed to build upstream DoH HTTP client")?;

    let mut upstreams = Vec::with_capacity(configs.len());
    for cfg in configs {
        let single = match cfg {
            UpstreamConfig::Dot { host, port, tls_name } => {
                let server_name = ServerName::try_from(tls_name.clone())
                    .with_context(|| format!("invalid upstream tls_name: {tls_name}"))?;
                SingleUpstream {
                    label: format!("dot://{host}:{port}"),
                    backend: Backend::Dot(Box::new(DotPool::new(host.clone(), *port, server_name, connector.clone()))),
                }
            }
            UpstreamConfig::Doh { url } => SingleUpstream {
                label: format!("doh://{url}"),
                backend: Backend::Doh {
                    url: url.clone(),
                    http: doh_http.clone(),
                },
            },
        };
        upstreams.push(single);
    }

    Ok(MultiUpstream::new(upstreams, strategy.into()))
}

async fn query_dot(pool: &DotPool, wire: &[u8]) -> Result<Vec<u8>> {
    let (mut conn, reused) = pool.checkout().await?;
    match exchange(&mut conn, wire).await {
        Ok(resp) => {
            pool.checkin(conn);
            Ok(resp)
        }
        // A pooled connection can go stale if the upstream closed it while idle;
        // retry exactly once against a guaranteed-fresh connection before giving up.
        Err(err) if reused => {
            warn!(error = format!("{err:#}"), "pooled DoT connection appears stale, reconnecting");
            let mut fresh = pool.connect().await?;
            let resp = exchange(&mut fresh, wire).await?;
            pool.checkin(fresh);
            Ok(resp)
        }
        Err(err) => Err(err),
    }
}

async fn exchange(tls: &mut TlsStream<TcpStream>, wire: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(wire.len()).context("query too large for DoT framing")?;
    tls.write_all(&len.to_be_bytes()).await?;
    tls.write_all(wire).await?;
    tls.flush().await?;

    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    tls.read_exact(&mut resp_buf).await?;
    Ok(resp_buf)
}

async fn query_doh(http: &reqwest::Client, url: &str, wire: &[u8]) -> Result<Vec<u8>> {
    match send_doh(http, url, wire).await {
        Ok(resp) => Ok(resp),
        // reqwest's pooled connections can go stale the same way DoT's can
        // (idle keep-alive closed by the server, mid-flight reset under load,
        // etc.); one retry lets reqwest dial a fresh connection instead of
        // failing the query outright. Don't retry real HTTP error statuses -
        // that's not a connection problem and won't fix itself.
        Err(err) if is_retryable(&err) => {
            warn!(upstream = url, error = describe_std_error(&err), "DoH connection failed, retrying once");
            send_doh(http, url, wire)
                .await
                .with_context(|| format!("DoH request to {url} failed (after retry)"))
        }
        Err(err) => Err(err).with_context(|| format!("DoH request to {url} failed")),
    }
}

fn is_retryable(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || err.is_request() || err.is_body()
}

/// `reqwest::Error`'s `Display` prints only its own top-level message (e.g.
/// "error sending request for url (...)") and ignores the alternate `{:#}`
/// flag, hiding the actual transport-level cause (broken pipe, connection
/// reset, timed out, ...) that `.source()` holds. Walk the chain by hand so
/// logs are actually actionable.
fn describe_std_error(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut cause = err.source();
    while let Some(err) = cause {
        parts.push(err.to_string());
        cause = err.source();
    }
    parts.join(": ")
}

async fn send_doh(http: &reqwest::Client, url: &str, wire: &[u8]) -> Result<Vec<u8>, reqwest::Error> {
    let resp = http
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire.to_vec())
        .send()
        .await?
        .error_for_status()?;
    Ok(resp.bytes().await?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration as StdDuration;

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{header, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::Router;
    use axum_server::tls_rustls::RustlsConfig;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::net::TcpListener;

    use crate::dns::test_support::TestUpstream as FakeUpstream;
    use crate::dns::test_tls;

    fn test_query() -> Message {
        let mut msg = Message::query();
        msg.metadata.id = 4242;
        msg.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
        msg
    }

    fn only_answer_ip(response: &Message) -> std::net::Ipv4Addr {
        match &response.answers[0].data {
            hickory_proto::rr::RData::A(a) => a.0,
            other => panic!("expected an A record, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sequential_falls_back_to_next_upstream_on_failure() {
        let bad = FakeUpstream::failing("bad");
        let good = FakeUpstream::answering("good", "10.0.0.1".parse().unwrap());
        let pool = MultiUpstream::new(vec![bad, good], Strategy::Sequential);

        let query = test_query();
        let response = pool.resolve(&query).await.expect("should fall back to the working upstream");

        assert_eq!(only_answer_ip(&response), "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(response.metadata.id, query.metadata.id, "caller's ID must be restored");
        assert_eq!(pool.upstreams[0].calls(), 1);
        assert_eq!(pool.upstreams[1].calls(), 1);
    }

    #[tokio::test]
    async fn sequential_does_not_try_later_upstreams_on_success() {
        let good = FakeUpstream::answering("good", "10.0.0.2".parse().unwrap());
        let never = FakeUpstream::answering("never", "10.0.0.3".parse().unwrap());
        let pool = MultiUpstream::new(vec![good, never], Strategy::Sequential);

        let response = pool.resolve(&test_query()).await.unwrap();

        assert_eq!(only_answer_ip(&response), "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(pool.upstreams[0].calls(), 1);
        assert_eq!(pool.upstreams[1].calls(), 0, "second upstream should never be queried after a success");
    }

    #[tokio::test]
    async fn sequential_fails_only_when_every_upstream_fails() {
        let pool = MultiUpstream::new(
            vec![FakeUpstream::failing("a"), FakeUpstream::failing("b")],
            Strategy::Sequential,
        );

        let err = pool.resolve(&test_query()).await.unwrap_err();
        assert!(err.to_string().contains('b'), "should surface the last upstream's error");
    }

    #[tokio::test]
    async fn race_returns_the_fastest_success() {
        let slow = FakeUpstream::answering("slow", "10.0.0.4".parse().unwrap()).with_delay(StdDuration::from_millis(200));
        let fast = FakeUpstream::answering("fast", "10.0.0.5".parse().unwrap());
        let pool = MultiUpstream::new(vec![slow, fast], Strategy::Race);

        let response = pool.resolve(&test_query()).await.unwrap();
        assert_eq!(only_answer_ip(&response), "10.0.0.5".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn race_falls_back_when_the_faster_upstream_fails() {
        let fast_but_broken = FakeUpstream::failing("fast_but_broken");
        let slower_but_working =
            FakeUpstream::answering("slower_but_working", "10.0.0.6".parse().unwrap()).with_delay(StdDuration::from_millis(50));
        let pool = MultiUpstream::new(vec![fast_but_broken, slower_but_working], Strategy::Race);

        let response = pool.resolve(&test_query()).await.unwrap();
        assert_eq!(only_answer_ip(&response), "10.0.0.6".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[tokio::test]
    async fn race_fails_only_when_every_upstream_fails() {
        let pool = MultiUpstream::new(
            vec![FakeUpstream::failing("a"), FakeUpstream::failing("b")],
            Strategy::Race,
        );

        assert!(pool.resolve(&test_query()).await.is_err());
    }

    #[tokio::test]
    async fn race_with_zero_upstreams_returns_an_error_instead_of_hanging() {
        let pool: MultiUpstream<FakeUpstream> = MultiUpstream::new(vec![], Strategy::Race);
        assert!(pool.resolve(&test_query()).await.is_err());
    }

    /// A minimal DoT-framed responder over a self-signed TLS listener:
    /// answers every well-formed query with a fixed A record. If
    /// `close_after_one` is set, the connection is dropped right after the
    /// first response (simulating a server that closed an idle keep-alive
    /// connection) instead of looping to serve more queries on it.
    async fn mock_dot_server(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor, accepts: Arc<AtomicUsize>, close_after_one: bool) {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            accepts.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                loop {
                    let mut len_buf = [0u8; 2];
                    if tls.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if tls.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let Ok(query) = Message::from_vec(&buf) else { return };
                    let mut response = Message::response(query.metadata.id, OpCode::Query);
                    response.add_query(query.queries[0].clone());
                    response.add_answer(Record::from_rdata(query.queries[0].name.clone(), 60, RData::A(A::from(Ipv4Addr::new(9, 9, 9, 9)))));
                    let wire = response.to_vec().unwrap();
                    let resp_len = (wire.len() as u16).to_be_bytes();
                    if tls.write_all(&resp_len).await.is_err() || tls.write_all(&wire).await.is_err() || tls.flush().await.is_err() {
                        return;
                    }
                    if close_after_one {
                        return; // dropping `tls` here closes the connection out from under the client's pool.
                    }
                }
            });
        }
    }

    #[tokio::test]
    async fn dot_pool_reconnects_after_a_stale_pooled_connection() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), true));

        let pool = DotPool::new("127.0.0.1".to_string(), addr.port(), tls.server_name, tls.connector);
        let wire = test_query().to_vec().unwrap();

        // Every one of these queries lands on a connection the server closes
        // right after answering, so every query after the first must hit
        // (and survive) the reused-but-stale retry path in `query_dot`.
        for _ in 0..5 {
            let resp_bytes = query_dot(&pool, &wire).await.expect("query should succeed despite the pooled connection going stale between queries");
            let resp = Message::from_vec(&resp_bytes).unwrap();
            assert_eq!(only_answer_ip(&resp), Ipv4Addr::new(9, 9, 9, 9));
        }
        assert!(
            accepts.load(Ordering::SeqCst) >= 5,
            "each stale reuse should have forced a fresh reconnect, got {} accepted connections",
            accepts.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn dot_pool_reuses_a_still_alive_idle_connection() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), false));

        let pool = DotPool::new("127.0.0.1".to_string(), addr.port(), tls.server_name, tls.connector);
        let wire = test_query().to_vec().unwrap();

        for _ in 0..5 {
            let resp_bytes = query_dot(&pool, &wire).await.unwrap();
            let resp = Message::from_vec(&resp_bytes).unwrap();
            assert_eq!(only_answer_ip(&resp), Ipv4Addr::new(9, 9, 9, 9));
        }
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "a healthy pooled connection should be reused, not redialed, for every query");
    }

    #[tokio::test]
    async fn dot_pool_keeps_only_one_idle_connection_across_a_concurrent_burst() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), false));

        let pool = DotPool::new("127.0.0.1".to_string(), addr.port(), tls.server_name, tls.connector);
        let wire = test_query().to_vec().unwrap();

        // Three concurrent queries all miss the (empty) idle slot, so each
        // must dial its own connection rather than blocking on one another.
        let (r1, r2, r3) = tokio::join!(query_dot(&pool, &wire), query_dot(&pool, &wire), query_dot(&pool, &wire));
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();
        let after_burst = accepts.load(Ordering::SeqCst);
        assert_eq!(after_burst, 3, "concurrent queries with no idle connection available must each dial their own, not queue");

        // A later serial query should reuse whichever single connection won
        // the race to check in, not dial a fourth.
        query_dot(&pool, &wire).await.unwrap();
        assert_eq!(accepts.load(Ordering::SeqCst), after_burst, "the idle slot should still hold one connection from the burst");
    }

    #[derive(Clone, Copy)]
    enum DohMockMode {
        /// First request's body fails mid-stream (as a live connection dying
        /// partway through a response would); every request after that
        /// succeeds normally.
        FailFirstBodyThenSucceed,
        /// Every request gets a real HTTP error status - not a transport
        /// problem, so `query_doh` must not retry it.
        AlwaysServerError,
    }

    async fn doh_mock_handler(State((counter, mode)): State<(Arc<AtomicUsize>, DohMockMode)>) -> Response {
        let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
        match mode {
            DohMockMode::AlwaysServerError => (StatusCode::INTERNAL_SERVER_ERROR, "mock upstream failure").into_response(),
            DohMockMode::FailFirstBodyThenSucceed if n == 1 => {
                let chunks: Vec<std::result::Result<axum::body::Bytes, std::io::Error>> = vec![
                    Ok(axum::body::Bytes::from_static(b"\x00\x01")),
                    Err(std::io::Error::other("simulated mid-body connection drop")),
                ];
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/dns-message")
                    .body(Body::from_stream(futures_util::stream::iter(chunks)))
                    .unwrap()
            }
            DohMockMode::FailFirstBodyThenSucceed => {
                (StatusCode::OK, [(header::CONTENT_TYPE, "application/dns-message")], b"good-response".to_vec()).into_response()
            }
        }
    }

    /// Binds a self-signed-TLS mock DoH server on an OS-assigned port and
    /// returns its address plus a shared counter of requests it has received.
    async fn spawn_doh_mock(tls_config: Arc<rustls::ServerConfig>, mode: DohMockMode) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route("/dns-query", post(doh_mock_handler)).with_state((Arc::clone(&counter), mode));

        let handle = axum_server::Handle::new();
        let rustls_config = RustlsConfig::from_config(tls_config);
        let bind_handle = handle.clone();
        tokio::spawn(async move {
            let _ = axum_server::bind_rustls("127.0.0.1:0".parse().unwrap(), rustls_config)
                .handle(bind_handle)
                .serve(app.into_make_service())
                .await;
        });
        let addr = handle.listening().await.expect("mock DoH server failed to bind");
        (addr, counter)
    }

    fn doh_test_client(tls: &test_tls::TestTls) -> reqwest::Client {
        let cert = reqwest::Certificate::from_pem(&tls.cert_pem).expect("failed to parse generated test cert as PEM");
        reqwest::Client::builder()
            .add_root_certificate(cert)
            .timeout(StdDuration::from_secs(5))
            .build()
            .expect("failed to build test reqwest client")
    }

    #[tokio::test]
    async fn doh_retries_once_after_a_body_read_failure_then_succeeds() {
        let tls = test_tls::generate("127.0.0.1");
        let http = doh_test_client(&tls);
        let (addr, counter) = spawn_doh_mock(tls.server_config, DohMockMode::FailFirstBodyThenSucceed).await;

        let url = format!("https://127.0.0.1:{}/dns-query", addr.port());
        let response = query_doh(&http, &url, b"query-bytes").await.expect("should succeed after retrying once");

        assert_eq!(response, b"good-response");
        assert_eq!(counter.load(Ordering::SeqCst), 2, "exactly one retry should have been attempted");
    }

    #[tokio::test]
    async fn doh_does_not_retry_a_real_http_error_status() {
        let tls = test_tls::generate("127.0.0.1");
        let http = doh_test_client(&tls);
        let (addr, counter) = spawn_doh_mock(tls.server_config, DohMockMode::AlwaysServerError).await;

        let url = format!("https://127.0.0.1:{}/dns-query", addr.port());
        let err = query_doh(&http, &url, b"query-bytes").await.expect_err("a real HTTP error status must surface as an error");

        assert_eq!(counter.load(Ordering::SeqCst), 1, "a real HTTP error status must not be retried");
        assert!(!format!("{err:#}").is_empty());
    }
}
