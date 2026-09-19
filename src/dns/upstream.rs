use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures_util::future::select_ok;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::config::{UpstreamConfig, UpstreamStrategy};

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the preferred upstream gets to answer before a hedged query is
/// sent to the next one. Healthy nearby resolvers finish comfortably within
/// this; a slow one no longer owns the entire client-visible critical path.
const HEDGE_DELAY: Duration = Duration::from_millis(25);

/// How often an idle upstream DoH connection sends an HTTP/2 PING. Well
/// under the ~30-60s public resolvers take to reap an idle connection, so
/// the connection stays established between query bursts.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// How long a keepalive PING may go unanswered before the connection is
/// considered dead and dropped from the pool - on the keepalive's own
/// timeline rather than on a query's.
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// DoT has no transport-level PING equivalent. Send a tiny root-NS query on
/// idle connections at the same cadence as the DoH h2 PING so the upstream
/// doesn't reap them between real query bursts.
const DOT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// A single upstream resolver. Implemented by the real `SingleUpstream` and
/// by network-free test doubles (see `test_support`).
pub trait Upstream: Send + Sync {
    fn label(&self) -> &str;
    fn resolve(&self, query: &Message) -> impl Future<Output = Result<Message>> + Send;
}

/// How many idle DoT connections are kept warm per upstream. A single slot
/// meant any burst of concurrent queries past the first had to dial its own
/// connection and then throw it away on checkin, paying a full TCP+TLS
/// handshake (two round trips to a public resolver, so tens of
/// milliseconds) on every query in the burst. Keeping a few lets a burst
/// reuse what the previous burst established.
///
/// Small on purpose: public DoT resolvers close idle connections within
/// seconds, so connections beyond the working set go stale before they're
/// reused and cost a reconnect anyway.
const MAX_IDLE_DOT_CONNECTIONS: usize = 8;

/// Persistent, reusable DoT connection to one upstream, avoiding a fresh
/// TCP+TLS handshake per query (RFC 7858). No in-flight multiplexing — a
/// checked-out connection serves exactly one query before returning.
struct DotPool {
    host: String,
    port: u16,
    addresses: Box<[SocketAddr]>,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    /// Up to `MAX_IDLE_DOT_CONNECTIONS` are kept warm for reuse. Used as a
    /// stack (take and return at the end) so the most-recently-used
    /// connection is handed out first: that's the one least likely to have
    /// been closed by the upstream while idle.
    idle: Mutex<Vec<TlsStream<TcpStream>>>,
}

impl DotPool {
    fn new(
        host: String,
        port: u16,
        addresses: Box<[SocketAddr]>,
        server_name: ServerName<'static>,
        connector: TlsConnector,
    ) -> Self {
        Self {
            host,
            port,
            addresses,
            server_name,
            connector,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Returns a connection plus whether it came from the idle pool (vs.
    /// freshly dialed) — a reused one gets a one-shot retry on failure.
    async fn checkout(&self) -> Result<(TlsStream<TcpStream>, bool)> {
        if let Some(conn) = self.idle.lock().unwrap().pop() {
            return Ok((conn, true));
        }
        Ok((self.connect().await?, false))
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        // `addresses` was resolved once while the state was built. Calling
        // `TcpStream::connect((host, port))` here would run `getaddrinfo` for
        // every new connection, putting a blocking system-DNS lookup in
        // front of the TCP+TLS handshake on a cache miss. It can also become
        // circular when the host's resolver points back at this server.
        let tcp = TcpStream::connect(&*self.addresses)
            .await
            .with_context(|| format!("failed to connect to {}:{}", self.host, self.port))?;
        tcp.set_nodelay(true).ok();
        self.connector
            .connect(self.server_name.clone(), tcp)
            .await
            .context("TLS handshake with upstream failed")
    }

    /// Parks this connection for the next query, unless the pool is already
    /// at capacity, in which case it's simply dropped/closed.
    fn checkin(&self, conn: TlsStream<TcpStream>) {
        let mut idle = self.idle.lock().unwrap();
        if idle.len() < MAX_IDLE_DOT_CONNECTIONS {
            idle.push(conn);
        }
    }

    /// Keeps every currently-idle connection alive without delaying real
    /// queries. Each connection is checked out before its probe, so a client
    /// arriving concurrently either takes another idle connection or dials;
    /// it never waits behind keepalive traffic on the same stream.
    async fn keepalive(&self) {
        let count = self.idle.lock().unwrap().len();
        let mut connections = Vec::with_capacity(count);
        {
            let mut idle = self.idle.lock().unwrap();
            for _ in 0..count {
                if let Some(conn) = idle.pop() {
                    connections.push(conn);
                }
            }
        }

        let mut probe = Message::query();
        probe.metadata.id = rand::random();
        probe.add_query(Query::query(Name::root(), RecordType::NS));
        let Ok(wire) = probe.to_vec() else { return };

        for mut conn in connections {
            match timeout(H2_KEEPALIVE_TIMEOUT, exchange(&mut conn, &wire)).await {
                Ok(Ok(response)) if Message::from_vec(&response).is_ok() => self.checkin(conn),
                _ => debug!(upstream = %self.host, "dropping dead idle DoT connection during keepalive"),
            }
        }
    }
}

fn start_dot_keepalive(pool: &Arc<DotPool>) {
    let pool = Arc::downgrade(pool);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DOT_KEEPALIVE_INTERVAL);
        interval.tick().await; // tokio intervals fire the first tick immediately
        loop {
            interval.tick().await;
            let Some(pool) = pool.upgrade() else { return };
            pool.keepalive().await;
        }
    });
}

enum Backend {
    // Shared because the keepalive task holds only a `Weak<DotPool>`: that
    // lets it inspect idle connections without extending this backend's
    // lifetime across a config reload.
    Dot(Arc<DotPool>),
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
            // `Bytes` instead of `&[u8]`: reqwest's request body needs
            // ownership, and the retry-once path in query_doh needs the
            // same bytes twice - wrapping once here (no copy, just takes
            // the Vec's buffer) means both uses are a cheap refcount clone
            // instead of each paying their own full byte copy.
            Backend::Doh { url, http } => query_doh(http, url, Bytes::from(wire)).await?,
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
    /// Start in order with `HEDGE_DELAY` between attempts; use the first
    /// successful answer.
    Hedged,
    /// Query every upstream at once, use whichever answers first.
    Race,
}

impl From<UpstreamStrategy> for Strategy {
    fn from(value: UpstreamStrategy) -> Self {
        match value {
            UpstreamStrategy::Sequential => Self::Sequential,
            UpstreamStrategy::Hedged => Self::Hedged,
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

impl SingleUpstream {
    /// Establishes this upstream's connection before any client needs it, so
    /// the first real query doesn't pay the TCP+TLS handshake itself.
    ///
    /// A probe query rather than a bare dial: reqwest has no connect-only
    /// API, so for DoH the only way to get a pooled connection established
    /// is to actually send something. `. NS` is the smallest universally-
    /// answered query there is, and using the same path for DoT keeps one
    /// code path instead of two.
    async fn warm(&self) -> Result<()> {
        let mut probe = Message::query();
        probe.add_query(Query::query(Name::root(), RecordType::NS));
        self.resolve(&probe).await.map(|_| ())
    }
}

impl MultiUpstream<SingleUpstream> {
    /// Dials every upstream up front so the first client query doesn't pay a
    /// handshake that a background task could have paid instead.
    ///
    /// Failures are logged, not returned: an upstream being unreachable at
    /// startup is exactly the case the fallback/race logic exists to handle,
    /// and it must not keep the server from coming up.
    pub async fn warm_all(&self) {
        futures_util::future::join_all(self.upstreams.iter().map(|upstream| async move {
            match upstream.warm().await {
                Ok(()) => debug!(upstream = upstream.label(), "upstream connection warmed"),
                Err(err) => warn!(
                    upstream = upstream.label(),
                    error = format!("{err:#}"),
                    "failed to warm upstream connection, leaving it to the first query"
                ),
            }
        }))
        .await;
    }
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
            Strategy::Hedged => self.resolve_hedged(query).await,
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

    /// Gives the preferred upstream a short head start, then introduces each
    /// fallback in order. Unlike `Race`, the common case sends only one
    /// request; unlike `Sequential`, one slow-but-not-failed upstream cannot
    /// consume the whole client-visible timeout before a healthy fallback is
    /// tried.
    async fn resolve_hedged(&self, query: &Message) -> Result<Message> {
        if self.upstreams.is_empty() {
            bail!("no upstream resolvers configured");
        }

        let futures = self.upstreams.iter().enumerate().map(|(index, upstream)| {
            let fut = async move {
                if index > 0 {
                    tokio::time::sleep(HEDGE_DELAY * index as u32).await;
                }
                match upstream.resolve(query).await {
                    Ok(response) => Ok(response),
                    Err(err) => {
                        warn!(upstream = upstream.label(), error = format!("{err:#}"), "upstream query failed (hedged)");
                        Err(err)
                    }
                }
            };
            Box::pin(fut) as Pin<Box<dyn Future<Output = Result<Message>> + Send + '_>>
        });

        match timeout(UPSTREAM_TIMEOUT, select_ok(futures)).await {
            Ok(result) => result.map(|(response, _still_running)| response),
            Err(_) => bail!("all hedged upstream queries timed out"),
        }
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

/// Builds the production upstream pool from parsed config. Every hostname is
/// resolved here once and pinned into its transport; reconnects then go
/// straight to those addresses instead of putting a system-DNS lookup in
/// front of every fresh TCP connection.
pub async fn build(configs: &[UpstreamConfig], strategy: UpstreamStrategy) -> Result<MultiUpstream<SingleUpstream>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(tls_config);

    // One reqwest client is still shared by every DoH upstream so its h2
    // pool stays shared too. Each configured host gets a resolver override;
    // reqwest copies these addresses into the builder, so the temporary Vecs
    // can be dropped after each iteration.
    let mut doh_builder = reqwest::Client::builder()
        .user_agent(concat!("dns-rs/", env!("CARGO_PKG_VERSION")))
        .timeout(UPSTREAM_TIMEOUT)
        // Public DoH resolvers drop idle h2 connections quickly. Without
        // these, a query arriving after a lull pays a fresh TCP+TLS
        // handshake - or worse, discovers the connection is dead only on
        // send and eats the `query_doh` retry on top. PINGing while idle
        // keeps the connection established and lets the pool notice a dead
        // one out-of-band instead of on a client's critical path.
        .http2_keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .http2_keep_alive_timeout(H2_KEEPALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true)
        // Keepalive is what actually holds the connection open now, so
        // don't let the pool's own idle timer reap a healthy one first.
        .pool_idle_timeout(None);
    for cfg in configs {
        if let UpstreamConfig::Doh { url } = cfg {
            let parsed = reqwest::Url::parse(url).with_context(|| format!("invalid upstream DoH URL: {url}"))?;
            let host = parsed.host_str().ok_or_else(|| anyhow!("upstream DoH URL has no host: {url}"))?;
            if host.parse::<std::net::IpAddr>().is_err() {
                let addresses = resolve_addresses(host, parsed.port_or_known_default().unwrap_or(443)).await?;
                doh_builder = doh_builder.resolve_to_addrs(host, &addresses);
            }
        }
    }
    let doh_http = doh_builder.build().context("failed to build upstream DoH HTTP client")?;

    let mut upstreams = Vec::with_capacity(configs.len());
    for cfg in configs {
        let single = match cfg {
            UpstreamConfig::Dot { host, port, tls_name } => {
                let server_name = ServerName::try_from(tls_name.clone())
                    .with_context(|| format!("invalid upstream tls_name: {tls_name}"))?;
                let addresses = resolve_addresses(host, *port).await?.into_boxed_slice();
                let pool = Arc::new(DotPool::new(
                    host.clone(),
                    *port,
                    addresses,
                    server_name,
                    connector.clone(),
                ));
                start_dot_keepalive(&pool);
                SingleUpstream {
                    label: format!("dot://{host}:{port}"),
                    backend: Backend::Dot(pool),
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

async fn resolve_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addresses: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve upstream host {host}"))?
        .collect();
    if addresses.is_empty() {
        bail!("upstream host {host} resolved to no addresses");
    }
    Ok(addresses)
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
    // One write for the length prefix + body, rather than two, so it's a
    // single TCP segment instead of two back-to-back ones (same reasoning
    // as the server side's framing in server::dot::handle_connection).
    let mut framed = Vec::with_capacity(2 + wire.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(wire);
    tls.write_all(&framed).await?;
    tls.flush().await?;

    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    tls.read_exact(&mut resp_buf).await?;
    Ok(resp_buf)
}

async fn query_doh(http: &reqwest::Client, url: &str, wire: Bytes) -> Result<Vec<u8>> {
    // Only clone (a cheap refcount bump, not a byte copy) if a retry might
    // need the same payload again; the original `wire` stays intact for
    // that second attempt without ever copying the bytes twice.
    match send_doh(http, url, wire.clone()).await {
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

async fn send_doh(http: &reqwest::Client, url: &str, wire: Bytes) -> Result<Vec<u8>, reqwest::Error> {
    let resp = http
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire)
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

    #[cfg(feature = "doh-tls")]
    use axum::body::Body;
    #[cfg(feature = "doh-tls")]
    use axum::extract::State;
    #[cfg(feature = "doh-tls")]
    use axum::http::{header, StatusCode};
    #[cfg(feature = "doh-tls")]
    use axum::response::{IntoResponse, Response};
    #[cfg(feature = "doh-tls")]
    use axum::routing::post;
    #[cfg(feature = "doh-tls")]
    use axum::Router;
    #[cfg(feature = "doh-tls")]
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
    async fn hedged_does_not_touch_fallback_when_preferred_answers_within_head_start() {
        let preferred = FakeUpstream::answering("preferred", "1.1.1.1".parse().unwrap());
        let fallback = FakeUpstream::answering("fallback", "9.9.9.9".parse().unwrap());
        let pool = MultiUpstream::new(vec![preferred, fallback], Strategy::Hedged);

        let response = pool.resolve(&test_query()).await.unwrap();

        assert_eq!(only_answer_ip(&response), "1.1.1.1".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(pool.upstreams[0].calls(), 1);
        assert_eq!(
            pool.upstreams[1].calls(),
            0,
            "a prompt preferred answer must cancel the delayed fallback before it sends duplicate upstream traffic"
        );
    }

    #[tokio::test]
    async fn hedged_uses_fallback_without_waiting_for_slow_preferred() {
        let preferred = FakeUpstream::answering("preferred", "1.1.1.1".parse().unwrap()).with_delay(StdDuration::from_millis(200));
        let fallback = FakeUpstream::answering("fallback", "9.9.9.9".parse().unwrap());
        let pool = MultiUpstream::new(vec![preferred, fallback], Strategy::Hedged);

        let started = Instant::now();
        let response = pool.resolve(&test_query()).await.unwrap();

        assert_eq!(only_answer_ip(&response), "9.9.9.9".parse::<std::net::Ipv4Addr>().unwrap());
        assert!(
            started.elapsed() < StdDuration::from_millis(150),
            "fallback should win shortly after the hedge delay rather than waiting 200ms for the preferred upstream"
        );
        assert_eq!(pool.upstreams[0].calls(), 1);
        assert_eq!(pool.upstreams[1].calls(), 1);
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

        let pool = DotPool::new("127.0.0.1".to_string(), addr.port(), vec![addr].into_boxed_slice(), tls.server_name, tls.connector);
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
    async fn dot_keepalive_removes_connections_the_upstream_closed_while_idle() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), true));

        let pool = DotPool::new(
            "127.0.0.1".to_string(),
            addr.port(),
            vec![addr].into_boxed_slice(),
            tls.server_name,
            tls.connector,
        );
        query_dot(&pool, &test_query().to_vec().unwrap()).await.unwrap();
        assert_eq!(pool.idle.lock().unwrap().len(), 1, "the answered connection should initially be parked as idle");

        // The mock closed its side immediately after answering. The probe
        // must discover that before a real query checks this connection out.
        pool.keepalive().await;
        assert_eq!(
            pool.idle.lock().unwrap().len(),
            0,
            "a connection that fails its keepalive probe must not go back into the idle pool"
        );
    }

    #[tokio::test]
    async fn dot_pool_reuses_a_still_alive_idle_connection() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), false));

        let pool = DotPool::new("127.0.0.1".to_string(), addr.port(), vec![addr].into_boxed_slice(), tls.server_name, tls.connector);
        let wire = test_query().to_vec().unwrap();

        for _ in 0..5 {
            let resp_bytes = query_dot(&pool, &wire).await.unwrap();
            let resp = Message::from_vec(&resp_bytes).unwrap();
            assert_eq!(only_answer_ip(&resp), Ipv4Addr::new(9, 9, 9, 9));
        }
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "a healthy pooled connection should be reused, not redialed, for every query");
    }

    #[tokio::test]
    async fn dot_pool_keeps_every_connection_from_a_concurrent_burst_for_reuse() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), false));

        let pool = DotPool::new("127.0.0.1".to_string(), addr.port(), vec![addr].into_boxed_slice(), tls.server_name, tls.connector);
        let wire = test_query().to_vec().unwrap();

        // Three concurrent queries all find the idle pool empty, so each
        // must dial its own connection rather than blocking on one another.
        let (r1, r2, r3) = tokio::join!(query_dot(&pool, &wire), query_dot(&pool, &wire), query_dot(&pool, &wire));
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();
        let after_burst = accepts.load(Ordering::SeqCst);
        assert_eq!(after_burst, 3, "concurrent queries with no idle connection available must each dial their own, not queue");

        // All three should have been kept, so a second identical burst is
        // served entirely from the pool without dialing again - this is the
        // whole point of a pool deeper than one slot.
        let (r1, r2, r3) = tokio::join!(query_dot(&pool, &wire), query_dot(&pool, &wire), query_dot(&pool, &wire));
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            after_burst,
            "a repeat burst should reuse the connections the first burst established, not redial"
        );
    }

    #[tokio::test]
    async fn dot_pool_does_not_keep_more_than_its_idle_ceiling() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), false));

        let pool = DotPool::new("127.0.0.1".to_string(), addr.port(), vec![addr].into_boxed_slice(), tls.server_name, tls.connector);
        let wire = test_query().to_vec().unwrap();

        // A burst wider than the ceiling: every query still gets served, but
        // the pool must not grow without bound holding all of them open.
        let burst = MAX_IDLE_DOT_CONNECTIONS + 4;
        let results = futures_util::future::join_all((0..burst).map(|_| query_dot(&pool, &wire))).await;
        for result in results {
            result.expect("every query in an oversized burst should still be answered");
        }

        assert_eq!(
            pool.idle.lock().unwrap().len(),
            MAX_IDLE_DOT_CONNECTIONS,
            "the idle pool must cap at its ceiling and close the excess rather than hold every connection a burst opened"
        );
    }

    #[tokio::test]
    async fn warm_all_establishes_a_connection_before_any_client_query() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), false));

        let upstream = SingleUpstream {
            label: "dot://test".to_string(),
            backend: Backend::Dot(Arc::new(DotPool::new(
                "127.0.0.1".to_string(),
                addr.port(),
                vec![addr].into_boxed_slice(),
                tls.server_name,
                tls.connector,
            ))),
        };
        let pool = MultiUpstream::new(vec![upstream], Strategy::Sequential);

        pool.warm_all().await;
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "warming should have dialed the upstream");

        // The warmed connection must be parked for reuse, not left dangling:
        // a real query after warming should not dial a second time.
        pool.resolve(&test_query()).await.unwrap();
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "the first real query should reuse the warmed connection, not redial");
    }

    #[tokio::test]
    async fn warm_all_survives_an_unreachable_upstream() {
        // Port 1 on loopback: nothing listening, so the dial fails fast.
        let unreachable = SingleUpstream {
            label: "dot://unreachable".to_string(),
            backend: Backend::Dot(Arc::new(DotPool::new(
                "127.0.0.1".to_string(),
                1,
                vec!["127.0.0.1:1".parse().unwrap()].into_boxed_slice(),
                ServerName::try_from("localhost").unwrap(),
                TlsConnector::from(Arc::new(
                    rustls::ClientConfig::builder().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth(),
                )),
            ))),
        };
        let pool = MultiUpstream::new(vec![unreachable], Strategy::Sequential);

        // Must return rather than propagate: an upstream that's down at
        // startup is exactly what the fallback logic exists for, and it
        // must never keep the server from coming up.
        pool.warm_all().await;
    }

    #[cfg(feature = "doh-tls")]
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

    #[cfg(feature = "doh-tls")]
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

    #[cfg(feature = "doh-tls")]
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

    #[cfg(feature = "doh-tls")]
    fn doh_test_client(tls: &test_tls::TestTls) -> reqwest::Client {
        let cert = reqwest::Certificate::from_pem(&tls.cert_pem).expect("failed to parse generated test cert as PEM");
        reqwest::Client::builder()
            .add_root_certificate(cert)
            .timeout(StdDuration::from_secs(5))
            .build()
            .expect("failed to build test reqwest client")
    }

    #[cfg(feature = "doh-tls")]
    #[tokio::test]
    async fn doh_retries_once_after_a_body_read_failure_then_succeeds() {
        let tls = test_tls::generate("127.0.0.1");
        let http = doh_test_client(&tls);
        let (addr, counter) = spawn_doh_mock(tls.server_config, DohMockMode::FailFirstBodyThenSucceed).await;

        let url = format!("https://127.0.0.1:{}/dns-query", addr.port());
        let response = query_doh(&http, &url, Bytes::from_static(b"query-bytes")).await.expect("should succeed after retrying once");

        assert_eq!(response, b"good-response");
        assert_eq!(counter.load(Ordering::SeqCst), 2, "exactly one retry should have been attempted");
    }

    #[cfg(feature = "doh-tls")]
    #[tokio::test]
    async fn doh_does_not_retry_a_real_http_error_status() {
        let tls = test_tls::generate("127.0.0.1");
        let http = doh_test_client(&tls);
        let (addr, counter) = spawn_doh_mock(tls.server_config, DohMockMode::AlwaysServerError).await;

        let url = format!("https://127.0.0.1:{}/dns-query", addr.port());
        let err = query_doh(&http, &url, Bytes::from_static(b"query-bytes")).await.expect_err("a real HTTP error status must surface as an error");

        assert_eq!(counter.load(Ordering::SeqCst), 1, "a real HTTP error status must not be retried");
        assert!(!format!("{err:#}").is_empty());
    }
}
