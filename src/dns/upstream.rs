use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

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
/// How many idle DoT connections to keep warm per upstream. Concurrent
/// queries beyond this just open extra connections rather than blocking;
/// only the idle *retention* is capped.
const MAX_IDLE_DOT_CONNECTIONS: usize = 8;

/// A single upstream resolver capable of answering a query. Implemented by
/// the real network-backed `SingleUpstream`, and by test doubles that never
/// touch the network — see `dns::upstream::tests` and `MultiUpstream`'s own
/// tests for how that's used to exercise fallback/race behavior directly.
pub trait Upstream: Send + Sync {
    fn label(&self) -> &str;
    fn resolve(&self, query: &Message) -> impl Future<Output = Result<Message>> + Send;
}

/// A small pool of persistent, reusable DoT connections to a single upstream.
/// RFC 7858 recommends keeping connections open rather than paying a fresh
/// TCP+TLS handshake per query, which otherwise dominates uncached query
/// latency. There's no in-flight multiplexing here (each checked-out
/// connection is used for exactly one query/response before being returned),
/// but avoiding the handshake on the warm path is the bulk of the win.
struct DotPool {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    idle: Mutex<Vec<TlsStream<TcpStream>>>,
}

impl DotPool {
    fn new(host: String, port: u16, server_name: ServerName<'static>, connector: TlsConnector) -> Self {
        Self {
            host,
            port,
            server_name,
            connector,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Returns a connection and whether it came from the idle pool (as
    /// opposed to being freshly dialed), so callers can decide whether a
    /// failure warrants a one-shot retry against a guaranteed-fresh connection.
    async fn checkout(&self) -> Result<(TlsStream<TcpStream>, bool)> {
        if let Some(conn) = self.idle.lock().unwrap().pop() {
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

    fn checkin(&self, conn: TlsStream<TcpStream>) {
        let mut idle = self.idle.lock().unwrap();
        if idle.len() < MAX_IDLE_DOT_CONNECTIONS {
            idle.push(conn);
        }
    }
}

enum Backend {
    Dot(DotPool),
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
    /// Try each upstream in order, falling back to the next on failure or
    /// timeout. One request in flight at a time.
    Sequential,
    /// Fire the query at every upstream at once and use whichever answers
    /// first. Lower worst-case latency and tolerant of any single upstream
    /// having a bad moment, at the cost of every query hitting every
    /// configured upstream.
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

/// An ordered list of configured upstream resolvers, queried according to
/// `strategy`. Generic over `Upstream` so the selection logic itself
/// (fallback ordering, race-first-wins) can be unit-tested against fake
/// upstreams with no real network/TLS involved.
pub struct MultiUpstream<U> {
    upstreams: Vec<U>,
    strategy: Strategy,
}

impl<U: Upstream> MultiUpstream<U> {
    pub fn new(upstreams: Vec<U>, strategy: Strategy) -> Self {
        Self { upstreams, strategy }
    }

    /// Forwards `query` per `strategy`. The outgoing query ID is randomized
    /// per attempt (by each `Upstream` impl) and the caller's original ID is
    /// restored on the returned message.
    pub async fn resolve(&self, query: &Message) -> Result<Message> {
        let original_id = query.metadata.id;
        let mut response = match self.strategy {
            Strategy::Sequential => self.resolve_sequential(query).await,
            Strategy::Race => self.resolve_race(query).await,
        }?;
        response.metadata.id = original_id;
        Ok(response)
    }

    async fn resolve_sequential(&self, query: &Message) -> Result<Message> {
        let mut last_err = None;

        for upstream in &self.upstreams {
            match timeout(UPSTREAM_TIMEOUT, upstream.resolve(query)).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(err)) => {
                    warn!(upstream = upstream.label(), error = %err, "upstream query failed");
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
                        warn!(upstream = upstream.label(), error = %err, "upstream query failed (race)");
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
                    backend: Backend::Dot(DotPool::new(host.clone(), *port, server_name, connector.clone())),
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
            warn!(error = %err, "pooled DoT connection appears stale, reconnecting");
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
    let resp = http
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire.to_vec())
        .send()
        .await
        .context("DoH request failed")?
        .error_for_status()
        .context("DoH upstream returned an error status")?;
    let bytes = resp.bytes().await.context("failed to read DoH response body")?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    use crate::dns::test_support::TestUpstream as FakeUpstream;

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
}
