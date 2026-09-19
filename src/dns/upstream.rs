use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures_util::future::select_ok;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use rustc_hash::FxHashMap;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, OwnedSemaphorePermit, RwLock, Semaphore};
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

const MAX_DOT_CONNECTIONS: usize = 2;
const MAX_DOT_IN_FLIGHT: usize = 256;
const ADDRESS_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(2);
const DOT_RESPONSE_BODY_TIMEOUT: Duration = Duration::from_secs(5);

type DotReply = std::result::Result<Message, DotFailure>;

#[derive(Debug, Clone)]
enum DotFailure {
    Connection(String),
    Protocol(String),
}

impl std::fmt::Display for DotFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(message) | Self::Protocol(message) => formatter.write_str(message),
        }
    }
}

struct PendingQuery {
    reply: oneshot::Sender<DotReply>,
    expected_queries: Vec<Query>,
    _permit: OwnedSemaphorePermit,
}

struct PendingQueryGuard {
    connection: Arc<DotConnection>,
    id: Option<u16>,
}

impl Drop for PendingQueryGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.connection.pending.lock().unwrap().remove(&id);
        }
    }
}

struct DotConnection {
    writes: mpsc::UnboundedSender<Vec<u8>>,
    pending: Mutex<FxHashMap<u16, PendingQuery>>,
    capacity: Arc<Semaphore>,
    last_used: AtomicU64,
    dead: AtomicBool,
}

impl DotConnection {
    fn start(tls: TlsStream<TcpStream>) -> Arc<Self> {
        let (reader, writer) = tokio::io::split(tls);
        let (writes, write_rx) = mpsc::unbounded_channel();
        let connection = Arc::new(Self {
            writes,
            pending: Mutex::new(FxHashMap::default()),
            capacity: Arc::new(Semaphore::new(MAX_DOT_IN_FLIGHT)),
            last_used: AtomicU64::new(monotonic_millis()),
            dead: AtomicBool::new(false),
        });
        tokio::spawn(dot_writer(Arc::downgrade(&connection), writer, write_rx));
        tokio::spawn(dot_reader(Arc::downgrade(&connection), reader));
        connection
    }

    fn is_alive(&self) -> bool {
        !self.dead.load(Ordering::Acquire)
    }

    fn try_reserve(self: &Arc<Self>) -> Option<OwnedSemaphorePermit> {
        self.capacity.clone().try_acquire_owned().ok()
    }

    async fn query(self: &Arc<Self>, query: &Message, permit: OwnedSemaphorePermit) -> DotReply {
        if !self.is_alive() {
            return Err(DotFailure::Connection("DoT connection closed".to_string()));
        }

        self.last_used.store(monotonic_millis(), Ordering::Release);
        let (reply_tx, reply_rx) = oneshot::channel();
        let mut outgoing = query.clone();
        let mut frame;
        let id;
        {
            let mut pending = self.pending.lock().unwrap();
            if !self.is_alive() {
                return Err(DotFailure::Connection("DoT connection closed".to_string()));
            }

            id = next_available_id(&pending, rand::random());
            outgoing.metadata.id = id;
            let wire = outgoing
                .to_vec()
                .map_err(|err| DotFailure::Protocol(format!("failed to encode upstream query: {err}")))?;
            let len = u16::try_from(wire.len())
                .map_err(|_| DotFailure::Protocol("query too large for DoT framing".to_string()))?;
            frame = Vec::with_capacity(2 + wire.len());
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&wire);
            pending.insert(
                id,
                PendingQuery {
                    reply: reply_tx,
                    expected_queries: std::mem::take(&mut outgoing.queries),
                    _permit: permit,
                },
            );
        }
        let mut guard = PendingQueryGuard {
            connection: Arc::clone(self),
            id: Some(id),
        };
        if self.writes.send(frame).is_err() {
            self.fail(DotFailure::Connection("DoT writer stopped".to_string()));
        }

        let result = match reply_rx.await {
            Ok(result) => result,
            Err(_) => Err(DotFailure::Connection("DoT connection closed".to_string())),
        };
        guard.id = None;
        result
    }

    fn was_idle_for(&self, duration: Duration) -> bool {
        monotonic_millis().saturating_sub(self.last_used.load(Ordering::Acquire))
            >= duration.as_millis() as u64
    }

    fn fail(&self, error: DotFailure) {
        if self.dead.swap(true, Ordering::AcqRel) {
            return;
        }
        for (_, pending) in self.pending.lock().unwrap().drain() {
            let _ = pending.reply.send(Err(error.clone()));
        }
    }
}

fn monotonic_millis() -> u64 {
    static STARTED: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    STARTED.get_or_init(Instant::now).elapsed().as_millis() as u64
}

fn next_available_id<T>(pending: &FxHashMap<u16, T>, start: u16) -> u16 {
    (start..=u16::MAX)
        .chain(0..start)
        .find(|id| !pending.contains_key(id))
        .expect("DoT in-flight limit keeps ID space from filling")
}

async fn dot_writer(
    connection: std::sync::Weak<DotConnection>,
    mut writer: WriteHalf<TlsStream<TcpStream>>,
    mut writes: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(frame) = writes.recv().await {
        let result = async {
            writer.write_all(&frame).await?;
            writer.flush().await
        }
        .await;
        if let Err(err) = result {
            if let Some(connection) = connection.upgrade() {
                connection.fail(DotFailure::Connection(format!("failed to write DoT query: {err}")));
            }
            return;
        }
    }
}

async fn dot_reader(connection: std::sync::Weak<DotConnection>, mut reader: ReadHalf<TlsStream<TcpStream>>) {
    loop {
        let mut len = [0u8; 2];
        if let Err(err) = reader.read_exact(&mut len).await {
            if let Some(connection) = connection.upgrade() {
                connection.fail(DotFailure::Connection(format!("failed to read DoT response length: {err}")));
            }
            return;
        }
        let mut wire = vec![0u8; u16::from_be_bytes(len) as usize];
        if wire.is_empty() {
            if let Some(connection) = connection.upgrade() {
                connection.fail(DotFailure::Protocol("empty DoT response".to_string()));
            }
            return;
        }
        match timeout(DOT_RESPONSE_BODY_TIMEOUT, reader.read_exact(&mut wire)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                if let Some(connection) = connection.upgrade() {
                    connection.fail(DotFailure::Connection(format!("failed to read DoT response: {err}")));
                }
                return;
            }
            Err(_) => {
                if let Some(connection) = connection.upgrade() {
                    connection.fail(DotFailure::Connection("timed out reading DoT response".to_string()));
                }
                return;
            }
        }
        let response = match Message::from_vec(&wire) {
            Ok(response) => response,
            Err(err) => {
                if let Some(connection) = connection.upgrade() {
                    connection.fail(DotFailure::Protocol(format!("invalid DoT response: {err}")));
                }
                return;
            }
        };
        let Some(connection) = connection.upgrade() else { return };
        let pending = connection.pending.lock().unwrap().remove(&response.metadata.id);
        match pending {
            Some(pending) if response.queries == pending.expected_queries => {
                let _ = pending.reply.send(Ok(response));
            }
            Some(pending) => {
                let error = DotFailure::Protocol(format!(
                    "DoT response question mismatch for ID {}",
                    response.metadata.id
                ));
                let _ = pending.reply.send(Err(error));
                connection.fail(DotFailure::Connection(
                    "DoT connection closed after response question mismatch".to_string(),
                ));
                return;
            }
            None => {
                connection.fail(DotFailure::Protocol(format!(
                    "unexpected DoT response ID {}",
                    response.metadata.id
                )));
                return;
            }
        }
    }
}

struct DotPool {
    host: String,
    port: u16,
    addresses: RwLock<Box<[SocketAddr]>>,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    connections: AsyncMutex<Vec<Arc<DotConnection>>>,
    dialing: AsyncMutex<()>,
}

impl DotPool {
    fn new(host: String, port: u16, addresses: Box<[SocketAddr]>, server_name: ServerName<'static>, connector: TlsConnector) -> Self {
        Self {
            host,
            port,
            addresses: RwLock::new(addresses),
            server_name,
            connector,
            connections: AsyncMutex::new(Vec::new()),
            dialing: AsyncMutex::new(()),
        }
    }

    async fn connection(self: &Arc<Self>) -> Result<(Arc<DotConnection>, OwnedSemaphorePermit)> {
        loop {
            {
                let mut connections = self.connections.lock().await;
                connections.retain(|connection| connection.is_alive());
                if let Some(pair) = connections
                    .iter()
                    .find_map(|connection| connection.try_reserve().map(|permit| (Arc::clone(connection), permit)))
                {
                    return Ok(pair);
                }
                if connections.len() >= MAX_DOT_CONNECTIONS {
                    let waits: Vec<_> = connections
                        .iter()
                        .map(|connection| {
                            let connection = Arc::clone(connection);
                            Box::pin(async move {
                                let permit = connection.capacity.clone().acquire_owned().await;
                                (connection, permit)
                            })
                        })
                        .collect();
                    drop(connections);
                    let ((connection, permit), _, _) = futures_util::future::select_all(waits).await;
                    let permit = permit.map_err(|_| anyhow!("DoT connection closed"))?;
                    if connection.is_alive() {
                        return Ok((connection, permit));
                    }
                    continue;
                }
            }

            let _dialing = self.dialing.lock().await;
            let mut connections = self.connections.lock().await;
            connections.retain(|connection| connection.is_alive());
            if let Some(pair) = connections
                .iter()
                .find_map(|connection| connection.try_reserve().map(|permit| (Arc::clone(connection), permit)))
            {
                return Ok(pair);
            }
            if connections.len() < MAX_DOT_CONNECTIONS {
                drop(connections);
                let connection = DotConnection::start(self.connect().await?);
                let permit = connection
                    .try_reserve()
                    .ok_or_else(|| anyhow!("new DoT connection has no capacity"))?;
                self.connections.lock().await.push(Arc::clone(&connection));
                return Ok((connection, permit));
            }
        }
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        let cached = self.addresses.read().await.clone();
        if !cached.is_empty() {
            return self.connect_to(&cached).await;
        }

        let refreshed = resolve_addresses(&self.host, self.port).await?;
        *self.addresses.write().await = refreshed.clone().into_boxed_slice();
        self.connect_to(&refreshed).await
    }

    async fn connect_to(&self, addresses: &[SocketAddr]) -> Result<TlsStream<TcpStream>> {
        if addresses.is_empty() {
            bail!("upstream host {} has no cached addresses", self.host);
        }
        let tcp = TcpStream::connect(addresses)
            .await
            .with_context(|| format!("failed to connect to {}:{}", self.host, self.port))?;
        tcp.set_nodelay(true).ok();
        self.connector
            .connect(self.server_name.clone(), tcp)
            .await
            .context("TLS handshake with upstream failed")
    }

    async fn query(self: &Arc<Self>, query: &Message) -> Result<Message> {
        let mut retried = false;
        loop {
            let (connection, permit) = self.connection().await?;
            match connection.query(query, permit).await {
                Ok(response) => return Ok(response),
                Err(DotFailure::Connection(err)) if !retried => {
                    retried = true;
                    warn!(error = %err, "DoT connection failed, retrying once");
                }
                Err(err) => return Err(anyhow!(err)),
            }
        }
    }

    async fn keepalive(self: &Arc<Self>) {
        let connections = {
            let mut connections = self.connections.lock().await;
            connections.retain(|connection| connection.is_alive());
            connections.clone()
        };
        let mut probe = Message::query();
        probe.add_query(Query::query(Name::root(), RecordType::NS));
        let probes = connections.into_iter().filter_map(|connection| {
            if !connection.was_idle_for(DOT_KEEPALIVE_INTERVAL) {
                return None;
            }
            let permit = connection.try_reserve()?;
            let probe = probe.clone();
            Some(async move {
                match timeout(H2_KEEPALIVE_TIMEOUT, connection.query(&probe, permit)).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => connection.fail(err),
                    Err(_) => connection.fail(DotFailure::Connection("DoT keepalive timed out".to_string())),
                }
            })
        });
        futures_util::future::join_all(probes).await;
    }
}

fn start_dot_keepalive(pool: &Arc<DotPool>) {
    let pool = Arc::downgrade(pool);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DOT_KEEPALIVE_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(pool) = pool.upgrade() else { return };
            pool.keepalive().await;
        }
    });
}

enum Backend {
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
        match &self.backend {
            Backend::Dot(pool) => pool.query(query).await,
            Backend::Doh { url, http } => {
                let mut outgoing = query.clone();
                outgoing.metadata.id = rand::random();
                let expected_id = outgoing.metadata.id;
                let wire = outgoing.to_vec().context("failed to encode upstream query")?;
                let response_bytes = query_doh(http, url, Bytes::from(wire)).await?;
                let response = Message::from_vec(&response_bytes).context("failed to decode upstream response")?;
                if response.metadata.id != expected_id {
                    bail!("upstream response ID mismatch");
                }
                Ok(response)
            }
        }
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

/// Builds production upstream pool. DoT hostnames are resolved eagerly so
/// healthy reconnects skip system DNS; failed initial resolution falls back to
/// lazy dialing, keeping unrelated listeners available. DoH uses reqwest's
/// resolver cache so addresses can rotate after TTL expiry.
pub async fn build(configs: &[UpstreamConfig], strategy: UpstreamStrategy) -> Result<MultiUpstream<SingleUpstream>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(tls_config);

    // One reqwest client is shared by every DoH upstream so h2 pooling and
    // reqwest's resolver cache are shared too. Unlike permanent address
    // overrides, normal resolution can recover when a provider rotates IPs.
    let doh_builder = reqwest::Client::builder()
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
    let doh_http = doh_builder.build().context("failed to build upstream DoH HTTP client")?;

    let mut upstreams = Vec::with_capacity(configs.len());
    for cfg in configs {
        let single = match cfg {
            UpstreamConfig::Dot { host, port, tls_name } => {
                let server_name = ServerName::try_from(tls_name.clone())
                    .with_context(|| format!("invalid upstream tls_name: {tls_name}"))?;
                let addresses = match resolve_addresses(host, *port).await {
                    Ok(addresses) => addresses,
                    Err(err) => {
                        warn!(upstream = %host, error = format!("{err:#}"), "failed to resolve DoT host at startup, deferring to first connection");
                        Vec::new()
                    }
                }
                .into_boxed_slice();
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
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addresses: Vec<_> = timeout(ADDRESS_RESOLUTION_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .with_context(|| format!("timed out resolving upstream host {host}"))?
        .with_context(|| format!("failed to resolve upstream host {host}"))?
        .collect();
    if addresses.is_empty() {
        bail!("upstream host {host} resolved to no addresses");
    }
    Ok(addresses)
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
    async fn concurrent_dot_queries_share_one_tls_connection() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), false));

        let pool = Arc::new(DotPool::new(
            "127.0.0.1".to_string(),
            addr.port(),
            vec![addr].into_boxed_slice(),
            tls.server_name,
            tls.connector,
        ));
        let queries: Vec<_> = (0..100).map(|_| test_query()).collect();
        let results = futures_util::future::join_all(queries.iter().map(|query| pool.query(query))).await;

        for response in results {
            assert_eq!(only_answer_ip(&response.unwrap()), Ipv4Addr::new(9, 9, 9, 9));
        }
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            1,
            "one multiplexed DoT connection should carry the whole concurrent burst"
        );
    }

    #[tokio::test]
    async fn dot_pool_reconnects_after_the_upstream_closes_a_connection() {
        let tls = test_tls::generate("localhost");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        tokio::spawn(mock_dot_server(listener, tls.acceptor, Arc::clone(&accepts), true));

        let pool = Arc::new(DotPool::new(
            "127.0.0.1".to_string(),
            addr.port(),
            vec![addr].into_boxed_slice(),
            tls.server_name,
            tls.connector,
        ));

        for _ in 0..5 {
            let response = pool.query(&test_query()).await.unwrap();
            assert_eq!(only_answer_ip(&response), Ipv4Addr::new(9, 9, 9, 9));
            tokio::task::yield_now().await;
        }
        assert!(
            accepts.load(Ordering::SeqCst) >= 5,
            "later queries should reconnect after each server-side close"
        );
    }

    #[test]
    fn dot_request_ids_never_replace_an_existing_waiter() {
        let pending = FxHashMap::from_iter([(7, ()), (8, ())]);

        let id = next_available_id(&pending, 7);

        assert_eq!(id, 9, "ID allocation must skip every active waiter rather than overwrite one");
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
