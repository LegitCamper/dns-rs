use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use hickory_proto::op::Message;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::warn;

use crate::config::UpstreamConfig;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// How many idle DoT connections to keep warm per upstream. Concurrent
/// queries beyond this just open extra connections rather than blocking;
/// only the idle *retention* is capped.
const MAX_IDLE_DOT_CONNECTIONS: usize = 8;

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

struct SingleUpstream {
    label: String,
    backend: Backend,
}

/// An ordered list of configured upstream DoT/DoH resolvers. Queries are
/// tried against each in order until one succeeds, giving basic failover.
pub struct UpstreamPool {
    upstreams: Vec<SingleUpstream>,
}

impl UpstreamPool {
    pub fn new(configs: &[UpstreamConfig]) -> Result<Self> {
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
                UpstreamConfig::Dot {
                    host,
                    port,
                    tls_name,
                } => {
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

        Ok(Self { upstreams })
    }

    /// Forwards `query` to the first upstream that answers successfully.
    /// The outgoing query ID is randomized per attempt and the caller's
    /// original ID is restored on the returned message.
    pub async fn resolve(&self, query: &Message) -> Result<Message> {
        let original_id = query.metadata.id;
        let mut last_err = None;

        for upstream in &self.upstreams {
            match timeout(UPSTREAM_TIMEOUT, upstream.query(query)).await {
                Ok(Ok(mut response)) => {
                    response.metadata.id = original_id;
                    return Ok(response);
                }
                Ok(Err(err)) => {
                    warn!(upstream = %upstream.label, error = %err, "upstream query failed");
                    last_err = Some(err);
                }
                Err(_) => {
                    warn!(upstream = %upstream.label, "upstream query timed out");
                    last_err = Some(anyhow!("timed out querying {}", upstream.label));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("no upstream resolvers configured")))
    }
}

impl SingleUpstream {
    async fn query(&self, query: &Message) -> Result<Message> {
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
