use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use hickory_proto::op::Message;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::config::UpstreamConfig;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

enum Backend {
    Dot {
        host: String,
        port: u16,
        server_name: ServerName<'static>,
        connector: TlsConnector,
    },
    Doh {
        url: String,
        http: reqwest::Client,
    },
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
                        backend: Backend::Dot {
                            host: host.clone(),
                            port: *port,
                            server_name,
                            connector: connector.clone(),
                        },
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
            Backend::Dot {
                host,
                port,
                server_name,
                connector,
            } => query_dot(host, *port, server_name.clone(), connector, &wire).await?,
            Backend::Doh { url, http } => query_doh(http, url, &wire).await?,
        };

        let response = Message::from_vec(&response_bytes).context("failed to decode upstream response")?;
        if response.metadata.id != outgoing.metadata.id {
            bail!("upstream response ID mismatch");
        }
        Ok(response)
    }
}

async fn query_dot(
    host: &str,
    port: u16,
    server_name: ServerName<'static>,
    connector: &TlsConnector,
    wire: &[u8],
) -> Result<Vec<u8>> {
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("failed to connect to {host}:{port}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake with upstream failed")?;

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
