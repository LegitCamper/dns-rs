mod blocklist;
mod config;
mod dns;
mod memlimit;
mod server;
mod state;
mod tls;
mod util;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use config::Config;
use state::AppState;

/// Polling (not inotify) is deliberate: trivially correct across
/// atomic-rename config writes, no extra dependency, and reload latency of a
/// few seconds is a non-issue here.
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// If set, its content is used as the whole TOML config document instead of
/// reading `--config <path>` — for platforms that inject config as a secret
/// rather than mounting a file. Takes priority over `--config` when present.
const CONFIG_ENV: &str = "DNS_RS_CONFIG";

#[derive(Parser)]
#[command(name = "dns-rs", about = "Lightweight adblocking DNS server (DoT/DoH only)")]
struct Cli {
    /// Path to the TOML config file. Ignored if DNS_RS_CONFIG is set.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

/// Where the raw config document comes from. Read on every reload poll tick
/// the same way regardless of variant — for `Env`, re-reading the env var on
/// every tick is harmless (env vars don't change under a running process)
/// and keeps the poll loop uniform instead of needing a special case.
enum ConfigSource {
    File(PathBuf),
    Env,
}

impl ConfigSource {
    fn read(&self) -> Result<String> {
        match self {
            ConfigSource::File(path) => {
                std::fs::read_to_string(path).with_context(|| format!("failed to read config file at {}", path.display()))
            }
            ConfigSource::Env => {
                std::env::var(CONFIG_ENV).with_context(|| format!("{CONFIG_ENV} is not set"))
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            ConfigSource::File(path) => format!("file {}", path.display()),
            ConfigSource::Env => format!("{CONFIG_ENV} env var"),
        }
    }
}

/// Raw text kept alongside the parsed config so a later poll can cheaply
/// check "did the source actually change" before re-parsing.
struct LoadedConfig {
    config: Config,
    raw: String,
}

fn load_config(source: &ConfigSource) -> Result<LoadedConfig> {
    let raw = source.read()?;
    let config = Config::parse(&raw).with_context(|| format!("failed to load config from {}", source.describe()))?;
    Ok(LoadedConfig { config, raw })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let source = if std::env::var(CONFIG_ENV).is_ok() {
        ConfigSource::Env
    } else {
        ConfigSource::File(cli.config)
    };
    let mut loaded = load_config(&source)?;

    loop {
        let shutdown = CancellationToken::new();
        let (dot_handle, doh_handle) = spawn_listeners(&loaded.config, shutdown.clone()).await?;
        info!("dns-rs is up");

        match wait_for_reload_or_exit(&source, &loaded.raw, dot_handle, doh_handle, &shutdown).await? {
            Outcome::Exit => break,
            Outcome::Reload(next) => {
                info!("config changed, reloading");
                loaded = *next;
            }
        }
    }

    Ok(())
}

async fn spawn_listeners(
    config: &Config,
    shutdown: CancellationToken,
) -> Result<(JoinHandle<Result<()>>, JoinHandle<Result<()>>)> {
    let state = Arc::new(AppState::build(config, shutdown.clone()).await?);
    let (cert_pem, key_pem) = tls::resolve_tls_material(&config.server.tls_cert, &config.server.tls_key)?;
    let dot_tls_config = tls::load_server_config(&cert_pem, &key_pem)?;

    let dot_addr = config.server.dot_listen();
    let doh_addr = config.server.doh_listen();
    let doh_cert = cert_pem.clone();
    let doh_key = key_pem.clone();

    let dot_state = Arc::clone(&state);
    let dot_shutdown = shutdown.clone();
    let dot_handle =
        tokio::spawn(async move { server::dot::serve(dot_addr, dot_tls_config, dot_state, dot_shutdown).await });

    let doh_state = Arc::clone(&state);
    let doh_handle = tokio::spawn(async move {
        server::doh::serve(doh_addr, &doh_cert, &doh_key, doh_state, shutdown).await
    });

    Ok((dot_handle, doh_handle))
}

enum Outcome {
    Exit,
    Reload(Box<LoadedConfig>),
}

/// Waits for a listener to exit, Ctrl-C, or the config file changing.
/// Ctrl-C/reload both cancel `shutdown` and wait for every task hanging off
/// it to stop, so the next loop iteration never fights the previous
/// generation for a port.
async fn wait_for_reload_or_exit(
    source: &ConfigSource,
    current_raw: &str,
    mut dot_handle: JoinHandle<Result<()>>,
    mut doh_handle: JoinHandle<Result<()>>,
    shutdown: &CancellationToken,
) -> Result<Outcome> {
    let mut poll = tokio::time::interval(CONFIG_POLL_INTERVAL);
    poll.tick().await; // first tick fires immediately; not a real check

    loop {
        tokio::select! {
            res = &mut dot_handle => {
                shutdown.cancel();
                let _ = doh_handle.await;
                report_listener_exit("DoT", res);
                return Ok(Outcome::Exit);
            }
            res = &mut doh_handle => {
                shutdown.cancel();
                let _ = dot_handle.await;
                report_listener_exit("DoH", res);
                return Ok(Outcome::Exit);
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
                shutdown.cancel();
                let _ = tokio::join!(dot_handle, doh_handle);
                return Ok(Outcome::Exit);
            }
            _ = poll.tick() => {
                match source.read() {
                    Ok(raw) if raw == current_raw => {}
                    Ok(_) => match load_config(source) {
                        Ok(next) => {
                            shutdown.cancel();
                            let _ = tokio::join!(dot_handle, doh_handle);
                            return Ok(Outcome::Reload(Box::new(next)));
                        }
                        Err(err) => {
                            warn!(error = %err, "config changed but failed to load, keeping previous config");
                        }
                    },
                    Err(err) => warn!(error = %err, "failed to read config while polling for changes"),
                }
            }
        }
    }
}

fn report_listener_exit(name: &str, res: std::result::Result<Result<()>, tokio::task::JoinError>) {
    match res {
        Ok(Ok(())) => {}
        Ok(Err(err)) => error!(error = %err, "{name} listener exited"),
        Err(err) => error!(error = %err, "{name} task panicked"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_source_file_reads_existing_and_errors_on_missing() {
        let dir = std::env::temp_dir().join(format!("dns-rs-main-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "hello").unwrap();

        assert_eq!(ConfigSource::File(path.clone()).read().unwrap(), "hello");
        assert!(ConfigSource::File(dir.join("missing.toml")).read().is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Single test (not two) for the same reason as the equivalent TLS test
    /// in `tls.rs`: `CONFIG_ENV` is process-global and `cargo test` runs
    /// tests in parallel within one process.
    #[test]
    fn config_source_env_reads_when_set_and_errors_when_unset() {
        assert!(std::env::var(CONFIG_ENV).is_err(), "test env polluted by another test");
        assert!(ConfigSource::Env.read().is_err());

        // SAFETY: this is the only test in the binary that touches
        // CONFIG_ENV; `set_var`/`remove_var` are `unsafe` as of the 2024
        // edition purely because mutating process env is undefined behavior
        // if it races with another thread reading/writing it.
        unsafe {
            std::env::set_var(CONFIG_ENV, "hello");
        }
        let result = ConfigSource::Env.read();
        unsafe {
            std::env::remove_var(CONFIG_ENV);
        }
        assert_eq!(result.unwrap(), "hello");
    }
}
