#[cfg(not(any(feature = "dot", feature = "doh")))]
compile_error!("enable at least one listener feature: dot or doh");

mod blocklist;
mod config;
mod dns;
mod server;
mod state;
#[cfg(all(feature = "dot", not(feature = "certless")))]
mod tls;
mod util;

#[cfg(not(feature = "serverless"))]
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(not(feature = "serverless"))]
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(not(feature = "serverless"))]
use clap::Parser;
use futures_util::future::select_all;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;
#[cfg(not(feature = "serverless"))]
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

use config::Config;
use state::AppState;

/// Startup may spend this long establishing upstream connections before it
/// begins accepting client traffic. This makes warming deterministic for
/// healthy resolvers without turning an unreachable upstream into a long
/// readiness outage.
const UPSTREAM_WARMUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Polling (not inotify) is deliberate: trivially correct across
/// atomic-rename config writes, no extra dependency, and reload latency of a
/// few seconds is a non-issue here.
#[cfg(not(feature = "serverless"))]
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(5);

type Listener = (&'static str, JoinHandle<Result<()>>);

#[cfg(not(feature = "serverless"))]
#[derive(Parser)]
#[command(name = "dns-rs", about = "Lightweight adblocking DNS server (DoT/DoH)")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[cfg(not(feature = "serverless"))]
struct LoadedConfig {
    config: Config,
    /// Raw text kept alongside the parsed config so a later poll can cheaply
    /// check "did the file actually change" before re-parsing.
    raw: String,
}

#[cfg(not(feature = "serverless"))]
fn load_config(path: &Path) -> Result<LoadedConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file at {}", path.display()))?;
    let config = Config::load(path)
        .with_context(|| format!("failed to load config from {}", path.display()))?;
    Ok(LoadedConfig { config, raw })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    #[cfg(feature = "serverless")]
    return run_serverless().await;

    #[cfg(not(feature = "serverless"))]
    run_configured().await
}

#[cfg(feature = "serverless")]
async fn run_serverless() -> Result<()> {
    let config = Config::from_env()?;
    let shutdown = CancellationToken::new();
    let mut listeners = spawn_listeners(&config, shutdown.clone()).await?;
    info!("dns-rs is up");

    // Container platforms stop a revision with SIGTERM, not Ctrl-C; without
    // handling it the DoH drain below never runs and in-flight queries die.
    let stop_signal = async {
        #[cfg(unix)]
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    };

    tokio::select! {
        completed = select_all(listeners.iter_mut().map(|(_, handle)| handle)) => {
            let (result, index, _) = completed;
            let name = listeners[index].0;
            shutdown.cancel();
            listeners.swap_remove(index);
            for (_, handle) in listeners {
                let _ = handle.await;
            }
            return match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => Err(err).with_context(|| format!("{name} listener exited")),
                Err(err) => Err(err).with_context(|| format!("{name} task panicked")),
            };
        }
        _ = stop_signal => {
            info!("received shutdown signal");
            shutdown.cancel();
        }
    }
    for (_, handle) in listeners {
        let _ = handle.await;
    }
    Ok(())
}

#[cfg(not(feature = "serverless"))]
async fn run_configured() -> Result<()> {
    let cli = Cli::parse();
    let mut loaded = load_config(&cli.config)?;

    loop {
        let shutdown = CancellationToken::new();
        let listeners = spawn_listeners(&loaded.config, shutdown.clone()).await?;
        info!("dns-rs is up");

        match wait_for_reload_or_exit(&cli.config, &loaded.raw, listeners, &shutdown).await? {
            Outcome::Exit => break,
            Outcome::Reload(next) => {
                info!("config file changed, reloading");
                loaded = *next;
            }
        }
    }
    Ok(())
}

async fn spawn_listeners(config: &Config, shutdown: CancellationToken) -> Result<Vec<Listener>> {
    let state = Arc::new(AppState::build(config, shutdown.clone()).await?);

    // Warm before binding listeners: a detached task raced the first client,
    // so the one query this optimization was meant to help could still dial
    // alongside the probe and pay the full handshake. Bound the wait so a
    // down upstream delays readiness by at most one second; `warm_all` logs
    // individual failures and the ordinary fallback path remains available.
    let _ = tokio::time::timeout(UPSTREAM_WARMUP_TIMEOUT, state.upstreams.warm_all()).await;

    let mut listeners = Vec::new();

    #[cfg(feature = "dot")]
    {
        let addr = config.server.dot_listen();
        let state = Arc::clone(&state);
        let shutdown = shutdown.clone();
        #[cfg(not(feature = "certless"))]
        let tls_config = tls::load_server_config(&config.server.tls_cert, &config.server.tls_key)?;
        listeners.push((
            "DoT",
            tokio::spawn(async move {
                #[cfg(feature = "certless")]
                return server::dot::serve(addr, state, shutdown).await;
                #[cfg(not(feature = "certless"))]
                server::dot::serve(addr, tls_config, state, shutdown).await
            }),
        ));
    }

    #[cfg(feature = "doh")]
    {
        let addr = config.server.doh_listen();
        let state = Arc::clone(&state);
        #[cfg(not(feature = "certless"))]
        {
            let cert = config.server.tls_cert.clone();
            let key = config.server.tls_key.clone();
            listeners.push((
                "DoH",
                tokio::spawn(async move {
                    server::doh::serve(addr, &cert, &key, state, shutdown).await
                }),
            ));
        }
        #[cfg(feature = "certless")]
        listeners.push((
            "DoH",
            tokio::spawn(async move { server::doh::serve(addr, state, shutdown).await }),
        ));
    }

    Ok(listeners)
}

#[cfg(not(feature = "serverless"))]
enum Outcome {
    Exit,
    Reload(Box<LoadedConfig>),
}

/// Waits for a listener to exit, Ctrl-C, or the config file changing.
/// Ctrl-C/reload both cancel `shutdown` and wait for every task hanging off
/// it to stop, so the next loop iteration never fights the previous
/// generation for a port.
#[cfg(not(feature = "serverless"))]
async fn wait_for_reload_or_exit(
    config_path: &Path,
    current_raw: &str,
    mut listeners: Vec<Listener>,
    shutdown: &CancellationToken,
) -> Result<Outcome> {
    let mut poll = tokio::time::interval(CONFIG_POLL_INTERVAL);
    poll.tick().await; // first tick fires immediately; not a real check

    loop {
        tokio::select! {
            completed = select_all(listeners.iter_mut().map(|(_, handle)| handle)) => {
                let (result, index, _) = completed;
                let name = listeners[index].0;
                shutdown.cancel();
                report_listener_exit(name, result);
                listeners.swap_remove(index);
                for (other_name, handle) in listeners {
                    if let Ok(result) = handle.await {
                        report_listener_exit(other_name, Ok(result));
                    }
                }
                return Ok(Outcome::Exit);
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
                shutdown.cancel();
                for (_, handle) in listeners {
                    let _ = handle.await;
                }
                return Ok(Outcome::Exit);
            }
            _ = poll.tick() => {
                match std::fs::read_to_string(config_path) {
                    Ok(raw) if raw == current_raw => {}
                    Ok(_) => match load_config(config_path) {
                        Ok(next) => {
                            shutdown.cancel();
                            for (_, handle) in listeners {
                                let _ = handle.await;
                            }
                            return Ok(Outcome::Reload(Box::new(next)));
                        }
                        Err(err) => warn!(error = %err, "config file changed but failed to load, keeping previous config"),
                    },
                    Err(err) => warn!(error = %err, "failed to read config file while polling for changes"),
                }
            }
        }
    }
}

#[cfg(not(feature = "serverless"))]
fn report_listener_exit(name: &str, res: std::result::Result<Result<()>, tokio::task::JoinError>) {
    match res {
        Ok(Ok(())) => {}
        Ok(Err(err)) => error!(error = %err, "{name} listener exited"),
        Err(err) => error!(error = %err, "{name} task panicked"),
    }
}
