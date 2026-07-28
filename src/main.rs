mod blocklist;
mod config;
mod dns;
mod server;
mod state;
mod tls;
mod util;

use std::path::{Path, PathBuf};
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

/// How often the config file is checked for changes. Polling (rather than
/// inotify/`notify`) is deliberate: it's trivially correct across the
/// atomic-rename-based writes tools like Ansible use, needs no extra
/// dependency, and a few seconds of reload latency is a non-issue here.
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(name = "dns-rs", about = "Lightweight adblocking DNS server (DoT/DoH only)")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

/// A loaded config plus the raw text it was parsed from, so a later poll can
/// cheaply detect "did the file actually change" before paying for a re-parse.
struct LoadedConfig {
    config: Config,
    raw: String,
}

fn load_config(path: &Path) -> Result<LoadedConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file at {}", path.display()))?;
    let config = Config::load(path).with_context(|| format!("failed to load config from {}", path.display()))?;
    Ok(LoadedConfig { config, raw })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let mut loaded = load_config(&cli.config)?;

    loop {
        let shutdown = CancellationToken::new();
        let (dot_handle, doh_handle) = spawn_listeners(&loaded.config, shutdown.clone()).await?;
        info!("dns-rs is up");

        match wait_for_reload_or_exit(&cli.config, &loaded.raw, dot_handle, doh_handle, &shutdown).await? {
            Outcome::Exit => break,
            Outcome::Reload(next) => {
                info!("config file changed, reloading");
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
    let dot_tls_config = tls::load_server_config(&config.server.tls_cert, &config.server.tls_key)?;

    let dot_addr = config.server.dot_listen();
    let doh_addr = config.server.doh_listen();
    let doh_cert = config.server.tls_cert.clone();
    let doh_key = config.server.tls_key.clone();

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

/// Waits for whichever comes first: a listener task ending (error or, in
/// practice, never on success since they only return after `shutdown`),
/// Ctrl-C, or the config file changing on disk. Either of the latter two
/// triggers `shutdown` and waits for both listener tasks — and every
/// background task hanging off the same token, like blocklist refreshes —
/// to actually stop before this returns, so the next loop iteration never
/// tries to rebind a port the previous generation is still holding.
async fn wait_for_reload_or_exit(
    config_path: &Path,
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
                match std::fs::read_to_string(config_path) {
                    Ok(raw) if raw == current_raw => {}
                    Ok(_) => match load_config(config_path) {
                        Ok(next) => {
                            shutdown.cancel();
                            let _ = tokio::join!(dot_handle, doh_handle);
                            return Ok(Outcome::Reload(Box::new(next)));
                        }
                        Err(err) => {
                            warn!(error = %err, "config file changed but failed to load, keeping previous config");
                        }
                    },
                    Err(err) => warn!(error = %err, "failed to read config file while polling for changes"),
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
