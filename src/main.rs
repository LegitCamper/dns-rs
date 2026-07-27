mod blocklist;
mod config;
mod dns;
mod server;
mod state;
mod tls;
mod util;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use config::Config;
use state::AppState;

#[derive(Parser)]
#[command(name = "dns-rs", about = "Lightweight adblocking DNS server (DoT/DoH only)")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;

    let state = Arc::new(AppState::build(&config).await?);
    let dot_tls_config = tls::load_server_config(&config.server.tls_cert, &config.server.tls_key)?;

    let dot_addr = config.server.dot_listen;
    let doh_addr = config.server.doh_listen;
    let doh_cert = config.server.tls_cert.clone();
    let doh_key = config.server.tls_key.clone();

    let dot_state = Arc::clone(&state);
    let dot_handle = tokio::spawn(async move { server::dot::serve(dot_addr, dot_tls_config, dot_state).await });

    let doh_state = Arc::clone(&state);
    let doh_handle =
        tokio::spawn(async move { server::doh::serve(doh_addr, &doh_cert, &doh_key, doh_state).await });

    info!("dns-rs is up");

    tokio::select! {
        res = dot_handle => {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!(error = %err, "DoT listener exited"),
                Err(err) => error!(error = %err, "DoT task panicked"),
            }
        }
        res = doh_handle => {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!(error = %err, "DoH listener exited"),
                Err(err) => error!(error = %err, "DoH task panicked"),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    Ok(())
}
