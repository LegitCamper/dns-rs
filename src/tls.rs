use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// If both are set (to base64-encoded PEM content), they take priority over
/// `server.tls_cert`/`server.tls_key` file paths — for platforms that inject
/// secrets as env vars rather than mounting files. Setting only one is a
/// startup error (see `config::validate`).
pub const TLS_CERT_ENV: &str = "DNS_RS_TLS_CERT_B64";
pub const TLS_KEY_ENV: &str = "DNS_RS_TLS_KEY_B64";

/// Resolves the raw PEM bytes for the cert chain and private key, from
/// whichever source is active. Called fresh on every listener spawn
/// (initial start and every config reload), matching the existing
/// "TLS material reloads from scratch every generation" behavior.
pub fn resolve_tls_material(cert_path: &Option<PathBuf>, key_path: &Option<PathBuf>) -> Result<(Vec<u8>, Vec<u8>)> {
    match (std::env::var(TLS_CERT_ENV), std::env::var(TLS_KEY_ENV)) {
        (Ok(cert_b64), Ok(key_b64)) => {
            let cert = STANDARD
                .decode(cert_b64.trim())
                .with_context(|| format!("{TLS_CERT_ENV} is not valid base64"))?;
            let key = STANDARD
                .decode(key_b64.trim())
                .with_context(|| format!("{TLS_KEY_ENV} is not valid base64"))?;
            Ok((cert, key))
        }
        (Err(_), Err(_)) => {
            // `config::validate` already guarantees both paths are `Some` and
            // point at real files whenever neither env var is set.
            let cert_path = cert_path.as_ref().context("server.tls_cert is not set")?;
            let key_path = key_path.as_ref().context("server.tls_key is not set")?;
            let cert = std::fs::read(cert_path).with_context(|| format!("failed to read {}", cert_path.display()))?;
            let key = std::fs::read(key_path).with_context(|| format!("failed to read {}", key_path.display()))?;
            Ok((cert, key))
        }
        _ => bail!("both {TLS_CERT_ENV} and {TLS_KEY_ENV} must be set together, or neither"),
    }
}

/// Loads a PEM certificate chain + private key into a rustls `ServerConfig`
/// for the DoT listener (the DoH listener uses axum-server's own PEM loader).
pub fn load_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(cert_pem)?;
    let key = load_key(key_pem)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate/key pair")?;

    Ok(Arc::new(config))
}

fn load_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut Cursor::new(pem)).collect();
    let certs = certs.context("failed to parse certificate chain")?;
    if certs.is_empty() {
        bail!("no certificates found");
    }
    Ok(certs)
}

fn load_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .context("failed to parse private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_pem_pair() -> (Vec<u8>, Vec<u8>) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(["localhost".to_string()]).expect("failed to generate test cert");
        (cert.pem().into_bytes(), signing_key.serialize_pem().into_bytes())
    }

    #[test]
    fn load_server_config_accepts_generated_pem_bytes() {
        let (cert_pem, key_pem) = generate_pem_pair();
        load_server_config(&cert_pem, &key_pem).expect("should build a ServerConfig from valid PEM bytes");
    }

    /// Both scenarios (file source, env source) live in one test rather than
    /// two, since `cargo test` runs tests in parallel within one process and
    /// these env vars are process-global — a separate "env vars are unset"
    /// test would race against a separate "env vars are set" test.
    #[test]
    fn resolve_tls_material_reads_file_then_prefers_env_when_both_set() {
        let (cert_pem, key_pem) = generate_pem_pair();

        assert!(std::env::var(TLS_CERT_ENV).is_err(), "test env polluted by another test");
        assert!(std::env::var(TLS_KEY_ENV).is_err(), "test env polluted by another test");

        let dir = std::env::temp_dir().join(format!("dns-rs-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let (file_cert, file_key) = resolve_tls_material(&Some(cert_path), &Some(key_path)).unwrap();
        assert_eq!(file_cert, cert_pem);
        assert_eq!(file_key, key_pem);
        std::fs::remove_dir_all(&dir).ok();

        let (other_cert_pem, other_key_pem) = generate_pem_pair();
        // SAFETY: this is the only test in the binary that touches these two
        // env vars, so there's no cross-test interference despite parallel
        // test execution; `set_var`/`remove_var` are `unsafe` as of the 2024
        // edition purely because mutating process env is undefined behavior
        // if it races with another thread reading/writing it.
        unsafe {
            std::env::set_var(TLS_CERT_ENV, STANDARD.encode(&other_cert_pem));
            std::env::set_var(TLS_KEY_ENV, STANDARD.encode(&other_key_pem));
        }
        let result = resolve_tls_material(&None, &None);
        unsafe {
            std::env::remove_var(TLS_CERT_ENV);
            std::env::remove_var(TLS_KEY_ENV);
        }
        let (env_cert, env_key) = result.unwrap();
        assert_eq!(env_cert, other_cert_pem);
        assert_eq!(env_key, other_key_pem);
    }
}
