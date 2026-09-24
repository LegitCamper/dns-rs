//! Test-only helper for spinning up self-signed TLS material and matching
//! client trust roots, shared by `dns::upstream`'s DoT/DoH integration
//! tests. Never compiled outside `cfg(test)`.

use std::sync::Arc;

use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// A self-signed cert/key pair plus a ready-to-use server acceptor and a
/// client connector that trusts exactly that cert (nothing else).
pub(crate) struct TestTls {
    pub server_name: ServerName<'static>,
    #[cfg(feature = "doh")]
    pub server_config: Arc<rustls::ServerConfig>,
    /// PEM-encoded cert, for handing to `reqwest::Certificate::from_pem` in
    /// DoH tests (reqwest doesn't take a rustls `RootCertStore` directly).
    #[cfg(feature = "doh")]
    pub cert_pem: Vec<u8>,
    pub acceptor: TlsAcceptor,
    pub connector: TlsConnector,
}

/// Generates a fresh self-signed cert valid for `name` and builds both sides
/// of the TLS handshake from it: a server `ServerConfig` presenting the cert,
/// and a client `ClientConfig` whose root store contains only that cert (so
/// it validates the mock server without touching the real webpki root store).
pub(crate) fn generate(name: &str) -> TestTls {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed([name.to_string()])
            .expect("failed to generate self-signed test cert");

    #[cfg(feature = "doh")]
    let cert_pem = cert.pem().into_bytes();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der =
        PrivateKeyDer::try_from(signing_key.serialize_der()).expect("invalid generated test key");

    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("invalid self-signed test cert/key pair"),
    );

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(cert_der)
        .expect("failed to trust the test cert");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    TestTls {
        server_name: ServerName::try_from(name.to_string()).expect("invalid test server name"),
        acceptor: TlsAcceptor::from(Arc::clone(&server_config)),
        connector: TlsConnector::from(Arc::new(client_config)),
        #[cfg(feature = "doh")]
        server_config,
        #[cfg(feature = "doh")]
        cert_pem,
    }
}
