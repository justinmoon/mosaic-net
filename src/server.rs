use crate::ALPN_QUIC_MOSAIC;
use crate::error::Error;
use mosaic_core::SecretKey;
use quinn::ServerConfig as QuinnServerConfig;
use rustls::ServerConfig as TlsServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;

/// A configuration for creating a `Server`
#[derive(Debug, Clone)]
pub struct ServerConfig {
    #[allow(dead_code)]
    secret_key: SecretKey,
    socket: SocketAddr,
    quinn: QuinnServerConfig,
}

impl ServerConfig {
    /// Create a new `ServerConfig` for starting a server
    ///
    /// # Errors
    ///
    /// Errors on numerous things that should not occur based on input, but might occur
    /// as software changes over time.
    #[allow(clippy::missing_panics_doc)]
    pub fn new(secret_key: SecretKey, socket: SocketAddr) -> Result<ServerConfig, Error> {
        // Create a Mosaic-compliant self-signed TLS identity
        let (certificate_der, private_key_der) = alt_tls::self_signed_tls_identity(
            &secret_key.to_signing_key(),
            vec![
                "mosaic".to_string(),
                "IGNORE THE NAME, DETERMINE TRUST FROM THE KEY".to_string(),
            ],
        )?;

        // Create a Mosaic-compliant client certificate verifier that accepts self-signed
        // client certificates using ed25519
        let verifier = Arc::new(alt_tls::SelfSignedCertificateVerifier::new(
            alt_tls::SUPPORTED_ALGORITHMS,
            vec![rustls::SignatureScheme::ED25519],
            None, // any public key works for the server (unlike for the client)
        ));

        // Build a rustls TLS configuration from the Mosaic-compliant alt-tls provider
        // and the above created things
        let rustls_server_config = {
            let mut server_config =
                TlsServerConfig::builder_with_provider(alt_tls::provider().into())
                    .with_protocol_versions(&[&rustls::version::TLS13])?
                    .with_client_cert_verifier(verifier.clone())
                    .with_single_cert(vec![certificate_der], private_key_der)?;

            server_config.alpn_protocols = vec![ALPN_QUIC_MOSAIC.to_vec()];

            Arc::new(server_config)
        };

        // Create a QUIC server configuration from the rustls TLS configuration
        let qsc = Arc::new(quinn_proto::crypto::rustls::QuicServerConfig::try_from(
            rustls_server_config,
        )?);
        let mut quinn_server_config = QuinnServerConfig::with_crypto(qsc);

        // Tweak the QUIC server configuration
        let transport_config = Arc::get_mut(&mut quinn_server_config.transport).unwrap();
        let _ = transport_config.max_concurrent_uni_streams(0_u8.into());

        Ok(ServerConfig {
            secret_key,
            socket,
            quinn: quinn_server_config,
        })
    }

    /// Create a Mosaic network server from this configuration
    ///
    /// # Errors
    ///
    /// Errors if the server could not be setup.
    pub fn server(&self) -> Result<Server, Error> {
        let endpoint = quinn::Endpoint::server(self.quinn.clone(), self.socket)?;
        Ok(Server {
            config: self.clone(),
            endpoint,
        })
    }
}

/// A Mosaic network Server
#[derive(Debug)]
pub struct Server {
    #[allow(dead_code)]
    config: ServerConfig,
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
}
