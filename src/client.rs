use crate::ALPN_QUIC_MOSAIC;
use crate::error::Error;
use mosaic_core::{PublicKey, SecretKey};
use quinn::ClientConfig as QuinnClientConfig;
use rustls::ClientConfig as TlsClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;

/// This configuration is used to produce a `Client`
#[derive(Debug)]
pub struct ClientConfig {
    #[allow(dead_code)]
    server_public_key: PublicKey,
    server_socket: SocketAddr,
    client_secret_key: Option<SecretKey>,
    quinn: QuinnClientConfig,
}

impl ClientConfig {
    /// Create a `ClientConfig` from parts.
    ///
    /// To authenticate to the server, supply a `client_secret_key`. Otherwise
    /// the client will connect anonymously.
    ///
    /// # Errors
    ///
    /// Errors on numerous things that should not occur based on input, but might occur
    /// as software changes over time.
    pub fn new(
        server_public_key: PublicKey,
        server_socket: SocketAddr,
        client_secret_key: Option<SecretKey>,
    ) -> Result<ClientConfig, Error> {
        let verifier = Arc::new(alt_tls::SelfSignedCertificateVerifier::new(
            alt_tls::SUPPORTED_ALGORITHMS,
            vec![rustls::SignatureScheme::ED25519],
            Some(server_public_key.as_bytes().to_vec()),
        ));

        let rustls_client_config = {
            let builder = TlsClientConfig::builder_with_provider(alt_tls::provider().into())
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone());

            let mut client_config = if let Some(ref sk) = client_secret_key {
                let (certificate_der, private_key_der) = alt_tls::self_signed_tls_identity(
                    &sk.to_signing_key(),
                    vec![
                        "mosaic".to_string(),
                        "IGNORE THE NAME, DETERMINE TRUST FROM THE KEY".to_string(),
                    ],
                )?;
                builder.with_client_auth_cert(vec![certificate_der], private_key_der)?
            } else {
                builder.with_no_client_auth()
            };

            client_config.alpn_protocols = vec![ALPN_QUIC_MOSAIC.to_vec()];

            Arc::new(client_config)
        };

        let quinn_client_config = QuinnClientConfig::new(Arc::new(
            quinn_proto::crypto::rustls::QuicClientConfig::try_from(rustls_client_config)?,
        ));

        Ok(ClientConfig {
            server_public_key,
            server_socket,
            client_secret_key,
            quinn: quinn_client_config,
        })
    }

    /// Create a `Client` from this `ClientConfig` by connecting to the `Server`
    ///
    /// `local_socket` should usually be `None` but can be any local socket address or the
    /// a wildcard address like `(std::net::Ipv6Addr::UNSPECIFIED, 0).into()` or
    /// `(std::net::Ipv4Addr::UNSPECIFIED, 0).into()`
    ///
    /// # Errors
    ///
    /// Errors if the client could not be setup, or the server could not be connected to.
    pub async fn client(&self, local_socket: Option<SocketAddr>) -> Result<Client, Error> {
        // find out if IPv4 or IPv6
        let local_socket: SocketAddr = if let Some(lc) = local_socket {
            lc
        } else if self.server_socket.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };

        let mut endpoint = quinn::Endpoint::client(local_socket)?;
        endpoint.set_default_client_config(self.quinn.clone());

        // We use a dummy expected hostname. Our certificate verifier doesn't care.
        // It instead demands an exact expected key.
        let connecting = endpoint.connect(self.server_socket, "mosaic")?;

        let connection = connecting.await?;
        Ok(Client {
            local_endpoint: endpoint,
            remote_socket: self.server_socket,
            connection,
            server_public_key: self.server_public_key,
            client_secret_key: self.client_secret_key.clone(),
        })
    }
}

/// A mosaic `Client`, connected to a specific mosaic `Server`
///
/// use `ClientConfig` to create a `Client`
#[derive(Debug)]
pub struct Client {
    #[allow(dead_code)]
    local_endpoint: quinn::Endpoint,
    #[allow(dead_code)]
    remote_socket: SocketAddr,
    #[allow(dead_code)]
    connection: quinn::Connection,
    #[allow(dead_code)]
    server_public_key: PublicKey,
    #[allow(dead_code)]
    #[allow(clippy::struct_field_names)]
    client_secret_key: Option<SecretKey>,
}

impl Client {
    /// Get at the inner `quinn::Connection`
    #[must_use]
    pub fn inner(&self) -> &quinn::Connection {
        &self.connection
    }

    /// Get at the inner `quinn::Connection`
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut quinn::Connection {
        &mut self.connection
    }

    /// Get public key of authenticated server
    #[must_use]
    pub fn peer(&self) -> PublicKey {
        self.server_public_key
    }

    /// Close down gracefully.
    ///
    /// `message` will be truncated if it does not fit in a single packet
    pub async fn close(self, code: u32, reason: &[u8]) {
        self.connection.close(code.into(), reason);
        self.local_endpoint.wait_idle().await;
    }
}
