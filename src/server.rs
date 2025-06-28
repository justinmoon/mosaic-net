use crate::ALPN_QUIC_MOSAIC;
use crate::error::{Error, InnerError};
use mosaic_core::{PublicKey, SecretKey};
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

/// A Mosaic network `Server`
///
/// use `ServerConfig` to create a `Server`
#[derive(Debug)]
pub struct Server {
    #[allow(dead_code)]
    config: ServerConfig,
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
}

impl Server {
    /// Accept a new connection. This returns as soon as it can so that the
    /// thread that calls it can get on with other clients.
    ///
    /// # Errors
    ///
    /// Errors if the endpoint is closed
    pub async fn accept(&self) -> Result<IncomingClient, Error> {
        self.endpoint
            .accept()
            .await
            .map(IncomingClient)
            .ok_or::<Error>(InnerError::EndpointIsClosed.into())
    }
}

/// Whether or not a connection is allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Approval {
    /// Approve
    Approve,

    /// Refuse
    Refuse,

    /// Refuse silently
    SilentlyRefuse,
}

/// An incoming client that is not fully accepted yet, but should probably be
/// handled and awaited upon in in a separate task from the main server
/// accepting thread
#[derive(Debug)]
pub struct IncomingClient(quinn::Incoming);

impl IncomingClient {
    #[allow(clippy::doc_markdown)]
    /// Accept (or reject) the incoming client based on the `approve` function
    /// which allows you to block IP addresses.
    ///
    /// Internally this requires stateless retry to verify that the client
    /// actually controls the IP address and port it claims to be connecting
    /// from, which requires a round-trip but significantly reduces the effect
    /// of DoS attacks.
    pub async fn accept<F>(self, approve: F) -> Result<ClientConnection, Error>
    where
        F: Fn(SocketAddr) -> Approval,
    {
        // We don't talk to brand new endpoints until they prove that they
        // control the remote IP and PORT that the packet claims. This is
        // called "stateless retry". The first connection they make must
        // contain a DCID we recognize. This requires 1-RTT, but only the
        // first time they connect to us (not having a token). It prevents
        // certain kinds of security problems, at the cost of a RTT.
        if !self.0.remote_address_validated() {
            self.0.retry()?;
            return Err(InnerError::StatelessRetryRequired.into());
        }

        let remote_address: SocketAddr = self.0.remote_address();

        match approve(remote_address) {
            Approval::Approve => {}
            Approval::Refuse => {
                self.0.refuse();
                return Err(InnerError::RemoteAddressNotApproved.into());
            }
            Approval::SilentlyRefuse => {
                self.0.ignore();
                return Err(InnerError::RemoteAddressNotApproved.into());
            }
        }

        let connecting = self.0.accept()?;
        let connection = connecting.await?;

        let mut peer: Option<PublicKey> = None;
        if let Some(id) = connection.peer_identity() {
            match id.downcast_ref::<Vec<rustls::pki_types::CertificateDer>>() {
                Some(vec) => {
                    for cert in vec {
                        if let Ok(vk) = alt_tls::public_key_from_certificate_der(cert) {
                            peer = Some(PublicKey::from_verifying_key(&vk));
                        }
                    }
                }
                None => {
                    panic!("Invalid downcast code");
                }
            }
        }

        Ok(ClientConnection {
            inner: connection,
            peer,
        })
    }
}

/// A connection to a client
#[derive(Debug)]
pub struct ClientConnection {
    inner: quinn::Connection,
    peer: Option<PublicKey>,
}

impl ClientConnection {
    /// Get at the inner `quinn::Connection`
    pub fn inner(&self) -> &quinn::Connection {
        &self.inner
    }

    /// Get at the inner `quinn::Connection`
    pub fn inner_mut(&mut self) -> &mut quinn::Connection {
        &mut self.inner
    }

    /// Get authenticated peer
    pub fn peer(&self) -> Option<PublicKey> {
        self.peer
    }
}
