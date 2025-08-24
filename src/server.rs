use crate::ALPN_QUIC_MOSAIC;
use crate::channel::Channel;
use crate::error::{Error, InnerError};
use mosaic_core::{PublicKey, SecretKey};
use quinn::ServerConfig as QuinnServerConfig;
use rustls::ServerConfig as TlsServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A configuration for creating a `Server`
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Mosaic ed25519 secret key for the server
    pub secret_key: SecretKey,

    /// Socket address to bind to
    pub socket_addr: SocketAddr,

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
    pub fn new(secret_key: SecretKey, socket_addr: SocketAddr) -> Result<ServerConfig, Error> {
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
            socket_addr,
            quinn: quinn_server_config,
        })
    }

    /// Retrieve the socket address
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }
}

/// A Mosaic network `Server`
///
/// use `ServerConfig` to create a `Server`
#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
    endpoint: quinn::Endpoint,
    shutting_down: AtomicBool,
}

impl Server {
    /// Create a Mosaic network server
    ///
    /// # Errors
    ///
    /// Errors if the server could not be setup.
    pub fn new(config: ServerConfig) -> Result<Server, Error> {
        let endpoint = quinn::Endpoint::server(config.quinn.clone(), config.socket_addr)?;
        Ok(Self {
            config,
            endpoint,
            shutting_down: AtomicBool::new(false),
        })
    }

    /// Accept a new connection. This returns as soon as it can so that the
    /// thread that calls it can get on with other clients.
    ///
    /// # Errors
    ///
    /// Errors if the endpoint is closed
    pub async fn accept(&self) -> Result<IncomingClient, Error> {
        if self.is_shutting_down() {
            return Err(InnerError::ShuttingDown.into());
        }

        self.endpoint
            .accept()
            .await
            .map(IncomingClient)
            .ok_or::<Error>(InnerError::EndpointIsClosed.into())
    }

    /// If the server is shutting down
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Shut down gracefully.
    pub async fn shut_down(&self, code: u32, reason: &[u8]) {
        if !self.shutting_down.load(Ordering::Acquire) {
            self.shutting_down.store(true, Ordering::Release);
            self.endpoint.close(code.into(), reason);
            self.endpoint.wait_idle().await;
        }
    }

    /// Retrieve the configuration
    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if !self.shutting_down.load(Ordering::Acquire) {
            eprintln!("Server Dropping without Shutdown!!!!");
        }
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

/// An object that handles approval and rejection of clients.
/// This occurs before the TLS handshake, so it is based on `SocketAddr` only.
pub trait Approver: Send + Sync {
    /// Should we allow this client to connect?
    fn is_client_allowed(&self, s: SocketAddr) -> Approval;
}

/// An `Approver` that always accepts
#[derive(Debug, Clone, Copy)]
pub struct AlwaysAllowedApprover;

impl Approver for AlwaysAllowedApprover {
    fn is_client_allowed(&self, _: SocketAddr) -> Approval {
        Approval::Approve
    }
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
    ///
    /// # Errors
    ///
    /// Errors if client does not perform stateless retry properly, if the
    /// remote address is not approved, or if there is a problem connecting.
    #[allow(clippy::missing_panics_doc)]
    pub async fn accept<A: Approver>(self, approver: &A) -> Result<ClientConnection, Error> {
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

        let remote_socket_addr: SocketAddr = self.0.remote_address();

        match approver.is_client_allowed(remote_socket_addr) {
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

        let mut connecting = self.0.accept()?;

        // Verify ALPN
        match connecting
            .handshake_data()
            .await?
            .downcast_ref::<quinn::crypto::rustls::HandshakeData>()
        {
            Some(hd) => match &hd.protocol {
                Some(alpn) => {
                    if alpn != ALPN_QUIC_MOSAIC {
                        return Err(InnerError::WrongAlpn.into());
                    }
                }
                None => return Err(InnerError::MissingAlpn.into()),
            },
            None => panic!("Invalid downcast code"),
        }

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
                None => panic!("Invalid downcast code"),
            }
        }

        Ok(ClientConnection {
            remote_socket_addr,
            inner: connection,
            peer,
        })
    }

    /// Get at the inner `quinn::Incoming`
    #[must_use]
    pub fn inner(&self) -> &quinn::Incoming {
        &self.0
    }
}

/// A connection to a client
#[derive(Debug)]
pub struct ClientConnection {
    inner: quinn::Connection,
    remote_socket_addr: SocketAddr,
    peer: Option<PublicKey>,
}

impl ClientConnection {
    /// Get at the inner `quinn::Connection`
    #[must_use]
    pub fn inner(&self) -> &quinn::Connection {
        &self.inner
    }

    /// Get at the inner `quinn::Connection`
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut quinn::Connection {
        &mut self.inner
    }

    /// Get authenticated peer
    #[must_use]
    pub fn peer(&self) -> Option<PublicKey> {
        self.peer
    }

    /// Get remote socket
    #[must_use]
    pub fn remote_socket_addr(&self) -> SocketAddr {
        self.remote_socket_addr
    }

    /// Close down gracefully.
    ///
    /// `message` will be truncated if it does not fit in a single packet
    pub fn close(self, code: u32, message: &[u8]) {
        self.inner.close(code.into(), message);
    }

    /// Get the next `Channel` created by the client
    ///
    /// # Errors
    ///
    /// Returns an Err if there was a QUIC `accept_bi()` problem
    pub async fn next_channel(&self) -> Result<Channel, Error> {
        let (send, recv) = self.inner.accept_bi().await?;
        Ok(Channel::new(send, recv))
    }
}
