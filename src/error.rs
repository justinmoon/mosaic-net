use std::convert::Infallible;
use std::error::Error as StdError;
use std::panic::Location;

/// A Mosaic server error
#[derive(Debug)]
pub struct Error {
    /// The error itself
    pub inner: InnerError,
    location: &'static Location<'static>,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.inner)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, {}", self.inner, self.location)
    }
}

/// Errors that can occur in this crate
#[derive(Debug)]
pub enum InnerError {
    /// Alt-TLS error
    AltTls(alt_tls::Error),

    /// Channel already finished
    ChannelAlreadyFinished,

    /// Connect
    ConnectError(quinn::ConnectError),

    /// Connection
    ConnectionError(quinn::ConnectionError),

    /// Endpoint is closed
    EndpointIsClosed,

    /// General error
    General(String),

    /// I/O error
    Io(std::io::Error),

    /// Missing ALPN
    MissingAlpn,

    /// Mosaic Core
    MosaicCore(mosaic_core::Error),

    /// `NoInitialCipherSuite`
    NoInitialCipherSuite(quinn::crypto::rustls::NoInitialCipherSuite),

    /// Quic Read error
    QuicRead(Box<quinn::ReadError>),

    /// Quic Write error
    QuicWrite(Box<quinn::WriteError>),

    /// Remote address not approved
    RemoteAddressNotApproved,

    /// Retry Error
    RetryError(Box<quinn::RetryError>),

    /// Stateless Retry was required
    StatelessRetryRequired,

    /// TLS
    Tls(rustls::Error),

    /// Wrong ALPN
    WrongAlpn,
}

impl std::fmt::Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::AltTls(e) => write!(f, "Alt TLS Error: {e}"),
            InnerError::ChannelAlreadyFinished => write!(f, "Channel already finished"),
            InnerError::ConnectError(e) => write!(f, "QUIC connect error: {e}"),
            InnerError::ConnectionError(e) => write!(f, "QUIC connection error: {e}"),
            InnerError::EndpointIsClosed => write!(f, "Endpoint is closed"),
            InnerError::General(s) => write!(f, "General Error: {s}"),
            InnerError::Io(e) => write!(f, "I/O Error: {e}"),
            InnerError::MissingAlpn => write!(f, "ALPN not specified by peer"),
            InnerError::MosaicCore(e) => write!(f, "Mosaic error: {e}"),
            InnerError::NoInitialCipherSuite(_) => write!(f, "No initial cipher suite"),
            InnerError::QuicRead(e) => write!(f, "QUIC read error: {e}"),
            InnerError::QuicWrite(e) => write!(f, "QUIC write error: {e}"),
            InnerError::RemoteAddressNotApproved => write!(f, "Remote address not approved"),
            InnerError::RetryError(e) => write!(f, "QUIC retry error: {e}"),
            InnerError::StatelessRetryRequired => write!(f, "Stateless retry required"),
            InnerError::Tls(e) => write!(f, "TLS Error: {e}"),
            InnerError::WrongAlpn => write!(f, "Wrong ALPN (peer did not specify mosaic)"),
        }
    }
}

impl StdError for InnerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            InnerError::AltTls(e) => Some(e),
            InnerError::ConnectError(e) => Some(e),
            InnerError::ConnectionError(e) => Some(e),
            InnerError::Io(e) => Some(e),
            InnerError::MosaicCore(e) => Some(e),
            InnerError::NoInitialCipherSuite(e) => Some(e),
            InnerError::QuicRead(e) => Some(e),
            InnerError::QuicWrite(e) => Some(e),
            InnerError::RetryError(e) => Some(e),
            InnerError::Tls(e) => Some(e),
            _ => None,
        }
    }
}

// Note: we impl Into because our typical pattern is InnerError::Variant.into()
//       when we tried implementing From, the location was deep in rust code's
//       blanket into implementation, which wasn't the line number we wanted.
//
//       As for converting other error types, the try! macro uses From so it
//       is correct.
#[allow(clippy::from_over_into)]
impl Into<Error> for InnerError {
    #[track_caller]
    fn into(self) -> Error {
        Error {
            inner: self,
            location: Location::caller(),
        }
    }
}

// Use this to avoid complex type qualification
impl InnerError {
    /// Convert an `InnerError` into an `Error`
    #[track_caller]
    #[must_use]
    pub fn into_err(self) -> Error {
        Error {
            inner: self,
            location: Location::caller(),
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::other(e)
    }
}

impl From<Infallible> for Error {
    #[track_caller]
    fn from(_: Infallible) -> Self {
        panic!("INFALLIBLE")
    }
}

impl From<()> for Error {
    #[track_caller]
    fn from((): ()) -> Self {
        Error {
            inner: InnerError::General("Error".to_owned()),
            location: Location::caller(),
        }
    }
}

impl From<alt_tls::Error> for Error {
    #[track_caller]
    fn from(e: alt_tls::Error) -> Self {
        Error {
            inner: InnerError::AltTls(e),
            location: Location::caller(),
        }
    }
}

impl From<quinn::ConnectError> for Error {
    #[track_caller]
    fn from(e: quinn::ConnectError) -> Self {
        Error {
            inner: InnerError::ConnectError(e),
            location: Location::caller(),
        }
    }
}

impl From<quinn::ConnectionError> for Error {
    #[track_caller]
    fn from(e: quinn::ConnectionError) -> Self {
        Error {
            inner: InnerError::ConnectionError(e),
            location: Location::caller(),
        }
    }
}

impl From<std::io::Error> for Error {
    #[track_caller]
    fn from(e: std::io::Error) -> Error {
        Error {
            inner: InnerError::Io(e),
            location: Location::caller(),
        }
    }
}

impl From<mosaic_core::Error> for Error {
    #[track_caller]
    fn from(e: mosaic_core::Error) -> Self {
        Error {
            inner: InnerError::MosaicCore(e),
            location: Location::caller(),
        }
    }
}

impl From<quinn::crypto::rustls::NoInitialCipherSuite> for Error {
    #[track_caller]
    fn from(e: quinn::crypto::rustls::NoInitialCipherSuite) -> Self {
        Error {
            inner: InnerError::NoInitialCipherSuite(e),
            location: Location::caller(),
        }
    }
}

impl From<quinn::ReadError> for Error {
    #[track_caller]
    fn from(e: quinn::ReadError) -> Self {
        Error {
            inner: InnerError::QuicRead(Box::new(e)),
            location: Location::caller(),
        }
    }
}

impl From<quinn::WriteError> for Error {
    #[track_caller]
    fn from(e: quinn::WriteError) -> Self {
        Error {
            inner: InnerError::QuicWrite(Box::new(e)),
            location: Location::caller(),
        }
    }
}

impl From<quinn::RetryError> for Error {
    #[track_caller]
    fn from(e: quinn::RetryError) -> Self {
        Error {
            inner: InnerError::RetryError(Box::new(e)),
            location: Location::caller(),
        }
    }
}

impl From<rustls::Error> for Error {
    #[track_caller]
    fn from(e: rustls::Error) -> Self {
        Error {
            inner: InnerError::Tls(e),
            location: Location::caller(),
        }
    }
}
