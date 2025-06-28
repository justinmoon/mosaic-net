//! Mosaic net is a networking library for running the
//! [Mosaic protocol](https://stevefarroll.github.io/mosaic-spec/)
//! over [QUIC](https://www.rfc-editor.org/rfc/rfc9000) transport.

#![warn(clippy::pedantic)]
#![deny(
    missing_debug_implementations,
    trivial_numeric_casts,
    clippy::string_slice,
    unused_import_braces,
    unused_results,
    unused_lifetimes,
    unused_labels,
    unused_extern_crates,
    non_ascii_idents,
    keyword_idents,
    deprecated_in_future,
    unstable_features,
    single_use_lifetimes,
    unreachable_pub,
    missing_copy_implementations,
    missing_docs
)]

mod error;
pub use error::{Error, InnerError};

/// The Application-Layer protocol string used within QUIC for Mosaic
pub const ALPN_QUIC_MOSAIC: &[u8] = b"mosaic";

mod client;
pub use client::{Client, ClientConfig};

mod server;
pub use server::{Server, ServerConfig};
