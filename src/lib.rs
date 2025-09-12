//! A lightweight HTTP connector that routes all traffic through an
//! `arti_client::TorClient`.
//!
//! No DNS resolution happens here: Tor handles hostname/onion resolution.
//!
//! We do not expose local/remote socket addresses (they are abstracted by Tor).

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use arti_client::{DataStream, StreamPrefs, TorClient};
use http::Uri;
use http::uri::Scheme;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tor_rtcompat::Runtime;
use tower_service::Service;

/// Error creating or using a Tor-backed HTTP connection.
///
/// This (or a wrapper) will get transformed into a `hyper::Error` upstream.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum ConnectionError {
    /// Unsupported or missing URI scheme.
    ///
    /// Only `http` and `https` are accepted (we allow `https` so that a TLS
    /// layer above us can terminate it; this layer itself stays plaintext).
    #[error("unsupported URI scheme in {uri:?}")]
    UnsupportedUriScheme {
        /// The full URI that failed validation.
        uri: Uri,
    },

    /// Missing hostname part in the `Uri`.
    #[error("missing hostname in {uri:?}")]
    MissingHostname {
        /// The full URI that failed validation.
        uri: Uri,
    },

    /// Tor (Arti) connection failed.
    #[error("arti connection failed")]
    Arti(#[source] arti_client::Error),
}

impl From<arti_client::Error> for ConnectionError {
    fn from(err: arti_client::Error) -> Self {
        ConnectionError::Arti(err)
    }
}

/// A Hyper-compatible HTTP connector that establishes streams through Tor.
#[derive(Clone)]
pub struct ArtiConnector<R: Runtime> {
    client: TorClient<R>,
    prefs: Option<StreamPrefs>,
}

impl<R: Runtime> ArtiConnector<R> {
    /// Create a new Tor HTTP connector with default behavior.
    pub fn new(client: TorClient<R>) -> Self {
        Self {
            client,
            prefs: None,
        }
    }

    pub fn new_with_prefs(client: TorClient<R>, prefs: StreamPrefs) -> Self {
        Self {
            client,
            prefs: Some(prefs),
        }
    }

    /// Provide custom `StreamPrefs` (e.g. to allow onion services explicitly).
    pub fn set_stream_prefs(&mut self, prefs: StreamPrefs) {
        self.prefs = Some(prefs);
    }
}

impl<R: Runtime> Service<Uri> for ArtiConnector<R> {
    type Response = TokioIo<TorStream>;
    type Error = ConnectionError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // TorClient is internally ready for multiple concurrent connections.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        // Synchronous validation first so errors are immediate.
        let scheme = match uri.scheme().cloned() {
            Some(s) if s == Scheme::HTTP || s == Scheme::HTTPS => s,
            _ => {
                let err = ConnectionError::UnsupportedUriScheme { uri };
                return Box::pin(async { Err(err) });
            }
        };

        let host = match uri.host() {
            Some(h) => h.to_string(),
            None => {
                let err = ConnectionError::MissingHostname { uri };
                return Box::pin(async { Err(err) });
            }
        };

        let is_https = scheme == Scheme::HTTPS;
        let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });

        let prefs = self.prefs.clone().unwrap_or_default();
        let client = self.client.clone();

        Box::pin(async move {
            let tor_stream = client
                .connect_with_prefs((host.as_str(), port), &prefs)
                .await?;

            Ok(TokioIo::new(TorStream { inner: tor_stream }))
        })
    }
}

/// Wrapper around `arti_client::DataStream` so we can implement `Connection` and provide Debug.
pub struct TorStream {
    inner: DataStream,
}

impl fmt::Debug for TorStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TorStream").finish()
    }
}

impl Connection for TorStream {
    fn connected(&self) -> Connected {
        // No meaningful socket address information to expose through Tor.
        Connected::new()
    }
}

impl AsyncRead for TorStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        AsyncRead::poll_read(inner, cx, buf)
    }
}

impl AsyncWrite for TorStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        AsyncWrite::poll_write(inner, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        AsyncWrite::poll_flush(inner, cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        AsyncWrite::poll_shutdown(inner, cx)
    }
}
