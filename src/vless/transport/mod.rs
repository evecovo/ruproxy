pub mod raw;
pub mod tls;
pub mod websocket;

use tokio::io::{AsyncRead, AsyncWrite};

/// A type-erased bidirectional stream that vless::listener can use uniformly
/// regardless of the underlying transport (raw TCP / TLS / WS / WS+TLS).
pub type BoxStream = Box<dyn Stream>;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
