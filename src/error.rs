use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid WireGuard frame: {0}")]
    InvalidFrame(String),

    #[error("Session evicted (idle timeout)")]
    SessionEvicted,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Codec error: {0}")]
    Codec(String),
}
