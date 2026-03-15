use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("key store error: {0}")]
    KeyStore(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("not found: {0}")]
    NotFound(String),

    /// The key group has been frozen and cannot be used for signing.
    #[error("key group frozen: {0}")]
    KeyFrozen(String),

    /// A password is required but was not provided.
    #[error("password required: {0}")]
    PasswordRequired(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        CoreError::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::KeyStore(e.to_string())
    }
}
