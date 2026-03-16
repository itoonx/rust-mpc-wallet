use thiserror::Error;

/// The top-level error type returned by all fallible operations in `mpc-wallet-core`.
///
/// Each variant carries a human-readable description of the failure. Callers
/// should match on the variant to distinguish recoverable from non-recoverable
/// failures, and forward the inner string to logs or user-facing messages.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The MPC protocol encountered an error during key generation or signing.
    /// Contains a human-readable description of the failure. Callers should
    /// treat this as non-recoverable for the current session; a fresh keygen
    /// or signing round must be initiated.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// A failure occurred in the underlying transport layer (e.g. send timeout,
    /// channel closed, or deserialization of an incoming message failed).
    /// The current protocol round cannot continue; the session must be retried.
    #[error("transport error: {0}")]
    Transport(String),

    /// A key store I/O or consistency error (e.g. failed to write an encrypted
    /// share to disk, or the directory structure is unexpected). The inner string
    /// includes the OS-level error where available.
    #[error("key store error: {0}")]
    KeyStore(String),

    /// The caller supplied a configuration that violates an invariant (e.g.
    /// `threshold > total_parties`, or an unsupported parameter combination).
    /// The operation was rejected before any state was mutated.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Encoding or decoding of a protocol message, key share, or transaction
    /// payload failed. This usually indicates a version mismatch or data
    /// corruption rather than a programming error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A low-level cryptographic operation failed (e.g. signature verification,
    /// elliptic-curve arithmetic, or hash computation returned an error).
    /// This is distinct from [`CoreError::Protocol`] which covers higher-level
    /// MPC round failures.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// AES-256-GCM encryption or decryption of a key share failed. Common
    /// causes: wrong password (authentication tag mismatch), truncated ciphertext,
    /// or corrupt salt/nonce bytes in the stored file.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// The requested resource (key share, key group, or transaction) could not
    /// be found in the store. The inner string identifies what was looked up.
    #[error("not found: {0}")]
    NotFound(String),

    /// The key group has been frozen and cannot be used for signing.
    /// Callers must unfreeze the group via [`crate::key_store::KeyStore::unfreeze`]
    /// before any further signing operations.
    #[error("key group frozen: {0}")]
    KeyFrozen(String),

    /// A password is required but was not provided.
    /// Returned by storage operations that need a key-derivation password when
    /// none was supplied (e.g. opening an encrypted file store with an empty password).
    #[error("password required: {0}")]
    PasswordRequired(String),

    /// The caller supplied an argument that fails basic validity checks (e.g.
    /// an address string with an invalid prefix or wrong length). The inner
    /// string identifies which argument was rejected and why.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// No signing policy is loaded; a valid policy must be set before a signing
    /// session can start. This enforces the "no policy → no sign" rule (FR-B5).
    ///
    /// Returned by [`crate::policy::PolicyStore::check`] when no policy has been
    /// loaded via [`crate::policy::PolicyStore::load`]. Callers must load a policy
    /// before creating any signing session.
    #[error("policy required: {0}")]
    PolicyRequired(String),

    /// A signing session error (e.g. duplicate `tx_fingerprint`, invalid state
    /// transition, or session not found). The inner string identifies the session
    /// and the failure reason.
    ///
    /// Returned by [`crate::session::SessionManager`] operations when the requested
    /// operation cannot be completed given the current session state.
    #[error("session error: {0}")]
    SessionError(String),

    /// An approval workflow error (e.g. insufficient quorum, SoD violation,
    /// approver already submitted, or hold period not elapsed).
    ///
    /// Returned by [`crate::approvals::ApprovalStore`] when the approval
    /// workflow rejects an operation (FR-C).
    #[error("approval error: {0}")]
    ApprovalRequired(String),

    /// An audit ledger error (e.g. hash-chain integrity violation, service
    /// signature failure, or append I/O error).
    ///
    /// Returned by [`crate::audit::AuditLedger`] operations (FR-F).
    #[error("audit error: {0}")]
    AuditError(String),

    /// An EVM ECDSA signature has a high-S value that violates EIP-2 / low-S
    /// canonicalization. Callers must normalise the signature before broadcasting.
    ///
    /// SEC-012: high-S signatures are rejected by many EVM infrastructure providers
    /// and wallets. `finalize_evm_transaction` enforces low-S automatically; this
    /// error is returned if the input MpcSignature cannot be normalised.
    #[error("evm low-s violation: {0}")]
    EvmLowS(String),

    /// A catch-all error variant for cases not covered by the more specific
    /// variants above. Prefer using a specific variant whenever possible so
    /// that callers can handle errors programmatically.
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
