//! Handshake message types and session types.

use serde::{Deserialize, Serialize};

/// Protocol version for the key-exchange handshake.
pub const PROTOCOL_VERSION: &str = "mpc-wallet-auth-v1";

/// Maximum allowed timestamp drift (seconds).
pub const MAX_TIMESTAMP_DRIFT_SECS: u64 = 30;

/// Default session TTL (seconds).
pub const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour

/// Supported ECDH algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyExchangeAlgorithm {
    #[serde(rename = "x25519")]
    X25519,
}

/// Supported signature algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
}

/// Supported AEAD algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

/// Client's initial handshake message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// Protocol version.
    pub protocol_version: String,
    /// Supported key exchange algorithms.
    pub supported_kex: Vec<KeyExchangeAlgorithm>,
    /// Supported signature algorithms.
    pub supported_sig: Vec<SignatureAlgorithm>,
    /// Client's ephemeral X25519 public key (32 bytes, hex-encoded).
    pub client_ephemeral_pubkey: String,
    /// Client's random nonce (32 bytes, hex-encoded).
    pub client_nonce: String,
    /// Timestamp (UNIX seconds).
    pub timestamp: u64,
    /// Client's static public key ID (hex-encoded Ed25519 pubkey or key fingerprint).
    pub client_key_id: String,
}

/// Server's response with ephemeral key and challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    /// Protocol version.
    pub protocol_version: String,
    /// Selected key exchange algorithm.
    pub selected_kex: KeyExchangeAlgorithm,
    /// Selected signature algorithm.
    pub selected_sig: SignatureAlgorithm,
    /// Selected AEAD algorithm for session.
    pub selected_aead: AeadAlgorithm,
    /// Server's ephemeral X25519 public key (32 bytes, hex-encoded).
    pub server_ephemeral_pubkey: String,
    /// Server's random nonce (32 bytes, hex-encoded).
    pub server_nonce: String,
    /// Server challenge (32 bytes, hex-encoded) — client must sign this.
    pub server_challenge: String,
    /// Timestamp (UNIX seconds).
    pub timestamp: u64,
    /// Server's static public key ID (hex-encoded Ed25519 pubkey fingerprint).
    pub server_key_id: String,
    /// Server's Ed25519 signature over transcript(ClientHello || ServerHello fields).
    pub server_signature: String,
}

/// Client's authentication proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    /// Client's Ed25519 signature over transcript(ClientHello || ServerHello || challenge).
    pub client_signature: String,
    /// Client's static Ed25519 public key (32 bytes, hex-encoded).
    pub client_static_pubkey: String,
}

/// Session establishment confirmation from server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEstablished {
    /// Unique session ID.
    pub session_id: String,
    /// Session expiration (UNIX seconds).
    pub expires_at: u64,
    /// Session token (opaque, encrypted with session key).
    pub session_token: String,
    /// Fingerprint of the session key (SHA-256 of derived key, first 16 bytes hex).
    pub key_fingerprint: String,
}

/// An active authenticated session.
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    /// Unique session ID.
    pub session_id: String,
    /// Client's static Ed25519 public key.
    pub client_pubkey: [u8; 32],
    /// Client key ID.
    pub client_key_id: String,
    /// Derived session encryption key (client→server direction).
    pub client_write_key: [u8; 32],
    /// Derived session encryption key (server→client direction).
    pub server_write_key: [u8; 32],
    /// Session expiration (UNIX seconds).
    pub expires_at: u64,
    /// Session creation (UNIX seconds).
    pub created_at: u64,
}
