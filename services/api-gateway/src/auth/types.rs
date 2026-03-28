//! Handshake message types, session types, and shared utilities.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use mpc_wallet_core::rbac::ApiRole;

/// Protocol version for the key-exchange handshake.
pub const PROTOCOL_VERSION: &str = "mpc-wallet-auth-v1";

/// Maximum allowed timestamp drift (seconds).
pub const MAX_TIMESTAMP_DRIFT_SECS: u64 = 30;

/// Default session TTL (seconds).
pub const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour

/// Maximum entries in replay cache / pending handshakes (DoS protection).
pub const MAX_CACHE_ENTRIES: usize = 100_000;

// ── Utility Functions ──────────────────────────────────────────────

/// Get current UNIX timestamp in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a 32-byte random nonce.
pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    nonce
}

/// Generate a random Ed25519 signing key.
pub fn gen_ed25519_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&random_nonce())
}

/// Parse a role string into `ApiRole`. Unknown roles default to Viewer.
pub fn parse_role(s: &str) -> ApiRole {
    match s {
        "admin" => ApiRole::Admin,
        "initiator" => ApiRole::Initiator,
        "approver" => ApiRole::Approver,
        _ => ApiRole::Viewer,
    }
}

/// Auth failure response — returns `ApiError` with UNAUTHORIZED status.
pub fn auth_failed() -> crate::errors::ApiError {
    crate::errors::ApiError::unauthorized("authentication failed")
}

// ── Transcript Hashing ─────────────────────────────────────────────

/// Canonical bytes for ServerHello (excluding server_signature) for transcript.
pub fn server_hello_transcript_bytes(sh: &ServerHello) -> Vec<u8> {
    let val = serde_json::json!({
        "protocol_version": sh.protocol_version,
        "selected_kex": sh.selected_kex,
        "selected_sig": sh.selected_sig,
        "selected_aead": sh.selected_aead,
        "server_ephemeral_pubkey": sh.server_ephemeral_pubkey,
        "server_nonce": sh.server_nonce,
        "server_challenge": sh.server_challenge,
        "timestamp": sh.timestamp,
        "server_key_id": sh.server_key_id,
    });
    serde_json::to_vec(&val).expect("ServerHello serialization cannot fail")
}

/// Canonical bytes for ClientAuth (excluding client_signature) for transcript.
pub fn client_auth_transcript_bytes(client_static_pubkey: &str) -> Vec<u8> {
    let val = serde_json::json!({
        "client_static_pubkey": client_static_pubkey,
    });
    serde_json::to_vec(&val).expect("ClientAuth serialization cannot fail")
}

/// Compute the full transcript hash for a handshake.
///
/// `transcript = SHA-256(ClientHello || ServerHello_no_sig || ClientAuth_no_sig)`
pub fn compute_transcript_hash(
    client_hello: &ClientHello,
    server_hello: &ServerHello,
    client_static_pubkey: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(client_hello).expect("ClientHello serialization"));
    hasher.update(server_hello_transcript_bytes(server_hello));
    hasher.update(client_auth_transcript_bytes(client_static_pubkey));
    hasher.finalize().into()
}

/// Compute the partial transcript hash (ClientHello + ServerHello_no_sig only).
/// Used by server to sign before ClientAuth is available.
pub fn compute_partial_transcript_hash(
    client_hello: &ClientHello,
    server_hello: &ServerHello,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(client_hello).expect("ClientHello serialization"));
    hasher.update(server_hello_transcript_bytes(server_hello));
    hasher.finalize().into()
}

// ── Key Derivation ─────────────────────────────────────────────────

/// Derive directional session keys from ECDH shared secret.
///
/// Returns `(client_write_key, server_write_key)`.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Result<([u8; 32], [u8; 32]), &'static str> {
    let mut salt = Vec::with_capacity(client_nonce.len() + server_nonce.len());
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);

    let mut client_write_key = [0u8; 32];
    let mut server_write_key = [0u8; 32];

    hk.expand(b"mpc-wallet-session-v1-client-write", &mut client_write_key)
        .map_err(|_| "HKDF client-write expand failed")?;
    hk.expand(b"mpc-wallet-session-v1-server-write", &mut server_write_key)
        .map_err(|_| "HKDF server-write expand failed")?;

    Ok((client_write_key, server_write_key))
}

// ── Algorithm Enums ────────────────────────────────────────────────

/// Supported ECDH algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum KeyExchangeAlgorithm {
    #[serde(rename = "x25519")]
    X25519,
}

/// Supported signature algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum SignatureAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
}

/// Supported AEAD algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum AeadAlgorithm {
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

// ── Message Types ──────────────────────────────────────────────────

/// Client's initial handshake message.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ClientHello {
    pub protocol_version: String,
    pub supported_kex: Vec<KeyExchangeAlgorithm>,
    pub supported_sig: Vec<SignatureAlgorithm>,
    /// Client's ephemeral X25519 public key (32 bytes, hex-encoded).
    pub client_ephemeral_pubkey: String,
    /// Client's random nonce (32 bytes, hex-encoded).
    pub client_nonce: String,
    pub timestamp: u64,
    /// Client's static public key ID (first 8 bytes of Ed25519 pubkey, hex).
    pub client_key_id: String,
}

/// Server's response with ephemeral key and challenge.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ServerHello {
    pub protocol_version: String,
    pub selected_kex: KeyExchangeAlgorithm,
    pub selected_sig: SignatureAlgorithm,
    pub selected_aead: AeadAlgorithm,
    pub server_ephemeral_pubkey: String,
    pub server_nonce: String,
    pub server_challenge: String,
    pub timestamp: u64,
    pub server_key_id: String,
    pub server_signature: String,
}

/// Client's authentication proof.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ClientAuth {
    pub client_signature: String,
    pub client_static_pubkey: String,
}

/// Session establishment confirmation from server.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SessionEstablished {
    pub session_id: String,
    pub expires_at: u64,
    pub session_token: String,
    pub key_fingerprint: String,
}

/// An active authenticated session.
///
/// Session keys are zeroized on drop to prevent key material lingering in memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatedSession {
    pub session_id: String,
    pub client_pubkey: [u8; 32],
    pub client_key_id: String,
    pub client_write_key: [u8; 32],
    pub server_write_key: [u8; 32],
    pub expires_at: u64,
    pub created_at: u64,
}

impl std::fmt::Debug for AuthenticatedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedSession")
            .field("session_id", &self.session_id)
            .field("client_key_id", &self.client_key_id)
            .field("client_write_key", &"[REDACTED]")
            .field("server_write_key", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}
