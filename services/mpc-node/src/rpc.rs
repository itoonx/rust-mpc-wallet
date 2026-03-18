//! NATS RPC protocol messages between Gateway (orchestrator) and MPC Nodes.
//!
//! Gateway publishes requests on control channels, nodes subscribe and respond.
//!
//! # Control channels
//! - `mpc.control.keygen.{group_id}` — keygen ceremony coordination
//! - `mpc.control.sign.{group_id}` — sign request with SignAuthorization
//! - `mpc.control.freeze.{group_id}` — freeze/unfreeze key group
//!
//! # Protocol channels (existing)
//! - `mpc.{session_id}.party.{party_id}` — MPC protocol messages (SignedEnvelope)

use serde::{Deserialize, Serialize};

/// Request from gateway to nodes: initiate keygen ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenRequest {
    /// Unique group ID for this key group.
    pub group_id: String,
    /// Human-readable label.
    pub label: String,
    /// Crypto scheme (e.g., "gg20-ecdsa", "frost-ed25519").
    pub scheme: String,
    /// Signing threshold (t).
    pub threshold: u16,
    /// Total parties (n).
    pub total_parties: u16,
    /// Session ID for NATS protocol channel.
    pub session_id: String,
    /// Ed25519 verifying keys of ALL parties (hex-encoded), indexed by party_id.
    /// Nodes use these to register peer keys for SignedEnvelope verification.
    pub peer_keys: Vec<PeerKeyEntry>,
}

/// A party's Ed25519 verifying key for envelope authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerKeyEntry {
    pub party_id: u16,
    pub verifying_key_hex: String,
}

/// Response from a node after keygen completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenResponse {
    pub party_id: u16,
    pub group_id: String,
    /// Hex-encoded group public key (shared across all parties).
    pub group_pubkey_hex: String,
    /// Whether keygen succeeded.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Request from gateway to nodes: sign a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub group_id: String,
    /// Hex-encoded message to sign.
    pub message_hex: String,
    /// Which parties should participate (party_ids).
    pub signer_ids: Vec<u16>,
    /// Session ID for NATS protocol channel.
    pub session_id: String,
    /// Ed25519 verifying keys of signing parties.
    pub peer_keys: Vec<PeerKeyEntry>,
    /// SignAuthorization proof from gateway (JSON-serialized).
    /// Nodes MUST verify this before participating.
    pub sign_authorization: String,
}

/// Response from coordinator node after sign completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub party_id: u16,
    pub group_id: String,
    /// JSON-serialized MpcSignature.
    pub signature_json: Option<String>,
    pub success: bool,
    pub error: Option<String>,
}

/// Request to freeze/unfreeze a key group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezeRequest {
    pub group_id: String,
    pub freeze: bool,
}

/// Response to freeze/unfreeze.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FreezeResponse {
    pub party_id: u16,
    pub group_id: String,
    pub success: bool,
    pub error: Option<String>,
}
