//! NATS RPC protocol messages between Gateway (orchestrator) and MPC Nodes.
//!
//! Shared by both `services/api-gateway` and `services/mpc-node`.
//!
//! # Control channels
//! - `mpc.control.keygen.{group_id}` — keygen ceremony coordination
//! - `mpc.control.sign.{group_id}` — sign request with SignAuthorization
//! - `mpc.control.freeze.{group_id}` — freeze/unfreeze key group
//! - `mpc.control.keygen.{group_id}.reply` — keygen responses from nodes
//! - `mpc.control.sign.{group_id}.reply` — sign responses from nodes

use serde::{Deserialize, Serialize};

/// A party's Ed25519 verifying key for envelope authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerKeyEntry {
    pub party_id: u16,
    pub verifying_key_hex: String,
}

// ── Keygen ───────────────────────────────────────────────────────────

/// Request from gateway to nodes: initiate keygen ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenRequest {
    pub group_id: String,
    pub label: String,
    /// Crypto scheme string (e.g., "gg20-ecdsa").
    pub scheme: String,
    pub threshold: u16,
    pub total_parties: u16,
    /// Session ID for NATS protocol channel.
    pub session_id: String,
    /// Ed25519 verifying keys of ALL parties.
    pub peer_keys: Vec<PeerKeyEntry>,
}

/// Response from a node after keygen completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenResponse {
    pub party_id: u16,
    pub group_id: String,
    pub group_pubkey_hex: String,
    pub success: bool,
    pub error: Option<String>,
}

// ── Sign ─────────────────────────────────────────────────────────────

/// Request from gateway to nodes: sign a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub group_id: String,
    pub message_hex: String,
    pub signer_ids: Vec<u16>,
    pub session_id: String,
    pub peer_keys: Vec<PeerKeyEntry>,
    /// JSON-serialized SignAuthorization proof from gateway.
    pub sign_authorization: String,
}

/// Response from a signing node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub party_id: u16,
    pub group_id: String,
    /// JSON-serialized MpcSignature (only from coordinator).
    pub signature_json: Option<String>,
    pub success: bool,
    pub error: Option<String>,
}

// ── Freeze ───────────────────────────────────────────────────────────

/// Request to freeze/unfreeze a key group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezeRequest {
    pub group_id: String,
    pub freeze: bool,
}

/// Response to freeze/unfreeze.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezeResponse {
    pub party_id: u16,
    pub group_id: String,
    pub success: bool,
    pub error: Option<String>,
}

// ── NATS Subject Helpers ─────────────────────────────────────────────

/// Generate the NATS subject for a control request.
pub fn keygen_subject(group_id: &str) -> String {
    format!("mpc.control.keygen.{group_id}")
}

pub fn keygen_reply_subject(group_id: &str) -> String {
    format!("mpc.control.keygen.{group_id}.reply")
}

pub fn sign_subject(group_id: &str) -> String {
    format!("mpc.control.sign.{group_id}")
}

pub fn sign_reply_subject(group_id: &str) -> String {
    format!("mpc.control.sign.{group_id}.reply")
}

pub fn freeze_subject(group_id: &str) -> String {
    format!("mpc.control.freeze.{group_id}")
}
