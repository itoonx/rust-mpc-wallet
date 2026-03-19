/// In-process transport using tokio mpsc channels (for testing and single-process simulation).
///
/// Gated behind `#[cfg(any(test, feature = "local-transport"))]` to prevent accidental
/// production use. Enable the `local-transport` feature flag for CLI/demo usage (SEC-014).
#[cfg(any(test, feature = "local-transport"))]
pub mod local;
/// NATS-based transport for multi-process and multi-machine MPC deployments.
pub mod nats;
pub use nats::NatsTlsConfig;
/// NATS JetStream subject configuration and ACL for MPC message streams (Epic E5).
pub mod jetstream;
/// Per-session ECDH key exchange and ChaCha20-Poly1305 encryption (Epic E3).
pub mod session_key;
/// SEC-007 fix: Ed25519-signed message envelope with seq_no replay protection.
///
/// Use [`signed_envelope::SignedEnvelope::sign`] before sending and
/// [`signed_envelope::SignedEnvelope::verify`] on receipt to authenticate senders
/// and prevent replay attacks.
pub mod signed_envelope;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::types::PartyId;

/// A message exchanged between parties during MPC protocol execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Sender party ID.
    pub from: PartyId,
    /// Recipient party ID (None = broadcast).
    pub to: Option<PartyId>,
    /// Protocol round number.
    pub round: u16,
    /// Serialized message payload.
    pub payload: Vec<u8>,
}

/// Transport layer for exchanging messages between MPC parties.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a message to a specific party or broadcast.
    async fn send(&self, msg: ProtocolMessage) -> Result<(), CoreError>;

    /// Receive the next message for this party.
    async fn recv(&self) -> Result<ProtocolMessage, CoreError>;

    /// The party ID that this transport belongs to.
    fn party_id(&self) -> PartyId;
}
