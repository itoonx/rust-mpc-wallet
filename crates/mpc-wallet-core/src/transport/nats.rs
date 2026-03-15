use async_nats::Client;
use async_trait::async_trait;

use crate::error::CoreError;
use crate::transport::{ProtocolMessage, Transport};
use crate::types::PartyId;

/// NATS-backed transport for MPC protocol messages.
///
/// Each party subscribes to a subject `mpc.{session_id}.party.{party_id}` and publishes
/// to `mpc.{session_id}.party.{target_party_id}`. Messages are serialized with serde_json.
///
/// # Security Note
/// Production use requires:
/// - TLS (nats-tls feature) with certificate pinning
/// - Per-session ECDH envelope encryption (X25519 + ChaCha20-Poly1305)
/// - Signed message envelopes with monotonic seq_no + TTL for replay protection
pub struct NatsTransport {
    client: Client,
    party_id: PartyId,
    /// Unique per keygen/sign session, used as NATS subject prefix.
    session_id: String,
}

impl NatsTransport {
    /// Connect to a NATS server and return a NatsTransport for this party.
    pub async fn connect(
        nats_url: &str,
        party_id: PartyId,
        session_id: String,
    ) -> Result<Self, CoreError> {
        todo!("connect to NATS server at nats_url")
    }

    /// Subject this party listens on: `mpc.{session_id}.party.{party_id}`
    fn inbox_subject(&self) -> String {
        todo!()
    }

    /// Subject to send to a specific party: `mpc.{session_id}.party.{target_id}`
    fn party_subject(session_id: &str, target: PartyId) -> String {
        todo!()
    }
}

#[async_trait]
impl Transport for NatsTransport {
    async fn send(&self, msg: ProtocolMessage) -> Result<(), CoreError> {
        todo!("serialize msg with serde_json, publish to party_subject")
    }

    async fn recv(&self) -> Result<ProtocolMessage, CoreError> {
        todo!("subscribe to inbox_subject, deserialize next message with serde_json")
    }

    fn party_id(&self) -> PartyId {
        self.party_id
    }
}
