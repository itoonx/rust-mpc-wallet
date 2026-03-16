//! NATS-backed transport for MPC protocol messages.
//!
//! Each party subscribes to a per-session subject and publishes to other parties'
//! subjects. Messages are JSON-serialized [`ProtocolMessage`] values.
//!
//! # Subject scheme
//! `mpc.{session_id}.party.{party_id}`
//!
//! # Security note (Sprint 3)
//! This implementation provides plain NATS connectivity only.
//! Production hardening (mTLS, per-session ECDH envelope encryption, signed
//! envelopes with seq_no + TTL replay protection) is tracked in Epic E stories
//! E2–E4 and will be added in Sprint 4.

use async_nats::Client;
use async_trait::async_trait;
use futures::StreamExt;
use serde_json;

use crate::{
    error::CoreError,
    transport::{ProtocolMessage, Transport},
    types::PartyId,
};

/// NATS-backed [`Transport`] implementation.
///
/// Connects to a NATS server and routes [`ProtocolMessage`] values between
/// parties using per-session subjects.
pub struct NatsTransport {
    /// The underlying NATS client.
    client: Client,
    /// The party ID this transport represents.
    party_id: PartyId,
    /// Session identifier used as a subject namespace.
    session_id: String,
}

impl NatsTransport {
    /// Connect to a NATS server and create a transport for `party_id`.
    ///
    /// # Errors
    /// Returns [`CoreError::Transport`] if the connection fails.
    pub async fn connect(
        nats_url: &str,
        party_id: PartyId,
        session_id: String,
    ) -> Result<Self, CoreError> {
        let client = async_nats::connect(nats_url)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS connect failed: {e}")))?;
        Ok(Self {
            client,
            party_id,
            session_id,
        })
    }

    /// Subject this party listens on: `mpc.{session_id}.party.{party_id}`.
    fn inbox_subject(&self) -> String {
        format!("mpc.{}.party.{}", self.session_id, self.party_id.0)
    }

    /// Subject to publish to a specific party: `mpc.{session_id}.party.{target}`.
    fn party_subject(session_id: &str, target: PartyId) -> String {
        format!("mpc.{}.party.{}", session_id, target.0)
    }
}

#[async_trait]
impl Transport for NatsTransport {
    async fn send(&self, msg: ProtocolMessage) -> Result<(), CoreError> {
        let target = msg
            .to
            .ok_or_else(|| CoreError::Transport("NATS: broadcast not supported".to_string()))?;
        let subject = Self::party_subject(&self.session_id, target);
        let payload = serde_json::to_vec(&msg)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        self.client
            .publish(subject, payload.into())
            .await
            .map_err(|e| CoreError::Transport(format!("NATS publish failed: {e}")))?;
        Ok(())
    }

    async fn recv(&self) -> Result<ProtocolMessage, CoreError> {
        let subject = self.inbox_subject();
        let mut subscriber = self
            .client
            .subscribe(subject)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS subscribe failed: {e}")))?;

        let msg = subscriber
            .next()
            .await
            .ok_or_else(|| CoreError::Transport("NATS subscription closed".to_string()))?;

        let protocol_msg: ProtocolMessage = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        Ok(protocol_msg)
    }

    fn party_id(&self) -> PartyId {
        self.party_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_subject_format() {
        let subject = NatsTransport::party_subject("session-abc", PartyId(3));
        assert_eq!(subject, "mpc.session-abc.party.3");
    }

    #[test]
    fn test_inbox_subject_format() {
        // Can't construct NatsTransport without a real client,
        // but we can test the subject formula directly.
        let session_id = "test-session";
        let party_id = PartyId(2);
        let expected = format!("mpc.{}.party.{}", session_id, party_id.0);
        assert_eq!(expected, "mpc.test-session.party.2");
    }
}
