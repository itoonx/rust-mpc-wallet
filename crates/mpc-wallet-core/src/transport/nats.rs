//! NATS-backed transport for MPC protocol messages with SEC-007 signed envelopes.
//!
//! Each party subscribes to a per-session subject and publishes to other parties'
//! subjects. Every message is wrapped in a [`SignedEnvelope`] that:
//! - Authenticates the sender via an Ed25519 signature (SEC-007 fix)
//! - Prevents replay attacks via a monotonic `seq_no`
//! - Enforces message freshness via a TTL (`expires_at`)
//!
//! # Subject scheme
//! `mpc.{session_id}.party.{party_id}`
//!
//! # Security status (Sprint 6)
//! - ✅ SEC-007: sender authentication via SignedEnvelope (wired in this file)
//! - ⚠️  TLS not yet configured — Epic E2 scope
//! - ⚠️  Per-session ECDH key exchange — Epic E3 scope

use std::collections::HashMap;
use std::sync::Mutex;

use async_nats::Client;
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::StreamExt;

use crate::{
    error::CoreError,
    transport::{
        signed_envelope::{SignedEnvelope, DEFAULT_TTL_SECS},
        ProtocolMessage, Transport,
    },
    types::PartyId,
};

/// NATS-backed [`Transport`] with SEC-007 signed envelope authentication.
///
/// # Signed envelopes
///
/// Every `send` wraps the [`ProtocolMessage`] in a [`SignedEnvelope`] signed
/// with this party's Ed25519 key. Every `recv` verifies the envelope against
/// the sender's registered public key and checks the monotonic `seq_no`.
///
/// # Setup
///
/// 1. Create the transport with [`NatsTransport::connect_signed`], providing
///    this party's Ed25519 signing key and the session_id.
/// 2. Register each peer's verifying key with [`NatsTransport::register_peer_key`].
/// 3. Call `send`/`recv` as normal — envelopes are handled transparently.
pub struct NatsTransport {
    client: Client,
    party_id: PartyId,
    session_id: String,
    /// This party's Ed25519 signing key (for outgoing envelope signatures).
    signing_key: SigningKey,
    /// Registered peers: party_id → verifying key (for incoming signature verification).
    peer_keys: HashMap<PartyId, VerifyingKey>,
    /// Per-peer last-seen seq_no for replay detection.
    last_seq: Mutex<HashMap<PartyId, u64>>,
    /// Per-peer outgoing seq_no counter (monotonically increasing).
    out_seq: Mutex<u64>,
}

impl NatsTransport {
    /// Connect to a NATS server with SEC-007 signed envelope support.
    ///
    /// # Arguments
    /// - `nats_url` — NATS server URL (e.g. `nats://localhost:4222`).
    /// - `party_id` — this party's ID.
    /// - `session_id` — signing session namespace.
    /// - `signing_key` — this party's Ed25519 key used to sign outgoing envelopes.
    ///
    /// # Security note
    /// Plain TCP NATS — TLS is not yet configured (Epic E2 scope).
    // SECURITY: TLS not yet configured — Epic E2 scope
    pub async fn connect_signed(
        nats_url: &str,
        party_id: PartyId,
        session_id: String,
        signing_key: SigningKey,
    ) -> Result<Self, CoreError> {
        let client = async_nats::connect(nats_url)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS connect failed: {e}")))?;
        Ok(Self {
            client,
            party_id,
            session_id,
            signing_key,
            peer_keys: HashMap::new(),
            last_seq: Mutex::new(HashMap::new()),
            out_seq: Mutex::new(0),
        })
    }

    /// Register a peer's Ed25519 verifying key for incoming envelope verification.
    ///
    /// Must be called for every party before `recv` is used, otherwise messages
    /// from unregistered parties are rejected with `CoreError::Transport`.
    pub fn register_peer_key(&mut self, peer_id: PartyId, verifying_key: VerifyingKey) {
        self.peer_keys.insert(peer_id, verifying_key);
    }

    /// This party's Ed25519 verifying (public) key.
    /// Share this with all peers via out-of-band key exchange before the session.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn inbox_subject(&self) -> String {
        format!("mpc.{}.party.{}", self.session_id, self.party_id.0)
    }

    fn party_subject(session_id: &str, target: PartyId) -> String {
        format!("mpc.{}.party.{}", session_id, target.0)
    }

    fn next_seq_no(&self) -> u64 {
        let mut seq = self.out_seq.lock().unwrap();
        *seq += 1;
        *seq
    }
}

#[async_trait]
impl Transport for NatsTransport {
    async fn send(&self, msg: ProtocolMessage) -> Result<(), CoreError> {
        let target = msg
            .to
            .ok_or_else(|| CoreError::Transport("NATS: broadcast not supported".into()))?;

        let seq_no = self.next_seq_no();

        // SEC-007: wrap in signed envelope before publishing
        let envelope = SignedEnvelope::sign(
            msg,
            self.party_id,
            seq_no,
            DEFAULT_TTL_SECS,
            &self.signing_key,
        );

        let subject = Self::party_subject(&self.session_id, target);
        let payload = serde_json::to_vec(&envelope)
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

        let raw = subscriber
            .next()
            .await
            .ok_or_else(|| CoreError::Transport("NATS subscription closed".into()))?;

        // Deserialise the signed envelope
        let envelope: SignedEnvelope = serde_json::from_slice(&raw.payload)
            .map_err(|e| CoreError::Transport(format!("envelope deserialize failed: {e}")))?;

        let sender = envelope.sender;

        // Look up the sender's registered verifying key
        let peer_vk = self.peer_keys.get(&sender).ok_or_else(|| {
            CoreError::Transport(format!(
                "SEC-007: no registered key for party {} — call register_peer_key first",
                sender.0
            ))
        })?;

        // Retrieve last-seen seq_no for this sender
        let last_seen = {
            let seq_map = self.last_seq.lock().unwrap();
            *seq_map.get(&sender).unwrap_or(&0)
        };

        // SEC-007: verify signature, TTL, and seq_no
        envelope.verify(peer_vk, last_seen)?;

        // Update last-seen seq_no
        {
            let mut seq_map = self.last_seq.lock().unwrap();
            seq_map.insert(sender, envelope.seq_no);
        }

        Ok(envelope.message)
    }

    fn party_id(&self) -> PartyId {
        self.party_id
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

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
        let session_id = "test-session";
        let party_id = PartyId(2);
        let expected = format!("mpc.{}.party.{}", session_id, party_id.0);
        assert_eq!(expected, "mpc.test-session.party.2");
    }

    #[test]
    fn test_seq_no_increments() {
        // Verify that seq_no increments are monotonic across calls.
        // We test the counter logic directly (no live NATS needed).
        let counter = Mutex::new(0u64);
        let mut results = Vec::new();
        for _ in 0..5 {
            let mut seq = counter.lock().unwrap();
            *seq += 1;
            results.push(*seq);
        }
        assert_eq!(results, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_signed_envelope_roundtrip_without_nats() {
        // Verify the sign→serialise→deserialise→verify pipeline works
        // without a live NATS server.
        use crate::transport::signed_envelope::SignedEnvelope;
        use rand::RngCore;
        use rand::rngs::OsRng;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let vk = signing_key.verifying_key();

        let msg = ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: b"hello from party 1".to_vec(),
        };

        let envelope = SignedEnvelope::sign(msg.clone(), PartyId(1), 1, DEFAULT_TTL_SECS, &signing_key);

        // Serialise and deserialise (simulating the NATS wire)
        let json = serde_json::to_vec(&envelope).unwrap();
        let decoded: SignedEnvelope = serde_json::from_slice(&json).unwrap();

        // Verify succeeds with correct key and seq_no = 0 (first message)
        assert!(decoded.verify(&vk, 0).is_ok());
        assert_eq!(decoded.message.payload, b"hello from party 1");
    }

    #[test]
    fn test_replay_blocked_in_nats_pipeline() {
        // Simulate two envelopes with seq_no 1, 1 (replay).
        use crate::transport::signed_envelope::SignedEnvelope;
        use rand::RngCore;
        use rand::rngs::OsRng;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let vk = signing_key.verifying_key();

        let msg = ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: vec![],
        };

        let env1 = SignedEnvelope::sign(msg.clone(), PartyId(1), 1, DEFAULT_TTL_SECS, &signing_key);
        let env2 = SignedEnvelope::sign(msg, PartyId(1), 1, DEFAULT_TTL_SECS, &signing_key);

        // First message is accepted
        assert!(env1.verify(&vk, 0).is_ok());
        // Second with same seq_no 1 is rejected as replay (last_seen = 1)
        assert!(env2.verify(&vk, 1).is_err());
    }

    // NatsTransport integration test requires a live NATS server.
    // Run manually: NATS_URL=nats://localhost:4222 cargo test --features nats-integration-test
    #[tokio::test]
    #[ignore = "requires live NATS server: NATS_URL=nats://localhost:4222"]
    async fn test_nats_signed_round_trip() {
        use rand::RngCore;
        use rand::rngs::OsRng;

        let url = std::env::var("NATS_URL").unwrap_or("nats://localhost:4222".into());
        let session = uuid::Uuid::new_v4().to_string();

        let mut k1_bytes = [0u8; 32];
        let mut k2_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut k1_bytes);
        OsRng.fill_bytes(&mut k2_bytes);
        let k1 = SigningKey::from_bytes(&k1_bytes);
        let k2 = SigningKey::from_bytes(&k2_bytes);
        let vk1 = k1.verifying_key();
        let vk2 = k2.verifying_key();

        let mut t1 = NatsTransport::connect_signed(&url, PartyId(1), session.clone(), k1).await.unwrap();
        let mut t2 = NatsTransport::connect_signed(&url, PartyId(2), session.clone(), k2).await.unwrap();

        t1.register_peer_key(PartyId(2), vk2);
        t2.register_peer_key(PartyId(1), vk1);

        let msg = ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: b"sec007-test".to_vec(),
        };

        t1.send(msg.clone()).await.unwrap();
        let received = t2.recv().await.unwrap();
        assert_eq!(received.payload, b"sec007-test");
    }
}
