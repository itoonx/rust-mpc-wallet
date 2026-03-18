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
use std::path::PathBuf;
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

/// TLS configuration for mTLS-enabled NATS connections (Epic E2).
///
/// Provides mutual TLS: the client authenticates the server via `ca_cert_path`
/// and presents its own certificate (`client_cert_path` + `client_key_path`)
/// so the NATS server can authenticate the client.
#[derive(Debug, Clone)]
pub struct NatsTlsConfig {
    /// Path to PEM-encoded CA certificate for server verification.
    pub ca_cert_path: PathBuf,
    /// Path to PEM-encoded client certificate (for mutual TLS).
    pub client_cert_path: PathBuf,
    /// Path to PEM-encoded client private key.
    pub client_key_path: PathBuf,
}

impl NatsTlsConfig {
    /// Build a [`rustls::ClientConfig`] from PEM files on disk.
    ///
    /// Loads the CA cert, client cert, and client key from the configured paths.
    /// The client key bytes are zeroized after use (SEC-004 pattern).
    pub fn build_rustls_config(&self) -> Result<rustls::ClientConfig, CoreError> {
        use std::io::BufReader;
        use zeroize::Zeroize;

        // 1. Load CA cert
        let ca_pem = std::fs::read(&self.ca_cert_path).map_err(|e| {
            CoreError::Transport(format!("read CA cert {}: {e}", self.ca_cert_path.display()))
        })?;
        let mut ca_reader = BufReader::new(ca_pem.as_slice());
        let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Transport(format!("parse CA cert: {e}")))?;

        if ca_certs.is_empty() {
            return Err(CoreError::Transport(
                "no CA certificates found in PEM file".into(),
            ));
        }

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| CoreError::Transport(format!("add CA cert to root store: {e}")))?;
        }

        // 2. Load client cert
        let client_pem = std::fs::read(&self.client_cert_path).map_err(|e| {
            CoreError::Transport(format!(
                "read client cert {}: {e}",
                self.client_cert_path.display()
            ))
        })?;
        let mut client_reader = BufReader::new(client_pem.as_slice());
        let client_certs: Vec<_> = rustls_pemfile::certs(&mut client_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Transport(format!("parse client cert: {e}")))?;

        // 3. Load client key (zeroize raw bytes after use — SEC-004 pattern)
        let mut key_pem = std::fs::read(&self.client_key_path).map_err(|e| {
            CoreError::Transport(format!(
                "read client key {}: {e}",
                self.client_key_path.display()
            ))
        })?;
        let mut key_reader = BufReader::new(key_pem.as_slice());
        let client_key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| CoreError::Transport(format!("parse client key: {e}")))?
            .ok_or_else(|| CoreError::Transport("no private key found in PEM file".into()))?;
        key_pem.zeroize(); // SEC-004 pattern: zeroize key bytes

        // 4. Build rustls config — TLS 1.2+ with default safe cipher suites
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .map_err(|e| CoreError::Transport(format!("build TLS config: {e}")))?;

        Ok(config)
    }
}

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
    /// Persistent subscription for receiving messages (lazy-initialized on first recv).
    /// This ensures messages published between recv() calls are not lost.
    subscriber: tokio::sync::Mutex<Option<async_nats::Subscriber>>,
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

        // Subscribe eagerly so no messages are lost between connect and first recv().
        let inbox = format!("mpc.{}.party.{}", session_id, party_id.0);
        let subscriber = client
            .subscribe(inbox)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS subscribe failed: {e}")))?;

        Ok(Self {
            client,
            party_id,
            session_id,
            signing_key,
            peer_keys: HashMap::new(),
            last_seq: Mutex::new(HashMap::new()),
            out_seq: Mutex::new(0),
            subscriber: tokio::sync::Mutex::new(Some(subscriber)),
        })
    }

    /// Connect to a NATS server with mTLS + SEC-007 signed envelope support (Epic E2).
    ///
    /// Like [`connect_signed`](Self::connect_signed), but the NATS connection is
    /// secured with mutual TLS: the client verifies the server's certificate
    /// against the provided CA cert, and presents its own client certificate for
    /// server-side authentication.
    ///
    /// # Arguments
    /// - `nats_url` — NATS server URL (e.g. `tls://nats.example.com:4222`).
    /// - `party_id` — this party's ID.
    /// - `session_id` — signing session namespace.
    /// - `signing_key` — this party's Ed25519 key used to sign outgoing envelopes.
    /// - `tls_config` — mTLS certificate paths (CA, client cert, client key).
    pub async fn connect_signed_tls(
        nats_url: &str,
        party_id: PartyId,
        session_id: String,
        signing_key: SigningKey,
        tls_config: NatsTlsConfig,
    ) -> Result<Self, CoreError> {
        let tls_client_config = tls_config.build_rustls_config()?;

        let client = async_nats::ConnectOptions::new()
            .tls_client_config(tls_client_config)
            .connect(nats_url)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS TLS connect failed: {e}")))?;

        let inbox = format!("mpc.{}.party.{}", session_id, party_id.0);
        let subscriber = client
            .subscribe(inbox)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS TLS subscribe failed: {e}")))?;

        Ok(Self {
            client,
            party_id,
            session_id,
            signing_key,
            peer_keys: HashMap::new(),
            last_seq: Mutex::new(HashMap::new()),
            out_seq: Mutex::new(0),
            subscriber: tokio::sync::Mutex::new(Some(subscriber)),
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
        if let Some(target) = msg.to {
            // Unicast: send to specific party.
            let seq_no = self.next_seq_no();
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
        } else {
            // Broadcast: send to all registered peers (one message per peer).
            let peers: Vec<PartyId> = self.peer_keys.keys().copied().collect();
            for peer_id in peers {
                let seq_no = self.next_seq_no();
                let envelope = SignedEnvelope::sign(
                    msg.clone(),
                    self.party_id,
                    seq_no,
                    DEFAULT_TTL_SECS,
                    &self.signing_key,
                );
                let subject = Self::party_subject(&self.session_id, peer_id);
                let payload = serde_json::to_vec(&envelope)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
                self.client
                    .publish(subject, payload.into())
                    .await
                    .map_err(|e| CoreError::Transport(format!("NATS publish failed: {e}")))?;
            }
        }

        Ok(())
    }

    async fn recv(&self) -> Result<ProtocolMessage, CoreError> {
        // Use the persistent subscription established at connect time.
        // This ensures no messages are lost between send() and recv() calls.
        let mut sub_guard = self.subscriber.lock().await;
        let subscriber = sub_guard
            .as_mut()
            .ok_or_else(|| CoreError::Transport("NATS subscriber not initialized".into()))?;

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
        use rand::rngs::OsRng;
        use rand::RngCore;

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

        let envelope =
            SignedEnvelope::sign(msg.clone(), PartyId(1), 1, DEFAULT_TTL_SECS, &signing_key);

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
        use rand::rngs::OsRng;
        use rand::RngCore;

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

    // ─── mTLS tests ────────────────────────────────────────────────────

    #[test]
    fn test_tls_config_rejects_missing_ca_cert() {
        let config = NatsTlsConfig {
            ca_cert_path: "/nonexistent/ca.pem".into(),
            client_cert_path: "/nonexistent/client.pem".into(),
            client_key_path: "/nonexistent/key.pem".into(),
        };
        let result = config.build_rustls_config();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("read CA cert"),
            "error should mention CA cert: {err}"
        );
    }

    #[test]
    fn test_tls_config_rejects_invalid_pem() {
        let dir = tempfile::tempdir().unwrap();

        // Write garbage (not valid PEM) to all three files
        let ca_path = dir.path().join("ca.pem");
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&ca_path, b"not a valid PEM").unwrap();
        std::fs::write(&cert_path, b"not a valid PEM").unwrap();
        std::fs::write(&key_path, b"not a valid PEM").unwrap();

        let config = NatsTlsConfig {
            ca_cert_path: ca_path,
            client_cert_path: cert_path,
            client_key_path: key_path,
        };
        let result = config.build_rustls_config();
        // Should fail because no valid certs were found in the garbage PEM
        assert!(result.is_err(), "invalid PEM should fail: {:?}", result);
    }

    #[test]
    fn test_tls_config_struct_construction() {
        let config = NatsTlsConfig {
            ca_cert_path: "/tmp/test-ca.pem".into(),
            client_cert_path: "/tmp/test-client.pem".into(),
            client_key_path: "/tmp/test-key.pem".into(),
        };
        // Verify Debug works and doesn't panic
        let debug = format!("{:?}", config);
        assert!(debug.contains("NatsTlsConfig"), "Debug impl should work");
        // Verify Clone works
        let _cloned = config.clone();
    }

    #[tokio::test]
    async fn test_connect_signed_tls_rejects_bad_config() {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);

        let bad_config = NatsTlsConfig {
            ca_cert_path: "/nonexistent/ca.pem".into(),
            client_cert_path: "/nonexistent/client.pem".into(),
            client_key_path: "/nonexistent/key.pem".into(),
        };

        let result = NatsTransport::connect_signed_tls(
            "tls://localhost:4222",
            PartyId(1),
            "test-session".into(),
            signing_key,
            bad_config,
        )
        .await;

        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for bad TLS config"),
        };
        // Should fail at TLS config build (file not found), not at NATS connect
        assert!(
            err.contains("read CA cert"),
            "should fail on TLS config, got: {err}"
        );
    }

    // NatsTransport integration test requires a live NATS server.
    // Run manually: NATS_URL=nats://localhost:4222 cargo test --features nats-integration-test
    #[tokio::test]
    #[ignore = "requires live NATS server: NATS_URL=nats://localhost:4222"]
    async fn test_nats_signed_round_trip() {
        use rand::rngs::OsRng;
        use rand::RngCore;

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

        let mut t1 = NatsTransport::connect_signed(&url, PartyId(1), session.clone(), k1)
            .await
            .unwrap();
        let mut t2 = NatsTransport::connect_signed(&url, PartyId(2), session.clone(), k2)
            .await
            .unwrap();

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
