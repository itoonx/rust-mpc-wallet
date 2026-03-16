//! Signed message envelope with Ed25519 sender authentication and seq_no replay protection.
//!
//! # SEC-007 fix
//!
//! `ProtocolMessage.from` is self-reported by the sender — any party can claim any `from`
//! value and impersonate another party. This module introduces [`SignedEnvelope`], which
//! wraps a [`ProtocolMessage`] and adds:
//!
//! - **Ed25519 sender signature** over the canonical envelope bytes (authenticates the sender)
//! - **Monotonic `seq_no`** (per session, per party) to detect replayed messages
//! - **TTL** (`expires_at` timestamp) to reject stale messages
//!
//! # Usage
//!
//! 1. Each party holds an Ed25519 [`SigningKey`] for their node identity.
//! 2. Before sending, wrap the message with [`SignedEnvelope::sign`].
//! 3. On receipt, call [`SignedEnvelope::verify`] with the sender's verifying key and the
//!    current expected `seq_no`. This both authenticates the sender and detects replays.
//!
//! # Sprint 5 scope
//!
//! - Ed25519 signing + verification
//! - `seq_no` monotonicity check (caller manages the counter)
//! - `expires_at` TTL check
//!
//! **Not in Sprint 5:** integration into `NatsTransport` (Sprint 6), JetStream ACLs.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::transport::ProtocolMessage;
use crate::types::PartyId;

/// Default message TTL: 30 seconds from signing time.
pub const DEFAULT_TTL_SECS: u64 = 30;

/// A signed and replay-protected envelope wrapping a [`ProtocolMessage`].
///
/// The envelope commits to the inner message, the sender's party ID, the sequence
/// number, and the expiry timestamp. The sender's Ed25519 signature covers the
/// SHA-256 hash of the canonical JSON of these fields (with `signature` set to empty).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    /// The wrapped protocol message.
    pub message: ProtocolMessage,
    /// The sender's party ID (must match `message.from`; authenticated by signature).
    pub sender: PartyId,
    /// Monotonically increasing sequence number per (session, sender) pair.
    /// Receivers must reject envelopes where `seq_no <= last_seen_seq_no`.
    pub seq_no: u64,
    /// Unix timestamp (seconds) after which this envelope is invalid.
    pub expires_at: u64,
    /// Ed25519 signature over the canonical bytes (SHA-256 of JSON with empty sig).
    pub signature: Vec<u8>,
    /// Ed25519 public key of the sender (32 bytes), for verification.
    pub sender_pubkey: Vec<u8>,
}

impl SignedEnvelope {
    /// Compute the canonical bytes for signing/verification.
    ///
    /// Produces SHA-256 of the JSON of this envelope with `signature` set to empty.
    /// This ensures the signature covers all fields deterministically.
    fn canonical_hash(&self) -> Vec<u8> {
        let mut copy = self.clone();
        copy.signature = Vec::new();
        let json = serde_json::to_vec(&copy).unwrap_or_default();
        Sha256::digest(&json).to_vec()
    }

    /// Sign a [`ProtocolMessage`] and produce a [`SignedEnvelope`].
    ///
    /// # Arguments
    /// - `message` — the protocol message to wrap.
    /// - `sender` — the sender's party ID (should match `message.from`).
    /// - `seq_no` — the next monotonic sequence number for this sender in this session.
    /// - `ttl_secs` — how many seconds until this envelope expires. Use [`DEFAULT_TTL_SECS`].
    /// - `signing_key` — the sender's Ed25519 signing key.
    pub fn sign(
        message: ProtocolMessage,
        sender: PartyId,
        seq_no: u64,
        ttl_secs: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut envelope = SignedEnvelope {
            message,
            sender,
            seq_no,
            expires_at: now + ttl_secs,
            signature: Vec::new(), // filled below
            sender_pubkey: signing_key.verifying_key().to_bytes().to_vec(),
        };

        let hash = envelope.canonical_hash();
        let sig: Signature = signing_key.sign(&hash);
        envelope.signature = sig.to_bytes().to_vec();
        envelope
    }

    /// Verify the authenticity and freshness of this envelope.
    ///
    /// Checks in order:
    /// 1. **TTL**: `expires_at > now` (rejects stale messages).
    /// 2. **Seq_no**: `seq_no > last_seen_seq_no` (rejects replays).
    /// 3. **Signature**: Ed25519 verification against `expected_pubkey`.
    ///
    /// # Arguments
    /// - `expected_pubkey` — the verifying key of the expected sender.
    /// - `last_seen_seq_no` — the highest `seq_no` seen from this sender so far.
    ///   Pass `0` if no previous message has been seen.
    ///   After a successful verify, callers must update their state to `self.seq_no`.
    ///
    /// # Returns
    /// `Ok(())` if all checks pass, `Err(CoreError::Transport(...))` otherwise.
    pub fn verify(
        &self,
        expected_pubkey: &VerifyingKey,
        last_seen_seq_no: u64,
    ) -> Result<(), CoreError> {
        // 1. TTL check
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.expires_at <= now {
            return Err(CoreError::Transport(format!(
                "SEC-007: envelope from party {} is expired \
                 (expires_at={}, now={})",
                self.sender.0, self.expires_at, now
            )));
        }

        // 2. Seq_no replay protection
        if self.seq_no <= last_seen_seq_no {
            return Err(CoreError::Transport(format!(
                "SEC-007: replay detected from party {} — \
                 seq_no {} ≤ last_seen {}",
                self.sender.0, self.seq_no, last_seen_seq_no
            )));
        }

        // 3. Signature verification
        let sig_bytes: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            CoreError::Transport(format!(
                "SEC-007: invalid signature length from party {}",
                self.sender.0
            ))
        })?;

        let sig = Signature::from_bytes(&sig_bytes);
        let hash = self.canonical_hash();

        expected_pubkey.verify(&hash, &sig).map_err(|_| {
            CoreError::Transport(format!(
                "SEC-007: signature verification failed for party {}",
                self.sender.0
            ))
        })?;

        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PartyId;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn new_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn make_msg(from: u16, to: u16) -> ProtocolMessage {
        ProtocolMessage {
            from: PartyId(from),
            to: Some(PartyId(to)),
            round: 1,
            payload: b"test payload".to_vec(),
        }
    }

    #[test]
    fn test_sign_and_verify_succeeds() {
        let key = new_key();
        let msg = make_msg(1, 2);
        let envelope = SignedEnvelope::sign(msg, PartyId(1), 1, DEFAULT_TTL_SECS, &key);
        assert!(envelope.verify(&key.verifying_key(), 0).is_ok());
    }

    #[test]
    fn test_replay_rejected_same_seq_no() {
        let key = new_key();
        let msg = make_msg(1, 2);
        let envelope = SignedEnvelope::sign(msg, PartyId(1), 5, DEFAULT_TTL_SECS, &key);
        // last_seen_seq_no = 5 → seq_no 5 is a replay
        let err = envelope.verify(&key.verifying_key(), 5).unwrap_err();
        assert!(matches!(err, CoreError::Transport(_)));
        let msg = format!("{}", err);
        assert!(msg.contains("replay") || msg.contains("seq_no"));
    }

    #[test]
    fn test_replay_rejected_older_seq_no() {
        let key = new_key();
        let msg = make_msg(1, 2);
        let envelope = SignedEnvelope::sign(msg, PartyId(1), 3, DEFAULT_TTL_SECS, &key);
        // last_seen = 10 → seq_no 3 is old
        let err = envelope.verify(&key.verifying_key(), 10).unwrap_err();
        assert!(matches!(err, CoreError::Transport(_)));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let signer = new_key();
        let wrong_key = new_key();
        let msg = make_msg(1, 2);
        let envelope = SignedEnvelope::sign(msg, PartyId(1), 1, DEFAULT_TTL_SECS, &signer);
        // Verify with wrong pubkey
        let err = envelope.verify(&wrong_key.verifying_key(), 0).unwrap_err();
        assert!(matches!(err, CoreError::Transport(_)));
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let key = new_key();
        let msg = make_msg(1, 2);
        let mut envelope = SignedEnvelope::sign(msg, PartyId(1), 1, DEFAULT_TTL_SECS, &key);
        // Tamper with the payload after signing
        envelope.message.payload = b"TAMPERED".to_vec();
        let err = envelope.verify(&key.verifying_key(), 0).unwrap_err();
        assert!(matches!(err, CoreError::Transport(_)));
    }

    #[test]
    fn test_expired_envelope_rejected() {
        let key = new_key();
        let msg = make_msg(1, 2);
        // TTL = 0 → already expired
        let mut envelope = SignedEnvelope::sign(msg, PartyId(1), 1, 0, &key);
        // Force expires_at to be in the past
        envelope.expires_at = 1; // Unix epoch + 1 second — definitely expired
                                 // Re-sign with updated expires_at
        let hash = envelope.canonical_hash();
        let sig: Signature = key.sign(&hash);
        envelope.signature = sig.to_bytes().to_vec();

        let err = envelope.verify(&key.verifying_key(), 0).unwrap_err();
        assert!(matches!(err, CoreError::Transport(_)));
        let msg_str = format!("{}", err);
        assert!(
            msg_str.contains("expired") || msg_str.contains("TTL") || msg_str.contains("expires")
        );
    }

    #[test]
    fn test_seq_no_increments_are_accepted() {
        let key = new_key();
        let vk = key.verifying_key();
        let mut last_seen = 0u64;

        for seq in 1..=5 {
            let msg = make_msg(1, 2);
            let envelope = SignedEnvelope::sign(msg, PartyId(1), seq, DEFAULT_TTL_SECS, &key);
            assert!(envelope.verify(&vk, last_seen).is_ok());
            last_seen = seq;
        }
    }
}
