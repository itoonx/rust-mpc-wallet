//! Per-session ECDH key exchange and symmetric encryption (Epic E3, FR-E.3).
//!
//! Provides defense-in-depth: even if TLS is compromised, protocol message
//! payloads remain encrypted with per-session keys derived via X25519 ECDH + HKDF.

use std::collections::HashMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::CoreError;
use crate::types::PartyId;

/// Per-session encryption context for a single party.
///
/// Each party generates an ephemeral X25519 key pair per session, exchanges
/// public keys with peers, derives per-peer symmetric keys via HKDF, and
/// encrypts/decrypts payloads with ChaCha20-Poly1305.
pub struct SessionEncryption {
    /// This party's ephemeral X25519 public key (shared with peers).
    pub local_public_key: PublicKey,
    /// Per-peer derived symmetric keys (32 bytes each).
    peer_ciphers: HashMap<PartyId, ChaCha20Poly1305>,
    /// Per-peer nonce counters (monotonically increasing).
    nonce_counters: HashMap<PartyId, u64>,
}

impl SessionEncryption {
    /// Create a new session encryption context.
    ///
    /// Generates an ephemeral X25519 key pair. The returned [`StaticSecret`]
    /// must be kept alive and passed to [`register_peer`] for each peer.
    /// Once all peers are registered the secret can be dropped.
    #[allow(unused_variables)]
    pub fn new(session_id: &str) -> (Self, StaticSecret) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&secret);
        let enc = SessionEncryption {
            local_public_key: public_key,
            peer_ciphers: HashMap::new(),
            nonce_counters: HashMap::new(),
        };
        (enc, secret)
    }

    /// Register a peer's public key and derive the shared encryption key.
    ///
    /// Uses X25519 ECDH to compute a shared secret, then HKDF-SHA256 to
    /// derive a 32-byte symmetric key bound to the session ID and party IDs.
    pub fn register_peer(
        &mut self,
        peer_id: PartyId,
        peer_public_key: &PublicKey,
        local_secret: &StaticSecret,
        session_id: &str,
        local_party_id: PartyId,
    ) -> Result<(), CoreError> {
        // X25519 ECDH
        let shared_secret = local_secret.diffie_hellman(peer_public_key);

        // HKDF-SHA256: derive 32-byte key with session+party binding.
        // Sort party IDs to ensure both sides derive the same key.
        let (id_a, id_b) = if local_party_id.0 < peer_id.0 {
            (local_party_id.0, peer_id.0)
        } else {
            (peer_id.0, local_party_id.0)
        };
        let info = format!("mpc-e3:{}:{}:{}", session_id, id_a, id_b);

        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut key_bytes = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key_bytes)
            .map_err(|_| CoreError::Transport("HKDF expand failed".into()))?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|e| CoreError::Transport(format!("ChaCha20 key init: {e}")))?;
        key_bytes.zeroize();

        self.peer_ciphers.insert(peer_id, cipher);
        self.nonce_counters.insert(peer_id, 0);
        Ok(())
    }

    /// Encrypt a payload for a specific peer.
    ///
    /// Uses a monotonically increasing nonce counter to prevent nonce reuse.
    /// The nonce includes the sender's party ID for domain separation.
    pub fn encrypt(
        &mut self,
        peer_id: PartyId,
        plaintext: &[u8],
        sender_id: PartyId,
    ) -> Result<Vec<u8>, CoreError> {
        let cipher = self.peer_ciphers.get(&peer_id).ok_or_else(|| {
            CoreError::Transport(format!("no session key for party {}", peer_id.0))
        })?;

        let counter = self
            .nonce_counters
            .get_mut(&peer_id)
            .ok_or_else(|| CoreError::Transport("nonce counter missing".into()))?;
        *counter += 1;

        // 12-byte nonce: [4 bytes sender_id LE][8 bytes counter LE]
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..2].copy_from_slice(&sender_id.0.to_le_bytes());
        // bytes [2..4] remain zero (padding for u16 → 4-byte slot)
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CoreError::Transport(format!("E3 encrypt failed: {e}")))?;

        // Prepend nonce to ciphertext so receiver can decrypt
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a payload from a specific peer.
    ///
    /// Extracts the nonce from the first 12 bytes of the ciphertext.
    pub fn decrypt(&self, peer_id: PartyId, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        if data.len() < 12 {
            return Err(CoreError::Transport("E3 ciphertext too short".into()));
        }

        let cipher = self.peer_ciphers.get(&peer_id).ok_or_else(|| {
            CoreError::Transport(format!("no session key for party {}", peer_id.0))
        })?;

        let nonce = Nonce::from_slice(&data[0..12]);
        let ciphertext = &data[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CoreError::Transport("E3 decrypt failed: authentication tag mismatch".into()))
    }

    /// Check if a peer has been registered.
    pub fn has_peer(&self, peer_id: &PartyId) -> bool {
        self.peer_ciphers.contains_key(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_encrypt_decrypt_roundtrip() {
        let session_id = "test-session-001";
        let (mut enc_a, secret_a) = SessionEncryption::new(session_id);
        let (mut enc_b, secret_b) = SessionEncryption::new(session_id);

        let party_a = PartyId(1);
        let party_b = PartyId(2);

        // Exchange public keys and register peers
        enc_a
            .register_peer(party_b, &enc_b.local_public_key, &secret_a, session_id, party_a)
            .unwrap();
        enc_b
            .register_peer(party_a, &enc_a.local_public_key, &secret_b, session_id, party_b)
            .unwrap();

        // Party A encrypts for Party B
        let plaintext = b"hello from party A";
        let ciphertext = enc_a.encrypt(party_b, plaintext, party_a).unwrap();

        // Party B decrypts
        let decrypted = enc_b.decrypt(party_a, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_peer_key_fails_decrypt() {
        let session_id = "test-session-002";
        let (mut enc_a, secret_a) = SessionEncryption::new(session_id);
        let (mut enc_b, secret_b) = SessionEncryption::new(session_id);
        let (enc_c, _secret_c) = SessionEncryption::new(session_id);

        let party_a = PartyId(1);
        let party_b = PartyId(2);

        enc_a
            .register_peer(party_b, &enc_b.local_public_key, &secret_a, session_id, party_a)
            .unwrap();
        // B registers with C's key instead of A's (wrong key)
        enc_b
            .register_peer(party_a, &enc_c.local_public_key, &secret_b, session_id, party_b)
            .unwrap();

        let ciphertext = enc_a.encrypt(party_b, b"secret data", party_a).unwrap();
        let result = enc_b.decrypt(party_a, &ciphertext);
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn test_ciphertext_too_short_rejected() {
        let session_id = "test-session-003";
        let (enc, _secret) = SessionEncryption::new(session_id);
        let result = enc.decrypt(PartyId(99), &[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_increments_per_message() {
        let session_id = "test-session-004";
        let (mut enc_a, secret_a) = SessionEncryption::new(session_id);
        let (enc_b, _secret_b) = SessionEncryption::new(session_id);

        enc_a
            .register_peer(PartyId(2), &enc_b.local_public_key, &secret_a, session_id, PartyId(1))
            .unwrap();

        let ct1 = enc_a.encrypt(PartyId(2), b"msg1", PartyId(1)).unwrap();
        let ct2 = enc_a.encrypt(PartyId(2), b"msg2", PartyId(1)).unwrap();

        // Nonces (first 12 bytes) must differ
        assert_ne!(&ct1[..12], &ct2[..12], "nonces must be unique per message");
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let session_id = "test-session-005";
        let (mut enc_a, secret_a) = SessionEncryption::new(session_id);
        let (mut enc_b, secret_b) = SessionEncryption::new(session_id);

        enc_a
            .register_peer(PartyId(2), &enc_b.local_public_key, &secret_a, session_id, PartyId(1))
            .unwrap();
        enc_b
            .register_peer(PartyId(1), &enc_a.local_public_key, &secret_b, session_id, PartyId(2))
            .unwrap();

        let mut ciphertext = enc_a.encrypt(PartyId(2), b"important data", PartyId(1)).unwrap();
        // Tamper with ciphertext (flip a byte after nonce)
        if ciphertext.len() > 13 {
            ciphertext[13] ^= 0xFF;
        }
        let result = enc_b.decrypt(PartyId(1), &ciphertext);
        assert!(result.is_err(), "tampered ciphertext must fail authentication");
    }

    #[test]
    fn test_bidirectional_encryption() {
        let session_id = "test-session-006";
        let (mut enc_a, secret_a) = SessionEncryption::new(session_id);
        let (mut enc_b, secret_b) = SessionEncryption::new(session_id);

        let party_a = PartyId(1);
        let party_b = PartyId(2);

        enc_a
            .register_peer(party_b, &enc_b.local_public_key, &secret_a, session_id, party_a)
            .unwrap();
        enc_b
            .register_peer(party_a, &enc_a.local_public_key, &secret_b, session_id, party_b)
            .unwrap();

        // A -> B
        let ct_ab = enc_a.encrypt(party_b, b"A to B", party_a).unwrap();
        assert_eq!(enc_b.decrypt(party_a, &ct_ab).unwrap(), b"A to B");

        // B -> A
        let ct_ba = enc_b.encrypt(party_a, b"B to A", party_b).unwrap();
        assert_eq!(enc_a.decrypt(party_b, &ct_ba).unwrap(), b"B to A");
    }

    #[test]
    fn test_unregistered_peer_encrypt_fails() {
        let session_id = "test-session-007";
        let (mut enc, _secret) = SessionEncryption::new(session_id);
        let result = enc.encrypt(PartyId(99), b"test", PartyId(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_has_peer() {
        let session_id = "test-session-008";
        let (mut enc_a, secret_a) = SessionEncryption::new(session_id);
        let (enc_b, _) = SessionEncryption::new(session_id);

        assert!(!enc_a.has_peer(&PartyId(2)));
        enc_a
            .register_peer(PartyId(2), &enc_b.local_public_key, &secret_a, session_id, PartyId(1))
            .unwrap();
        assert!(enc_a.has_peer(&PartyId(2)));
    }
}
