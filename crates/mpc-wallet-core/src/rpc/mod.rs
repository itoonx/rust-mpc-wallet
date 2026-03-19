//! NATS RPC protocol messages between Gateway (orchestrator) and MPC Nodes.
//!
//! Shared by both `services/api-gateway` and `services/mpc-node`.
//!
//! # Control channels (NATS Request-Reply)
//! - `mpc.control.keygen.{group_id}` — keygen ceremony coordination
//! - `mpc.control.sign.{group_id}` — sign request with SignAuthorization
//! - `mpc.control.freeze.{group_id}` — freeze/unfreeze key group
//!
//! Responses use NATS request-reply pattern (msg.reply inbox) instead of
//! separate `.reply` subjects, eliminating subscribe-before-publish timing issues.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// NATS URL for MPC protocol transport (separate from control plane).
    /// Nodes use this to connect for the actual MPC protocol rounds.
    #[serde(default)]
    pub nats_url: Option<String>,
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
    /// NATS URL for MPC protocol transport (separate from control plane).
    /// Nodes use this to connect for the actual MPC protocol rounds.
    #[serde(default)]
    pub nats_url: Option<String>,
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

/// Deprecated: use NATS request-reply pattern (msg.reply inbox) instead.
/// Kept for backward compatibility with existing E2E tests.
pub fn keygen_reply_subject(group_id: &str) -> String {
    format!("mpc.control.keygen.{group_id}.reply")
}

pub fn sign_subject(group_id: &str) -> String {
    format!("mpc.control.sign.{group_id}")
}

/// Deprecated: use NATS request-reply pattern (msg.reply inbox) instead.
/// Kept for backward compatibility with existing E2E tests.
pub fn sign_reply_subject(group_id: &str) -> String {
    format!("mpc.control.sign.{group_id}.reply")
}

pub fn freeze_subject(group_id: &str) -> String {
    format!("mpc.control.freeze.{group_id}")
}

// ── Signed Control Message (SEC-026) ────────────────────────────────

/// Wrapper for control plane messages with Ed25519 signature.
///
/// The gateway signs every control message (keygen/sign/freeze) before
/// publishing on NATS. MPC nodes verify the signature against the
/// known gateway public key before processing the inner payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedControlMessage {
    /// The serialized inner payload (JSON bytes of KeygenRequest, SignRequest, etc.).
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
    /// Ed25519 signature over SHA-256(payload).
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
    /// Ed25519 public key of the signer (gateway).
    #[serde(with = "base64_bytes")]
    pub pubkey: Vec<u8>,
}

/// Serde helper for Vec<u8> as base64.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        // Use hex encoding for simplicity (already a dependency)
        hex::encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Sign a control plane message payload with the gateway's Ed25519 key.
///
/// Returns a `SignedControlMessage` containing the original payload,
/// the Ed25519 signature over SHA-256(payload), and the gateway's public key.
pub fn sign_control_message(payload: &[u8], signing_key: &SigningKey) -> SignedControlMessage {
    let digest = Sha256::digest(payload);
    let signature = signing_key.sign(&digest);

    SignedControlMessage {
        payload: payload.to_vec(),
        signature: signature.to_bytes().to_vec(),
        pubkey: signing_key.verifying_key().to_bytes().to_vec(),
    }
}

/// Verify a signed control message against an expected gateway public key.
///
/// Returns `Ok(payload)` if the signature is valid, or an error string if not.
/// The `expected_pubkey` MUST match the pubkey embedded in the message —
/// this prevents an attacker from signing with their own key.
pub fn verify_control_message(
    msg: &SignedControlMessage,
    expected_pubkey: &VerifyingKey,
) -> Result<Vec<u8>, String> {
    // Verify the embedded pubkey matches the expected gateway pubkey
    let msg_pubkey_bytes: [u8; 32] = msg
        .pubkey
        .as_slice()
        .try_into()
        .map_err(|_| "invalid pubkey length (expected 32 bytes)".to_string())?;

    let msg_pubkey =
        VerifyingKey::from_bytes(&msg_pubkey_bytes).map_err(|e| format!("invalid pubkey: {e}"))?;

    if msg_pubkey != *expected_pubkey {
        return Err("pubkey mismatch: message signed by unknown key".to_string());
    }

    // Verify signature over SHA-256(payload)
    let sig_bytes: [u8; 64] = msg
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "invalid signature length (expected 64 bytes)".to_string())?;

    let signature = Signature::from_bytes(&sig_bytes);

    let digest = Sha256::digest(&msg.payload);
    expected_pubkey
        .verify(&digest, &signature)
        .map_err(|e| format!("signature verification failed: {e}"))?;

    Ok(msg.payload.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_control_message() {
        let signing_key = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            SigningKey::from_bytes(&bytes)
        };
        let verifying_key = signing_key.verifying_key();

        let payload = serde_json::to_vec(&FreezeRequest {
            group_id: "test-group".to_string(),
            freeze: true,
        })
        .unwrap();

        let signed = sign_control_message(&payload, &signing_key);
        let result = verify_control_message(&signed, &verifying_key);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let signing_key = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            SigningKey::from_bytes(&bytes)
        };
        let other_key = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            SigningKey::from_bytes(&bytes)
        };

        let payload = b"test payload";
        let signed = sign_control_message(payload, &signing_key);

        // Verify against a different key should fail
        let result = verify_control_message(&signed, &other_key.verifying_key());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("pubkey mismatch"));
    }

    #[test]
    fn test_verify_rejects_tampered_payload() {
        let signing_key = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            SigningKey::from_bytes(&bytes)
        };
        let verifying_key = signing_key.verifying_key();

        let payload = b"original payload";
        let mut signed = sign_control_message(payload, &signing_key);

        // Tamper with the payload
        signed.payload = b"tampered payload".to_vec();

        let result = verify_control_message(&signed, &verifying_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("signature verification failed"));
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let signing_key = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            SigningKey::from_bytes(&bytes)
        };
        let verifying_key = signing_key.verifying_key();

        let payload = b"test payload";
        let mut signed = sign_control_message(payload, &signing_key);

        // Tamper with the signature
        if !signed.signature.is_empty() {
            signed.signature[0] ^= 0xff;
        }

        let result = verify_control_message(&signed, &verifying_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_message_serialization_roundtrip() {
        let signing_key = {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            SigningKey::from_bytes(&bytes)
        };

        let payload = serde_json::to_vec(&KeygenRequest {
            group_id: "g1".to_string(),
            label: "test".to_string(),
            scheme: "gg20-ecdsa".to_string(),
            threshold: 2,
            total_parties: 3,
            session_id: "s1".to_string(),
            peer_keys: vec![],
            nats_url: None,
        })
        .unwrap();

        let signed = sign_control_message(&payload, &signing_key);

        // Serialize to JSON and back
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedControlMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(signed.payload, deserialized.payload);
        assert_eq!(signed.signature, deserialized.signature);
        assert_eq!(signed.pubkey, deserialized.pubkey);

        // Verify still works after roundtrip
        let result = verify_control_message(&deserialized, &signing_key.verifying_key());
        assert!(result.is_ok());
    }
}
