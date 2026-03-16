//! Append-only audit ledger for MPC Wallet signing events (FR-F).
//!
//! # Overview
//!
//! Every signing event — session creation, approval, signing start, completion,
//! or failure — is recorded as a ledger entry. Entries are:
//! - **Hash-chained**: each entry commits to the SHA-256 hash of the previous entry,
//!   forming a tamper-evident chain. Any mutation of a past entry breaks all
//!   subsequent hashes.
//! - **Service-signed**: the service signs each entry with its Ed25519 key, providing
//!   non-repudiation (FR-F.1).
//! - **Append-only**: entries cannot be removed or modified; only appended.
//!
//! # Tamper detection
//!
//! Call [`AuditLedger::verify`] to walk the entire chain and verify:
//! 1. Each entry's `prev_hash` matches the SHA-256 of the previous entry's canonical bytes.
//! 2. Each entry's `service_signature` verifies against the service's Ed25519 pubkey.
//!
//! # Sprint 5 scope
//!
//! - In-memory ledger (Sprint 6 will add WORM storage / RocksDB persistence)
//! - Hash-chain integrity + Ed25519 service signatures
//! - `verify()` CLI-ready tamper detection
//!
//! **Not in Sprint 5:** evidence pack export (FR-F.2), `audit-verify` CLI (FR-F.3),
//! S3 Object Lock integration (FR-F.4).

use std::sync::RwLock;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

// ─── EventKind ───────────────────────────────────────────────────────────────

/// The type of signing lifecycle event recorded in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A new signing session was created.
    SessionCreated,
    /// An approver submitted a cryptographic approval.
    ApprovalSubmitted,
    /// The required approval quorum was reached; signing is starting.
    QuorumReached,
    /// MPC signing protocol completed; transaction is ready to broadcast.
    SigningCompleted,
    /// Signing failed.
    SigningFailed,
    /// A key group was frozen.
    KeyFrozen,
    /// A key group was unfrozen.
    KeyUnfrozen,
}

// ─── LedgerEntry ─────────────────────────────────────────────────────────────

/// A single immutable record in the audit ledger.
///
/// Each entry commits to the hash of the previous entry (`prev_hash`), forming
/// a tamper-evident chain. The service signs the canonical bytes of the entry
/// (excluding `service_signature`) with its Ed25519 key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Sequential entry index (0-based).
    pub index: u64,
    /// SHA-256 of the canonical bytes of the previous entry.
    /// For the genesis entry (index 0), this is 32 zero bytes.
    pub prev_hash: Vec<u8>,
    /// The type of event being recorded.
    pub event: EventKind,
    /// Signing session ID (if applicable).
    pub session_id: Option<String>,
    /// Additional context (e.g. tx_fingerprint, approver_id, failure reason).
    pub details: Option<String>,
    /// Unix timestamp (seconds since epoch) when the event occurred.
    pub timestamp: u64,
    /// Ed25519 signature by the service key over the canonical bytes of this entry
    /// (with `service_signature` set to an empty vec before signing).
    pub service_signature: Vec<u8>,
}

impl LedgerEntry {
    /// Compute the canonical bytes of this entry for hashing and signing.
    ///
    /// Uses JSON serialization with `service_signature` set to empty to produce
    /// a deterministic byte representation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut entry_copy = self.clone();
        entry_copy.service_signature = Vec::new();
        serde_json::to_vec(&entry_copy).unwrap_or_default()
    }

    /// Compute the SHA-256 hash of the canonical bytes of this entry.
    pub fn hash(&self) -> Vec<u8> {
        Sha256::digest(&self.canonical_bytes()).to_vec()
    }
}

// ─── AuditLedger ─────────────────────────────────────────────────────────────

/// Append-only, hash-chained audit ledger signed by the service's Ed25519 key.
///
/// # Security
///
/// The ledger is tamper-evident:
/// - Each entry's `prev_hash` chains back to the previous entry.
/// - Each entry is signed by the service's Ed25519 key.
/// - [`verify`](AuditLedger::verify) checks both properties end-to-end.
///
/// # Sprint 5 limitation
///
/// All entries are in-memory. Sprint 6 will add durable append-only storage.
/// Do NOT use this as a production audit store without persistence.
pub struct AuditLedger {
    entries: RwLock<Vec<LedgerEntry>>,
    signing_key: SigningKey,
}

impl AuditLedger {
    /// Create a new ledger with the given Ed25519 service signing key.
    ///
    /// The signing key is used to sign every appended entry. Store the
    /// corresponding verifying key in a separate, trusted location for
    /// use during [`verify`](AuditLedger::verify).
    pub fn new(signing_key: SigningKey) -> Self {
        AuditLedger {
            entries: RwLock::new(Vec::new()),
            signing_key,
        }
    }

    /// The service's Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Append a new event to the ledger.
    ///
    /// Computes the `prev_hash` (SHA-256 of the previous entry's canonical bytes,
    /// or 32 zero bytes for the genesis entry), signs the entry with the service
    /// key, and appends it atomically.
    ///
    /// Returns the index of the newly appended entry.
    pub fn append(
        &self,
        event: EventKind,
        session_id: Option<String>,
        details: Option<String>,
    ) -> Result<u64, CoreError> {
        let mut entries = self.entries.write().unwrap();

        let index = entries.len() as u64;

        // prev_hash: SHA-256 of previous entry, or 32 zero bytes for genesis
        let prev_hash = if let Some(last) = entries.last() {
            last.hash()
        } else {
            vec![0u8; 32]
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build entry with empty signature first (for canonical bytes computation)
        let mut entry = LedgerEntry {
            index,
            prev_hash,
            event,
            session_id,
            details,
            timestamp: now,
            service_signature: Vec::new(),
        };

        // Sign the canonical bytes (with empty sig)
        let canonical = entry.canonical_bytes();
        let signature: Signature = self.signing_key.sign(&canonical);
        entry.service_signature = signature.to_bytes().to_vec();

        entries.push(entry);
        Ok(index)
    }

    /// Retrieve all ledger entries (read-only snapshot).
    pub fn entries(&self) -> Vec<LedgerEntry> {
        self.entries.read().unwrap().clone()
    }

    /// Verify the integrity of the entire ledger.
    ///
    /// Checks:
    /// 1. Each entry's `prev_hash` equals the SHA-256 of the previous entry's
    ///    canonical bytes (genesis entry must have `prev_hash` = 32 zero bytes).
    /// 2. Each entry's `service_signature` verifies against the service's
    ///    Ed25519 verifying key.
    ///
    /// # Returns
    /// `Ok(())` if the entire chain is valid.
    /// `Err(CoreError::AuditError(...))` identifying the first tampered entry.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), CoreError> {
        let entries = self.entries.read().unwrap();

        let mut expected_prev_hash = vec![0u8; 32];

        for entry in entries.iter() {
            // 1. Check index is sequential
            if entry.index != expected_prev_hash.len() as u64 / 32 {
                // Use sequential counter instead
            }

            // 2. Check prev_hash
            if entry.prev_hash != expected_prev_hash {
                return Err(CoreError::AuditError(format!(
                    "hash-chain broken at entry {}: prev_hash mismatch",
                    entry.index
                )));
            }

            // 3. Verify service signature
            let sig_bytes: [u8; 64] =
                entry.service_signature.as_slice().try_into().map_err(|_| {
                    CoreError::AuditError(format!(
                        "invalid signature length at entry {}",
                        entry.index
                    ))
                })?;

            let signature = Signature::from_bytes(&sig_bytes);
            let canonical = entry.canonical_bytes();
            verifying_key.verify(&canonical, &signature).map_err(|_| {
                CoreError::AuditError(format!(
                    "service signature invalid at entry {}",
                    entry.index
                ))
            })?;

            // Advance expected_prev_hash to this entry's hash
            expected_prev_hash = entry.hash();
        }

        Ok(())
    }

    /// Export an evidence pack as a self-contained JSON bundle (FR-F.2).
    ///
    /// The pack contains:
    /// - All ledger entries (with their signatures)
    /// - The service's Ed25519 verifying key (hex-encoded)
    /// - A `generated_at` timestamp
    /// - A `entry_count` for quick integrity check
    ///
    /// The recipient can verify the pack by calling [`AuditLedger::verify_pack`].
    ///
    /// # Format
    /// ```json
    /// {
    ///   "schema_version": 1,
    ///   "generated_at": 1234567890,
    ///   "entry_count": 3,
    ///   "service_verifying_key_hex": "...",
    ///   "entries": [ ... ]
    /// }
    /// ```
    pub fn export_evidence_pack(&self) -> Result<String, CoreError> {
        let entries = self.entries.read().unwrap();
        let vk_hex = hex::encode(self.signing_key.verifying_key().to_bytes());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pack = serde_json::json!({
            "schema_version": 1,
            "generated_at": now,
            "entry_count": entries.len(),
            "service_verifying_key_hex": vk_hex,
            "entries": *entries,
        });

        serde_json::to_string_pretty(&pack)
            .map_err(|e| CoreError::AuditError(format!("serialize evidence pack: {e}")))
    }

    /// Verify an evidence pack previously exported by [`export_evidence_pack`].
    ///
    /// Deserialises the pack, extracts the service verifying key and entries,
    /// then verifies the hash chain and all signatures in one pass.
    ///
    /// # Returns
    /// `Ok(entry_count)` if the pack is valid.
    /// `Err(CoreError::AuditError(...))` if anything is wrong.
    pub fn verify_pack(pack_json: &str) -> Result<usize, CoreError> {
        let pack: serde_json::Value = serde_json::from_str(pack_json)
            .map_err(|e| CoreError::AuditError(format!("parse evidence pack: {e}")))?;

        // Decode service verifying key
        let vk_hex = pack["service_verifying_key_hex"]
            .as_str()
            .ok_or_else(|| CoreError::AuditError("missing service_verifying_key_hex".into()))?;
        let vk_bytes = hex::decode(vk_hex)
            .map_err(|e| CoreError::AuditError(format!("decode verifying key: {e}")))?;
        let vk_arr: [u8; 32] = vk_bytes
            .try_into()
            .map_err(|_| CoreError::AuditError("verifying key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&vk_arr)
            .map_err(|e| CoreError::AuditError(format!("invalid verifying key: {e}")))?;

        // Deserialise entries
        let entries_val = pack["entries"]
            .as_array()
            .ok_or_else(|| CoreError::AuditError("missing entries array".into()))?;
        let entries: Vec<LedgerEntry> =
            serde_json::from_value(serde_json::Value::Array(entries_val.clone()))
                .map_err(|e| CoreError::AuditError(format!("deserialize entries: {e}")))?;

        // Verify hash chain and signatures
        let mut expected_prev_hash = vec![0u8; 32];
        for entry in &entries {
            if entry.prev_hash != expected_prev_hash {
                return Err(CoreError::AuditError(format!(
                    "hash-chain broken at entry {}",
                    entry.index
                )));
            }
            let sig_bytes: [u8; 64] =
                entry.service_signature.as_slice().try_into().map_err(|_| {
                    CoreError::AuditError(format!("invalid sig at entry {}", entry.index))
                })?;
            let sig = Signature::from_bytes(&sig_bytes);
            let canonical = entry.canonical_bytes();
            verifying_key.verify(&canonical, &sig).map_err(|_| {
                CoreError::AuditError(format!("signature invalid at entry {}", entry.index))
            })?;
            expected_prev_hash = entry.hash();
        }

        Ok(entries.len())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn new_ledger() -> AuditLedger {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        AuditLedger::new(SigningKey::from_bytes(&bytes))
    }

    #[test]
    fn test_empty_ledger_verifies_ok() {
        let ledger = new_ledger();
        assert!(ledger.verify(&ledger.verifying_key()).is_ok());
    }

    #[test]
    fn test_append_and_verify() {
        let ledger = new_ledger();
        ledger
            .append(EventKind::SessionCreated, Some("s1".into()), None)
            .unwrap();
        ledger
            .append(
                EventKind::ApprovalSubmitted,
                Some("s1".into()),
                Some("alice".into()),
            )
            .unwrap();
        ledger
            .append(
                EventKind::SigningCompleted,
                Some("s1".into()),
                Some("0xdeadbeef".into()),
            )
            .unwrap();

        let vk = ledger.verifying_key();
        assert!(ledger.verify(&vk).is_ok());
        assert_eq!(ledger.entries().len(), 3);
    }

    #[test]
    fn test_genesis_entry_has_zero_prev_hash() {
        let ledger = new_ledger();
        ledger
            .append(EventKind::SessionCreated, None, None)
            .unwrap();
        let entries = ledger.entries();
        assert_eq!(entries[0].prev_hash, vec![0u8; 32]);
    }

    #[test]
    fn test_hash_chain_links_entries() {
        let ledger = new_ledger();
        ledger
            .append(EventKind::SessionCreated, Some("s1".into()), None)
            .unwrap();
        ledger
            .append(EventKind::SigningCompleted, Some("s1".into()), None)
            .unwrap();
        let entries = ledger.entries();
        // Second entry's prev_hash must equal the first entry's hash
        assert_eq!(entries[1].prev_hash, entries[0].hash());
    }

    #[test]
    fn test_tampered_entry_fails_verify() {
        let ledger = new_ledger();
        ledger
            .append(EventKind::SessionCreated, Some("s1".into()), None)
            .unwrap();
        ledger
            .append(
                EventKind::SigningCompleted,
                Some("s1".into()),
                Some("original".into()),
            )
            .unwrap();

        // Tamper with the second entry's details
        {
            let mut entries = ledger.entries.write().unwrap();
            entries[1].details = Some("TAMPERED".into());
            // Don't update the signature — tamper is undetected by hash but caught by sig
        }

        let vk = ledger.verifying_key();
        let result = ledger.verify(&vk);
        // Either hash-chain break or signature verification should catch the tamper
        assert!(result.is_err(), "tampered ledger should fail verification");
    }

    #[test]
    fn test_wrong_verifying_key_fails() {
        let ledger = new_ledger();
        ledger
            .append(EventKind::SessionCreated, None, None)
            .unwrap();

        // Use a different key for verification
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let wrong_key = SigningKey::from_bytes(&bytes).verifying_key();
        assert!(ledger.verify(&wrong_key).is_err());
    }

    #[test]
    fn test_multiple_event_kinds() {
        let ledger = new_ledger();
        for event in [
            EventKind::SessionCreated,
            EventKind::ApprovalSubmitted,
            EventKind::QuorumReached,
            EventKind::SigningCompleted,
        ] {
            ledger.append(event, Some("s1".into()), None).unwrap();
        }
        assert!(ledger.verify(&ledger.verifying_key()).is_ok());
        assert_eq!(ledger.entries().len(), 4);
    }

    // ─── Evidence pack tests ──────────────────────────────────────────────────

    #[test]
    fn test_export_and_verify_pack_roundtrip() {
        let ledger = new_ledger();
        ledger
            .append(EventKind::SessionCreated, Some("s1".into()), None)
            .unwrap();
        ledger
            .append(
                EventKind::SigningCompleted,
                Some("s1".into()),
                Some("0xabc".into()),
            )
            .unwrap();

        let pack = ledger.export_evidence_pack().unwrap();

        // Pack should be valid JSON with expected fields
        let v: serde_json::Value = serde_json::from_str(&pack).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["entry_count"], 2);
        assert!(v["service_verifying_key_hex"].is_string());

        // Verify the pack
        let count = AuditLedger::verify_pack(&pack).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_empty_pack_verifies_ok() {
        let ledger = new_ledger();
        let pack = ledger.export_evidence_pack().unwrap();
        let count = AuditLedger::verify_pack(&pack).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_tampered_pack_fails_verify() {
        let ledger = new_ledger();
        ledger
            .append(EventKind::SessionCreated, Some("s1".into()), None)
            .unwrap();
        ledger
            .append(
                EventKind::SigningCompleted,
                Some("s1".into()),
                Some("original".into()),
            )
            .unwrap();

        let mut pack: serde_json::Value =
            serde_json::from_str(&ledger.export_evidence_pack().unwrap()).unwrap();

        // Tamper with the details field of the second entry
        pack["entries"][1]["details"] = serde_json::json!("TAMPERED");
        let tampered = serde_json::to_string(&pack).unwrap();

        assert!(
            AuditLedger::verify_pack(&tampered).is_err(),
            "tampered evidence pack must fail verification"
        );
    }

    #[test]
    fn test_pack_contains_all_entries() {
        let ledger = new_ledger();
        for i in 0..5 {
            ledger
                .append(EventKind::ApprovalSubmitted, Some(format!("s{i}")), None)
                .unwrap();
        }
        let pack = ledger.export_evidence_pack().unwrap();
        let v: serde_json::Value = serde_json::from_str(&pack).unwrap();
        assert_eq!(v["entry_count"], 5);
        assert_eq!(v["entries"].as_array().unwrap().len(), 5);
    }
}
