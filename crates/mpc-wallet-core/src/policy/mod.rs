//! Policy engine for MPC Wallet signing operations.
//!
//! # "No policy → no sign"
//!
//! The [`PolicyStore`] enforces FR-B5: no signing session can start unless a valid
//! policy has been loaded. Any call to [`PolicyStore::check`] before [`PolicyStore::load`]
//! returns [`crate::error::CoreError::PolicyRequired`].
//!
//! # Usage
//!
//! ```rust,no_run
//! use mpc_wallet_core::policy::{Policy, PolicyStore};
//!
//! let store = PolicyStore::new();
//!
//! // Without a policy, all signing is blocked
//! assert!(store.check("ethereum", "0xabc", 100).is_err());
//!
//! // Load a policy to enable signing
//! store.load(Policy::allow_all("my-wallet")).unwrap();
//! assert!(store.check("ethereum", "0xabc", 100).is_ok());
//! ```

pub mod evaluator;
pub mod schema;

use std::sync::RwLock;

use crate::error::CoreError;
use crate::policy::evaluator::{evaluate, EvalResult};
pub use crate::policy::schema::{ChainPolicy, Policy, SignedPolicy, POLICY_SCHEMA_VERSION};

/// In-memory store for the active signing policy.
///
/// # "No policy → no sign"
///
/// Until [`PolicyStore::load`] is called, [`PolicyStore::check`] returns
/// [`CoreError::PolicyRequired`]. This enforces FR-B5: a signing session
/// cannot be created without an explicit policy.
///
/// # Thread safety
///
/// All operations are protected by an internal [`RwLock`]. Multiple signing
/// threads can call [`check`](PolicyStore::check) concurrently; [`load`](PolicyStore::load)
/// acquires a write lock briefly to update the stored policy.
///
/// # Sprint 4 limitation
///
/// The policy is stored in-memory only and is lost on process restart. Sprint 5
/// will add persistence to disk / the `KeyStore`. Daily velocity limits are stored
/// in the policy schema but not yet enforced (see `evaluator` module TODO).
pub struct PolicyStore {
    policy: RwLock<Option<Policy>>,
}

impl PolicyStore {
    /// Create a new, empty `PolicyStore`.
    ///
    /// No policy is loaded. Any call to [`check`](PolicyStore::check) will
    /// return [`CoreError::PolicyRequired`] until [`load`](PolicyStore::load) is called.
    pub fn new() -> Self {
        PolicyStore {
            policy: RwLock::new(None),
        }
    }

    /// Load (or replace) the active signing policy.
    ///
    /// The `policy.version` must equal [`POLICY_SCHEMA_VERSION`]. Policies
    /// with mismatched versions are rejected to prevent silent semantic mismatches.
    ///
    /// After a successful call, [`check`](PolicyStore::check) will evaluate
    /// transactions against the new policy.
    pub fn load(&self, policy: Policy) -> Result<(), CoreError> {
        if policy.version != POLICY_SCHEMA_VERSION {
            return Err(CoreError::PolicyRequired(format!(
                "policy schema version {} is not supported (expected {}); \
                 re-encode the policy with version {}",
                policy.version, POLICY_SCHEMA_VERSION, POLICY_SCHEMA_VERSION
            )));
        }
        *self.policy.write().unwrap() = Some(policy);
        Ok(())
    }

    /// Load a signed policy bundle after verifying its Ed25519 signature.
    ///
    /// Rejects the policy if:
    /// - Signature verification fails
    /// - Policy version doesn't match [`POLICY_SCHEMA_VERSION`]
    pub fn load_signed(&self, signed: &SignedPolicy) -> Result<(), CoreError> {
        let policy = signed.verify()?;
        self.load(policy.clone())
    }

    /// Clear the active policy.
    ///
    /// After this call, [`check`](PolicyStore::check) will return
    /// [`CoreError::PolicyRequired`] until [`load`](PolicyStore::load) is called again.
    pub fn clear(&self) {
        *self.policy.write().unwrap() = None;
    }

    /// Check whether a proposed transaction is permitted by the active policy.
    ///
    /// # Returns
    /// - `Ok(())` if the transaction is permitted.
    /// - `Err(CoreError::PolicyRequired(...))` if no policy has been loaded.
    /// - `Err(CoreError::Protocol(...))` if the loaded policy denies the transaction.
    ///
    /// This method must be called before initiating any signing session to enforce
    /// the "no policy → no sign" rule (FR-B5).
    ///
    /// # Arguments
    /// - `chain` — chain identifier (e.g. `"ethereum"`, `"bitcoin"`).
    /// - `to_address` — destination address as a string.
    /// - `amount` — transaction value in the chain's base unit.
    pub fn check(&self, chain: &str, to_address: &str, amount: u64) -> Result<(), CoreError> {
        let guard = self.policy.read().unwrap();
        let policy = guard.as_ref().ok_or_else(|| {
            CoreError::PolicyRequired("load a policy before creating a signing session".into())
        })?;
        match evaluate(policy, chain, to_address, amount) {
            EvalResult::Allow => Ok(()),
            EvalResult::Deny(reason) => {
                Err(CoreError::Protocol(format!("policy denied: {}", reason)))
            }
        }
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::ChainPolicy;
    use std::collections::HashMap;

    #[test]
    fn test_no_policy_returns_policy_required() {
        let store = PolicyStore::new();
        let err = store.check("ethereum", "0xabc", 100).unwrap_err();
        assert!(
            matches!(err, CoreError::PolicyRequired(_)),
            "expected PolicyRequired, got {:?}",
            err
        );
    }

    #[test]
    fn test_allow_all_policy_permits_any_tx() {
        let store = PolicyStore::new();
        store.load(Policy::allow_all("test")).unwrap();
        assert!(store.check("ethereum", "0xdeadbeef", 99999).is_ok());
        assert!(store.check("bitcoin", "bc1anything", 1).is_ok());
        assert!(store.check("solana", "any_address", 0).is_ok());
    }

    #[test]
    fn test_allowlist_blocks_unknown_address() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec!["0xAAA".into()],
                max_amount_per_tx: None,
                daily_velocity_limit: None,
            },
        );
        store
            .load(Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "test".into(),
                chains,
            })
            .unwrap();

        let err = store.check("ethereum", "0xBBB", 1).unwrap_err();
        assert!(
            matches!(err, CoreError::Protocol(_)),
            "expected Protocol (policy denied), got {:?}",
            err
        );
    }

    #[test]
    fn test_allowlist_permits_known_address_case_insensitive() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec!["0xaaa".into()],
                max_amount_per_tx: None,
                daily_velocity_limit: None,
            },
        );
        store
            .load(Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "test".into(),
                chains,
            })
            .unwrap();

        // uppercase variant should still match
        assert!(store.check("ethereum", "0xAAA", 1).is_ok());
    }

    #[test]
    fn test_amount_limit_blocks_over_limit() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: Some(1000),
                daily_velocity_limit: None,
            },
        );
        store
            .load(Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "test".into(),
                chains,
            })
            .unwrap();

        assert!(store.check("ethereum", "0xabc", 1000).is_ok());
        assert!(store.check("ethereum", "0xabc", 1001).is_err());
    }

    #[test]
    fn test_load_wrong_version_returns_policy_required() {
        let store = PolicyStore::new();
        let bad_policy = Policy {
            version: 999,
            name: "bad".into(),
            chains: HashMap::new(),
        };
        let err = store.load(bad_policy).unwrap_err();
        assert!(
            matches!(err, CoreError::PolicyRequired(_)),
            "expected PolicyRequired for wrong version, got {:?}",
            err
        );
    }

    #[test]
    fn test_clear_blocks_signing_again() {
        let store = PolicyStore::new();
        store.load(Policy::allow_all("test")).unwrap();
        assert!(store.check("ethereum", "0xabc", 1).is_ok());

        store.clear();
        let err = store.check("ethereum", "0xabc", 1).unwrap_err();
        assert!(matches!(err, CoreError::PolicyRequired(_)));
    }

    // --- Signed policy bundle tests ---

    fn make_signing_key() -> ed25519_dalek::SigningKey {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn test_signed_policy_roundtrip() {
        let signing_key = make_signing_key();
        let policy = Policy::allow_all("signed-test");
        let signed = SignedPolicy::sign(policy, &signing_key);

        assert!(signed.verify().is_ok());
        assert_eq!(signed.verify().unwrap().name, "signed-test");
    }

    #[test]
    fn test_signed_policy_tampered_rejected() {
        let signing_key = make_signing_key();
        let policy = Policy::allow_all("original");
        let mut signed = SignedPolicy::sign(policy, &signing_key);

        // Tamper with the policy name
        signed.policy.name = "TAMPERED".into();

        assert!(
            signed.verify().is_err(),
            "tampered policy must fail verification"
        );
    }

    #[test]
    fn test_signed_policy_wrong_key_rejected() {
        let key1 = make_signing_key();
        let key2 = make_signing_key();

        let policy = Policy::allow_all("test");
        let mut signed = SignedPolicy::sign(policy, &key1);
        // Replace signer key with a different key
        signed.signer_key_hex = hex::encode(key2.verifying_key().to_bytes());

        assert!(signed.verify().is_err());
    }

    #[test]
    fn test_load_signed_policy() {
        let signing_key = make_signing_key();
        let store = PolicyStore::new();
        let policy = Policy::allow_all("signed-loaded");
        let signed = SignedPolicy::sign(policy, &signing_key);

        store.load_signed(&signed).unwrap();
        assert!(store.check("ethereum", "0xabc", 100).is_ok());
    }

    #[test]
    fn test_load_signed_tampered_rejected() {
        let signing_key = make_signing_key();
        let store = PolicyStore::new();
        let policy = Policy::allow_all("test");
        let mut signed = SignedPolicy::sign(policy, &signing_key);
        signed.policy.name = "TAMPERED".into();

        assert!(store.load_signed(&signed).is_err());
    }
}
