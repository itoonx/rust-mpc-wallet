//! Policy schema types for the MPC Wallet signing policy engine.
//!
//! A [`Policy`] document describes the spending controls that govern which
//! transactions are permitted to be signed. The policy engine enforces the
//! "no policy → no sign" rule (FR-B5): a signing session cannot start unless
//! a valid policy has been loaded via [`super::PolicyStore::load`].

use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Current policy schema version. Policies with a different version number
/// are rejected by [`super::PolicyStore::load`].
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// A signing policy that governs what transactions are permitted.
///
/// # "No policy → no sign"
///
/// If no policy is loaded in [`super::PolicyStore`], all signing requests are
/// rejected with [`crate::error::CoreError::PolicyRequired`]. An empty `Policy`
/// with no per-chain rules allows all transactions — operators must explicitly
/// configure controls to restrict signing.
///
/// # Versioning
///
/// The `version` field must equal [`POLICY_SCHEMA_VERSION`] (currently 1).
/// Policies with mismatched versions are rejected at load time to prevent
/// silently using a policy whose semantics have changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Schema version — must equal [`POLICY_SCHEMA_VERSION`] (currently 1).
    pub version: u32,
    /// Human-readable name for this policy (e.g. `"exchange-hot-wallet-v1"`).
    pub name: String,
    /// Per-chain spending rules. The key is the chain identifier string
    /// (e.g. `"ethereum"`, `"bitcoin"`, `"solana"`, `"sui"`).
    ///
    /// If a chain has no entry, all transactions on that chain are allowed.
    pub chains: HashMap<String, ChainPolicy>,
}

/// Per-chain spending controls.
///
/// All fields are optional and default to "allow all" when absent.
/// Populate only the fields that should be restricted.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainPolicy {
    /// If non-empty, only transactions whose `to_address` appears in this list
    /// are permitted. Comparison is case-insensitive (both sides lowercased).
    ///
    /// An empty `allowlist` means all destination addresses are permitted.
    pub allowlist: Vec<String>,

    /// Maximum value (in the chain's base unit, e.g. wei for EVM, lamports for Solana)
    /// allowed per individual transaction. `None` means no per-transaction limit.
    pub max_amount_per_tx: Option<u64>,

    /// Maximum total value permitted in a rolling 24-hour window.
    /// `None` means no velocity limit.
    ///
    /// # Sprint 4 limitation
    /// This limit is tracked in-memory only and does not survive process restart.
    /// Sprint 5 will add persistent velocity tracking.
    pub daily_velocity_limit: Option<u64>,
}

impl Policy {
    /// Create a minimal policy that permits all transactions on all chains.
    ///
    /// This is a safe starting point for development. For production use,
    /// configure per-chain [`ChainPolicy`] rules to restrict signing.
    pub fn allow_all(name: impl Into<String>) -> Self {
        Policy {
            version: POLICY_SCHEMA_VERSION,
            name: name.into(),
            chains: HashMap::new(),
        }
    }
}

/// A policy document signed by an authorized policy administrator.
///
/// The signature covers the canonical JSON bytes of the inner `Policy`.
/// Use [`SignedPolicy::verify`] to check authenticity before loading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicy {
    /// The policy document.
    pub policy: Policy,
    /// Ed25519 signature over the canonical JSON of `policy`.
    pub signature: Vec<u8>,
    /// Hex-encoded Ed25519 verifying key of the signer.
    pub signer_key_hex: String,
}

impl SignedPolicy {
    /// Sign a policy with an Ed25519 signing key.
    pub fn sign(policy: Policy, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let canonical = serde_json::to_vec(&policy).expect("policy serialization cannot fail");
        let signature = signing_key.sign(&canonical);
        Self {
            policy,
            signature: signature.to_bytes().to_vec(),
            signer_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        }
    }

    /// Verify the signature and return the inner policy if valid.
    pub fn verify(&self) -> Result<&Policy, CoreError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let vk_bytes = hex::decode(&self.signer_key_hex)
            .map_err(|e| CoreError::PolicyRequired(format!("invalid signer key hex: {e}")))?;
        let vk_arr: [u8; 32] = vk_bytes
            .try_into()
            .map_err(|_| CoreError::PolicyRequired("signer key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&vk_arr)
            .map_err(|e| CoreError::PolicyRequired(format!("invalid verifying key: {e}")))?;

        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::PolicyRequired("signature must be 64 bytes".into()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let canonical =
            serde_json::to_vec(&self.policy).expect("policy serialization cannot fail");
        verifying_key
            .verify(&canonical, &signature)
            .map_err(|_| CoreError::PolicyRequired("policy signature verification failed".into()))?;

        Ok(&self.policy)
    }
}
