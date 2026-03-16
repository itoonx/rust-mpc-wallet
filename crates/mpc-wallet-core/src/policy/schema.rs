//! Policy schema types for the MPC Wallet signing policy engine.
//!
//! A [`Policy`] document describes the spending controls that govern which
//! transactions are permitted to be signed. The policy engine enforces the
//! "no policy → no sign" rule (FR-B5): a signing session cannot start unless
//! a valid policy has been loaded via [`super::PolicyStore::load`].

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
