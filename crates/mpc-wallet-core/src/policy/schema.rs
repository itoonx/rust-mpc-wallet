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

/// Pre-built policy templates for common enterprise use cases (Epic B4).
///
/// Each variant produces a [`Policy`] with sensible defaults via [`build`](PolicyTemplate::build).
/// Operators should customize the generated policy (e.g. populate allowlists,
/// adjust limits) before loading it into a [`super::PolicyStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTemplate {
    /// Exchange hot wallet: strict per-tx limits, low daily velocity.
    ///
    /// Covers ethereum, bitcoin, and solana with conservative limits.
    /// Allowlists are empty by default — operators **must** populate them.
    Exchange,
    /// Treasury: moderate limits, ethereum-only by default.
    ///
    /// Higher per-tx and daily limits than Exchange, suitable for internal
    /// treasury operations.
    Treasury,
    /// Custodian: permissive policy with no chain-specific restrictions.
    ///
    /// No per-chain rules are configured — all transactions on all chains
    /// are allowed. Operators should add chain rules as needed.
    Custodian,
}

impl PolicyTemplate {
    /// Generate a [`Policy`] from this template.
    ///
    /// The returned policy uses [`POLICY_SCHEMA_VERSION`] and can be loaded
    /// directly into a [`super::PolicyStore`].
    ///
    /// # Limits
    ///
    /// All monetary values are in the chain's native base unit (wei for EVM,
    /// satoshis for Bitcoin, lamports for Solana).
    pub fn build(&self) -> Policy {
        match self {
            PolicyTemplate::Exchange => Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "exchange-hot-wallet".into(),
                chains: {
                    let mut m = HashMap::new();
                    m.insert(
                        "ethereum".into(),
                        ChainPolicy {
                            allowlist: vec![], // operator must configure
                            max_amount_per_tx: Some(10_000_000_000_000_000_000), // 10 ETH in wei
                            daily_velocity_limit: Some(18_000_000_000_000_000_000), // 18 ETH in wei
                        },
                    );
                    m.insert(
                        "bitcoin".into(),
                        ChainPolicy {
                            allowlist: vec![],
                            max_amount_per_tx: Some(100_000_000), // 1 BTC in satoshis
                            daily_velocity_limit: Some(1_000_000_000), // 10 BTC in satoshis
                        },
                    );
                    m.insert(
                        "solana".into(),
                        ChainPolicy {
                            allowlist: vec![],
                            max_amount_per_tx: Some(10_000_000_000), // 10 SOL in lamports
                            daily_velocity_limit: Some(100_000_000_000), // 100 SOL in lamports
                        },
                    );
                    m
                },
            },
            PolicyTemplate::Treasury => Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "treasury".into(),
                chains: {
                    let mut m = HashMap::new();
                    m.insert(
                        "ethereum".into(),
                        ChainPolicy {
                            allowlist: vec![],
                            max_amount_per_tx: Some(15_000_000_000_000_000_000), // 15 ETH in wei
                            daily_velocity_limit: Some(18_000_000_000_000_000_000), // 18 ETH in wei
                        },
                    );
                    m
                },
            },
            PolicyTemplate::Custodian => Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "custodian".into(),
                chains: HashMap::new(), // no restrictions — allow all
            },
        }
    }
}

