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
pub mod parser;
pub mod schema;

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::CoreError;
use crate::policy::evaluator::{evaluate, EvalResult};
pub use crate::policy::schema::{
    ChainPolicy, Policy, PolicyRule, PolicyRuleSet, PolicyTemplate, SignedPolicy, MAX_RULE_DEPTH,
    POLICY_SCHEMA_VERSION,
};

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
/// # Daily velocity limits
///
/// The store tracks a rolling 24-hour window of signed transaction amounts per
/// chain. Call [`record_transaction`](PolicyStore::record_transaction) after each
/// successful signing to maintain accurate counters. The velocity is checked
/// automatically by [`check`](PolicyStore::check) when a `daily_velocity_limit`
/// is configured for a chain.
pub struct PolicyStore {
    policy: RwLock<Option<Policy>>,
    /// Rolling 24-hour velocity tracker: chain → list of (timestamp_secs, amount).
    velocity: RwLock<HashMap<String, Vec<(u64, u64)>>>,
}

impl PolicyStore {
    /// Create a new, empty `PolicyStore`.
    ///
    /// No policy is loaded. Any call to [`check`](PolicyStore::check) will
    /// return [`CoreError::PolicyRequired`] until [`load`](PolicyStore::load) is called.
    pub fn new() -> Self {
        PolicyStore {
            policy: RwLock::new(None),
            velocity: RwLock::new(HashMap::new()),
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

    /// Clear the active policy.
    ///
    /// After this call, [`check`](PolicyStore::check) will return
    /// [`CoreError::PolicyRequired`] until [`load`](PolicyStore::load) is called again.
    pub fn clear(&self) {
        *self.policy.write().unwrap() = None;
        self.velocity.write().unwrap().clear();
    }

    /// Load a signed policy bundle after verifying its Ed25519 signature (Epic B2).
    pub fn load_signed(&self, signed: &SignedPolicy) -> Result<(), CoreError> {
        let policy = signed.verify()?;
        self.load(policy.clone())
    }

    /// Record a signed transaction for velocity tracking.
    ///
    /// Must be called after each successful signing to maintain accurate
    /// daily velocity counters.
    pub fn record_transaction(&self, chain: &str, amount: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut vel = self.velocity.write().unwrap();
        vel.entry(chain.to_string())
            .or_default()
            .push((now, amount));
    }

    /// Get the total amount signed in the last 24 hours for a chain.
    fn daily_total(&self, chain: &str) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(86400);
        let vel = self.velocity.read().unwrap();
        vel.get(chain)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(ts, _)| *ts >= cutoff)
                    .map(|(_, amt)| amt)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Prune velocity entries older than 24 hours to prevent unbounded growth.
    pub fn prune_velocity(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(86400);
        let mut vel = self.velocity.write().unwrap();
        for entries in vel.values_mut() {
            entries.retain(|(ts, _)| *ts >= cutoff);
        }
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
            EvalResult::Allow => {}
            EvalResult::Deny(reason) => {
                return Err(CoreError::Protocol(format!("policy denied: {}", reason)));
            }
        }

        // Daily velocity limit check
        if let Some(chain_policy) = policy.chains.get(chain) {
            if let Some(daily_limit) = chain_policy.daily_velocity_limit {
                let current_total = self.daily_total(chain);
                if current_total + amount > daily_limit {
                    return Err(CoreError::Protocol(format!(
                        "policy denied: daily velocity limit exceeded on chain '{}' \
                         (current: {}, requested: {}, limit: {})",
                        chain, current_total, amount, daily_limit
                    )));
                }
            }
        }

        Ok(())
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Extended Velocity Limits (Sprint 26) ─────────────────────────────────────

/// Time window for velocity tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VelocityWindow {
    /// 1 hour (3600 seconds).
    Hourly,
    /// 24 hours (86400 seconds).
    Daily,
    /// 7 days (604800 seconds).
    Weekly,
    /// 30 days (2592000 seconds).
    Monthly,
}

impl VelocityWindow {
    /// Returns the window duration in seconds.
    pub fn duration_secs(&self) -> u64 {
        match self {
            VelocityWindow::Hourly => 3600,
            VelocityWindow::Daily => 86400,
            VelocityWindow::Weekly => 604_800,
            VelocityWindow::Monthly => 2_592_000,
        }
    }
}

/// Map type for velocity tracking: (scope, window) -> list of (timestamp, amount).
type VelocityMap = HashMap<(String, VelocityWindow), Vec<(u64, u64)>>;

/// Tracks spending velocity per scope (key_group/team/org) per time window.
///
/// Uses `RwLock<VelocityMap>` where each entry maps `(scope, window)` to a
/// list of `(timestamp, amount)` records. Expired entries are pruned on each
/// `check` call.
pub struct VelocityTracker {
    /// (scope, window) -> list of (timestamp_secs, amount).
    entries: RwLock<VelocityMap>,
}

impl VelocityTracker {
    /// Create a new empty velocity tracker.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Record a spending event for the given scope and window.
    pub fn record(&self, scope: &str, amount: u64, window: VelocityWindow) {
        let now = Self::now();
        let mut entries = self.entries.write().unwrap();
        entries
            .entry((scope.to_string(), window))
            .or_default()
            .push((now, amount));
    }

    /// Check whether spending `amount` in the given scope/window would exceed `limit`.
    ///
    /// Returns `true` if the total (existing + proposed) is within the limit.
    /// Expired entries are pruned during this check.
    pub fn check(&self, scope: &str, amount: u64, window: VelocityWindow, limit: u64) -> bool {
        let now = Self::now();
        let cutoff = now.saturating_sub(window.duration_secs());

        let mut entries = self.entries.write().unwrap();
        let key = (scope.to_string(), window);

        // Prune expired entries
        if let Some(records) = entries.get_mut(&key) {
            records.retain(|(ts, _)| *ts >= cutoff);
        }

        let current_total: u64 = entries
            .get(&key)
            .map(|records| records.iter().map(|(_, amt)| amt).sum())
            .unwrap_or(0);

        current_total + amount <= limit
    }
}

impl Default for VelocityTracker {
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

    // ── Daily velocity limit tests ────────────────────────────────────────────

    #[test]
    fn test_daily_velocity_limit_allows_within_limit() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: None,
                daily_velocity_limit: Some(10000),
            },
        );
        store
            .load(Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "test".into(),
                chains,
            })
            .unwrap();

        // First tx: 3000 within 10000 limit
        assert!(store.check("ethereum", "0xabc", 3000).is_ok());
        store.record_transaction("ethereum", 3000);

        // Second tx: 3000 + 3000 = 6000, still within limit
        assert!(store.check("ethereum", "0xabc", 3000).is_ok());
        store.record_transaction("ethereum", 3000);

        // Third tx: 6000 + 3000 = 9000, still within limit
        assert!(store.check("ethereum", "0xabc", 3000).is_ok());
    }

    #[test]
    fn test_daily_velocity_limit_blocks_over_limit() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: None,
                daily_velocity_limit: Some(5000),
            },
        );
        store
            .load(Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "test".into(),
                chains,
            })
            .unwrap();

        // Record 4000 already signed
        store.record_transaction("ethereum", 4000);

        // New tx of 2000 would exceed 5000 limit (4000 + 2000 = 6000)
        let err = store.check("ethereum", "0xabc", 2000).unwrap_err();
        assert!(matches!(err, CoreError::Protocol(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("velocity"),
            "error should mention velocity: {msg}"
        );
    }

    #[test]
    fn test_velocity_different_chains_independent() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: None,
                daily_velocity_limit: Some(5000),
            },
        );
        chains.insert(
            "bitcoin".into(),
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: None,
                daily_velocity_limit: Some(5000),
            },
        );
        store
            .load(Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "test".into(),
                chains,
            })
            .unwrap();

        // Exhaust ethereum limit
        store.record_transaction("ethereum", 4500);
        assert!(store.check("ethereum", "0xabc", 1000).is_err());

        // Bitcoin is unaffected
        assert!(store.check("bitcoin", "bc1abc", 4000).is_ok());
    }

    #[test]
    fn test_velocity_no_limit_allows_all() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec![],
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

        store.record_transaction("ethereum", 999999);
        assert!(store.check("ethereum", "0xabc", 999999).is_ok());
    }

    #[test]
    fn test_velocity_exact_limit_allowed() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: None,
                daily_velocity_limit: Some(10000),
            },
        );
        store
            .load(Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "test".into(),
                chains,
            })
            .unwrap();

        store.record_transaction("ethereum", 5000);
        // Exactly at limit: 5000 + 5000 = 10000
        assert!(store.check("ethereum", "0xabc", 5000).is_ok());
        // Over by 1
        assert!(store.check("ethereum", "0xabc", 5001).is_err());
    }

    #[test]
    fn test_clear_resets_velocity() {
        let store = PolicyStore::new();
        let mut chains = HashMap::new();
        chains.insert(
            "ethereum".into(),
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: None,
                daily_velocity_limit: Some(1000),
            },
        );
        let policy = Policy {
            version: POLICY_SCHEMA_VERSION,
            name: "test".into(),
            chains,
        };
        store.load(policy.clone()).unwrap();

        store.record_transaction("ethereum", 900);
        assert!(store.check("ethereum", "0xabc", 200).is_err());

        // Clear resets everything
        store.clear();
        store.load(policy).unwrap();
        // Velocity counter should be zero now
        assert!(store.check("ethereum", "0xabc", 900).is_ok());
    }

    #[test]
    fn test_signed_policy_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        let policy = Policy::allow_all("signed-test");
        let signed = SignedPolicy::sign(policy, &sk);
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn test_signed_policy_tampered_rejected() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        let policy = Policy::allow_all("original");
        let mut signed = SignedPolicy::sign(policy, &sk);
        signed.policy.name = "TAMPERED".into();
        assert!(signed.verify().is_err());
    }

    #[test]
    fn test_load_signed_policy() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        let store = PolicyStore::new();
        let signed = SignedPolicy::sign(Policy::allow_all("test"), &sk);
        store.load_signed(&signed).unwrap();
        assert!(store.check("ethereum", "0xabc", 100).is_ok());
    }
}

#[cfg(test)]
mod template_tests {
    use super::*;

    #[test]
    fn test_exchange_template() {
        let p = PolicyTemplate::Exchange.build();
        assert_eq!(p.name, "exchange-hot-wallet");
        assert!(p
            .chains
            .get("ethereum")
            .unwrap()
            .max_amount_per_tx
            .is_some());
    }

    #[test]
    fn test_treasury_template() {
        let p = PolicyTemplate::Treasury.build();
        assert_eq!(p.name, "treasury");
        assert!(p.chains.contains_key("ethereum"));
    }

    #[test]
    fn test_custodian_template_permissive() {
        let p = PolicyTemplate::Custodian.build();
        assert!(p.chains.is_empty());
    }

    #[test]
    fn test_template_loads_into_store() {
        let store = PolicyStore::new();
        store.load(PolicyTemplate::Exchange.build()).unwrap();
        assert!(store.check("ethereum", "0xabc", 1000).is_ok());
    }
}

#[cfg(test)]
mod velocity_tracker_tests {
    use super::*;

    #[test]
    fn test_record_and_check_under_limit() {
        let tracker = VelocityTracker::new();
        tracker.record("team-a", 500, VelocityWindow::Daily);
        assert!(tracker.check("team-a", 400, VelocityWindow::Daily, 1000));
    }

    #[test]
    fn test_check_over_limit() {
        let tracker = VelocityTracker::new();
        tracker.record("team-a", 800, VelocityWindow::Daily);
        assert!(!tracker.check("team-a", 300, VelocityWindow::Daily, 1000));
    }

    #[test]
    fn test_hourly_window() {
        let tracker = VelocityTracker::new();
        tracker.record("team-a", 100, VelocityWindow::Hourly);
        assert!(tracker.check("team-a", 50, VelocityWindow::Hourly, 200));
        assert!(!tracker.check("team-a", 150, VelocityWindow::Hourly, 200));
    }

    #[test]
    fn test_weekly_window() {
        let tracker = VelocityTracker::new();
        tracker.record("org-1", 5000, VelocityWindow::Weekly);
        assert!(tracker.check("org-1", 4000, VelocityWindow::Weekly, 10000));
        assert!(!tracker.check("org-1", 6000, VelocityWindow::Weekly, 10000));
    }

    #[test]
    fn test_monthly_window() {
        let tracker = VelocityTracker::new();
        tracker.record("org-1", 10000, VelocityWindow::Monthly);
        assert!(tracker.check("org-1", 5000, VelocityWindow::Monthly, 20000));
        assert!(!tracker.check("org-1", 15000, VelocityWindow::Monthly, 20000));
    }

    #[test]
    fn test_multi_scope_independent() {
        let tracker = VelocityTracker::new();
        tracker.record("team-a", 900, VelocityWindow::Daily);
        tracker.record("team-b", 100, VelocityWindow::Daily);

        // team-a is near limit
        assert!(!tracker.check("team-a", 200, VelocityWindow::Daily, 1000));
        // team-b is well under
        assert!(tracker.check("team-b", 800, VelocityWindow::Daily, 1000));
    }

    #[test]
    fn test_exact_limit_allowed() {
        let tracker = VelocityTracker::new();
        tracker.record("scope", 500, VelocityWindow::Daily);
        assert!(tracker.check("scope", 500, VelocityWindow::Daily, 1000));
        assert!(!tracker.check("scope", 501, VelocityWindow::Daily, 1000));
    }

    #[test]
    fn test_empty_tracker_allows() {
        let tracker = VelocityTracker::new();
        assert!(tracker.check("any-scope", 1000, VelocityWindow::Daily, 1000));
    }

    #[test]
    fn test_window_duration_values() {
        assert_eq!(VelocityWindow::Hourly.duration_secs(), 3600);
        assert_eq!(VelocityWindow::Daily.duration_secs(), 86400);
        assert_eq!(VelocityWindow::Weekly.duration_secs(), 604_800);
        assert_eq!(VelocityWindow::Monthly.duration_secs(), 2_592_000);
    }
}
