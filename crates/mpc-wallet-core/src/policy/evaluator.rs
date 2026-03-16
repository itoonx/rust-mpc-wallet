//! Policy evaluation logic.
//!
//! The [`evaluate`] function checks a single proposed transaction against a
//! loaded [`Policy`], returning [`EvalResult::Allow`] or [`EvalResult::Deny`].

use crate::policy::schema::Policy;

/// The result of evaluating a transaction against a policy.
#[derive(Debug, PartialEq, Eq)]
pub enum EvalResult {
    /// The transaction is permitted by the policy.
    Allow,
    /// The transaction is denied. The inner string explains which rule was violated.
    Deny(String),
}

/// Evaluate a proposed transaction against a [`Policy`].
///
/// # Arguments
/// - `policy` — the loaded policy to evaluate against.
/// - `chain` — chain identifier string, must match the keys used in
///   `policy.chains` (e.g. `"ethereum"`, `"bitcoin"`).
/// - `to_address` — destination address as a string. Compared case-insensitively
///   against allowlist entries.
/// - `amount` — transaction value in the chain's smallest unit (e.g. wei for EVM).
///
/// # Returns
/// [`EvalResult::Allow`] if the transaction passes all rules for the given chain,
/// [`EvalResult::Deny`] with a human-readable reason if any rule rejects it.
///
/// If the policy has no rules for `chain`, the transaction is allowed by default.
pub fn evaluate(policy: &Policy, chain: &str, to_address: &str, amount: u64) -> EvalResult {
    let chain_policy = match policy.chains.get(chain) {
        Some(cp) => cp,
        // No rules for this chain → allow by default
        None => return EvalResult::Allow,
    };

    // ── Allowlist check ───────────────────────────────────────────────────────
    if !chain_policy.allowlist.is_empty() {
        let addr_lower = to_address.to_lowercase();
        let allowed = chain_policy
            .allowlist
            .iter()
            .any(|a| a.to_lowercase() == addr_lower);
        if !allowed {
            return EvalResult::Deny(format!(
                "destination address '{}' is not in the allowlist for chain '{}'",
                to_address, chain
            ));
        }
    }

    // ── Per-transaction amount limit ──────────────────────────────────────────
    if let Some(max) = chain_policy.max_amount_per_tx {
        if amount > max {
            return EvalResult::Deny(format!(
                "amount {} exceeds the per-transaction limit of {} on chain '{}'",
                amount, max, chain
            ));
        }
    }

    // ── Daily velocity limit ────────────────────────────────────────────────────
    // Velocity enforcement is handled by `PolicyStore::check()` which maintains
    // a rolling 24-hour window of signed amounts per chain. The pure evaluator
    // does not track state; it only checks stateless per-transaction rules.

    EvalResult::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::{ChainPolicy, Policy, POLICY_SCHEMA_VERSION};
    use std::collections::HashMap;

    fn make_policy(chain: &str, cp: ChainPolicy) -> Policy {
        let mut chains = HashMap::new();
        chains.insert(chain.to_string(), cp);
        Policy {
            version: POLICY_SCHEMA_VERSION,
            name: "test".into(),
            chains,
        }
    }

    #[test]
    fn test_no_chain_rules_allows_all() {
        let policy = Policy::allow_all("test");
        assert_eq!(
            evaluate(&policy, "ethereum", "0xabc", 9999),
            EvalResult::Allow
        );
    }

    #[test]
    fn test_empty_allowlist_allows_all_addresses() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: None,
                daily_velocity_limit: None,
            },
        );
        assert_eq!(
            evaluate(&policy, "ethereum", "0xdeadbeef", 1),
            EvalResult::Allow
        );
    }

    #[test]
    fn test_allowlist_permits_known_address() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec!["0xAAA".to_string()],
                max_amount_per_tx: None,
                daily_velocity_limit: None,
            },
        );
        // Case-insensitive match
        assert_eq!(evaluate(&policy, "ethereum", "0xaaa", 1), EvalResult::Allow);
        assert_eq!(evaluate(&policy, "ethereum", "0xAAA", 1), EvalResult::Allow);
    }

    #[test]
    fn test_allowlist_blocks_unknown_address() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec!["0xAAA".to_string()],
                max_amount_per_tx: None,
                daily_velocity_limit: None,
            },
        );
        let result = evaluate(&policy, "ethereum", "0xBBB", 1);
        assert!(matches!(result, EvalResult::Deny(_)));
    }

    #[test]
    fn test_amount_limit_permits_at_limit() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: Some(1000),
                daily_velocity_limit: None,
            },
        );
        assert_eq!(
            evaluate(&policy, "ethereum", "0xabc", 1000),
            EvalResult::Allow
        );
    }

    #[test]
    fn test_amount_limit_blocks_over_limit() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: Some(1000),
                daily_velocity_limit: None,
            },
        );
        let result = evaluate(&policy, "ethereum", "0xabc", 1001);
        assert!(matches!(result, EvalResult::Deny(_)));
    }

    #[test]
    fn test_unknown_chain_allows() {
        // Policy has rules only for "ethereum"; "bitcoin" is unconstrained
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec!["0xAAA".to_string()],
                max_amount_per_tx: Some(500),
                daily_velocity_limit: None,
            },
        );
        assert_eq!(
            evaluate(&policy, "bitcoin", "bc1anything", 99999),
            EvalResult::Allow
        );
    }
}
