//! Delegation Token — Ed25519-signed scoped authority transfer.
//!
//! Allows a delegator to grant time-limited, scope-restricted signing authority
//! to a delegate. The delegate can then present the `DelegationToken` to prove
//! they are authorized to sign on behalf of the delegator, within the defined scope.
//!
//! ```text
//! Delegator (creates token)       Delegate (presents token)
//! ┌──────────────────────┐       ┌──────────────────────────┐
//! │ 1. Define scope      │       │                          │
//! │ 2. Set time bounds   │       │ Verify:                  │
//! │ 3. Sign with Ed25519 │ ────► │  - Signature valid       │
//! │ 4. Issue to delegate │       │  - Not expired           │
//! └──────────────────────┘       │  - Scope matches request │
//!                                └──────────────────────────┘
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Defines what operations a delegate is authorized to perform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DelegationScope {
    /// Delegate can sign with any key — full authority.
    AllKeys,
    /// Delegate limited to a specific key group.
    KeyGroup(String),
    /// Delegate limited to a specific chain.
    Chain(String),
    /// Delegate limited to a maximum amount per transaction.
    AmountLimit(u64),
    /// Multiple restrictions — all must pass for the operation to be authorized.
    Combined(Vec<DelegationScope>),
}

/// An Ed25519-signed token granting scoped signing authority from delegator to delegate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Who grants authority (user ID or key ID of the delegator).
    pub delegator_id: String,
    /// Who receives authority (user ID or key ID of the delegate).
    pub delegate_id: String,
    /// The scope of delegated authority.
    pub scope: DelegationScope,
    /// Unix timestamp — token is not valid before this time.
    pub valid_from: u64,
    /// Unix timestamp — token expires after this time.
    pub valid_until: u64,
    /// Unique nonce for replay protection.
    pub nonce: String,
    /// Ed25519 signature over the SHA-256 hash of the token payload.
    pub signature: Vec<u8>,
}

impl DelegationToken {
    /// Create and sign a new delegation token.
    ///
    /// The delegator signs the token payload (all fields except `signature`) with
    /// their Ed25519 signing key. The resulting token can be verified by anyone
    /// who has the delegator's public key.
    pub fn sign(
        delegator_key: &SigningKey,
        delegator_id: String,
        delegate_id: String,
        scope: DelegationScope,
        valid_from: u64,
        valid_until: u64,
        nonce: String,
    ) -> Self {
        let payload_hash = Self::compute_payload_hash(
            &delegator_id,
            &delegate_id,
            &scope,
            valid_from,
            valid_until,
            &nonce,
        );
        let sig = delegator_key.sign(&payload_hash);

        Self {
            delegator_id,
            delegate_id,
            scope,
            valid_from,
            valid_until,
            nonce,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Verify the token's Ed25519 signature and check that it has not expired.
    ///
    /// Returns `Ok(())` if the signature is valid and the current time falls
    /// within `[valid_from, valid_until]`. Returns `CoreError::Protocol` on failure.
    pub fn verify(&self, delegator_pubkey: &VerifyingKey) -> Result<(), CoreError> {
        // 1. Verify signature.
        let payload_hash = Self::compute_payload_hash(
            &self.delegator_id,
            &self.delegate_id,
            &self.scope,
            self.valid_from,
            self.valid_until,
            &self.nonce,
        );

        if self.signature.len() != 64 {
            return Err(CoreError::Protocol(
                "delegation token: invalid signature length".into(),
            ));
        }

        let sig_bytes: [u8; 64] = self
            .signature
            .clone()
            .try_into()
            .map_err(|_| CoreError::Protocol("delegation token: invalid signature".into()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        delegator_pubkey
            .verify(&payload_hash, &signature)
            .map_err(|_| {
                CoreError::Protocol(
                    "delegation token: invalid signature — verification failed".into(),
                )
            })?;

        // 2. Check expiry.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now < self.valid_from {
            return Err(CoreError::Protocol(format!(
                "delegation token: not yet valid (valid_from={}, now={})",
                self.valid_from, now
            )));
        }

        if now > self.valid_until {
            return Err(CoreError::Protocol(format!(
                "delegation token: expired (valid_until={}, now={})",
                self.valid_until, now
            )));
        }

        Ok(())
    }

    /// Check whether the requested operation falls within this token's scope.
    ///
    /// - `chain`: the chain being signed for (e.g. "ethereum", "bitcoin")
    /// - `amount`: the transaction amount
    /// - `group_id`: the key group being used
    ///
    /// Returns `Ok(())` if the operation is within scope, or `CoreError::Protocol`
    /// describing which scope constraint was violated.
    pub fn check_scope(&self, chain: &str, amount: u64, group_id: &str) -> Result<(), CoreError> {
        Self::check_scope_inner(&self.scope, chain, amount, group_id)
    }

    /// Recursive scope checker for `Combined` scopes.
    fn check_scope_inner(
        scope: &DelegationScope,
        chain: &str,
        amount: u64,
        group_id: &str,
    ) -> Result<(), CoreError> {
        match scope {
            DelegationScope::AllKeys => Ok(()),
            DelegationScope::KeyGroup(allowed_group) => {
                if allowed_group == group_id {
                    Ok(())
                } else {
                    Err(CoreError::Protocol(format!(
                        "delegation scope: key group '{}' not authorized (allowed: '{}')",
                        group_id, allowed_group
                    )))
                }
            }
            DelegationScope::Chain(allowed_chain) => {
                if allowed_chain == chain {
                    Ok(())
                } else {
                    Err(CoreError::Protocol(format!(
                        "delegation scope: chain '{}' not authorized (allowed: '{}')",
                        chain, allowed_chain
                    )))
                }
            }
            DelegationScope::AmountLimit(max_amount) => {
                if amount <= *max_amount {
                    Ok(())
                } else {
                    Err(CoreError::Protocol(format!(
                        "delegation scope: amount {} exceeds limit {}",
                        amount, max_amount
                    )))
                }
            }
            DelegationScope::Combined(scopes) => {
                for s in scopes {
                    Self::check_scope_inner(s, chain, amount, group_id)?;
                }
                Ok(())
            }
        }
    }

    /// Compute SHA-256 hash of the token payload (everything except the signature).
    fn compute_payload_hash(
        delegator_id: &str,
        delegate_id: &str,
        scope: &DelegationScope,
        valid_from: u64,
        valid_until: u64,
        nonce: &str,
    ) -> [u8; 32] {
        let scope_json =
            serde_json::to_string(scope).expect("DelegationScope serialization cannot fail");
        let payload = format!(
            "delegation:{}:{}:{}:{}:{}:{}",
            delegator_id, delegate_id, scope_json, valid_from, valid_until, nonce
        );
        Sha256::digest(payload.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        SigningKey::from_bytes(&bytes)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_token(key: &SigningKey) -> DelegationToken {
        let now = now_secs();
        DelegationToken::sign(
            key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::AllKeys,
            now - 60,
            now + 3600, // 1 hour validity
            "nonce-001".into(),
        )
    }

    #[test]
    fn test_delegation_sign_verify_roundtrip() {
        let key = test_key();
        let token = make_token(&key);

        let result = token.verify(&key.verifying_key());
        assert!(result.is_ok(), "valid token should verify: {result:?}");
    }

    #[test]
    fn test_delegation_expired_token_rejected() {
        let key = test_key();
        let now = now_secs();
        let token = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::AllKeys,
            1000,
            1500, // expired long ago
            "nonce-expired".into(),
        );

        let result = token.verify(&key.verifying_key());
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("expired"),
            "should report expiry: {result:?}"
        );

        // Also test not-yet-valid.
        let future_token = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::AllKeys,
            now + 9999,
            now + 99999,
            "nonce-future".into(),
        );
        let result = future_token.verify(&key.verifying_key());
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("not yet valid"),
            "should report not-yet-valid: {result:?}"
        );
    }

    #[test]
    fn test_delegation_wrong_key_rejected() {
        let key = test_key();
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]);
        let token = make_token(&key);

        let result = token.verify(&wrong_key.verifying_key());
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("verification failed"),
            "should detect wrong key: {result:?}"
        );
    }

    #[test]
    fn test_delegation_tampered_rejected() {
        let key = test_key();
        let mut token = make_token(&key);

        // Tamper with delegate_id after signing.
        token.delegate_id = "attacker-eve".into();

        let result = token.verify(&key.verifying_key());
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("verification failed"),
            "should detect tampering: {result:?}"
        );
    }

    #[test]
    fn test_delegation_scope_chain_pass() {
        let key = test_key();
        let now = now_secs();
        let token = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::Chain("ethereum".into()),
            now - 60,
            now + 3600,
            "nonce-chain-pass".into(),
        );

        let result = token.check_scope("ethereum", 1000, "group-1");
        assert!(result.is_ok(), "ethereum should be in scope: {result:?}");
    }

    #[test]
    fn test_delegation_scope_chain_fail() {
        let key = test_key();
        let now = now_secs();
        let token = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::Chain("ethereum".into()),
            now - 60,
            now + 3600,
            "nonce-chain-fail".into(),
        );

        let result = token.check_scope("bitcoin", 1000, "group-1");
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("chain 'bitcoin' not authorized"),
            "should reject wrong chain: {result:?}"
        );
    }

    #[test]
    fn test_delegation_scope_amount_pass() {
        let key = test_key();
        let now = now_secs();
        let token = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::AmountLimit(10_000),
            now - 60,
            now + 3600,
            "nonce-amount-pass".into(),
        );

        let result = token.check_scope("ethereum", 5_000, "group-1");
        assert!(result.is_ok(), "5000 <= 10000 should pass: {result:?}");

        // Exact limit should also pass.
        let result = token.check_scope("ethereum", 10_000, "group-1");
        assert!(result.is_ok(), "exact limit should pass: {result:?}");
    }

    #[test]
    fn test_delegation_scope_amount_fail() {
        let key = test_key();
        let now = now_secs();
        let token = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::AmountLimit(10_000),
            now - 60,
            now + 3600,
            "nonce-amount-fail".into(),
        );

        let result = token.check_scope("ethereum", 10_001, "group-1");
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("exceeds limit"),
            "should reject over-limit amount: {result:?}"
        );
    }

    #[test]
    fn test_delegation_scope_combined() {
        let key = test_key();
        let now = now_secs();
        let token = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::Combined(vec![
                DelegationScope::Chain("ethereum".into()),
                DelegationScope::AmountLimit(50_000),
                DelegationScope::KeyGroup("group-prod".into()),
            ]),
            now - 60,
            now + 3600,
            "nonce-combined".into(),
        );

        // All constraints pass.
        let result = token.check_scope("ethereum", 25_000, "group-prod");
        assert!(result.is_ok(), "all constraints met: {result:?}");

        // Wrong chain fails.
        let result = token.check_scope("bitcoin", 25_000, "group-prod");
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("chain 'bitcoin' not authorized"));

        // Over amount fails.
        let result = token.check_scope("ethereum", 100_000, "group-prod");
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("exceeds limit"));

        // Wrong group fails.
        let result = token.check_scope("ethereum", 25_000, "group-dev");
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("key group 'group-dev' not authorized"));
    }

    #[test]
    fn test_delegation_nonce_unique() {
        let key = test_key();
        let now = now_secs();

        let token1 = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::AllKeys,
            now - 60,
            now + 3600,
            "nonce-unique-001".into(),
        );

        let token2 = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::AllKeys,
            now - 60,
            now + 3600,
            "nonce-unique-002".into(),
        );

        // Different nonces should produce different signatures.
        assert_ne!(
            token1.signature, token2.signature,
            "different nonces must produce different signatures"
        );
        assert_ne!(token1.nonce, token2.nonce, "nonces must be distinct");

        // Both should verify independently.
        assert!(token1.verify(&key.verifying_key()).is_ok());
        assert!(token2.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn test_delegation_scope_key_group() {
        let key = test_key();
        let now = now_secs();
        let token = DelegationToken::sign(
            &key,
            "delegator-alice".into(),
            "delegate-bob".into(),
            DelegationScope::KeyGroup("group-treasury".into()),
            now - 60,
            now + 3600,
            "nonce-group".into(),
        );

        // Correct group passes.
        let result = token.check_scope("ethereum", 1000, "group-treasury");
        assert!(result.is_ok(), "correct group should pass: {result:?}");

        // Wrong group fails.
        let result = token.check_scope("ethereum", 1000, "group-exchange");
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("key group 'group-exchange' not authorized"));
    }

    #[test]
    fn test_delegation_all_keys_scope_allows_everything() {
        let key = test_key();
        let token = make_token(&key);

        // AllKeys should allow any chain, amount, and group.
        assert!(token.check_scope("ethereum", u64::MAX, "any-group").is_ok());
        assert!(token.check_scope("bitcoin", 0, "").is_ok());
        assert!(token.check_scope("solana", 999_999, "group-xyz").is_ok());
    }

    #[test]
    fn test_delegation_forged_signature_rejected() {
        let key = test_key();
        let mut token = make_token(&key);

        // Replace signature with garbage.
        token.signature = vec![0xFF; 64];

        let result = token.verify(&key.verifying_key());
        assert!(result.is_err());
        assert!(
            format!("{result:?}").contains("verification failed"),
            "should detect forged signature: {result:?}"
        );
    }
}
