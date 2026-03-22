//! Property-based tests for MPC wallet core cryptographic invariants.
//!
//! Uses proptest to verify protocol properties hold across many random inputs.
//! Run with: `cargo test --test property_tests --features local-transport`

use mpc_wallet_core::paillier::keygen::test_keypair;
use mpc_wallet_core::paillier::mta::{MtaPartyA, MtaPartyB};
use mpc_wallet_core::paillier::{PaillierPublicKey, PaillierSecretKey};
use num_bigint::BigUint;
use proptest::prelude::*;
use std::sync::LazyLock;
use zeroize::Zeroizing;

// Shared test keypair (512-bit, cached)
static TEST_KEYS: LazyLock<(PaillierPublicKey, PaillierSecretKey)> = LazyLock::new(test_keypair);

// ─────────────────────────────────────────────────────────────────────────────
// 1. Paillier Homomorphic Properties
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Enc(a) * Enc(b) = Enc(a + b mod N) for all a, b
    #[test]
    fn paillier_homomorphic_addition(a in 0u64..1_000_000, b in 0u64..1_000_000) {
        let (pk, sk) = &*TEST_KEYS;
        let a_big = BigUint::from(a);
        let b_big = BigUint::from(b);

        let ca = pk.encrypt(&a_big);
        let cb = pk.encrypt(&b_big);
        let c_sum = pk.add(&ca, &cb);

        let decrypted = sk.decrypt(pk, &c_sum);
        prop_assert_eq!(decrypted, a_big + b_big);
    }

    /// Enc(a)^k = Enc(a * k mod N) for all a, k
    #[test]
    fn paillier_homomorphic_scalar_mult(a in 1u64..100_000, k in 1u64..100_000) {
        let (pk, sk) = &*TEST_KEYS;
        let a_big = BigUint::from(a);
        let k_big = BigUint::from(k);

        let ca = pk.encrypt(&a_big);
        let c_mul = pk.scalar_mult(&ca, &k_big);

        let decrypted = sk.decrypt(pk, &c_mul);
        let n = pk.n_biguint();
        prop_assert_eq!(decrypted, (a_big * k_big) % n);
    }

    /// Encrypt then decrypt = identity for all plaintexts < N
    #[test]
    fn paillier_encrypt_decrypt_roundtrip(m in 0u64..10_000_000) {
        let (pk, sk) = &*TEST_KEYS;
        let m_big = BigUint::from(m);

        let ct = pk.encrypt(&m_big);
        let decrypted = sk.decrypt(pk, &ct);
        prop_assert_eq!(decrypted, m_big);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. MtA Correctness (new formula: alpha - beta = a*b)
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// MtA produces shares where alpha - beta = a * b (mod N)
    #[test]
    fn mta_correctness_property(a in 1u64..1_000_000, b in 1u64..1_000_000) {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();

        let a_big = BigUint::from(a);
        let b_big = BigUint::from(b);

        let party_a = MtaPartyA::new(
            pk.clone(), sk.clone(),
            Zeroizing::new(a_big.to_bytes_be()),
        );
        let party_b = MtaPartyB::new(
            pk.clone(),
            Zeroizing::new(b_big.to_bytes_be()),
        );

        let round1 = party_a.round1();
        let round2 = party_b.round2(&round1);

        let alpha = BigUint::from_bytes_be(&party_a.round2_finish(&round2.ciphertext));
        let beta = BigUint::from_bytes_be(&round2.beta);

        // alpha - beta = a * b (mod N)
        let diff = (&alpha + &n - &beta) % &n;
        let product = (&a_big * &b_big) % &n;
        prop_assert_eq!(diff, product, "MtA: alpha-beta != a*b for a={}, b={}", a, b);
    }

    /// MtA with witness path also produces correct result
    #[test]
    fn mta_witness_correctness(a in 1u64..100_000, b in 1u64..100_000) {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();

        let party_a = MtaPartyA::new(
            pk.clone(), sk.clone(),
            Zeroizing::new(BigUint::from(a).to_bytes_be()),
        );
        let party_b = MtaPartyB::new(
            pk.clone(),
            Zeroizing::new(BigUint::from(b).to_bytes_be()),
        );

        let witness_a = party_a.round1_with_witness();
        let witness_b = party_b.round2_with_witness(&witness_a.message);

        let alpha = BigUint::from_bytes_be(&party_a.round2_finish(&witness_b.result.ciphertext));
        let beta = BigUint::from_bytes_be(&witness_b.result.beta);

        let diff = (&alpha + &n - &beta) % &n;
        let product = (BigUint::from(a) * BigUint::from(b)) % &n;
        prop_assert_eq!(diff, product, "MtA witness: alpha-beta != a*b");

        // Witness fields must be non-empty
        prop_assert!(!witness_a.plaintext_m.is_empty());
        prop_assert!(!witness_a.randomness_r.is_empty());
        prop_assert!(!witness_b.rho_y.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Paillier Semantic Security (ciphertexts are randomized)
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Two encryptions of the same plaintext produce different ciphertexts
    #[test]
    fn paillier_semantic_security(m in 0u64..1_000_000) {
        let (pk, _) = &*TEST_KEYS;
        let m_big = BigUint::from(m);

        let ct1 = pk.encrypt(&m_big);
        let ct2 = pk.encrypt(&m_big);

        prop_assert_ne!(ct1.data, ct2.data,
            "same plaintext must produce different ciphertexts (semantic security)");
    }
}
