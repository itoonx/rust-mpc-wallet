//! MtA (Multiplicative-to-Additive) sub-protocol for CGGMP21.
//!
//! Converts a multiplicative sharing between two parties into an additive sharing
//! using Paillier homomorphic encryption.
//!
//! Given: Party A has secret `a`, Party B has secret `b`.
//! Goal: produce shares alpha, beta such that `a * b = alpha + beta (mod N)`.
//!
//! Protocol flow:
//! 1. Party A encrypts `a` under its own Paillier key: `c_A = Enc_A(a)`
//! 2. Party A sends `c_A` to Party B (with Pi_enc range proof in production)
//! 3. Party B computes `c_B = c_A ^b * Enc_A(-beta') = Enc_A(a*b - beta')` and sends back
//! 4. Party A decrypts `c_B` to get `alpha = a*b - beta'`
//! 5. Party B keeps `beta = beta'`
//! 6. Result: `alpha + beta = a*b`

use super::{PaillierCiphertext, PaillierPublicKey, PaillierSecretKey};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Party A in the MtA protocol. Holds the Paillier keypair and secret `a`.
pub struct MtaPartyA {
    sk: PaillierSecretKey,
    pk: PaillierPublicKey,
    /// Secret scalar `a` as big-endian bytes.
    secret_a: Zeroizing<Vec<u8>>,
}

/// Party B in the MtA protocol. Holds Party A's public key and secret `b`.
pub struct MtaPartyB {
    /// Party A's Paillier public key.
    peer_pk: PaillierPublicKey,
    /// Secret scalar `b` as big-endian bytes.
    secret_b: Zeroizing<Vec<u8>>,
}

/// Round 1 message from Party A to Party B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaRound1 {
    /// Enc_A(a) — encryption of Party A's secret under A's Paillier key.
    pub ciphertext: PaillierCiphertext,
    // In production: + Pi_enc range proof
}

/// Round 2 output: message from B to A, plus B's local share.
///
/// Note: beta is secret material and must not be serialized over the wire.
/// Only the `ciphertext` field is sent to Party A. Party B retains `beta` locally.
pub struct MtaRound2 {
    /// Enc_A(a*b - beta') — for Party A to decrypt.
    pub ciphertext: PaillierCiphertext,
    /// beta' — Party B's additive share (big-endian bytes, secret).
    pub beta: Zeroizing<Vec<u8>>,
    // In production: + Pi_aff-g range proof
}

/// Wire message sent from Party B to Party A in Round 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaRound2Message {
    /// Enc_A(a*b - beta') — for Party A to decrypt.
    pub ciphertext: PaillierCiphertext,
}

// Manual Debug to redact secret beta.
impl std::fmt::Debug for MtaRound2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtaRound2")
            .field("ciphertext", &self.ciphertext)
            .field("beta", &"[REDACTED]")
            .finish()
    }
}

impl MtaPartyA {
    /// Create Party A with its Paillier keypair and secret scalar `a`.
    pub fn new(pk: PaillierPublicKey, sk: PaillierSecretKey, secret_a: Zeroizing<Vec<u8>>) -> Self {
        Self { sk, pk, secret_a }
    }

    /// Round 1: encrypt secret `a` and produce the message for Party B.
    pub fn round1(&self) -> MtaRound1 {
        let a = BigUint::from_bytes_be(&self.secret_a);
        let ciphertext = self.pk.encrypt(&a);
        MtaRound1 { ciphertext }
    }

    /// Finish: decrypt Party B's response to get alpha (Party A's additive share).
    ///
    /// Accepts the ciphertext from Party B's round 2 message.
    /// Returns alpha as big-endian bytes in a Zeroizing wrapper.
    pub fn round2_finish(&self, ciphertext: &PaillierCiphertext) -> Zeroizing<Vec<u8>> {
        let alpha = self.sk.decrypt(&self.pk, ciphertext);
        Zeroizing::new(alpha.to_bytes_be())
    }

    /// Get a reference to A's public key (for B to use).
    pub fn public_key(&self) -> &PaillierPublicKey {
        &self.pk
    }
}

impl MtaPartyB {
    /// Create Party B with Party A's public key and secret scalar `b`.
    pub fn new(peer_pk: PaillierPublicKey, secret_b: Zeroizing<Vec<u8>>) -> Self {
        Self { peer_pk, secret_b }
    }

    /// Round 2: given Party A's encrypted `a`, compute the MtA response.
    ///
    /// Computes: `c_B = c_A^b * Enc_A(-beta') mod N^2 = Enc_A(a*b - beta')`
    /// Returns the message for Party A plus Party B's local share beta.
    pub fn round2(&self, msg: &MtaRound1) -> MtaRound2 {
        let n = self.peer_pk.n_biguint();
        let b = BigUint::from_bytes_be(&self.secret_b);

        // c_A^b = Enc_A(a * b)
        let c_ab = self.peer_pk.scalar_mult(&msg.ciphertext, &b);

        // Sample random beta' in [0, N)
        let beta_prime = sample_mod_n(&n);

        // Compute -beta' mod N = N - beta'
        let neg_beta = if beta_prime.is_zero() {
            BigUint::zero()
        } else {
            &n - &beta_prime
        };

        // Enc_A(-beta')
        let c_neg_beta = self.peer_pk.encrypt(&neg_beta);

        // c_B = c_A^b * Enc_A(-beta') = Enc_A(a*b - beta') = Enc_A(a*b + N - beta')
        let c_b = self.peer_pk.add(&c_ab, &c_neg_beta);

        MtaRound2 {
            ciphertext: c_b,
            beta: Zeroizing::new(beta_prime.to_bytes_be()),
        }
    }
}

/// Sample a random value in [0, N).
fn sample_mod_n(n: &BigUint) -> BigUint {
    let byte_len = (n.bits() as usize).div_ceil(8);
    let mut buf = vec![0u8; byte_len];
    loop {
        OsRng.fill_bytes(&mut buf);
        let r = BigUint::from_bytes_be(&buf) % n;
        if !r.is_zero() {
            return r;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::keygen::test_keypair;
    use std::sync::LazyLock;

    // Shared 512-bit keypair — delegates to keygen::test_keypair() (process-wide LazyLock cache).
    static TEST_KEYS: LazyLock<(PaillierPublicKey, PaillierSecretKey)> =
        LazyLock::new(test_keypair);

    /// Helper: run MtA and return (alpha, beta, n) as BigUints.
    fn run_mta(a_val: &BigUint, b_val: &BigUint) -> (BigUint, BigUint, BigUint) {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();

        let party_a = MtaPartyA::new(pk.clone(), sk.clone(), Zeroizing::new(a_val.to_bytes_be()));
        let party_b = MtaPartyB::new(pk.clone(), Zeroizing::new(b_val.to_bytes_be()));

        let round1_msg = party_a.round1();
        let round2_result = party_b.round2(&round1_msg);

        let alpha_bytes = party_a.round2_finish(&round2_result.ciphertext);
        let alpha = BigUint::from_bytes_be(&alpha_bytes);
        let beta = BigUint::from_bytes_be(&round2_result.beta);

        (alpha, beta, n)
    }

    #[test]
    fn test_mta_correctness() {
        let a = BigUint::from(42u64);
        let b = BigUint::from(17u64);
        let (alpha, beta, n) = run_mta(&a, &b);

        // alpha + beta mod N should equal a * b mod N
        let sum = (&alpha + &beta) % &n;
        let product = (&a * &b) % &n;
        assert_eq!(sum, product, "alpha + beta must equal a * b mod N");
    }

    #[test]
    fn test_mta_different_values() {
        let test_cases: Vec<(u64, u64)> =
            vec![(1, 1), (100, 200), (7, 13), (999, 1001), (65537, 257)];

        for (a_val, b_val) in test_cases {
            let a = BigUint::from(a_val);
            let b = BigUint::from(b_val);
            let (alpha, beta, n) = run_mta(&a, &b);

            let sum = (&alpha + &beta) % &n;
            let product = (&a * &b) % &n;
            assert_eq!(
                sum, product,
                "MtA failed for a={}, b={}: alpha+beta={} != a*b={}",
                a_val, b_val, sum, product
            );
        }
    }

    #[test]
    fn test_mta_zero_input() {
        let a = BigUint::zero();
        let b = BigUint::from(42u64);
        let (alpha, beta, n) = run_mta(&a, &b);

        // a=0 means a*b=0, so alpha + beta = 0 mod N
        let sum = (&alpha + &beta) % &n;
        assert_eq!(sum, BigUint::zero(), "0 * b must give alpha + beta = 0");
    }

    #[test]
    fn test_mta_large_values() {
        // Use 256-bit values (secp256k1 scalar size)
        let (pk, _) = &*TEST_KEYS;
        let n = pk.n_biguint();

        // Generate large random values < N
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut a_bytes);
        OsRng.fill_bytes(&mut b_bytes);

        let a = BigUint::from_bytes_be(&a_bytes) % &n;
        let b = BigUint::from_bytes_be(&b_bytes) % &n;

        let (alpha, beta, n) = run_mta(&a, &b);
        let sum = (&alpha + &beta) % &n;
        let product = (&a * &b) % &n;
        assert_eq!(sum, product, "MtA must work with 256-bit scalars");
    }

    #[test]
    fn test_mta_shares_are_secret() {
        let a = BigUint::from(42u64);
        let b = BigUint::from(17u64);
        let (alpha, beta, n) = run_mta(&a, &b);

        // Neither alpha nor beta alone should equal a, b, or a*b
        let product = (&a * &b) % &n;
        assert_ne!(alpha, a, "alpha must not reveal a");
        assert_ne!(alpha, b, "alpha must not reveal b");
        assert_ne!(alpha, product, "alpha must not reveal a*b");
        assert_ne!(beta, a, "beta must not reveal a");
        assert_ne!(beta, b, "beta must not reveal b");
        assert_ne!(beta, product, "beta must not reveal a*b");
    }
}
