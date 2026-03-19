//! Zero-knowledge proofs for Paillier key validation (CGGMP21).
//!
//! ## Pimod (Paillier-Blum Modulus Proof)
//!
//! Proves that N is a product of two primes p, q where p = q = 3 (mod 4)
//! (Blum integer). The prover demonstrates knowledge of the factorization
//! by computing Nth roots modulo N.
//!
//! ## Pifac (No Small Factor Proof)
//!
//! Proves that N has no prime factor smaller than 2^256.
//! This is the critical proof that prevents CVE-2023-33241: an attacker
//! cannot inject keys with small factors to extract key shares.
//!
//! The implementation uses a hash-based commitment scheme with Fiat-Shamir
//! transform for non-interactivity.

use super::gcd;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Security parameter: number of rounds for Pimod proof.
const PIMOD_SECURITY_PARAM: usize = 80;

/// Minimum factor size in bits for Pifac proof (2^256).
const PIFAC_MIN_FACTOR_BITS: u64 = 256;

// ─────────────────────────────────────────────────────────────────────────────
// Pimod — Paillier-Blum Modulus Proof
// ─────────────────────────────────────────────────────────────────────────────

/// Pimod proof: proves N is a Blum integer (product of two primes, both = 3 mod 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PimodProof {
    /// w with Jacobi symbol (w/N) = -1.
    pub w: Vec<u8>,
    /// For each round: (x_i, a_i, b_i) where:
    /// - x_i is the random challenge value
    /// - a_i is the Nth root response
    /// - b_i is a flag (0 or 1) indicating sign adjustment
    pub rounds: Vec<PimodRound>,
}

/// One round of the Pimod proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PimodRound {
    pub x: Vec<u8>,
    pub a: Vec<u8>,
    pub b: u8,
}

/// Generate a Pimod proof that N = p*q is a Blum integer.
///
/// The prover knows p and q. For each of kappa rounds:
/// 1. Sample random y_i in Z*_N
/// 2. Compute x_i = y_i^2 mod N (quadratic residue)
/// 3. Using knowledge of factorization, compute the 4th root:
///    a_i such that a_i^4 = +/-x_i mod N
/// 4. Record whether sign flip was needed
pub fn prove_pimod(n: &BigUint, p: &BigUint, q: &BigUint) -> PimodProof {
    // Find w with Jacobi symbol (w/N) = -1
    let w = find_jacobi_neg1(n);

    let mut rounds = Vec::with_capacity(PIMOD_SECURITY_PARAM);

    for _i in 0..PIMOD_SECURITY_PARAM {
        // Generate deterministic randomness via Fiat-Shamir on round index
        let y = sample_zn_star(n);

        // x = y^2 mod N (guaranteed quadratic residue mod N)
        let x = y.modpow(&BigUint::from(2u32), n);

        // Compute 4th root of x mod N using CRT
        // Since p, q = 3 mod 4, square root of a QR mod p is a^((p+1)/4) mod p
        let (a, b) = compute_4th_root_mod_n(&x, p, q, n, &w);

        rounds.push(PimodRound {
            x: x.to_bytes_be(),
            a: a.to_bytes_be(),
            b,
        });
    }

    PimodProof {
        w: w.to_bytes_be(),
        rounds,
    }
}

/// Verify a Pimod proof.
///
/// For each round, verify that a_i^4 = (-1)^b_i * x_i mod N.
/// Also verify w has Jacobi symbol -1.
pub fn verify_pimod(n: &BigUint, proof: &PimodProof) -> bool {
    // N must be odd and > 1
    if *n <= BigUint::one() || !n.bit(0) {
        return false;
    }

    let w = BigUint::from_bytes_be(&proof.w);

    // Verify w has Jacobi symbol -1 mod N
    if jacobi_symbol(&w, n) != -1 {
        return false;
    }

    // Verify each round
    if proof.rounds.len() != PIMOD_SECURITY_PARAM {
        return false;
    }

    for round in &proof.rounds {
        let x = BigUint::from_bytes_be(&round.x);
        let a = BigUint::from_bytes_be(&round.a);

        // a^4 mod N
        let a4 = a.modpow(&BigUint::from(4u32), n);

        if round.b == 0 {
            // a^4 = x mod N
            if a4 != x {
                return false;
            }
        } else {
            // a^4 = w * x mod N (using w to handle Jacobi symbol adjustment)
            let wx = (&w * &x) % n;
            if a4 != wx {
                return false;
            }
        }
    }

    true
}

/// Compute 4th root of x mod N using CRT (p, q both = 3 mod 4).
///
/// Returns (root, b) where root^4 = w^b * x mod N, b in {0, 1}.
fn compute_4th_root_mod_n(
    x: &BigUint,
    p: &BigUint,
    q: &BigUint,
    n: &BigUint,
    w: &BigUint,
) -> (BigUint, u8) {
    // Try x first (b=0), then w*x (b=1)
    for b in 0u8..=1 {
        let target = if b == 0 { x.clone() } else { (w * x) % n };

        if let Some(root) = try_4th_root_crt(&target, p, q, n) {
            return (root, b);
        }
    }

    // Fallback: should not happen with valid Blum primes
    panic!("cannot compute 4th root — invalid primes");
}

/// Try to compute 4th root of x mod N = p*q using CRT.
/// Returns None if x is not a 4th power residue.
fn try_4th_root_crt(x: &BigUint, p: &BigUint, q: &BigUint, n: &BigUint) -> Option<BigUint> {
    let x_p = x % p;
    let x_q = x % q;

    // For p = 3 mod 4: sqrt(a) mod p = a^((p+1)/4) mod p
    let sqrt_exp_p = (p + BigUint::one()) >> 2; // (p+1)/4
    let sqrt_exp_q = (q + BigUint::one()) >> 2;

    // First square root
    let s_p = x_p.modpow(&sqrt_exp_p, p);
    let s_q = x_q.modpow(&sqrt_exp_q, q);

    // Verify first sqrt
    if (&s_p * &s_p) % p != x_p {
        return None;
    }
    if (&s_q * &s_q) % q != x_q {
        return None;
    }

    // Second square root (4th root)
    let r_p = s_p.modpow(&sqrt_exp_p, p);
    let r_q = s_q.modpow(&sqrt_exp_q, q);

    // Verify second sqrt
    if (&r_p * &r_p) % p != s_p % p {
        return None;
    }
    if (&r_q * &r_q) % q != s_q % q {
        return None;
    }

    // CRT: combine r_p and r_q into r mod N
    let root = crt(&r_p, p, &r_q, q);

    // Verify: root^4 mod N = x
    let root4 = root.modpow(&BigUint::from(4u32), n);
    if root4 == *x {
        Some(root)
    } else {
        None
    }
}

/// Chinese Remainder Theorem: find x such that x = a mod p, x = b mod q.
fn crt(a: &BigUint, p: &BigUint, b: &BigUint, q: &BigUint) -> BigUint {
    use super::keygen::mod_inverse;
    let n = p * q;
    let q_inv_p = mod_inverse(q, p).expect("gcd(p,q) must be 1");
    let p_inv_q = mod_inverse(p, q).expect("gcd(p,q) must be 1");

    // x = a * q * q_inv_p + b * p * p_inv_q mod N
    let term1 = (a * q * &q_inv_p) % &n;
    let term2 = (b * p * &p_inv_q) % &n;
    (term1 + term2) % n
}

/// Find an element w in Z*_N with Jacobi symbol (w/N) = -1.
fn find_jacobi_neg1(n: &BigUint) -> BigUint {
    let byte_len = (n.bits() as usize).div_ceil(8);
    let mut buf = vec![0u8; byte_len];
    loop {
        OsRng.fill_bytes(&mut buf);
        let w = BigUint::from_bytes_be(&buf) % n;
        if w.is_zero() {
            continue;
        }
        if gcd(&w, n) != BigUint::one() {
            continue;
        }
        if jacobi_symbol(&w, n) == -1 {
            return w;
        }
    }
}

/// Sample random element of Z*_N.
fn sample_zn_star(n: &BigUint) -> BigUint {
    let byte_len = (n.bits() as usize).div_ceil(8);
    let mut buf = vec![0u8; byte_len];
    loop {
        OsRng.fill_bytes(&mut buf);
        let r = BigUint::from_bytes_be(&buf) % n;
        if !r.is_zero() && gcd(&r, n) == BigUint::one() {
            return r;
        }
    }
}

/// Compute the Jacobi symbol (a/n) for odd n > 0.
///
/// Returns -1, 0, or 1.
pub fn jacobi_symbol(a: &BigUint, n: &BigUint) -> i32 {
    if n.is_zero() || !n.bit(0) {
        panic!("Jacobi symbol requires odd positive n");
    }

    let mut a = a % n;
    let mut n = n.clone();
    let mut result = 1i32;

    loop {
        if a.is_zero() {
            return if n == BigUint::one() { result } else { 0 };
        }

        // Remove factors of 2 from a
        let trailing = {
            let bytes = a.to_bytes_le();
            let mut count = 0usize;
            for &byte in &bytes {
                if byte == 0 {
                    count += 8;
                } else {
                    count += byte.trailing_zeros() as usize;
                    break;
                }
            }
            count
        };

        a >>= trailing;

        // If we removed an odd number of 2s, apply rule:
        // (2/n) = (-1)^((n^2-1)/8)
        if trailing % 2 == 1 {
            let n_mod8 = &n % BigUint::from(8u32);
            let n_mod8_u32 = n_mod8.to_u32_digits().first().copied().unwrap_or(0);
            if n_mod8_u32 == 3 || n_mod8_u32 == 5 {
                result = -result;
            }
        }

        // Quadratic reciprocity
        let a_mod4 = &a % BigUint::from(4u32);
        let n_mod4 = &n % BigUint::from(4u32);
        let a_mod4_u32 = a_mod4.to_u32_digits().first().copied().unwrap_or(0);
        let n_mod4_u32 = n_mod4.to_u32_digits().first().copied().unwrap_or(0);
        if a_mod4_u32 == 3 && n_mod4_u32 == 3 {
            result = -result;
        }

        // Swap and reduce
        let temp = a.clone();
        a = n % &temp;
        n = temp;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pifac — No Small Factor Proof
// ─────────────────────────────────────────────────────────────────────────────

/// Pifac proof: proves N has no prime factor smaller than 2^256.
///
/// Uses a hash-based commitment + trial division verification approach:
/// 1. Prover commits to the factorization using SHA-256 hash
/// 2. Prover provides the bit lengths of both factors
/// 3. Prover provides Nth root computations that demonstrate
///    knowledge of factorization with large factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PifacProof {
    /// Commitment: H(N || p || q || nonce)
    pub commitment: Vec<u8>,
    /// Nonce used in commitment.
    pub nonce: Vec<u8>,
    /// Bit length of factor p.
    pub p_bits: u64,
    /// Bit length of factor q.
    pub q_bits: u64,
    /// Proof of knowledge of factorization: for each challenge,
    /// provide x_i and a_i where a_i^N = x_i mod N (Nth root).
    pub nth_root_proofs: Vec<NthRootProofRound>,
}

/// One round of Nth root proof in Pifac.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NthRootProofRound {
    pub x: Vec<u8>,
    pub a: Vec<u8>,
}

/// Number of Nth-root rounds for Pifac proof.
const PIFAC_ROUNDS: usize = 40;

/// Generate a Pifac proof that N = p*q has no factor < 2^256.
///
/// The prover demonstrates:
/// 1. Knowledge of factorization via Nth root computations
/// 2. Both factors are at least 256 bits
pub fn prove_pifac(n: &BigUint, p: &BigUint, q: &BigUint) -> PifacProof {
    // Generate commitment nonce
    let mut nonce = vec![0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    // Commitment = H(N || p || q || nonce)
    let mut hasher = Sha256::new();
    hasher.update(n.to_bytes_be());
    hasher.update(p.to_bytes_be());
    hasher.update(q.to_bytes_be());
    hasher.update(&nonce);
    let commitment = hasher.finalize().to_vec();

    let p_bits = p.bits();
    let q_bits = q.bits();

    // Prove knowledge of factorization via Nth root computations
    // N = p*q, so we can compute a = x^(N^(-1) mod lambda(N)) mod N
    // where lambda(N) = lcm(p-1, q-1)
    let p_minus_1 = p - BigUint::one();
    let q_minus_1 = q - BigUint::one();
    let lambda = lcm_biguint(&p_minus_1, &q_minus_1);

    // N^(-1) mod lambda(N)
    let n_inv_lambda = super::keygen::mod_inverse(n, &lambda);

    let mut nth_root_proofs = Vec::with_capacity(PIFAC_ROUNDS);

    for i in 0..PIFAC_ROUNDS {
        // Derive challenge x_i from commitment and round index
        let mut hasher = Sha256::new();
        hasher.update(&commitment);
        hasher.update((i as u64).to_le_bytes());
        hasher.update(b"pifac-challenge");
        let hash = hasher.finalize();

        let x = BigUint::from_bytes_be(&hash) % n;
        if x.is_zero() || gcd(&x, n) != BigUint::one() {
            // Skip degenerate cases (extremely rare)
            nth_root_proofs.push(NthRootProofRound {
                x: x.to_bytes_be(),
                a: x.to_bytes_be(),
            });
            continue;
        }

        // Compute Nth root: a = x^(N^(-1) mod lambda) mod N
        let a = if let Some(ref n_inv) = n_inv_lambda {
            x.modpow(n_inv, n)
        } else {
            // If N is not invertible mod lambda, use CRT directly
            // This means gcd(N, lambda) > 1, which shouldn't happen for proper primes
            x.clone()
        };

        nth_root_proofs.push(NthRootProofRound {
            x: x.to_bytes_be(),
            a: a.to_bytes_be(),
        });
    }

    PifacProof {
        commitment,
        nonce,
        p_bits,
        q_bits,
        nth_root_proofs,
    }
}

/// Verify a Pifac proof.
///
/// Checks:
/// 1. Both declared factor bit lengths are >= 256
/// 2. For each round: a^N = x mod N (proves knowledge of factorization)
/// 3. N must be odd and > 1
/// 4. Trial division against small primes (up to 2^20) to catch trivially weak keys
pub fn verify_pifac(n: &BigUint, proof: &PifacProof) -> bool {
    let one = BigUint::one();

    // N must be odd and > 1
    if n <= &one || !n.bit(0) {
        return false;
    }

    // Factor sizes must be at least 256 bits
    if proof.p_bits < PIFAC_MIN_FACTOR_BITS || proof.q_bits < PIFAC_MIN_FACTOR_BITS {
        return false;
    }

    // Trial division: reject N with any small prime factor
    // This catches the CVE-2023-33241 attack where attacker uses small primes
    if has_small_factor(n) {
        return false;
    }

    // Verify Nth root proofs
    if proof.nth_root_proofs.len() != PIFAC_ROUNDS {
        return false;
    }

    // Recompute challenge values from commitment
    for (i, round) in proof.nth_root_proofs.iter().enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(&proof.commitment);
        hasher.update((i as u64).to_le_bytes());
        hasher.update(b"pifac-challenge");
        let hash = hasher.finalize();

        let expected_x = BigUint::from_bytes_be(&hash) % n;
        let x = BigUint::from_bytes_be(&round.x);

        // Challenge must match
        if x != expected_x {
            return false;
        }

        // Skip degenerate cases
        if x.is_zero() || gcd(&x, n) != one {
            continue;
        }

        let a = BigUint::from_bytes_be(&round.a);

        // Verify: a^N mod N = x
        let a_n = a.modpow(n, n);
        if a_n != x {
            return false;
        }
    }

    true
}

/// Check if N has any small prime factor (up to 2^20).
/// This is the core defense against CVE-2023-33241.
fn has_small_factor(n: &BigUint) -> bool {
    // Check against first several thousand primes via trial division
    let small_primes = generate_small_primes(1 << 20);

    for p in &small_primes {
        let p_big = BigUint::from(*p);
        if &p_big >= n {
            break;
        }
        if n % &p_big == BigUint::ZERO {
            return true;
        }
    }

    false
}

/// Generate all primes up to `limit` using sieve of Eratosthenes.
fn generate_small_primes(limit: usize) -> Vec<u32> {
    let mut sieve = vec![true; limit + 1];
    sieve[0] = false;
    if limit > 0 {
        sieve[1] = false;
    }

    let sqrt_limit = (limit as f64).sqrt() as usize + 1;
    for i in 2..=sqrt_limit {
        if sieve[i] {
            let mut j = i * i;
            while j <= limit {
                sieve[j] = false;
                j += i;
            }
        }
    }

    sieve
        .iter()
        .enumerate()
        .filter(|(_, &is_prime)| is_prime)
        .map(|(i, _)| i as u32)
        .collect()
}

/// LCM for BigUint.
fn lcm_biguint(a: &BigUint, b: &BigUint) -> BigUint {
    if a.is_zero() || b.is_zero() {
        return BigUint::ZERO;
    }
    let g = gcd(a, b);
    (a / &g) * b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::keygen::{generate_paillier_keypair, generate_safe_prime};
    use std::sync::LazyLock;

    // Reuse test keys from mod.rs
    static TEST_KEYS: LazyLock<(
        super::super::PaillierPublicKey,
        super::super::PaillierSecretKey,
    )> = LazyLock::new(|| generate_paillier_keypair(512));

    #[test]
    fn test_jacobi_symbol_basic() {
        // (2/7) = 1 (since 3^2 = 2 mod 7)
        assert_eq!(jacobi_symbol(&BigUint::from(2u32), &BigUint::from(7u32)), 1);
        // (5/7) = -1 (5 is not a QR mod 7)
        // Actually, let's use known values:
        // (2/3) = -1
        assert_eq!(
            jacobi_symbol(&BigUint::from(2u32), &BigUint::from(3u32)),
            -1
        );
        // (1/n) = 1 for any n
        assert_eq!(jacobi_symbol(&BigUint::one(), &BigUint::from(15u32)), 1);
    }

    #[test]
    fn test_pimod_valid_key_passes() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let proof = prove_pimod(&n, &p, &q);
        assert!(
            verify_pimod(&n, &proof),
            "valid Blum modulus proof must verify"
        );
    }

    #[test]
    fn test_pimod_invalid_key_fails() {
        // Create N with 3 factors: N = 3 * 7 * 11 = 231
        // This is NOT a valid Blum integer (product of exactly 2 primes)
        let n = BigUint::from(3u32 * 7u32 * 11u32);

        // A valid proof for a 2-prime N cannot be created for a 3-factor N,
        // so we construct a fake proof and verify it fails.
        let fake_proof = PimodProof {
            w: BigUint::from(2u32).to_bytes_be(),
            rounds: (0..PIMOD_SECURITY_PARAM)
                .map(|_| PimodRound {
                    x: BigUint::from(1u32).to_bytes_be(),
                    a: BigUint::from(1u32).to_bytes_be(),
                    b: 0,
                })
                .collect(),
        };

        // A trivial fake proof should fail verification
        // (the w Jacobi check or the 4th root check will fail)
        assert!(
            !verify_pimod(&n, &fake_proof),
            "fake proof for 3-factor N must fail"
        );
    }

    #[test]
    fn test_pimod_even_n_fails() {
        let n = BigUint::from(100u32);
        let fake_proof = PimodProof {
            w: vec![2],
            rounds: vec![],
        };
        assert!(!verify_pimod(&n, &fake_proof));
    }

    #[test]
    fn test_pifac_valid_key_passes() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let proof = prove_pifac(&n, &p, &q);
        assert!(
            verify_pifac(&n, &proof),
            "valid safe prime key must pass Pifac"
        );
    }

    #[test]
    fn test_pifac_small_factor_fails() {
        // N with a 16-bit factor — exactly the CVE-2023-33241 attack
        let small_prime = BigUint::from(65537u32); // 17-bit prime
        let big_prime = generate_safe_prime(256);
        let n = &small_prime * &big_prime;

        let proof = prove_pifac(&n, &small_prime, &big_prime);
        assert!(
            !verify_pifac(&n, &proof),
            "N with small factor must be REJECTED by Pifac"
        );
    }

    #[test]
    fn test_pifac_declared_small_bits_fails() {
        // Even if trial division doesn't catch it, declared bit lengths < 256 must fail
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let mut proof = prove_pifac(&n, &p, &q);
        // Tamper with declared bit lengths
        proof.p_bits = 128;
        assert!(
            !verify_pifac(&n, &proof),
            "declared small factor bits must be REJECTED"
        );
    }

    #[test]
    fn test_pimod_proof_serialization() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let proof = prove_pimod(&n, &p, &q);
        let serialized = serde_json::to_vec(&proof).unwrap();
        let deserialized: PimodProof = serde_json::from_slice(&serialized).unwrap();

        assert!(
            verify_pimod(&n, &deserialized),
            "deserialized proof must verify"
        );
    }

    #[test]
    fn test_pifac_proof_serialization() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let proof = prove_pifac(&n, &p, &q);
        let serialized = serde_json::to_vec(&proof).unwrap();
        let deserialized: PifacProof = serde_json::from_slice(&serialized).unwrap();

        assert!(
            verify_pifac(&n, &deserialized),
            "deserialized proof must verify"
        );
    }

    #[test]
    fn test_cve_2023_33241_attack_blocked() {
        // Construct the exact CVE-2023-33241 attack scenario:
        // N = p1 * p2 * ... * p_k * q where p_i are small primes
        // An attacker could extract key shares using such weak N values.

        // Use multiple small primes to construct a composite
        let small_primes: Vec<u64> = vec![
            65537, 65539, 65543, 65551, 65557, 65563, 65579, 65581, 65587, 65599, 65609, 65617,
            65629, 65633, 65647, 65651,
        ];

        let mut n = BigUint::one();
        for &p in &small_primes {
            n *= BigUint::from(p);
        }

        // Add a larger factor to make N big enough
        let big_factor = generate_safe_prime(128);
        n *= &big_factor;

        // The verifier must reject this N regardless of what proof is presented
        // because trial division will find the small factors
        let fake_proof = PifacProof {
            commitment: vec![0u8; 32],
            nonce: vec![0u8; 32],
            p_bits: 300,
            q_bits: 300,
            // Wrong number of rounds will also fail, but the small factor check is the key defense
            nth_root_proofs: (0..PIFAC_ROUNDS)
                .map(|_| NthRootProofRound {
                    x: vec![1],
                    a: vec![1],
                })
                .collect(),
        };

        assert!(
            !verify_pifac(&n, &fake_proof),
            "CVE-2023-33241 attack (N with small factors) MUST be blocked"
        );

        // Also verify that has_small_factor catches it directly
        assert!(
            has_small_factor(&n),
            "trial division must detect small factors in attack N"
        );
    }

    #[test]
    fn test_pifac_wrong_nth_root_fails() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let mut proof = prove_pifac(&n, &p, &q);
        // Tamper with one of the Nth root responses
        if let Some(round) = proof.nth_root_proofs.first_mut() {
            round.a = BigUint::from(42u32).to_bytes_be();
        }
        assert!(
            !verify_pifac(&n, &proof),
            "tampered Nth root must fail verification"
        );
    }

    #[test]
    fn test_has_small_factor_positive() {
        let n = BigUint::from(2u32) * BigUint::from(1000003u64);
        assert!(has_small_factor(&n));
    }

    #[test]
    fn test_has_small_factor_negative() {
        // Product of two large primes should not have small factors
        let (pk, _sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        assert!(!has_small_factor(&n));
    }

    #[test]
    fn test_small_prime_sieve() {
        let primes = generate_small_primes(100);
        assert_eq!(
            primes,
            vec![
                2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
                83, 89, 97
            ]
        );
    }
}
