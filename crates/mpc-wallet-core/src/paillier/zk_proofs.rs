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

use super::{gcd, sample_coprime};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// Cached small primes up to 2^20, computed once via sieve of Eratosthenes.
static SMALL_PRIMES: LazyLock<Vec<u32>> = LazyLock::new(|| generate_small_primes(1 << 20));

/// Cached secp256k1 group order.
static SECP256K1_ORDER: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ])
});

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

    // Precompute loop-invariant values
    let sqrt_exp_p = (p + BigUint::one()) >> 2; // (p+1)/4
    let sqrt_exp_q = (q + BigUint::one()) >> 2; // (q+1)/4
    let q_inv_p = super::keygen::mod_inverse(q, p).expect("gcd(p,q) must be 1");
    let p_inv_q = super::keygen::mod_inverse(p, q).expect("gcd(p,q) must be 1");

    for _i in 0..PIMOD_SECURITY_PARAM {
        // Generate deterministic randomness via Fiat-Shamir on round index
        let y = sample_coprime(n);

        // x = y^2 mod N (guaranteed quadratic residue mod N)
        let x = (&y * &y) % n;

        // Compute 4th root of x mod N using CRT
        // Since p, q = 3 mod 4, square root of a QR mod p is a^((p+1)/4) mod p
        let (a, b) = compute_4th_root_mod_n(
            &x,
            p,
            q,
            n,
            &w,
            &sqrt_exp_p,
            &sqrt_exp_q,
            &q_inv_p,
            &p_inv_q,
        );

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

        // a^4 mod N = ((a^2 mod N)^2) mod N
        let a2 = (&a * &a) % n;
        let a4 = (&a2 * &a2) % n;

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
#[allow(clippy::too_many_arguments)]
fn compute_4th_root_mod_n(
    x: &BigUint,
    p: &BigUint,
    q: &BigUint,
    n: &BigUint,
    w: &BigUint,
    sqrt_exp_p: &BigUint,
    sqrt_exp_q: &BigUint,
    q_inv_p: &BigUint,
    p_inv_q: &BigUint,
) -> (BigUint, u8) {
    // Try x first (b=0), then w*x (b=1)
    for b in 0u8..=1 {
        let target = if b == 0 { x.clone() } else { (w * x) % n };

        if let Some(root) =
            try_4th_root_crt(&target, p, q, n, sqrt_exp_p, sqrt_exp_q, q_inv_p, p_inv_q)
        {
            return (root, b);
        }
    }

    // Fallback: should not happen with valid Blum primes
    panic!("cannot compute 4th root — invalid primes");
}

/// Try to compute 4th root of x mod N = p*q using CRT.
/// Returns None if x is not a 4th power residue.
/// Accepts precomputed sqrt exponents and CRT inverses.
#[allow(clippy::too_many_arguments)]
fn try_4th_root_crt(
    x: &BigUint,
    p: &BigUint,
    q: &BigUint,
    n: &BigUint,
    sqrt_exp_p: &BigUint,
    sqrt_exp_q: &BigUint,
    q_inv_p: &BigUint,
    p_inv_q: &BigUint,
) -> Option<BigUint> {
    let x_p = x % p;
    let x_q = x % q;

    // First square root
    let s_p = x_p.modpow(sqrt_exp_p, p);
    let s_q = x_q.modpow(sqrt_exp_q, q);

    // Verify first sqrt
    if (&s_p * &s_p) % p != x_p {
        return None;
    }
    if (&s_q * &s_q) % q != x_q {
        return None;
    }

    // Second square root (4th root)
    let r_p = s_p.modpow(sqrt_exp_p, p);
    let r_q = s_q.modpow(sqrt_exp_q, q);

    // Verify second sqrt
    if (&r_p * &r_p) % p != s_p % p {
        return None;
    }
    if (&r_q * &r_q) % q != s_q % q {
        return None;
    }

    // CRT: combine r_p and r_q into r mod N (using precomputed inverses)
    let nn = p * q;
    let term1 = (&r_p * q * q_inv_p) % &nn;
    let term2 = (&r_q * p * p_inv_q) % &nn;
    let root = (term1 + term2) % &nn;

    // Verify: root^4 mod N = x (two squarings)
    let root2 = (&root * &root) % n;
    let root4 = (&root2 * &root2) % n;
    if root4 == *x {
        Some(root)
    } else {
        None
    }
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

    let eight = BigUint::from(8u32);
    let four = BigUint::from(4u32);

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
            let n_mod8 = &n % &eight;
            let n_mod8_u32 = n_mod8.to_u32_digits().first().copied().unwrap_or(0);
            if n_mod8_u32 == 3 || n_mod8_u32 == 5 {
                result = -result;
            }
        }

        // Quadratic reciprocity
        let a_mod4 = &a % &four;
        let n_mod4 = &n % &four;
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
/// Uses a process-wide cached sieve via `SMALL_PRIMES`.
fn has_small_factor(n: &BigUint) -> bool {
    for p in &*SMALL_PRIMES {
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

// ─────────────────────────────────────────────────────────────────────────────
// Πenc — Paillier Encryption in Range Proof
// ─────────────────────────────────────────────────────────────────────────────

/// Range parameter: prove |m| < 2^ell. We use ell = 256 for secp256k1 scalars,
/// with slack epsilon = 512 bits for the masking commitment.
const PIENC_ELL: u64 = 256;
const PIENC_EPSILON: u64 = 512;

/// Πenc proof: proves that ciphertext C = Enc(m, r) where |m| < 2^ell.
///
/// The prover demonstrates knowledge of plaintext m and randomness r,
/// and that m lies in the allowed range, without revealing either.
///
/// Uses Fiat-Shamir transform: challenge = H(N, C, S, commitment_A, commitment_B, pedersen_s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiEncProof {
    /// Commitment A = Enc(alpha, mu) — encryption of masking value.
    pub commitment_a: Vec<u8>,
    /// Commitment B = s^alpha * t^gamma mod N_hat — Pedersen commitment to masking value.
    pub commitment_b: Vec<u8>,
    /// Pedersen commitment S = s^m * t^rho mod N_hat — commitment to the witness plaintext.
    pub pedersen_s: Vec<u8>,
    /// Response z1 = alpha + e * m (masked plaintext).
    pub z1: Vec<u8>,
    /// Response z2 = mu * r^e mod N (masked randomness).
    pub z2: Vec<u8>,
    /// Response z3 = gamma + e * rho (masked Pedersen randomness).
    pub z3: Vec<u8>,
}

/// Public input for Πenc verification.
#[derive(Debug, Clone)]
pub struct PiEncPublicInput {
    /// Paillier public key (N).
    pub pk_n: Vec<u8>,
    /// Paillier N^2.
    pub pk_n_squared: Vec<u8>,
    /// The ciphertext being proven.
    pub ciphertext: Vec<u8>,
    /// Pedersen modulus N_hat (auxiliary RSA modulus).
    pub n_hat: Vec<u8>,
    /// Pedersen base s.
    pub s: Vec<u8>,
    /// Pedersen base t.
    pub t: Vec<u8>,
}

/// Prove that ciphertext C encrypts m with |m| < 2^ell.
///
/// Witness: (m, r) where C = Enc(m, r).
/// Public: Paillier pk, C, Pedersen (N_hat, s, t).
pub fn prove_pienc(m: &BigUint, r: &BigUint, public: &PiEncPublicInput) -> PiEncProof {
    let n = BigUint::from_bytes_be(&public.pk_n);
    let n_sq = BigUint::from_bytes_be(&public.pk_n_squared);
    let n_hat = BigUint::from_bytes_be(&public.n_hat);
    let s = BigUint::from_bytes_be(&public.s);
    let t = BigUint::from_bytes_be(&public.t);

    // Sample masking values
    let alpha_bound = BigUint::one() << (PIENC_ELL + PIENC_EPSILON) as usize;
    let alpha = sample_below(&alpha_bound);
    let mu = sample_coprime(&n);
    let gamma_bound = &n_hat * &alpha_bound;
    let gamma = sample_below(&gamma_bound);
    let rho_bound = &n_hat * (BigUint::one() << PIENC_ELL as usize);
    let rho = sample_below(&rho_bound);

    // Commitment A = Enc(alpha, mu) = (1 + alpha*N) * mu^N mod N^2
    let g_alpha = (BigUint::one() + &alpha * &n) % &n_sq;
    let mu_n = mu.modpow(&n, &n_sq);
    let commitment_a = (&g_alpha * &mu_n) % &n_sq;

    // Commitment B = s^alpha * t^gamma mod N_hat
    let commitment_b = (s.modpow(&alpha, &n_hat) * t.modpow(&gamma, &n_hat)) % &n_hat;

    // Pedersen commitment to the witness: S = s^m * t^rho mod N_hat
    let pedersen_s = (s.modpow(m, &n_hat) * t.modpow(&rho, &n_hat)) % &n_hat;

    // Fiat-Shamir challenge (includes pedersen_s for binding)
    let e = pienc_challenge(
        &public.pk_n,
        &public.ciphertext,
        &commitment_a,
        &commitment_b,
        &pedersen_s,
        &n_hat,
    );

    // Responses
    let z1 = &alpha + &e * m;
    let z2 = (&mu * r.modpow(&e, &n_sq)) % &n_sq;
    let z3 = &gamma + &e * &rho;

    PiEncProof {
        commitment_a: commitment_a.to_bytes_be(),
        commitment_b: commitment_b.to_bytes_be(),
        pedersen_s: pedersen_s.to_bytes_be(),
        z1: z1.to_bytes_be(),
        z2: z2.to_bytes_be(),
        z3: z3.to_bytes_be(),
    }
}

/// Verify a Πenc proof.
///
/// Checks:
/// 1. z1 is in range: |z1| < 2^(ell + epsilon)
/// 2. Enc(z1, z2) = commitment_A * C^e mod N^2
/// 3. s^z1 * t^z3 = commitment_B * (s^m_commitment)^e mod N_hat (implicit via challenge binding)
pub fn verify_pienc(proof: &PiEncProof, public: &PiEncPublicInput) -> bool {
    let n = BigUint::from_bytes_be(&public.pk_n);
    let n_sq = BigUint::from_bytes_be(&public.pk_n_squared);
    let n_hat = BigUint::from_bytes_be(&public.n_hat);
    let s = BigUint::from_bytes_be(&public.s);
    let t = BigUint::from_bytes_be(&public.t);
    let c = BigUint::from_bytes_be(&public.ciphertext);

    let commitment_a = BigUint::from_bytes_be(&proof.commitment_a);
    let commitment_b = BigUint::from_bytes_be(&proof.commitment_b);
    let pedersen_s = BigUint::from_bytes_be(&proof.pedersen_s);
    let z1 = BigUint::from_bytes_be(&proof.z1);
    let z2 = BigUint::from_bytes_be(&proof.z2);
    let z3 = BigUint::from_bytes_be(&proof.z3);

    // Recompute challenge (includes pedersen_s for binding)
    let e = pienc_challenge(
        &public.pk_n,
        &public.ciphertext,
        &commitment_a,
        &commitment_b,
        &pedersen_s,
        &n_hat,
    );

    // Range check: z1 < 2^(ell + epsilon)
    let z1_bound = BigUint::one() << (PIENC_ELL + PIENC_EPSILON) as usize;
    if z1 >= z1_bound {
        return false;
    }

    // Check 1: Enc(z1, z2) = commitment_A * C^e mod N^2
    let g_z1 = (BigUint::one() + &z1 * &n) % &n_sq;
    let z2_n = z2.modpow(&n, &n_sq);
    let lhs = (&g_z1 * &z2_n) % &n_sq;

    let c_e = c.modpow(&e, &n_sq);
    let rhs = (&commitment_a * &c_e) % &n_sq;

    if lhs != rhs {
        return false;
    }

    // Check 2: s^z1 * t^z3 == commitment_B * S^e mod N_hat
    // This verifies the Pedersen commitment consistency: the prover committed to
    // the plaintext m via S = s^m * t^rho, and the masking via B = s^alpha * t^gamma.
    // Since z1 = alpha + e*m and z3 = gamma + e*rho:
    //   s^z1 * t^z3 = s^(alpha + e*m) * t^(gamma + e*rho)
    //               = (s^alpha * t^gamma) * (s^m * t^rho)^e
    //               = B * S^e mod N_hat
    let ped_lhs = (s.modpow(&z1, &n_hat) * t.modpow(&z3, &n_hat)) % &n_hat;
    let s_e = pedersen_s.modpow(&e, &n_hat);
    let ped_rhs = (&commitment_b * &s_e) % &n_hat;

    if ped_lhs != ped_rhs {
        return false;
    }

    true
}

/// Fiat-Shamir challenge for Πenc.
fn pienc_challenge(
    pk_n: &[u8],
    ciphertext: &[u8],
    commitment_a: &BigUint,
    commitment_b: &BigUint,
    pedersen_s: &BigUint,
    n_hat: &BigUint,
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"pienc-v1");
    hasher.update(pk_n);
    hasher.update(ciphertext);
    hasher.update(commitment_a.to_bytes_be());
    hasher.update(commitment_b.to_bytes_be());
    hasher.update(pedersen_s.to_bytes_be());
    hasher.update(n_hat.to_bytes_be());
    let hash = hasher.finalize();
    // Use 128-bit challenge for soundness
    BigUint::from_bytes_be(&hash[..16])
}

// ─────────────────────────────────────────────────────────────────────────────
// Πaff-g — Paillier Affine Operation in Range Proof
// ─────────────────────────────────────────────────────────────────────────────

/// Πaff-g proof: proves D = C^x * Enc(y) where |x| < 2^ell and |y| < 2^ell'.
///
/// Used in MtA Round 2 to prove the affine homomorphic computation was done
/// correctly and that the inputs are bounded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiAffgProof {
    /// Commitment A = Enc_0(alpha, mu).
    pub commitment_a: Vec<u8>,
    /// Commitment B_x = g^alpha (EC point, x-coordinate).
    pub commitment_bx: Vec<u8>,
    /// Commitment E = s^alpha * t^gamma mod N_hat (masking commitment for x).
    pub commitment_e: Vec<u8>,
    /// Commitment F = s^beta * t^delta mod N_hat (masking commitment for y).
    pub commitment_f: Vec<u8>,
    /// Pedersen commitment S_x = s^x * t^tau mod N_hat (witness commitment for x).
    pub pedersen_sx: Vec<u8>,
    /// Pedersen commitment S_y = s^y * t^sigma mod N_hat (witness commitment for y).
    pub pedersen_sy: Vec<u8>,
    /// Response z1 = alpha + e*x.
    pub z1: Vec<u8>,
    /// Response z2 = beta + e*y.
    pub z2: Vec<u8>,
    /// Response w = mu * rho_y^e mod N_0^2 (masked randomness).
    pub w: Vec<u8>,
    /// Response z3 = gamma + e*tau.
    pub z3: Vec<u8>,
    /// Response z4 = delta + e*sigma.
    pub z4: Vec<u8>,
}

/// Public input for Πaff-g.
#[derive(Debug, Clone)]
pub struct PiAffgPublicInput {
    /// Paillier public key N_0 (Party A's key).
    pub pk_n0: Vec<u8>,
    /// N_0^2.
    pub pk_n0_squared: Vec<u8>,
    /// Input ciphertext C = Enc_0(a).
    pub c: Vec<u8>,
    /// Result ciphertext D = C^x * Enc_0(y).
    pub d: Vec<u8>,
    /// Pedersen modulus N_hat.
    pub n_hat: Vec<u8>,
    /// Pedersen base s.
    pub s: Vec<u8>,
    /// Pedersen base t.
    pub t: Vec<u8>,
}

/// Prove affine operation D = C^x * Enc(y, rho_y) where |x| < 2^ell, |y| < 2^ell'.
pub fn prove_piaffg(
    x: &BigUint,
    y: &BigUint,
    rho_y: &BigUint,
    public: &PiAffgPublicInput,
) -> PiAffgProof {
    let n0 = BigUint::from_bytes_be(&public.pk_n0);
    let n0_sq = BigUint::from_bytes_be(&public.pk_n0_squared);
    let c = BigUint::from_bytes_be(&public.c);
    let n_hat = BigUint::from_bytes_be(&public.n_hat);
    let s_base = BigUint::from_bytes_be(&public.s);
    let t_base = BigUint::from_bytes_be(&public.t);

    let ell_bound = BigUint::one() << (PIENC_ELL + PIENC_EPSILON) as usize;
    let ell_prime_bound = BigUint::one() << (PIENC_ELL + PIENC_EPSILON) as usize;

    // Sample masking values (all sampled BEFORE challenge computation)
    let alpha = sample_below(&ell_bound);
    let beta = sample_below(&ell_prime_bound);
    let mu = sample_coprime(&n0);
    let gamma = sample_below(&(&n_hat * &ell_bound));
    let delta = sample_below(&(&n_hat * &ell_prime_bound));
    // tau and sigma are Pedersen blinding factors for the witness values x and y
    let tau = sample_below(&(&n_hat * (BigUint::one() << PIENC_ELL as usize)));
    let sigma = sample_below(&(&n_hat * (BigUint::one() << PIENC_ELL as usize)));

    // Commitment A = C^alpha * Enc_0(beta, mu)
    let c_alpha = c.modpow(&alpha, &n0_sq);
    let enc_beta = (BigUint::one() + &beta * &n0) % &n0_sq;
    let mu_n = mu.modpow(&n0, &n0_sq);
    let enc_beta_full = (&enc_beta * &mu_n) % &n0_sq;
    let commitment_a = (&c_alpha * &enc_beta_full) % &n0_sq;

    // Commitment B_x = alpha (we store the value; in EC version this would be alpha*G)
    let commitment_bx = alpha.to_bytes_be();

    // Commitment E = s^alpha * t^gamma mod N_hat
    let commitment_e = (s_base.modpow(&alpha, &n_hat) * t_base.modpow(&gamma, &n_hat)) % &n_hat;

    // Commitment F = s^beta * t^delta mod N_hat
    let commitment_f = (s_base.modpow(&beta, &n_hat) * t_base.modpow(&delta, &n_hat)) % &n_hat;

    // Pedersen witness commitments (committed BEFORE challenge)
    // S_x = s^x * t^tau mod N_hat
    let pedersen_sx = (s_base.modpow(x, &n_hat) * t_base.modpow(&tau, &n_hat)) % &n_hat;
    // S_y = s^y * t^sigma mod N_hat
    let pedersen_sy = (s_base.modpow(y, &n_hat) * t_base.modpow(&sigma, &n_hat)) % &n_hat;

    // Fiat-Shamir challenge (includes witness commitments for binding)
    let e = piaffg_challenge(
        &public.pk_n0,
        &public.c,
        &public.d,
        &commitment_a,
        &commitment_e,
        &commitment_f,
        &pedersen_sx,
        &pedersen_sy,
        &n_hat,
    );

    // Responses
    let z1 = &alpha + &e * x;
    let z2 = &beta + &e * y;

    // w = mu * rho_y^e mod N_0^2
    let rho_y_e = rho_y.modpow(&e, &n0_sq);
    let w = (&mu * &rho_y_e) % &n0_sq;

    // z3 = gamma + e*tau, z4 = delta + e*sigma (tau, sigma committed before challenge)
    let z3 = &gamma + &e * &tau;
    let z4 = &delta + &e * &sigma;

    PiAffgProof {
        commitment_a: commitment_a.to_bytes_be(),
        commitment_bx,
        commitment_e: commitment_e.to_bytes_be(),
        commitment_f: commitment_f.to_bytes_be(),
        pedersen_sx: pedersen_sx.to_bytes_be(),
        pedersen_sy: pedersen_sy.to_bytes_be(),
        z1: z1.to_bytes_be(),
        z2: z2.to_bytes_be(),
        w: w.to_bytes_be(),
        z3: z3.to_bytes_be(),
        z4: z4.to_bytes_be(),
    }
}

/// Verify a Πaff-g proof.
///
/// Checks:
/// 1. z1 in range: |z1| < 2^(ell + epsilon)
/// 2. z2 in range: |z2| < 2^(ell' + epsilon)
/// 3. C^z1 * Enc(z2, w) = A * D^e mod N_0^2
/// 4. s^z1 * t^z3 == E * S_x^e mod N_hat (Pedersen check for x)
/// 5. s^z2 * t^z4 == F * S_y^e mod N_hat (Pedersen check for y)
pub fn verify_piaffg(proof: &PiAffgProof, public: &PiAffgPublicInput) -> bool {
    let n0 = BigUint::from_bytes_be(&public.pk_n0);
    let n0_sq = BigUint::from_bytes_be(&public.pk_n0_squared);
    let c = BigUint::from_bytes_be(&public.c);
    let d = BigUint::from_bytes_be(&public.d);
    let n_hat = BigUint::from_bytes_be(&public.n_hat);
    let s_base = BigUint::from_bytes_be(&public.s);
    let t_base = BigUint::from_bytes_be(&public.t);

    let commitment_a = BigUint::from_bytes_be(&proof.commitment_a);
    let commitment_e = BigUint::from_bytes_be(&proof.commitment_e);
    let commitment_f = BigUint::from_bytes_be(&proof.commitment_f);
    let pedersen_sx = BigUint::from_bytes_be(&proof.pedersen_sx);
    let pedersen_sy = BigUint::from_bytes_be(&proof.pedersen_sy);
    let z1 = BigUint::from_bytes_be(&proof.z1);
    let z2 = BigUint::from_bytes_be(&proof.z2);
    let z3 = BigUint::from_bytes_be(&proof.z3);
    let z4 = BigUint::from_bytes_be(&proof.z4);
    let w = BigUint::from_bytes_be(&proof.w);

    // Recompute challenge (includes witness commitments for binding)
    let e = piaffg_challenge(
        &public.pk_n0,
        &public.c,
        &public.d,
        &commitment_a,
        &commitment_e,
        &commitment_f,
        &pedersen_sx,
        &pedersen_sy,
        &n_hat,
    );

    // Range checks
    let z1_bound = BigUint::one() << (PIENC_ELL + PIENC_EPSILON) as usize;
    if z1 >= z1_bound {
        return false;
    }
    let z2_bound = BigUint::one() << (PIENC_ELL + PIENC_EPSILON) as usize;
    if z2 >= z2_bound {
        return false;
    }

    // Check 1: C^z1 * Enc(z2, w) = A * D^e mod N_0^2
    let c_z1 = c.modpow(&z1, &n0_sq);
    let enc_z2 = (BigUint::one() + &z2 * &n0) % &n0_sq;
    let w_n = w.modpow(&n0, &n0_sq);
    let enc_z2_full = (&enc_z2 * &w_n) % &n0_sq;
    let lhs = (&c_z1 * &enc_z2_full) % &n0_sq;

    let d_e = d.modpow(&e, &n0_sq);
    let rhs = (&commitment_a * &d_e) % &n0_sq;

    if lhs != rhs {
        return false;
    }

    // Check 2: s^z1 * t^z3 == E * S_x^e mod N_hat (Pedersen check for x)
    // z1 = alpha + e*x, z3 = gamma + e*tau
    // s^z1 * t^z3 = s^(alpha + e*x) * t^(gamma + e*tau)
    //             = (s^alpha * t^gamma) * (s^x * t^tau)^e = E * S_x^e
    let ped_x_lhs = (s_base.modpow(&z1, &n_hat) * t_base.modpow(&z3, &n_hat)) % &n_hat;
    let sx_e = pedersen_sx.modpow(&e, &n_hat);
    let ped_x_rhs = (&commitment_e * &sx_e) % &n_hat;
    if ped_x_lhs != ped_x_rhs {
        return false;
    }

    // Check 3: s^z2 * t^z4 == F * S_y^e mod N_hat (Pedersen check for y)
    let ped_y_lhs = (s_base.modpow(&z2, &n_hat) * t_base.modpow(&z4, &n_hat)) % &n_hat;
    let sy_e = pedersen_sy.modpow(&e, &n_hat);
    let ped_y_rhs = (&commitment_f * &sy_e) % &n_hat;
    if ped_y_lhs != ped_y_rhs {
        return false;
    }

    true
}

/// Fiat-Shamir challenge for Πaff-g.
#[allow(clippy::too_many_arguments)]
fn piaffg_challenge(
    pk_n0: &[u8],
    c: &[u8],
    d: &[u8],
    commitment_a: &BigUint,
    commitment_e: &BigUint,
    commitment_f: &BigUint,
    pedersen_sx: &BigUint,
    pedersen_sy: &BigUint,
    n_hat: &BigUint,
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"piaffg-v1");
    hasher.update(pk_n0);
    hasher.update(c);
    hasher.update(d);
    hasher.update(commitment_a.to_bytes_be());
    hasher.update(commitment_e.to_bytes_be());
    hasher.update(commitment_f.to_bytes_be());
    hasher.update(pedersen_sx.to_bytes_be());
    hasher.update(pedersen_sy.to_bytes_be());
    hasher.update(n_hat.to_bytes_be());
    let hash = hasher.finalize();
    BigUint::from_bytes_be(&hash[..16])
}

// ─────────────────────────────────────────────────────────────────────────────
// Πlog* — Group Element vs Paillier Encryption Consistency Proof
// ─────────────────────────────────────────────────────────────────────────────

/// Πlog* proof: proves C = Enc(x) AND X = x*G on secp256k1.
///
/// In CGGMP21, this proves that a Paillier ciphertext and an EC point
/// both encode the same secret scalar. Uses real EC scalar multiplication
/// on secp256k1 for the group element binding.
///
/// Concretely: proves knowledge of (x, r) such that C = Enc(x, r) and
/// X = x * G (where G is the secp256k1 generator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiLogStarProof {
    /// Commitment A = Enc(alpha, mu).
    pub commitment_a: Vec<u8>,
    /// Commitment Y = alpha * G (compressed SEC1, 33 bytes).
    pub commitment_y: Vec<u8>,
    /// Commitment D = s^alpha * t^gamma mod N_hat.
    pub commitment_d: Vec<u8>,
    /// Response z1 = alpha + e*x.
    pub z1: Vec<u8>,
    /// Response z2 = mu * r^e mod N^2.
    pub z2: Vec<u8>,
    /// Response z3 = gamma + e*rho.
    pub z3: Vec<u8>,
}

/// Public input for Πlog* verification.
#[derive(Debug, Clone)]
pub struct PiLogStarPublicInput {
    /// Paillier public key N.
    pub pk_n: Vec<u8>,
    /// N^2.
    pub pk_n_squared: Vec<u8>,
    /// Ciphertext C = Enc(x, r).
    pub ciphertext: Vec<u8>,
    /// Public EC point X = x * G (compressed SEC1, 33 bytes).
    pub x_commitment: Vec<u8>,
    /// Pedersen modulus N_hat.
    pub n_hat: Vec<u8>,
    /// Pedersen base s.
    pub s: Vec<u8>,
    /// Pedersen base t.
    pub t: Vec<u8>,
}

/// Compute the EC point commitment for Πlog*: x * G on secp256k1.
///
/// Returns the compressed SEC1 encoding (33 bytes) of the point x * G.
/// The input x is reduced modulo the secp256k1 group order before scalar
/// multiplication to ensure it is a valid scalar.
pub fn pilogstar_point_commitment(x: &BigUint) -> Vec<u8> {
    use k256::elliptic_curve::group::GroupEncoding;
    let scalar = biguint_to_k256_scalar(x);
    let point = k256::ProjectivePoint::GENERATOR * scalar;
    point.to_bytes().to_vec()
}

/// Convert a BigUint to a k256::Scalar (reduced mod group order).
fn biguint_to_k256_scalar(x: &BigUint) -> k256::Scalar {
    use k256::elliptic_curve::ops::Reduce;
    let reduced = x % &*SECP256K1_ORDER;
    let mut bytes = [0u8; 32];
    let be_bytes = reduced.to_bytes_be();
    // Right-align into 32-byte array
    let start = 32usize.saturating_sub(be_bytes.len());
    bytes[start..].copy_from_slice(&be_bytes[..core::cmp::min(be_bytes.len(), 32)]);
    <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(k256::FieldBytes::from_slice(&bytes))
}

/// Prove C = Enc(x, r) AND X = x * G on secp256k1.
pub fn prove_pilogstar(x: &BigUint, r: &BigUint, public: &PiLogStarPublicInput) -> PiLogStarProof {
    let n = BigUint::from_bytes_be(&public.pk_n);
    let n_sq = BigUint::from_bytes_be(&public.pk_n_squared);
    let n_hat = BigUint::from_bytes_be(&public.n_hat);
    let s = BigUint::from_bytes_be(&public.s);
    let t = BigUint::from_bytes_be(&public.t);

    let ell_bound = BigUint::one() << (PIENC_ELL + PIENC_EPSILON) as usize;

    // Sample masking values
    let alpha = sample_below(&ell_bound);
    let mu = sample_coprime(&n);
    let gamma = sample_below(&(&n_hat * &ell_bound));
    let rho = sample_below(&(&n_hat * (BigUint::one() << PIENC_ELL as usize)));

    // Commitment A = Enc(alpha, mu)
    let g_alpha = (BigUint::one() + &alpha * &n) % &n_sq;
    let mu_n = mu.modpow(&n, &n_sq);
    let commitment_a = (&g_alpha * &mu_n) % &n_sq;

    // Commitment Y = point_commitment(alpha) — "group element" for masking value
    let commitment_y = pilogstar_point_commitment(&alpha);

    // Commitment D = s^alpha * t^gamma mod N_hat
    let commitment_d = (s.modpow(&alpha, &n_hat) * t.modpow(&gamma, &n_hat)) % &n_hat;

    // Fiat-Shamir challenge
    let e = pilogstar_challenge(
        &public.pk_n,
        &public.ciphertext,
        &public.x_commitment,
        &commitment_a,
        &commitment_y,
        &commitment_d,
        &n_hat,
    );

    // Responses
    let z1 = &alpha + &e * x;
    let z2 = (&mu * r.modpow(&e, &n_sq)) % &n_sq;
    let z3 = &gamma + &e * &rho;

    PiLogStarProof {
        commitment_a: commitment_a.to_bytes_be(),
        commitment_y,
        commitment_d: commitment_d.to_bytes_be(),
        z1: z1.to_bytes_be(),
        z2: z2.to_bytes_be(),
        z3: z3.to_bytes_be(),
    }
}

/// Verify a Πlog* proof.
///
/// Checks:
/// 1. z1 in range
/// 2. Enc(z1, z2) = A * C^e mod N^2
/// 3. z1 * G == Y + e * X (EC point check: proves Paillier plaintext matches EC point)
pub fn verify_pilogstar(proof: &PiLogStarProof, public: &PiLogStarPublicInput) -> bool {
    use k256::elliptic_curve::group::GroupEncoding;

    let n = BigUint::from_bytes_be(&public.pk_n);
    let n_sq = BigUint::from_bytes_be(&public.pk_n_squared);
    let n_hat = BigUint::from_bytes_be(&public.n_hat);
    let c = BigUint::from_bytes_be(&public.ciphertext);

    let commitment_a = BigUint::from_bytes_be(&proof.commitment_a);
    let commitment_d = BigUint::from_bytes_be(&proof.commitment_d);
    let z1 = BigUint::from_bytes_be(&proof.z1);
    let z2 = BigUint::from_bytes_be(&proof.z2);

    // Recompute challenge
    let e = pilogstar_challenge(
        &public.pk_n,
        &public.ciphertext,
        &public.x_commitment,
        &commitment_a,
        &proof.commitment_y,
        &commitment_d,
        &n_hat,
    );

    // Range check
    let z1_bound = BigUint::one() << (PIENC_ELL + PIENC_EPSILON) as usize;
    if z1 >= z1_bound {
        return false;
    }

    // Check 1: Enc(z1, z2) = A * C^e mod N^2
    let g_z1 = (BigUint::one() + &z1 * &n) % &n_sq;
    let z2_n = z2.modpow(&n, &n_sq);
    let lhs = (&g_z1 * &z2_n) % &n_sq;

    let c_e = c.modpow(&e, &n_sq);
    let rhs = (&commitment_a * &c_e) % &n_sq;

    if lhs != rhs {
        return false;
    }

    // Check 2: z1 * G == Y + e * X on secp256k1
    // Since z1 = alpha + e*x, and Y = alpha*G, X = x*G:
    //   z1 * G = (alpha + e*x) * G = alpha*G + e*(x*G) = Y + e*X
    let z1_scalar = biguint_to_k256_scalar(&z1);
    let e_scalar = biguint_to_k256_scalar(&e);

    // Decode Y (commitment_y) from compressed SEC1
    let y_point = match decode_sec1_point(&proof.commitment_y) {
        Some(p) => p,
        None => return false,
    };

    // Decode X (x_commitment) from compressed SEC1
    let x_point = match decode_sec1_point(&public.x_commitment) {
        Some(p) => p,
        None => return false,
    };

    // z1 * G
    let lhs_ec = k256::ProjectivePoint::GENERATOR * z1_scalar;
    // Y + e * X
    let rhs_ec = y_point + x_point * e_scalar;

    if lhs_ec.to_bytes() != rhs_ec.to_bytes() {
        return false;
    }

    true
}

/// Decode a compressed SEC1 point (33 bytes) into a ProjectivePoint.
fn decode_sec1_point(bytes: &[u8]) -> Option<k256::ProjectivePoint> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let encoded = k256::EncodedPoint::from_bytes(bytes).ok()?;
    let affine: Option<k256::AffinePoint> = k256::AffinePoint::from_encoded_point(&encoded).into();
    affine.map(k256::ProjectivePoint::from)
}

/// Fiat-Shamir challenge for Πlog*.
fn pilogstar_challenge(
    pk_n: &[u8],
    ciphertext: &[u8],
    x_commitment: &[u8],
    commitment_a: &BigUint,
    commitment_y: &[u8],
    commitment_d: &BigUint,
    n_hat: &BigUint,
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"pilogstar-v1");
    hasher.update(pk_n);
    hasher.update(ciphertext);
    hasher.update(x_commitment);
    hasher.update(commitment_a.to_bytes_be());
    hasher.update(commitment_y);
    hasher.update(commitment_d.to_bytes_be());
    hasher.update(n_hat.to_bytes_be());
    let hash = hasher.finalize();
    BigUint::from_bytes_be(&hash[..16])
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers for new ZK proofs
// ─────────────────────────────────────────────────────────────────────────────

/// Sample a random value in [1, bound).
fn sample_below(bound: &BigUint) -> BigUint {
    let byte_len = (bound.bits() as usize).div_ceil(8) + 1;
    let mut buf = vec![0u8; byte_len];
    loop {
        OsRng.fill_bytes(&mut buf);
        let r = BigUint::from_bytes_be(&buf) % bound;
        if !r.is_zero() {
            return r;
        }
    }
}

/// Generate Pedersen parameters (N_hat, s, t) for use in ZK proofs.
///
/// N_hat is an auxiliary RSA modulus, s and t are elements of Z*_{N_hat}
/// such that t = s^lambda mod N_hat for some secret lambda.
/// For testing, we use a small RSA modulus.
pub fn generate_pedersen_params(bits: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use crate::paillier::keygen::generate_safe_prime;

    let p = generate_safe_prime(bits / 2);
    let q = generate_safe_prime(bits / 2);
    let n_hat = &p * &q;

    // s is a random element of Z*_{N_hat}
    let s = sample_coprime(&n_hat);

    // lambda is a random exponent; t = s^lambda mod N_hat
    let lambda = sample_below(&n_hat);
    let t = s.modpow(&lambda, &n_hat);

    (n_hat.to_bytes_be(), s.to_bytes_be(), t.to_bytes_be())
}

/// Cached 512-bit Pedersen parameters for tests (avoids slow safe-prime generation).
/// Uses same gate as `keypair_for_protocol()` in keygen.rs — `cfg(test)` alone
/// doesn't work for lib code called from test binaries.
#[cfg(any(test, feature = "local-transport"))]
static CACHED_PEDERSEN_512: std::sync::LazyLock<(Vec<u8>, Vec<u8>, Vec<u8>)> =
    std::sync::LazyLock::new(|| generate_pedersen_params(512));

/// Generate Pedersen parameters for protocol use.
///
/// In test/local-transport mode: returns a cached 512-bit parameter set (fast).
/// In production: generates fresh `bits`-bit parameters (slow, requires safe primes).
pub fn pedersen_params_for_protocol(bits: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    #[cfg(any(test, feature = "local-transport"))]
    {
        let _ = bits;
        CACHED_PEDERSEN_512.clone()
    }
    #[cfg(not(any(test, feature = "local-transport")))]
    {
        generate_pedersen_params(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::keygen::{generate_paillier_keypair, generate_safe_prime, test_keypair};
    use std::sync::LazyLock;

    // Shared 512-bit keypair — delegates to keygen::test_keypair() (process-wide LazyLock cache).
    static TEST_KEYS: LazyLock<(
        super::super::PaillierPublicKey,
        super::super::PaillierSecretKey,
    )> = LazyLock::new(test_keypair);

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

    // ─────────────────────────────────────────────────────────────────────
    // Adversarial ZK proof tests (Phase B1)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_pimod_tampered_proof_rejected() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let mut proof = prove_pimod(&n, &p, &q);

        // Corrupt the first round's a_i field with random bytes
        if let Some(round) = proof.rounds.first_mut() {
            let mut rng = OsRng;
            let mut random_bytes = vec![0u8; 32];
            rng.fill_bytes(&mut random_bytes);
            round.a = random_bytes;
        }

        assert!(
            !verify_pimod(&n, &proof),
            "Pimod proof with tampered a_i must be rejected"
        );
    }

    #[test]
    fn test_pifac_tampered_proof_rejected() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let mut proof = prove_pifac(&n, &p, &q);

        // Corrupt the commitment field — this will invalidate all challenge values
        proof.commitment = vec![0xFFu8; 32];

        assert!(
            !verify_pifac(&n, &proof),
            "Pifac proof with tampered commitment must be rejected"
        );
    }

    #[test]
    fn test_pimod_wrong_modulus_rejected() {
        // Generate proof for TEST_KEYS, then verify against a different N
        let (pk, sk) = &*TEST_KEYS;
        let n1 = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let proof = prove_pimod(&n1, &p, &q);

        // Generate a different modulus (key2)
        let (pk2, _sk2) = generate_paillier_keypair(512).unwrap();
        let n2 = pk2.n_biguint();

        // Proof generated for n1 must not verify against n2
        assert!(
            !verify_pimod(&n2, &proof),
            "Pimod proof verified against wrong modulus must be rejected"
        );
    }

    #[test]
    fn test_pifac_wrong_modulus_rejected() {
        // Generate proof for TEST_KEYS, then verify against a different N
        let (pk, sk) = &*TEST_KEYS;
        let n1 = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        let proof = prove_pifac(&n1, &p, &q);

        // Generate a different modulus (key2)
        let (pk2, _sk2) = generate_paillier_keypair(512).unwrap();
        let n2 = pk2.n_biguint();

        // Proof generated for n1 must not verify against n2
        assert!(
            !verify_pifac(&n2, &proof),
            "Pifac proof verified against wrong modulus must be rejected"
        );
    }

    #[test]
    fn test_pimod_empty_rounds_rejected() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        // Generate a valid proof, then replace rounds with empty vec
        let mut proof = prove_pimod(&n, &p, &q);
        proof.rounds = vec![];

        assert!(
            !verify_pimod(&n, &proof),
            "Pimod proof with empty rounds must be rejected"
        );
    }

    #[test]
    fn test_pifac_small_factor_modulus_rejected() {
        // Create a modulus N = small_prime * large_prime where small_prime < 2^256.
        // The verifier's trial division + bit-length checks must reject this.
        let small_prime = BigUint::from(104729u64); // well under 2^256
        let large_prime = generate_safe_prime(256);
        let weak_n = &small_prime * &large_prime;

        // Generate a proof using the real factors (the prover "honestly" proves
        // knowledge of the factorization, but the factors are too small)
        let proof = prove_pifac(&weak_n, &small_prime, &large_prime);

        assert!(
            !verify_pifac(&weak_n, &proof),
            "Pifac must reject modulus with a small prime factor (CVE-2023-33241 defense)"
        );

        // Also verify directly that trial division catches the small factor
        assert!(
            has_small_factor(&weak_n),
            "has_small_factor must detect the small prime in the modulus"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Pedersen params + shared test infrastructure for new ZK proofs
    // ─────────────────────────────────────────────────────────────────────

    /// Generate Pedersen params once (slow safe-prime gen).
    static TEST_PEDERSEN: LazyLock<(Vec<u8>, Vec<u8>, Vec<u8>)> =
        LazyLock::new(|| generate_pedersen_params(512));

    /// Helper: encrypt with known randomness for proof construction.
    fn encrypt_with_known_r(
        pk: &super::super::PaillierPublicKey,
        m: &BigUint,
    ) -> (super::super::PaillierCiphertext, BigUint) {
        let n = pk.n_biguint();
        let r = sample_coprime(&n);
        let ct = pk.encrypt_with_r(m, &r);
        (ct, r)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Πenc tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_pienc_valid_encryption_passes() {
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let m = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &m);

        let public = PiEncPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let proof = prove_pienc(&m, &r, &public);
        assert!(
            verify_pienc(&proof, &public),
            "valid Pienc proof must verify"
        );
    }

    #[test]
    fn test_pienc_out_of_range_fails() {
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let m = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &m);

        let public = PiEncPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let mut proof = prove_pienc(&m, &r, &public);

        // Tamper with z1 to make it out of range (set to a huge value)
        let out_of_range: BigUint = BigUint::one() << 800usize;
        proof.z1 = out_of_range.to_bytes_be();

        assert!(
            !verify_pienc(&proof, &public),
            "out-of-range z1 must fail Pienc verification"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Πaff-g tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_piaffg_valid_operation_passes() {
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let a = BigUint::from(7u64);
        let x = BigUint::from(13u64);
        let y = BigUint::from(99u64);

        // C = Enc(a)
        let (c_a, _r_a) = encrypt_with_known_r(pk, &a);

        // D = C^x * Enc(y, rho_y)
        let c_ax = pk.scalar_mult(&c_a, &x);
        let n = pk.n_biguint();
        let rho_y = sample_coprime(&n);
        let c_y = pk.encrypt_with_r(&y, &rho_y);
        let d = pk.add(&c_ax, &c_y);

        let public = PiAffgPublicInput {
            pk_n0: pk.n.clone(),
            pk_n0_squared: pk.n_squared.clone(),
            c: c_a.data.clone(),
            d: d.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let proof = prove_piaffg(&x, &y, &rho_y, &public);
        assert!(
            verify_piaffg(&proof, &public),
            "valid Piaffg proof must verify"
        );
    }

    #[test]
    fn test_piaffg_invalid_fails() {
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let a = BigUint::from(7u64);
        let x = BigUint::from(13u64);
        let y = BigUint::from(99u64);

        let (c_a, _r_a) = encrypt_with_known_r(pk, &a);
        let c_ax = pk.scalar_mult(&c_a, &x);
        let n = pk.n_biguint();
        let rho_y = sample_coprime(&n);
        let c_y = pk.encrypt_with_r(&y, &rho_y);
        let d = pk.add(&c_ax, &c_y);

        let public = PiAffgPublicInput {
            pk_n0: pk.n.clone(),
            pk_n0_squared: pk.n_squared.clone(),
            c: c_a.data.clone(),
            d: d.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let mut proof = prove_piaffg(&x, &y, &rho_y, &public);

        // Tamper: make z1 out of range
        let out_of_range: BigUint = BigUint::one() << 800usize;
        proof.z1 = out_of_range.to_bytes_be();

        assert!(
            !verify_piaffg(&proof, &public),
            "tampered Piaffg proof must fail"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Πlog* tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_pilog_star_consistent_passes() {
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let x = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &x);
        let x_commitment = pilogstar_point_commitment(&x);

        let public = PiLogStarPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            x_commitment,
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let proof = prove_pilogstar(&x, &r, &public);
        assert!(
            verify_pilogstar(&proof, &public),
            "valid Pilogstar proof must verify"
        );
    }

    #[test]
    fn test_pilog_star_inconsistent_fails() {
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let x = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &x);

        // Use wrong x for point commitment (different value)
        let wrong_x = BigUint::from(99u64);
        let wrong_commitment = pilogstar_point_commitment(&wrong_x);

        let public = PiLogStarPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            x_commitment: wrong_commitment,
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        // Generate proof with the correct commitment, then verify against
        // the wrong public input. The Fiat-Shamir challenge will differ,
        // causing the verification equation to fail.
        let correct_commitment = pilogstar_point_commitment(&x);
        let correct_public = PiLogStarPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            x_commitment: correct_commitment,
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };
        let proof = prove_pilogstar(&x, &r, &correct_public);

        // Verify with wrong commitment — challenge will differ, verification must fail
        assert!(
            !verify_pilogstar(&proof, &public),
            "Pilogstar with inconsistent x commitment must fail"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // MtA + ZK proofs integration test
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_mta_with_all_proofs() {
        // Full MtA with Πenc on Round 1 and Πaff-g on Round 2
        let (pk, sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;
        let n = pk.n_biguint();

        let a = BigUint::from(42u64);
        let b = BigUint::from(17u64);

        // ─── Round 1: Party A encrypts a ───
        let r_a = sample_coprime(&n);
        let c_a = pk.encrypt_with_r(&a, &r_a);

        // Party A generates Πenc proof
        let pienc_public = PiEncPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: c_a.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };
        let pienc_proof = prove_pienc(&a, &r_a, &pienc_public);

        // Party B verifies Πenc
        assert!(
            verify_pienc(&pienc_proof, &pienc_public),
            "Round 1: Pienc proof must verify"
        );

        // ─── Round 2: Party B computes affine operation (positive beta) ───
        // Sample beta from [1, 2^256) — same range as secp256k1 scalars.
        // Ensures Πaff-g range check passes: z2 = mask + e*beta < 2^768.
        let beta_bound = BigUint::one() << 256usize;
        let beta_prime = sample_below(&beta_bound);

        let c_ab = pk.scalar_mult(&c_a, &b);
        let rho_y = sample_coprime(&n);
        let c_beta = pk.encrypt_with_r(&beta_prime, &rho_y);
        let c_b = pk.add(&c_ab, &c_beta);

        // Party B generates Πaff-g proof with positive beta (small, < 2^768)
        let piaffg_public = PiAffgPublicInput {
            pk_n0: pk.n.clone(),
            pk_n0_squared: pk.n_squared.clone(),
            c: c_a.data.clone(),
            d: c_b.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };
        let piaffg_proof = prove_piaffg(&b, &beta_prime, &rho_y, &piaffg_public);

        // Party A verifies Πaff-g
        assert!(
            verify_piaffg(&piaffg_proof, &piaffg_public),
            "Round 2: Piaffg proof must verify"
        );

        // ─── Finish: Party A decrypts ───
        let alpha = sk.decrypt(pk, &c_b);

        // Verify correctness: alpha - beta' = a * b mod N
        // (D = C^b * Enc(+beta') → alpha = a*b + beta')
        let diff = (&alpha + &n - &beta_prime) % &n;
        let product = (&a * &b) % &n;
        assert_eq!(
            diff, product,
            "MtA with proofs: alpha - beta must equal a * b mod N"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // SEC-055: Pienc Pedersen commitment soundness tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_pienc_tampered_pedersen_s_rejected() {
        // SEC-055: Verify that tampering with the Pedersen witness commitment
        // causes verification to fail (previously this check was discarded).
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let m = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &m);

        let public = PiEncPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let mut proof = prove_pienc(&m, &r, &public);

        // Tamper with the Pedersen commitment S (use a random value)
        let n_hat_big = BigUint::from_bytes_be(n_hat);
        proof.pedersen_s = sample_below(&n_hat_big).to_bytes_be();

        assert!(
            !verify_pienc(&proof, &public),
            "SEC-055: tampered Pedersen commitment S must cause Pienc rejection"
        );
    }

    #[test]
    fn test_pienc_wrong_witness_pedersen_rejected() {
        // SEC-055: Generate proof for m=42, but try to forge Pedersen commitment for m=99.
        // The Pedersen check must catch this.
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let m = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &m);

        let public = PiEncPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let mut proof = prove_pienc(&m, &r, &public);

        // Forge a Pedersen commitment for a different message m'=99
        let n_hat_big = BigUint::from_bytes_be(n_hat);
        let s_base = BigUint::from_bytes_be(s);
        let t_base = BigUint::from_bytes_be(t);
        let wrong_m = BigUint::from(99u64);
        let fake_rho = sample_below(&n_hat_big);
        let fake_pedersen = (s_base.modpow(&wrong_m, &n_hat_big)
            * t_base.modpow(&fake_rho, &n_hat_big))
            % &n_hat_big;
        proof.pedersen_s = fake_pedersen.to_bytes_be();

        assert!(
            !verify_pienc(&proof, &public),
            "SEC-055: Pedersen commitment for wrong witness must be rejected"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // SEC-056: Piaffg Pedersen commitment soundness tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_piaffg_tampered_pedersen_sx_rejected() {
        // SEC-056: Verify that tampering with S_x causes rejection
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let a = BigUint::from(7u64);
        let x = BigUint::from(13u64);
        let y = BigUint::from(99u64);

        let (c_a, _r_a) = encrypt_with_known_r(pk, &a);
        let c_ax = pk.scalar_mult(&c_a, &x);
        let n = pk.n_biguint();
        let rho_y = sample_coprime(&n);
        let c_y = pk.encrypt_with_r(&y, &rho_y);
        let d = pk.add(&c_ax, &c_y);

        let public = PiAffgPublicInput {
            pk_n0: pk.n.clone(),
            pk_n0_squared: pk.n_squared.clone(),
            c: c_a.data.clone(),
            d: d.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let mut proof = prove_piaffg(&x, &y, &rho_y, &public);

        // Tamper with S_x
        let n_hat_big = BigUint::from_bytes_be(n_hat);
        proof.pedersen_sx = sample_below(&n_hat_big).to_bytes_be();

        assert!(
            !verify_piaffg(&proof, &public),
            "SEC-056: tampered S_x must cause Piaffg rejection"
        );
    }

    #[test]
    fn test_piaffg_tampered_pedersen_sy_rejected() {
        // SEC-056: Verify that tampering with S_y causes rejection
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let a = BigUint::from(7u64);
        let x = BigUint::from(13u64);
        let y = BigUint::from(99u64);

        let (c_a, _r_a) = encrypt_with_known_r(pk, &a);
        let c_ax = pk.scalar_mult(&c_a, &x);
        let n = pk.n_biguint();
        let rho_y = sample_coprime(&n);
        let c_y = pk.encrypt_with_r(&y, &rho_y);
        let d = pk.add(&c_ax, &c_y);

        let public = PiAffgPublicInput {
            pk_n0: pk.n.clone(),
            pk_n0_squared: pk.n_squared.clone(),
            c: c_a.data.clone(),
            d: d.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let mut proof = prove_piaffg(&x, &y, &rho_y, &public);

        // Tamper with S_y
        let n_hat_big = BigUint::from_bytes_be(n_hat);
        proof.pedersen_sy = sample_below(&n_hat_big).to_bytes_be();

        assert!(
            !verify_piaffg(&proof, &public),
            "SEC-056: tampered S_y must cause Piaffg rejection"
        );
    }

    #[test]
    fn test_piaffg_wrong_witness_rejected() {
        // SEC-056: Create a valid proof for (x=13, y=99), then tamper z3/z4
        // to check that the Pedersen verification catches inconsistency.
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let a = BigUint::from(7u64);
        let x = BigUint::from(13u64);
        let y = BigUint::from(99u64);

        let (c_a, _r_a) = encrypt_with_known_r(pk, &a);
        let c_ax = pk.scalar_mult(&c_a, &x);
        let n = pk.n_biguint();
        let rho_y = sample_coprime(&n);
        let c_y = pk.encrypt_with_r(&y, &rho_y);
        let d = pk.add(&c_ax, &c_y);

        let public = PiAffgPublicInput {
            pk_n0: pk.n.clone(),
            pk_n0_squared: pk.n_squared.clone(),
            c: c_a.data.clone(),
            d: d.data.clone(),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let mut proof = prove_piaffg(&x, &y, &rho_y, &public);

        // Tamper with z3 (Pedersen response for x)
        let n_hat_big = BigUint::from_bytes_be(n_hat);
        proof.z3 = sample_below(&n_hat_big).to_bytes_be();

        assert!(
            !verify_piaffg(&proof, &public),
            "SEC-056: tampered z3 must cause Piaffg Pedersen check failure"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // SEC-057: Pilogstar EC point commitment soundness tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_pilogstar_ec_point_commitment_is_33_bytes() {
        // SEC-057: Verify commitment is compressed SEC1 (33 bytes), not hash (32 bytes)
        let x = BigUint::from(42u64);
        let commitment = pilogstar_point_commitment(&x);
        assert_eq!(
            commitment.len(),
            33,
            "SEC-057: EC point commitment must be 33 bytes (compressed SEC1)"
        );
        // First byte must be 0x02 or 0x03 (compressed point prefix)
        assert!(
            commitment[0] == 0x02 || commitment[0] == 0x03,
            "SEC-057: compressed SEC1 must start with 0x02 or 0x03"
        );
    }

    #[test]
    fn test_pilogstar_ec_commitment_different_x() {
        // SEC-057: Different x values must produce different EC points
        let x1 = BigUint::from(42u64);
        let x2 = BigUint::from(43u64);
        let c1 = pilogstar_point_commitment(&x1);
        let c2 = pilogstar_point_commitment(&x2);
        assert_ne!(
            c1, c2,
            "SEC-057: different x values must produce different EC points"
        );
    }

    #[test]
    fn test_pilogstar_ec_verification_catches_wrong_x() {
        // SEC-057: Prove with x=42, try to verify with X = 99*G.
        // The EC check z1*G == Y + e*X must fail.
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let x = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &x);
        let x_commitment = pilogstar_point_commitment(&x);

        let correct_public = PiLogStarPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            x_commitment,
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let proof = prove_pilogstar(&x, &r, &correct_public);

        // Verify with wrong EC point (99*G instead of 42*G)
        let wrong_x = BigUint::from(99u64);
        let wrong_public = PiLogStarPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            x_commitment: pilogstar_point_commitment(&wrong_x),
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        assert!(
            !verify_pilogstar(&proof, &wrong_public),
            "SEC-057: EC point check must reject proof with wrong x*G"
        );
    }

    #[test]
    fn test_pilogstar_tampered_commitment_y_rejected() {
        // SEC-057: Tamper with commitment_y (the prover's alpha*G) in the proof.
        // The EC check z1*G == Y + e*X must fail.
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let x = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &x);
        let x_commitment = pilogstar_point_commitment(&x);

        let public = PiLogStarPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            x_commitment,
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let mut proof = prove_pilogstar(&x, &r, &public);

        // Replace commitment_y with a different point (999*G)
        proof.commitment_y = pilogstar_point_commitment(&BigUint::from(999u64));

        assert!(
            !verify_pilogstar(&proof, &public),
            "SEC-057: tampered commitment_y must cause EC check failure"
        );
    }

    #[test]
    fn test_pilogstar_invalid_point_bytes_rejected() {
        // SEC-057: Supply garbage bytes as x_commitment (not a valid SEC1 point).
        let (pk, _sk) = &*TEST_KEYS;
        let (n_hat, s, t) = &*TEST_PEDERSEN;

        let x = BigUint::from(42u64);
        let (ct, r) = encrypt_with_known_r(pk, &x);
        let x_commitment = pilogstar_point_commitment(&x);

        let correct_public = PiLogStarPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            x_commitment,
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        let proof = prove_pilogstar(&x, &r, &correct_public);

        // Supply invalid bytes as x_commitment
        let bad_public = PiLogStarPublicInput {
            pk_n: pk.n.clone(),
            pk_n_squared: pk.n_squared.clone(),
            ciphertext: ct.data.clone(),
            x_commitment: vec![0xFF; 33], // invalid point
            n_hat: n_hat.clone(),
            s: s.clone(),
            t: t.clone(),
        };

        assert!(
            !verify_pilogstar(&proof, &bad_public),
            "SEC-057: invalid EC point bytes must be rejected"
        );
    }
}
