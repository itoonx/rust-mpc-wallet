//! Paillier key generation with real safe primes.
//!
//! Safe prime p: both p and (p-1)/2 are prime.
//! Key: N = p*q, lambda = lcm(p-1, q-1), mu = L(g^lambda mod N^2)^(-1) mod N.

use super::{l_function, PaillierPublicKey, PaillierSecretKey};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::RngCore;

/// Number of Miller-Rabin rounds for primality testing (security parameter).
const MILLER_RABIN_ROUNDS: u32 = 40;

/// Generate a safe prime of `bits` size.
///
/// A safe prime p satisfies: p is prime AND (p-1)/2 is prime.
/// Uses probabilistic Miller-Rabin with 40 rounds.
pub fn generate_safe_prime(bits: usize) -> BigUint {
    loop {
        // Generate a random odd number of the target bit size.
        let candidate = random_odd_with_bits(bits);

        // Check if candidate is probable prime.
        if !is_probable_prime(&candidate, MILLER_RABIN_ROUNDS) {
            continue;
        }

        // Check if (candidate - 1) / 2 is prime (making candidate a safe prime).
        let sophie_germain = (&candidate - BigUint::one()) >> 1;
        if is_probable_prime(&sophie_germain, MILLER_RABIN_ROUNDS) {
            return candidate;
        }
    }
}

/// Generate a Paillier keypair with N being `bits` bits (each prime is `bits/2` bits).
///
/// Default: `bits = 2048` produces a 2048-bit modulus from two 1024-bit safe primes.
/// For tests, smaller values (e.g., 512) may be used for speed.
pub fn generate_paillier_keypair(bits: usize) -> (PaillierPublicKey, PaillierSecretKey) {
    let half_bits = bits / 2;

    // Generate two distinct safe primes.
    let p = generate_safe_prime(half_bits);
    let mut q = generate_safe_prime(half_bits);
    while p == q {
        q = generate_safe_prime(half_bits);
    }

    keypair_from_primes(&p, &q)
}

/// Build a Paillier keypair from given primes p and q.
/// Exposed for testing with known primes.
pub(crate) fn keypair_from_primes(
    p: &BigUint,
    q: &BigUint,
) -> (PaillierPublicKey, PaillierSecretKey) {
    let n = p * q;
    let n_sq = &n * &n;

    // lambda = lcm(p-1, q-1)
    let p_minus_1 = p - BigUint::one();
    let q_minus_1 = q - BigUint::one();
    let lambda = p_minus_1.lcm(&q_minus_1);

    // g = N + 1 (standard simplification)
    let g = &n + BigUint::one();

    // g^lambda mod N^2
    let g_lambda = g.modpow(&lambda, &n_sq);

    // L(g^lambda mod N^2) = (g^lambda mod N^2 - 1) / N
    let l_val = l_function(&g_lambda, &n);

    // mu = L(g^lambda mod N^2)^(-1) mod N
    let mu = mod_inverse(&l_val, &n).expect("L-value must be invertible mod N for valid primes");

    let pk = PaillierPublicKey {
        n: n.to_bytes_be(),
        n_squared: n_sq.to_bytes_be(),
    };

    let sk = PaillierSecretKey {
        p: p.to_bytes_be(),
        q: q.to_bytes_be(),
        lambda: lambda.to_bytes_be(),
        mu: mu.to_bytes_be(),
    };

    (pk, sk)
}

/// Generate a random odd number with exactly `bits` bits set.
fn random_odd_with_bits(bits: usize) -> BigUint {
    assert!(bits >= 2, "need at least 2 bits for a prime candidate");
    let byte_len = bits.div_ceil(8);
    let mut buf = vec![0u8; byte_len];
    OsRng.fill_bytes(&mut buf);

    // Set the highest bit to ensure the number has exactly `bits` bits.
    let top_bit_index = (bits - 1) % 8;
    buf[0] |= 1 << top_bit_index;

    // Clear any bits above `bits` in the top byte.
    if top_bit_index < 7 {
        let mask = (1u8 << (top_bit_index + 1)) - 1;
        buf[0] &= mask;
    }
    // If top_bit_index == 7, all 8 bits of buf[0] are valid, no masking needed.

    // Set lowest bit to make it odd.
    buf[byte_len - 1] |= 1;

    BigUint::from_bytes_be(&buf)
}

/// Miller-Rabin primality test with `rounds` iterations.
///
/// Returns true if `n` is probably prime (error probability < 4^(-rounds)).
/// With 40 rounds, probability of false positive < 2^(-80).
fn is_probable_prime(n: &BigUint, rounds: u32) -> bool {
    let one = BigUint::one();
    let two = BigUint::from(2u32);

    if *n < two {
        return false;
    }
    if *n == two || *n == BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n - 1 = 2^r * d where d is odd
    let n_minus_1 = n - &one;
    let r = trailing_zeros(&n_minus_1);
    let d = &n_minus_1 >> r;

    let byte_len = (n.bits() as usize).div_ceil(8);
    let mut buf = vec![0u8; byte_len];

    'witness: for _ in 0..rounds {
        // Pick random a in [2, n-2]
        let a = loop {
            OsRng.fill_bytes(&mut buf);
            let candidate = BigUint::from_bytes_be(&buf) % n;
            if candidate >= two && candidate <= &n_minus_1 - &one {
                break candidate;
            }
        };

        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..(r - 1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }

        return false;
    }

    true
}

/// Count trailing zero bits in n.
fn trailing_zeros(n: &BigUint) -> usize {
    if n.is_zero() {
        return 0;
    }
    let bytes = n.to_bytes_le();
    let mut count = 0;
    for &byte in &bytes {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.trailing_zeros() as usize;
            break;
        }
    }
    count
}

/// Modular inverse: a^(-1) mod m using extended Euclidean algorithm.
/// Returns None if gcd(a, m) != 1.
pub(crate) fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;

    let a_int = BigInt::from(a.clone());
    let m_int = BigInt::from(m.clone());

    let (g, x, _) = extended_gcd(&a_int, &m_int);

    if g != BigInt::one() {
        return None;
    }

    // Make sure x is positive
    let result = ((x % &m_int) + &m_int) % &m_int;
    Some(result.magnitude().clone())
}

/// Extended GCD: returns (gcd, x, y) such that a*x + b*y = gcd.
fn extended_gcd(
    a: &num_bigint::BigInt,
    b: &num_bigint::BigInt,
) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
    use num_bigint::BigInt;

    if b.is_zero() {
        return (a.clone(), BigInt::one(), BigInt::ZERO);
    }

    let (q, r) = a.div_rem(b);
    let (gcd, x1, y1) = extended_gcd(b, &r);
    let x = y1.clone();
    let y = x1 - q * y1;
    (gcd, x, y)
}

/// Check if `n` is a probable prime using Miller-Rabin with 40 rounds.
/// Public API for use in ZK proof verification.
pub fn is_prime(n: &BigUint) -> bool {
    is_probable_prime(n, MILLER_RABIN_ROUNDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static TEST_KEYS_512: LazyLock<(PaillierPublicKey, PaillierSecretKey)> =
        LazyLock::new(|| generate_paillier_keypair(512));

    #[test]
    fn test_safe_prime_is_safe() {
        // Generate a small safe prime for speed
        let p = generate_safe_prime(128);
        assert!(is_prime(&p), "p must be prime");
        let sophie = (&p - BigUint::one()) >> 1;
        assert!(is_prime(&sophie), "(p-1)/2 must be prime");
    }

    #[test]
    fn test_keypair_n_equals_p_times_q() {
        let (pk, sk) = &*TEST_KEYS_512;
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);
        let n = pk.n_biguint();
        assert_eq!(n, &p * &q, "N must equal p * q");
    }

    #[test]
    fn test_keypair_p_neq_q() {
        let (_pk, sk) = &*TEST_KEYS_512;
        assert_ne!(sk.p, sk.q, "p and q must be different");
    }

    #[test]
    fn test_keypair_primes_are_safe_primes() {
        let (_pk, sk) = &*TEST_KEYS_512;
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);

        assert!(is_prime(&p), "p must be prime");
        assert!(is_prime(&q), "q must be prime");

        let p_half = (&p - BigUint::one()) >> 1;
        let q_half = (&q - BigUint::one()) >> 1;
        assert!(is_prime(&p_half), "(p-1)/2 must be prime");
        assert!(is_prime(&q_half), "(q-1)/2 must be prime");
    }

    #[test]
    fn test_modulus_bit_size() {
        let (pk, _sk) = &*TEST_KEYS_512;
        let n = pk.n_biguint();
        // 512-bit key = two 256-bit primes, so N should be ~512 bits
        assert!(n.bits() >= 500, "N should be ~512 bits, got {}", n.bits());
    }

    #[test]
    fn test_lambda_correct() {
        let (_pk, sk) = &*TEST_KEYS_512;
        let p = BigUint::from_bytes_be(&sk.p);
        let q = BigUint::from_bytes_be(&sk.q);
        let lambda = BigUint::from_bytes_be(&sk.lambda);
        let expected_lambda = (&p - BigUint::one()).lcm(&(&q - BigUint::one()));
        assert_eq!(lambda, expected_lambda);
    }

    #[test]
    fn test_mu_is_inverse_of_l() {
        let (pk, sk) = &*TEST_KEYS_512;
        let n = pk.n_biguint();
        let n_sq = pk.n_squared_biguint();
        let lambda = BigUint::from_bytes_be(&sk.lambda);
        let mu = BigUint::from_bytes_be(&sk.mu);

        let g = &n + BigUint::one();
        let g_lambda = g.modpow(&lambda, &n_sq);
        let l_val = l_function(&g_lambda, &n);

        // mu * l_val mod N should be 1
        let product = (&mu * &l_val) % &n;
        assert_eq!(product, BigUint::one());
    }

    #[test]
    fn test_miller_rabin_known_primes() {
        let primes = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 97, 127, 8191];
        for p in primes {
            assert!(is_prime(&BigUint::from(p)), "{} should be prime", p);
        }
    }

    #[test]
    fn test_miller_rabin_known_composites() {
        let composites = [4u64, 6, 8, 9, 10, 15, 21, 25, 100, 1001];
        for c in composites {
            assert!(!is_prime(&BigUint::from(c)), "{} should not be prime", c);
        }
    }

    #[test]
    fn test_mod_inverse() {
        let a = BigUint::from(3u64);
        let m = BigUint::from(11u64);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!((&a * &inv) % &m, BigUint::one());
    }

    #[test]
    fn test_mod_inverse_no_inverse() {
        let a = BigUint::from(6u64);
        let m = BigUint::from(12u64);
        assert!(mod_inverse(&a, &m).is_none());
    }
}
