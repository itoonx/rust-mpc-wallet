//! Real Paillier cryptosystem for CGGMP21 MPC signing.
//!
//! Replaces the simulated (SHA-256 hash) Paillier used in Sprint 19.
//! Provides:
//! - Homomorphic encryption: `Enc(a) * Enc(b) = Enc(a + b)` and `Enc(a)^k = Enc(a * k)`
//! - Safe prime key generation (p, q are safe primes, N = p*q >= 2048 bits)
//! - ZK proofs: Pimod (Blum modulus) and Pifac (no small factor)
//!
//! ## CVE-2023-33241
//!
//! Without real Paillier + ZK proofs, an attacker can inject malicious keys with
//! small prime factors and extract private key shares in 16 signatures.
//! The Pifac proof rejects any N with a factor smaller than 2^256.

pub mod keygen;
pub mod mta;
pub mod zk_proofs;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Paillier public key: N = p*q where p, q are safe primes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    /// N as big-endian bytes.
    pub n: Vec<u8>,
    /// N^2 precomputed, big-endian bytes.
    pub n_squared: Vec<u8>,
}

/// Paillier secret key (zeroized on drop).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PaillierSecretKey {
    /// Prime p, big-endian bytes.
    pub p: Vec<u8>,
    /// Prime q, big-endian bytes.
    pub q: Vec<u8>,
    /// lambda = lcm(p-1, q-1), big-endian bytes.
    pub lambda: Vec<u8>,
    /// mu = L(g^lambda mod N^2)^(-1) mod N, big-endian bytes.
    pub mu: Vec<u8>,
}

// Manual Debug impl to redact secret material.
impl std::fmt::Debug for PaillierSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaillierSecretKey")
            .field("p", &"[REDACTED]")
            .field("q", &"[REDACTED]")
            .field("lambda", &"[REDACTED]")
            .field("mu", &"[REDACTED]")
            .finish()
    }
}

/// Paillier ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierCiphertext {
    /// Ciphertext as big-endian bytes.
    pub data: Vec<u8>,
}

impl PaillierPublicKey {
    /// Get N as BigUint.
    pub fn n_biguint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.n)
    }

    /// Get N^2 as BigUint.
    pub fn n_squared_biguint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.n_squared)
    }

    /// Encrypt plaintext m: c = (N+1)^m * r^N mod N^2
    ///
    /// Uses the simplified generator g = N+1 which gives (N+1)^m = 1 + m*N mod N^2
    /// for the L-function optimization. The randomness r is sampled from Z*_N.
    pub fn encrypt(&self, plaintext: &BigUint) -> PaillierCiphertext {
        let n = self.n_biguint();
        let n_sq = self.n_squared_biguint();

        // g = N + 1, so g^m mod N^2 = (1 + N)^m mod N^2 = 1 + m*N mod N^2
        let g_m = (BigUint::one() + plaintext * &n) % &n_sq;

        // Sample random r in Z*_N
        let r = sample_coprime(&n);
        // r^N mod N^2
        let r_n = r.modpow(&n, &n_sq);

        let c = (g_m * r_n) % &n_sq;

        PaillierCiphertext {
            data: c.to_bytes_be(),
        }
    }

    /// Encrypt with explicit randomness (for testing determinism).
    pub fn encrypt_with_r(&self, plaintext: &BigUint, r: &BigUint) -> PaillierCiphertext {
        let n = self.n_biguint();
        let n_sq = self.n_squared_biguint();

        let g_m = (BigUint::one() + plaintext * &n) % &n_sq;
        let r_n = r.modpow(&n, &n_sq);

        let c = (g_m * r_n) % &n_sq;

        PaillierCiphertext {
            data: c.to_bytes_be(),
        }
    }

    /// Homomorphic addition: Enc(a) * Enc(b) mod N^2 = Enc(a + b mod N)
    pub fn add(&self, c1: &PaillierCiphertext, c2: &PaillierCiphertext) -> PaillierCiphertext {
        let n_sq = self.n_squared_biguint();
        let ct1 = BigUint::from_bytes_be(&c1.data);
        let ct2 = BigUint::from_bytes_be(&c2.data);

        let result = (ct1 * ct2) % &n_sq;
        PaillierCiphertext {
            data: result.to_bytes_be(),
        }
    }

    /// Homomorphic scalar multiplication: Enc(a)^k mod N^2 = Enc(a * k mod N)
    pub fn scalar_mult(&self, c: &PaillierCiphertext, k: &BigUint) -> PaillierCiphertext {
        let n_sq = self.n_squared_biguint();
        let ct = BigUint::from_bytes_be(&c.data);

        let result = ct.modpow(k, &n_sq);
        PaillierCiphertext {
            data: result.to_bytes_be(),
        }
    }
}

impl PaillierSecretKey {
    /// Decrypt ciphertext: m = L(c^lambda mod N^2) * mu mod N
    /// where L(x) = (x - 1) / N
    pub fn decrypt(&self, pk: &PaillierPublicKey, ciphertext: &PaillierCiphertext) -> BigUint {
        let n = pk.n_biguint();
        let n_sq = pk.n_squared_biguint();
        let lambda = BigUint::from_bytes_be(&self.lambda);
        let mu = BigUint::from_bytes_be(&self.mu);

        let c = BigUint::from_bytes_be(&ciphertext.data);

        // c^lambda mod N^2
        let c_lambda = c.modpow(&lambda, &n_sq);

        // L(c_lambda) = (c_lambda - 1) / N
        let l_val = l_function(&c_lambda, &n);

        // m = L(c^lambda mod N^2) * mu mod N
        (l_val * mu) % &n
    }
}

/// L function: L(x) = (x - 1) / N
/// Assumes x = 1 mod N (which is guaranteed by Paillier construction).
fn l_function(x: &BigUint, n: &BigUint) -> BigUint {
    (x - BigUint::one()) / n
}

/// Sample a random number in Z*_N (coprime to N).
fn sample_coprime(n: &BigUint) -> BigUint {
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

/// GCD using Euclidean algorithm.
pub(crate) fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let t = b.clone();
        b = a % &t;
        a = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::keygen::{generate_paillier_keypair, test_keypair};
    use std::sync::LazyLock;

    // Shared 512-bit keypair — delegates to keygen::test_keypair() (process-wide LazyLock cache).
    static TEST_KEYS: LazyLock<(PaillierPublicKey, PaillierSecretKey)> =
        LazyLock::new(test_keypair);

    #[test]
    fn test_paillier_encrypt_decrypt_roundtrip() {
        let (pk, sk) = &*TEST_KEYS;
        let m = BigUint::from(42u64);
        let ct = pk.encrypt(&m);
        let decrypted = sk.decrypt(pk, &ct);
        assert_eq!(decrypted, m);
    }

    #[test]
    fn test_paillier_encrypt_decrypt_zero() {
        let (pk, sk) = &*TEST_KEYS;
        let m = BigUint::zero();
        let ct = pk.encrypt(&m);
        let decrypted = sk.decrypt(pk, &ct);
        assert_eq!(decrypted, m);
    }

    #[test]
    fn test_paillier_encrypt_decrypt_large() {
        let (pk, sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        // Use a value close to N-1
        let m = &n - BigUint::one();
        let ct = pk.encrypt(&m);
        let decrypted = sk.decrypt(pk, &ct);
        assert_eq!(decrypted, m);
    }

    #[test]
    fn test_paillier_homomorphic_addition() {
        let (pk, sk) = &*TEST_KEYS;
        let a = BigUint::from(123u64);
        let b = BigUint::from(456u64);

        let ca = pk.encrypt(&a);
        let cb = pk.encrypt(&b);
        let c_sum = pk.add(&ca, &cb);

        let decrypted = sk.decrypt(pk, &c_sum);
        assert_eq!(decrypted, a + b);
    }

    #[test]
    fn test_paillier_homomorphic_scalar() {
        let (pk, sk) = &*TEST_KEYS;
        let a = BigUint::from(7u64);
        let k = BigUint::from(13u64);

        let ca = pk.encrypt(&a);
        let c_mul = pk.scalar_mult(&ca, &k);

        let decrypted = sk.decrypt(pk, &c_mul);
        assert_eq!(decrypted, a * k);
    }

    #[test]
    fn test_paillier_different_keys_cant_decrypt() {
        let (pk1, _sk1) = &*TEST_KEYS;
        // Generate a second keypair
        let (_pk2, sk2) = generate_paillier_keypair(512);

        let m = BigUint::from(42u64);
        let ct = pk1.encrypt(&m);

        // Decrypting with wrong key should give wrong result
        let wrong_decrypt = sk2.decrypt(pk1, &ct);
        assert_ne!(wrong_decrypt, m, "wrong key must not decrypt correctly");
    }

    #[test]
    fn test_paillier_modulus_size() {
        let (pk, _sk) = &*TEST_KEYS;
        let n = pk.n_biguint();
        // 512-bit key means N is at least 512 bits
        assert!(
            n.bits() >= 500,
            "N should be at least ~512 bits, got {}",
            n.bits()
        );
    }

    #[test]
    fn test_paillier_ciphertext_randomized() {
        let (pk, _sk) = &*TEST_KEYS;
        let m = BigUint::from(42u64);
        let ct1 = pk.encrypt(&m);
        let ct2 = pk.encrypt(&m);
        // Same plaintext should produce different ciphertexts (semantic security)
        assert_ne!(ct1.data, ct2.data);
    }
}
