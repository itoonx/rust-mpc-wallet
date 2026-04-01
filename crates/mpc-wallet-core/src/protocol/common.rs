//! Shared helpers for secp256k1-based threshold protocols (GG20, CGGMP21).
//!
//! This module contains functions used by multiple protocol implementations
//! to avoid code duplication. All functions preserve their original signatures
//! and behavior.

use crate::error::CoreError;
use k256::{elliptic_curve::ops::Reduce, Scalar, U256};
use num_bigint::BigUint;

// ─────────────────────────────────────────────────────────────────────────────
// secp256k1 curve order constant
// ─────────────────────────────────────────────────────────────────────────────

/// Return the secp256k1 curve order as 32 big-endian bytes.
///
/// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub fn secp256k1_order_bytes() -> [u8; 32] {
    [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Lagrange coefficient
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the Lagrange coefficient λ_i for party `party_index` evaluated at x=0.
///
/// Given a set of party indices (1-indexed), computes:
///
/// ```text
/// λ_i = Π_{j ≠ i} (0 - x_j) / (x_i - x_j)
/// ```
///
/// This is used in both GG20 and CGGMP21 to convert Shamir shares into
/// additive shares at signing time.
pub fn lagrange_coefficient(party_index: u16, all_parties: &[u16]) -> Result<Scalar, CoreError> {
    let x_i = Scalar::from(party_index as u64);
    let mut basis = Scalar::ONE;
    for &j in all_parties {
        if j == party_index {
            continue;
        }
        let x_j = Scalar::from(j as u64);
        let num = Scalar::ZERO - x_j;
        let den = x_i - x_j;
        let den_inv = den.invert().into_option().ok_or_else(|| {
            CoreError::Crypto(
                "zero denominator in Lagrange coefficient — duplicate party index".into(),
            )
        })?;
        basis *= num * den_inv;
    }
    Ok(basis)
}

// ─────────────────────────────────────────────────────────────────────────────
// Signed scalar conversion for MtA
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a `BigUint` from Paillier ciphertext space to a secp256k1 `Scalar`,
/// correctly handling signed (two's complement) encoding.
///
/// Paillier MtA produces values in `Z_N` that represent signed integers. When
/// `value > N/2`, the true value is negative: `value - N`. We map this into the
/// secp256k1 scalar field by computing `-(N - value) mod q`.
///
/// This ensures `to_scalar_signed(alpha) + to_scalar_signed(beta) == a * b` as a
/// `Scalar`, even when the unsigned sum `alpha + beta` wraps modulo `N`.
pub fn to_scalar_signed(
    big: &BigUint,
    n: &BigUint,
    n_half: &BigUint,
    secp_order: &BigUint,
) -> Scalar {
    if big <= n_half {
        // Positive: reduce directly mod q
        let reduced = big % secp_order;
        let be = reduced.to_bytes_be();
        let mut padded = [0u8; 32];
        padded[32usize.saturating_sub(be.len())..].copy_from_slice(&be);
        <Scalar as Reduce<U256>>::reduce_bytes(k256::FieldBytes::from_slice(&padded))
    } else {
        // Negative: true value is big - N, so Scalar = -(N - big) mod q
        let abs_val = n - big;
        let reduced = &abs_val % secp_order;
        let be = reduced.to_bytes_be();
        let mut padded = [0u8; 32];
        padded[32usize.saturating_sub(be.len())..].copy_from_slice(&be);
        let pos = <Scalar as Reduce<U256>>::reduce_bytes(k256::FieldBytes::from_slice(&padded));
        Scalar::ZERO - pos
    }
}
