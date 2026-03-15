//! # ⚠️  SECURITY WARNING — SIMULATION ONLY
//!
//! This GG20 implementation is a **trusted-dealer simulation**.
//! During signing, every party reconstructs the full private key via Lagrange
//! interpolation. This completely negates the MPC security guarantee.
//!
//! This code is gated behind the `gg20-simulation` feature flag and MUST NOT
//! be enabled in production. It exists only to keep existing tests passing
//! while Sprint 2 implements real multi-party ECDSA (SEC-001).
//!
//! Status: SEC-001 CRITICAL — scheduled for replacement in Sprint 2 (T-S2-01).

use crate::error::CoreError;
use crate::protocol::{KeyShare, MpcProtocol, MpcSignature};
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};
use crate::transport::Transport;

#[cfg(feature = "gg20-simulation")]
use crate::protocol::GroupPublicKey;

// ─────────────────────────────────────────────────────────────────────────────
// SIMULATION build (feature = "gg20-simulation")
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "gg20-simulation")]
use async_trait::async_trait;
#[cfg(feature = "gg20-simulation")]
use k256::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(feature = "gg20-simulation")]
use k256::elliptic_curve::{Field, PrimeField};
#[cfg(feature = "gg20-simulation")]
use k256::{ProjectivePoint, Scalar, SecretKey};
#[cfg(feature = "gg20-simulation")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "gg20-simulation")]
use zeroize::ZeroizeOnDrop;
#[cfg(feature = "gg20-simulation")]
use crate::transport::ProtocolMessage;

/// Simulated GG20 threshold ECDSA protocol.
///
/// Uses Shamir's secret sharing for keygen and Lagrange interpolation + k256 ECDSA
/// for signing. Produces real, verifiable ECDSA signatures.
///
/// # ⚠️  SECURITY: SIMULATION ONLY — reconstructs full private key — NOT FOR PRODUCTION
///
/// Gated behind `gg20-simulation` feature. See module-level doc for details (SEC-001).
#[cfg(feature = "gg20-simulation")]
pub struct Gg20Protocol;

#[cfg(feature = "gg20-simulation")]
impl Gg20Protocol {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "gg20-simulation")]
impl Default for Gg20Protocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Data stored per-party in KeyShare.share_data
#[cfg(feature = "gg20-simulation")]
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct Gg20ShareData {
    /// This party's x-coordinate (1-indexed party number)
    x: u16,
    /// This party's share value y = f(x), as 32 bytes (big-endian scalar)
    y: Vec<u8>,
}

/// Evaluate polynomial at a point: f(x) = coefficients[0] + coefficients[1]*x + ...
#[cfg(feature = "gg20-simulation")]
fn poly_eval(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut x_pow = Scalar::ONE;
    for coeff in coefficients {
        result += coeff * &x_pow;
        x_pow *= x;
    }
    result
}

/// Shamir secret sharing: split a secret into n shares with threshold t.
#[cfg(feature = "gg20-simulation")]
fn shamir_split(
    secret: &Scalar,
    threshold: u16,
    total: u16,
) -> Vec<(u16, Scalar)> {
    let mut rng = rand::thread_rng();
    let mut coefficients = vec![*secret];
    for _ in 1..threshold {
        coefficients.push(Scalar::random(&mut rng));
    }

    (1..=total)
        .map(|i| {
            let x = Scalar::from(i as u64);
            let y = poly_eval(&coefficients, &x);
            (i, y)
        })
        .collect()
}

/// Lagrange interpolation at x=0 to reconstruct the secret.
#[cfg(feature = "gg20-simulation")]
fn lagrange_interpolate(shares: &[(u16, Scalar)]) -> Scalar {
    let mut result = Scalar::ZERO;
    for (i, &(x_i, ref y_i)) in shares.iter().enumerate() {
        let x_i_s = Scalar::from(x_i as u64);
        let mut basis = Scalar::ONE;
        for (j, &(x_j, _)) in shares.iter().enumerate() {
            if i != j {
                let x_j_s = Scalar::from(x_j as u64);
                // L_i(0) = product_{j!=i} (0 - x_j) / (x_i - x_j)
                let num = Scalar::ZERO - x_j_s;
                let den = x_i_s - x_j_s;
                let den_inv = den.invert();
                // den should never be zero since x_i != x_j
                assert!(bool::from(den_inv.is_some()), "zero denominator in Lagrange");
                basis *= num * den_inv.unwrap();
            }
        }
        result += *y_i * basis;
    }
    result
}

#[cfg(feature = "gg20-simulation")]
#[async_trait]
impl MpcProtocol for Gg20Protocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Gg20Ecdsa
    }

    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        // Party 1 generates the secret and distributes shares.
        // Other parties receive their share.
        if party_id == PartyId(1) {
            // Do all RNG + crypto work before any .await to avoid Send issues
            let secret = Scalar::random(&mut rand::thread_rng());
            let public_point = (ProjectivePoint::GENERATOR * secret).to_affine();
            let public_key = k256::PublicKey::from_affine(public_point)
                .map_err(|e| CoreError::Crypto(e.to_string()))?;
            let uncompressed = public_key.to_encoded_point(false);
            let compressed = public_key.to_encoded_point(true);
            let group_pubkey_bytes = compressed.as_bytes().to_vec();
            let group_pubkey_uncompressed = uncompressed.as_bytes().to_vec();
            let shares = shamir_split(&secret, config.threshold, config.total_parties);

            // Pre-serialize all messages before entering async code
            let mut messages = Vec::new();
            for &(x, ref y) in &shares {
                let target = PartyId(x);
                if target == party_id {
                    continue;
                }
                let share_data = Gg20ShareData {
                    x,
                    y: y.to_repr().to_vec(),
                };
                let payload = serde_json::to_vec(&share_data)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
                let msg_data = serde_json::to_vec(&(payload.clone(), group_pubkey_bytes.clone(), group_pubkey_uncompressed.clone()))
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
                messages.push((target, msg_data));
            }

            // Now send via transport (async)
            for (target, msg_data) in messages {
                transport
                    .send(ProtocolMessage {
                        from: party_id,
                        to: Some(target),
                        round: 1,
                        payload: msg_data,
                    })
                    .await?;
            }

            // Party 1's own share
            let my_share = shares.iter().find(|(x, _)| *x == 1).unwrap();
            let share_data = Gg20ShareData {
                x: my_share.0,
                y: my_share.1.to_repr().to_vec(),
            };

            Ok(KeyShare {
                scheme: CryptoScheme::Gg20Ecdsa,
                party_id,
                config,
                group_public_key: GroupPublicKey::Secp256k1(group_pubkey_bytes),
                share_data: serde_json::to_vec(&share_data)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?,
            })
        } else {
            // Receive share from party 1
            let msg = transport.recv().await?;
            let (share_bytes, group_pubkey_bytes, _uncompressed): (Vec<u8>, Vec<u8>, Vec<u8>) =
                serde_json::from_slice(&msg.payload)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;

            // share_bytes is the serialized Gg20ShareData
            // Validate it deserializes correctly
            let _share_data: Gg20ShareData = serde_json::from_slice(&share_bytes)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

            Ok(KeyShare {
                scheme: CryptoScheme::Gg20Ecdsa,
                party_id,
                config,
                group_public_key: GroupPublicKey::Secp256k1(group_pubkey_bytes),
                share_data: share_bytes,
            })
        }
    }

    async fn sign(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        message: &[u8],
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        let my_share: Gg20ShareData = serde_json::from_slice(&key_share.share_data)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let my_y = Scalar::from_repr(
            *k256::FieldBytes::from_slice(&my_share.y),
        );
        if bool::from(my_y.is_none()) {
            return Err(CoreError::Crypto("invalid share scalar".into()));
        }
        let my_y = my_y.unwrap();

        // Broadcast our share to all other signers
        let payload = serde_json::to_vec(&(my_share.x, my_share.y.clone()))
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        transport
            .send(ProtocolMessage {
                from: key_share.party_id,
                to: None,
                round: 1,
                payload,
            })
            .await?;

        // Collect shares from other signers
        let mut collected_shares: Vec<(u16, Scalar)> = vec![(my_share.x, my_y)];
        for _ in 0..(signers.len() - 1) {
            let msg = transport.recv().await?;
            let (x, y_bytes): (u16, Vec<u8>) = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let y = Scalar::from_repr(*k256::FieldBytes::from_slice(&y_bytes));
            if bool::from(y.is_none()) {
                return Err(CoreError::Crypto("invalid share from peer".into()));
            }
            collected_shares.push((x, y.unwrap()));
        }

        // Reconstruct the secret via Lagrange interpolation
        // ⚠️  SECURITY: SIMULATION ONLY — this reconstructs the full private key
        let secret = lagrange_interpolate(&collected_shares);

        // Sign with k256 ECDSA
        let secret_key = SecretKey::from_bytes(&secret.to_repr())
            .map_err(|e| CoreError::Crypto(e.to_string()))?;
        let signing_key = k256::ecdsa::SigningKey::from(secret_key);

        // Use RFC 6979 deterministic signing
        use k256::ecdsa::signature::Signer;
        let sig: k256::ecdsa::Signature = signing_key.sign(message);

        let r = sig.r().to_bytes().to_vec();
        let s = sig.s().to_bytes().to_vec();

        // Compute recovery_id by trying both values
        let verifying_key = signing_key.verifying_key();
        let recovery_id = (0u8..2)
            .find(|&v| {
                let recid = k256::ecdsa::RecoveryId::try_from(v).unwrap();
                k256::ecdsa::VerifyingKey::recover_from_prehash(
                    // For non-prehash signing, we need to hash first
                    &{
                        use sha2::Digest;
                        sha2::Sha256::digest(message)
                    },
                    &sig,
                    recid,
                )
                .map(|recovered| recovered == *verifying_key)
                .unwrap_or(false)
            })
            .unwrap_or(0);

        Ok(MpcSignature::Ecdsa { r, s, recovery_id })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PRODUCTION stub (feature = "gg20-simulation" is OFF — the default)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(feature = "gg20-simulation"))]
/// Placeholder — real GG20/CGGMP21 implementation coming in Sprint 2 (T-S2-01).
/// See SEC-001 in docs/SECURITY_FINDINGS.md.
pub struct Gg20Protocol;

#[cfg(not(feature = "gg20-simulation"))]
impl Gg20Protocol {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "gg20-simulation"))]
impl Default for Gg20Protocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "gg20-simulation"))]
#[async_trait::async_trait]
impl MpcProtocol for Gg20Protocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Gg20Ecdsa
    }

    async fn keygen(
        &self,
        _config: ThresholdConfig,
        _party_id: PartyId,
        _transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        Err(CoreError::Protocol(
            "GG20 real implementation not yet available — see Sprint 2 T-S2-01".to_string(),
        ))
    }

    async fn sign(
        &self,
        _key_share: &KeyShare,
        _signers: &[PartyId],
        _message: &[u8],
        _transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        Err(CoreError::Protocol(
            "GG20 real implementation not yet available — see Sprint 2 T-S2-01".to_string(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — only compiled when the simulation feature is enabled
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "gg20-simulation"))]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_roundtrip() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let shares = shamir_split(&secret, 2, 3);

        // Any 2 of 3 shares should reconstruct the secret
        let reconstructed = lagrange_interpolate(&shares[..2]);
        assert_eq!(secret, reconstructed);

        let reconstructed2 = lagrange_interpolate(&[shares[0], shares[2]]);
        assert_eq!(secret, reconstructed2);

        let reconstructed3 = lagrange_interpolate(&[shares[1], shares[2]]);
        assert_eq!(secret, reconstructed3);
    }
}
