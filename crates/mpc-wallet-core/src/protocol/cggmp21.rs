//! # CGGMP21 Threshold ECDSA Protocol (secp256k1)
//!
//! Implementation of the Canetti-Gennaro-Goldfeder-Makriyannis-Peled 2021
//! threshold ECDSA protocol with identifiable abort on secp256k1.
//!
//! ## Keygen Protocol
//!
//! The keygen runs in three rounds plus Feldman VSS:
//!
//! 1. **Round 1 — Commitment:** Each party generates a secret share `x_i`,
//!    computes `X_i = x_i * G`, and broadcasts `V_i = H(X_i || sid || i)`.
//!
//! 2. **Round 2 — Decommit + Schnorr proof:** Each party reveals `X_i` and
//!    a Schnorr proof of knowledge of `x_i`. All parties verify all proofs.
//!
//! 3. **Round 3 — Feldman VSS:** Each party distributes Feldman shares of
//!    their secret to all other parties, with verifiable commitments.
//!
//! 4. **Aux info:** Each party generates Paillier key pair `(N_i, p_i, q_i)`
//!    and Pedersen parameters `(s_i, t_i)` for use in the signing protocol.
//!
//! ## Security Properties
//!
//! - The full private key `x = Σ x_i` is **never reconstructed** during keygen.
//! - Identifiable abort: dishonest parties can be identified by verifying
//!   Schnorr proofs and Feldman commitments.
//! - All secret scalars are wrapped in `Zeroizing` for SEC-008 compliance.

use crate::error::CoreError;
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::{ProtocolMessage, Transport};
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

use async_trait::async_trait;
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, Field, PrimeField},
    ProjectivePoint, Scalar,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ─────────────────────────────────────────────────────────────────────────────
// Share data structures
// ─────────────────────────────────────────────────────────────────────────────

/// Per-party CGGMP21 key share data stored in `KeyShare.share_data`.
///
/// Contains the party's secret Feldman share, all public key shares, the
/// group public key, and auxiliary cryptographic parameters (Paillier, Pedersen)
/// needed for the signing protocol.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Cggmp21ShareData {
    /// This party's index (1-indexed).
    pub party_index: u16,
    /// This party's secret Feldman share (32 bytes, secp256k1 scalar).
    /// SEC-008: zeroized on drop via the containing struct's ZeroizeOnDrop.
    pub secret_share: Vec<u8>,
    /// All parties' public key shares X_i (compressed SEC1, 33 bytes each).
    #[zeroize(skip)]
    pub public_shares: Vec<Vec<u8>>,
    /// The combined group public key (compressed SEC1, 33 bytes).
    #[zeroize(skip)]
    pub group_public_key: Vec<u8>,
    /// Paillier secret key: serialized (p, q) primes.
    pub paillier_sk: Vec<u8>,
    /// Paillier public key: serialized N = p * q.
    #[zeroize(skip)]
    pub paillier_pk: Vec<u8>,
    /// Pedersen commitment parameters: serialized (s, t, N_hat).
    #[zeroize(skip)]
    pub pedersen_params: Vec<u8>,
}

/// Commitment message for Round 1.
#[derive(Serialize, Deserialize)]
struct Round1Commitment {
    /// Party index.
    party_index: u16,
    /// SHA-256 commitment hash: H(X_i || schnorr_proof || party_index).
    commitment: Vec<u8>,
}

/// Decommitment message for Round 2.
#[derive(Serialize, Deserialize)]
struct Round2Decommit {
    /// Party index.
    party_index: u16,
    /// Public key share X_i (compressed SEC1, 33 bytes).
    public_share: Vec<u8>,
    /// Schnorr proof of knowledge: (R, s) where R = k*G, s = k + e*x_i.
    schnorr_r: Vec<u8>,
    schnorr_s: Vec<u8>,
}

/// Feldman VSS share message for Round 3.
#[derive(Serialize, Deserialize)]
struct Round3FeldmanShare {
    /// Sender party index.
    from_party: u16,
    /// The Feldman share value for the recipient (32 bytes scalar).
    share_value: Vec<u8>,
    /// Feldman commitments: C_k = a_k * G for k = 0..t-1.
    commitments: Vec<Vec<u8>>,
}

/// Simulated Paillier key pair.
#[derive(Serialize, Deserialize)]
struct PaillierKeyPair {
    /// First prime p (32 bytes for simulation).
    p: Vec<u8>,
    /// Second prime q (32 bytes for simulation).
    q: Vec<u8>,
    /// Modulus N = p * q (conceptually; stored as the hash for simulation).
    n: Vec<u8>,
}

/// Simulated Pedersen parameters.
#[derive(Serialize, Deserialize)]
struct PedersenParams {
    /// Parameter s.
    s: Vec<u8>,
    /// Parameter t.
    t: Vec<u8>,
    /// Modulus N_hat.
    n_hat: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Polynomial helpers (Feldman VSS)
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate polynomial at `x`: `f(x) = c[0] + c[1]*x + c[2]*x^2 + ...`
fn poly_eval(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut x_pow = Scalar::ONE;
    for coeff in coefficients {
        result += coeff * &x_pow;
        x_pow *= x;
    }
    result
}

/// Compute Lagrange coefficient lambda_i(0) for party `i` in the given set.
/// Used in the signing protocol (T-S19-04).
#[allow(dead_code)]
fn lagrange_coefficient(party_index: u16, all_parties: &[u16]) -> Result<Scalar, CoreError> {
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
// Schnorr proof helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a Schnorr proof of knowledge of discrete log.
///
/// Proves knowledge of `x` such that `X = x * G`.
/// Returns (R, s) where R = k*G, e = H(R || X || party_index), s = k + e*x.
fn schnorr_prove(x: &Scalar, x_pub: &[u8], party_index: u16) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let k = Zeroizing::new(Scalar::random(&mut rng));
    let r_point = (ProjectivePoint::GENERATOR * *k).to_affine();
    let r_bytes = k256::PublicKey::from_affine(r_point)
        .expect("valid point")
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // Challenge: e = H(R || X || party_index)
    let mut hasher = Sha256::new();
    hasher.update(&r_bytes);
    hasher.update(x_pub);
    hasher.update(party_index.to_le_bytes());
    let e_bytes = hasher.finalize();
    let e = Scalar::from_repr(*k256::FieldBytes::from_slice(&e_bytes))
        .into_option()
        .unwrap_or_else(|| {
            // If the hash doesn't reduce to a valid scalar, reduce it modularly
            // by taking the lower 32 bytes as-is (it will be < 2^256 which is fine
            // for secp256k1 order ~2^256).
            Scalar::from_repr(*k256::FieldBytes::from_slice(&e_bytes))
                .into_option()
                .unwrap_or(Scalar::ONE)
        });

    let s = *k + e * x;
    let s_bytes = s.to_repr().to_vec();

    (r_bytes, s_bytes)
}

/// Verify a Schnorr proof of knowledge.
///
/// Checks that s*G == R + e*X where e = H(R || X || party_index).
fn schnorr_verify(
    x_pub_bytes: &[u8],
    r_bytes: &[u8],
    s_bytes: &[u8],
    party_index: u16,
) -> Result<bool, CoreError> {
    // Parse X
    let x_pub = k256::PublicKey::from_sec1_bytes(x_pub_bytes)
        .map_err(|e| CoreError::Crypto(format!("invalid public key: {e}")))?;
    let x_point = x_pub.to_projective();

    // Parse R
    let r_pub = k256::PublicKey::from_sec1_bytes(r_bytes)
        .map_err(|e| CoreError::Crypto(format!("invalid Schnorr R: {e}")))?;
    let r_point = r_pub.to_projective();

    // Parse s
    let s = Scalar::from_repr(*k256::FieldBytes::from_slice(s_bytes))
        .into_option()
        .ok_or_else(|| CoreError::Crypto("invalid Schnorr s scalar".into()))?;

    // Challenge: e = H(R || X || party_index)
    let mut hasher = Sha256::new();
    hasher.update(r_bytes);
    hasher.update(x_pub_bytes);
    hasher.update(party_index.to_le_bytes());
    let e_bytes = hasher.finalize();
    let e = Scalar::from_repr(*k256::FieldBytes::from_slice(&e_bytes))
        .into_option()
        .unwrap_or(Scalar::ONE);

    // Verify: s*G == R + e*X
    let lhs = ProjectivePoint::GENERATOR * s;
    let rhs = r_point + x_point * e;

    Ok(lhs == rhs)
}

// ─────────────────────────────────────────────────────────────────────────────
// Auxiliary info generation
// ─────────────────────────────────────────────────────────────────────────────

/// Generate simulated Paillier key pair deterministically from party secret.
///
/// In production, these would be large (2048-bit) primes. For simulation
/// purposes, we derive 32-byte values from the party's secret using SHA-256.
fn generate_paillier_keypair(secret: &Scalar, party_index: u16) -> PaillierKeyPair {
    let secret_bytes = secret.to_repr();

    // Derive p from H("paillier-p" || secret || party_index)
    let mut hasher = Sha256::new();
    hasher.update(b"paillier-p");
    hasher.update(secret_bytes.as_slice());
    hasher.update(party_index.to_le_bytes());
    let p = hasher.finalize().to_vec();

    // Derive q from H("paillier-q" || secret || party_index)
    let mut hasher = Sha256::new();
    hasher.update(b"paillier-q");
    hasher.update(secret_bytes.as_slice());
    hasher.update(party_index.to_le_bytes());
    let q = hasher.finalize().to_vec();

    // N = H("paillier-n" || p || q) (simulated modulus)
    let mut hasher = Sha256::new();
    hasher.update(b"paillier-n");
    hasher.update(&p);
    hasher.update(&q);
    let n = hasher.finalize().to_vec();

    PaillierKeyPair { p, q, n }
}

/// Generate simulated Pedersen parameters from party secret.
fn generate_pedersen_params(secret: &Scalar, party_index: u16) -> PedersenParams {
    let secret_bytes = secret.to_repr();

    let mut hasher = Sha256::new();
    hasher.update(b"pedersen-s");
    hasher.update(secret_bytes.as_slice());
    hasher.update(party_index.to_le_bytes());
    let s = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(b"pedersen-t");
    hasher.update(secret_bytes.as_slice());
    hasher.update(party_index.to_le_bytes());
    let t = hasher.finalize().to_vec();

    let mut hasher = Sha256::new();
    hasher.update(b"pedersen-n-hat");
    hasher.update(secret_bytes.as_slice());
    hasher.update(party_index.to_le_bytes());
    let n_hat = hasher.finalize().to_vec();

    PedersenParams { s, t, n_hat }
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol struct
// ─────────────────────────────────────────────────────────────────────────────

/// CGGMP21 threshold ECDSA protocol on secp256k1.
///
/// Supports identifiable abort — dishonest parties can be detected via
/// Schnorr proof verification and Feldman commitment checks.
pub struct Cggmp21Protocol;

impl Cggmp21Protocol {
    /// Create a new `Cggmp21Protocol` instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for Cggmp21Protocol {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MpcProtocol impl
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl MpcProtocol for Cggmp21Protocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Cggmp21Secp256k1
    }

    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        cggmp21_keygen(config, party_id, transport).await
    }

    async fn sign(
        &self,
        _key_share: &KeyShare,
        _signers: &[PartyId],
        _message: &[u8],
        _transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        // Signing will be implemented in a future sprint (T-S19-04).
        Err(CoreError::Protocol(
            "CGGMP21 signing not yet implemented".into(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CGGMP21 Keygen — 3 rounds + Feldman VSS + aux info
// ─────────────────────────────────────────────────────────────────────────────

/// CGGMP21 distributed keygen with Feldman VSS and auxiliary info generation.
///
/// Protocol flow:
/// 1. Round 1: Each party generates secret x_i, computes X_i = x_i*G,
///    broadcasts commitment V_i = H(X_i || schnorr_proof || i).
/// 2. Round 2: Each party reveals X_i and Schnorr proof of knowledge of x_i.
///    All parties verify proofs and compute group public key.
/// 3. Round 3: Each party performs Feldman VSS — distributes shares of x_i
///    with verifiable commitments to all other parties.
/// 4. Each party generates Paillier and Pedersen auxiliary parameters.
///
/// The full private key x = Σ x_i is NEVER reconstructed.
async fn cggmp21_keygen(
    config: ThresholdConfig,
    party_id: PartyId,
    transport: &dyn Transport,
) -> Result<KeyShare, CoreError> {
    let n = config.total_parties;
    let t = config.threshold;
    let my_index = party_id.0;

    // ── Step 1: Generate all random values before any .await ──────────
    // SEC-008: wrap secret scalar in Zeroizing.
    // ThreadRng is not Send, so generate all randomness upfront.
    let (x_i, feldman_extra_coeffs) = {
        let mut rng = rand::thread_rng();
        let x_i = Zeroizing::new(Scalar::random(&mut rng));
        let mut extra_coeffs: Vec<Zeroizing<Scalar>> = Vec::with_capacity((t - 1) as usize);
        for _ in 1..t {
            extra_coeffs.push(Zeroizing::new(Scalar::random(&mut rng)));
        }
        (x_i, extra_coeffs)
    };

    let x_i_point = (ProjectivePoint::GENERATOR * *x_i).to_affine();
    let x_i_pub =
        k256::PublicKey::from_affine(x_i_point).map_err(|e| CoreError::Crypto(e.to_string()))?;
    let x_i_pub_bytes = x_i_pub.to_encoded_point(true).as_bytes().to_vec();

    // Generate Schnorr proof of knowledge of x_i
    let (schnorr_r, schnorr_s) = schnorr_prove(&x_i, &x_i_pub_bytes, my_index);

    // ── Round 1: Broadcast commitment ───────────────────────────────────
    let mut hasher = Sha256::new();
    hasher.update(&x_i_pub_bytes);
    hasher.update(&schnorr_r);
    hasher.update(&schnorr_s);
    hasher.update(my_index.to_le_bytes());
    let commitment = hasher.finalize().to_vec();

    let round1_msg = Round1Commitment {
        party_index: my_index,
        commitment: commitment.clone(),
    };
    let round1_payload =
        serde_json::to_vec(&round1_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    // Broadcast to all other parties
    transport
        .send(ProtocolMessage {
            from: party_id,
            to: None,
            round: 1,
            payload: round1_payload,
        })
        .await?;

    // Receive commitments from all other parties
    let mut commitments: Vec<Round1Commitment> = vec![round1_msg];
    for _ in 1..n {
        let msg = transport.recv().await?;
        let r1: Round1Commitment = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        commitments.push(r1);
    }

    // Sort commitments by party index for deterministic ordering
    commitments.sort_by_key(|c| c.party_index);

    // ── Round 2: Broadcast decommitment + Schnorr proof ─────────────────
    let round2_msg = Round2Decommit {
        party_index: my_index,
        public_share: x_i_pub_bytes.clone(),
        schnorr_r: schnorr_r.clone(),
        schnorr_s: schnorr_s.clone(),
    };
    let round2_payload =
        serde_json::to_vec(&round2_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: party_id,
            to: None,
            round: 2,
            payload: round2_payload,
        })
        .await?;

    // Receive decommitments from all other parties
    let mut decommits: Vec<Round2Decommit> = vec![round2_msg];
    for _ in 1..n {
        let msg = transport.recv().await?;
        let r2: Round2Decommit = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        decommits.push(r2);
    }
    decommits.sort_by_key(|d| d.party_index);

    // ── Verify commitments and Schnorr proofs ───────────────────────────
    for decommit in &decommits {
        // Verify commitment: V_i == H(X_i || R || s || i)
        let mut hasher = Sha256::new();
        hasher.update(&decommit.public_share);
        hasher.update(&decommit.schnorr_r);
        hasher.update(&decommit.schnorr_s);
        hasher.update(decommit.party_index.to_le_bytes());
        let expected = hasher.finalize().to_vec();

        let stored_commitment = commitments
            .iter()
            .find(|c| c.party_index == decommit.party_index)
            .ok_or_else(|| {
                CoreError::Protocol(format!(
                    "missing commitment for party {}",
                    decommit.party_index
                ))
            })?;

        if stored_commitment.commitment != expected {
            return Err(CoreError::Protocol(format!(
                "commitment mismatch for party {} — identifiable abort",
                decommit.party_index
            )));
        }

        // Verify Schnorr proof of knowledge
        let valid = schnorr_verify(
            &decommit.public_share,
            &decommit.schnorr_r,
            &decommit.schnorr_s,
            decommit.party_index,
        )?;

        if !valid {
            return Err(CoreError::Protocol(format!(
                "invalid Schnorr proof from party {} — identifiable abort",
                decommit.party_index
            )));
        }
    }

    // ── Compute group public key: X = Σ X_i ─────────────────────────────
    let mut group_point = ProjectivePoint::IDENTITY;
    let mut public_shares: Vec<Vec<u8>> = Vec::with_capacity(n as usize);
    for decommit in &decommits {
        let pk = k256::PublicKey::from_sec1_bytes(&decommit.public_share)
            .map_err(|e| CoreError::Crypto(format!("invalid public share: {e}")))?;
        group_point += pk.to_projective();
        public_shares.push(decommit.public_share.clone());
    }

    let group_affine = group_point.to_affine();
    let group_pubkey =
        k256::PublicKey::from_affine(group_affine).map_err(|e| CoreError::Crypto(e.to_string()))?;
    let group_pubkey_bytes = group_pubkey.to_encoded_point(true).as_bytes().to_vec();

    // ── Round 3: Feldman VSS ────────────────────────────────────────────
    // Each party creates a polynomial f_i(x) with f_i(0) = x_i, degree t-1.
    // They send f_i(j) to party j, and broadcast commitments C_k = a_k * G.
    let mut feldman_coeffs: Vec<Zeroizing<Scalar>> = Vec::with_capacity(t as usize);
    feldman_coeffs.push(Zeroizing::new(*x_i));
    feldman_coeffs.extend(feldman_extra_coeffs);

    // Compute Feldman commitments: C_k = a_k * G
    let feldman_commitments: Vec<Vec<u8>> = feldman_coeffs
        .iter()
        .map(|coeff| {
            let point = (ProjectivePoint::GENERATOR * **coeff).to_affine();
            k256::PublicKey::from_affine(point)
                .expect("valid point")
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()
        })
        .collect();

    // Send Feldman shares to each party
    let raw_coeffs: Vec<Scalar> = feldman_coeffs.iter().map(|z| **z).collect();
    for j in 1..=n {
        if j == my_index {
            continue;
        }
        let x_j = Scalar::from(j as u64);
        let share_val = poly_eval(&raw_coeffs, &x_j);
        let share_msg = Round3FeldmanShare {
            from_party: my_index,
            share_value: share_val.to_repr().to_vec(),
            commitments: feldman_commitments.clone(),
        };
        let payload =
            serde_json::to_vec(&share_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;
        transport
            .send(ProtocolMessage {
                from: party_id,
                to: Some(PartyId(j)),
                round: 3,
                payload,
            })
            .await?;
    }

    // Compute our own share f_i(my_index)
    let my_x = Scalar::from(my_index as u64);
    let my_own_feldman_share = Zeroizing::new(poly_eval(&raw_coeffs, &my_x));

    // Explicitly zeroize the raw coefficients copy (SEC-008)
    let mut raw_coeffs = raw_coeffs;
    for coeff in raw_coeffs.iter_mut() {
        coeff.zeroize();
    }
    drop(raw_coeffs);

    // Receive Feldman shares from all other parties
    let mut received_shares: Vec<Round3FeldmanShare> = Vec::new();
    for _ in 1..(n) {
        let msg = transport.recv().await?;
        let r3: Round3FeldmanShare = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        received_shares.push(r3);
    }

    // ── Verify Feldman commitments and accumulate final share ────────────
    // Our final secret share = Σ_{j=1}^{n} f_j(my_index)
    let mut final_share = Zeroizing::new(*my_own_feldman_share);

    for share in &received_shares {
        // Parse share value
        let share_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(&share.share_value))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid Feldman share scalar".into()))?;

        // Verify: share_scalar * G == Σ_{k=0}^{t-1} C_k * my_index^k
        let share_point = ProjectivePoint::GENERATOR * share_scalar;
        let mut expected_point = ProjectivePoint::IDENTITY;
        let my_x_scalar = Scalar::from(my_index as u64);
        let mut x_pow = Scalar::ONE;
        for commitment_bytes in &share.commitments {
            let c_k = k256::PublicKey::from_sec1_bytes(commitment_bytes)
                .map_err(|e| CoreError::Crypto(format!("invalid Feldman commitment: {e}")))?;
            expected_point += c_k.to_projective() * x_pow;
            x_pow *= my_x_scalar;
        }

        if share_point != expected_point {
            return Err(CoreError::Protocol(format!(
                "Feldman verification failed for share from party {} — identifiable abort",
                share.from_party
            )));
        }

        // Accumulate into final share
        *final_share += share_scalar;
    }

    // ── Generate auxiliary info (Paillier + Pedersen) ────────────────────
    let paillier = generate_paillier_keypair(&x_i, my_index);
    let pedersen = generate_pedersen_params(&x_i, my_index);

    let paillier_sk_bytes = serde_json::to_vec(&(paillier.p.clone(), paillier.q.clone()))
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    let paillier_pk_bytes = paillier.n.clone();
    let pedersen_bytes =
        serde_json::to_vec(&pedersen).map_err(|e| CoreError::Serialization(e.to_string()))?;

    // ── Build share data ────────────────────────────────────────────────
    let share_data = Cggmp21ShareData {
        party_index: my_index,
        secret_share: final_share.to_repr().to_vec(),
        public_shares,
        group_public_key: group_pubkey_bytes.clone(),
        paillier_sk: paillier_sk_bytes,
        paillier_pk: paillier_pk_bytes,
        pedersen_params: pedersen_bytes,
    };

    let share_bytes =
        serde_json::to_vec(&share_data).map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(KeyShare {
        scheme: CryptoScheme::Cggmp21Secp256k1,
        party_id,
        config,
        group_public_key: GroupPublicKey::Secp256k1(group_pubkey_bytes),
        share_data: Zeroizing::new(share_bytes),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Schnorr proof tests ─────────────────────────────────────────────

    #[test]
    fn test_schnorr_proof_valid() {
        let mut rng = rand::thread_rng();
        let x = Scalar::random(&mut rng);
        let x_point = (ProjectivePoint::GENERATOR * x).to_affine();
        let x_pub = k256::PublicKey::from_affine(x_point)
            .unwrap()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let (r, s) = schnorr_prove(&x, &x_pub, 1);
        assert!(schnorr_verify(&x_pub, &r, &s, 1).unwrap());
    }

    #[test]
    fn test_schnorr_proof_wrong_index_fails() {
        let mut rng = rand::thread_rng();
        let x = Scalar::random(&mut rng);
        let x_point = (ProjectivePoint::GENERATOR * x).to_affine();
        let x_pub = k256::PublicKey::from_affine(x_point)
            .unwrap()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let (r, s) = schnorr_prove(&x, &x_pub, 1);
        // Verify with wrong party index should fail
        assert!(!schnorr_verify(&x_pub, &r, &s, 2).unwrap());
    }

    // ── Feldman polynomial tests ────────────────────────────────────────

    #[test]
    fn test_poly_eval_constant() {
        let c = Scalar::from(42u64);
        assert_eq!(poly_eval(&[c], &Scalar::from(5u64)), c);
    }

    #[test]
    fn test_poly_eval_linear() {
        // f(x) = 3 + 7x => f(2) = 17
        let coeffs = [Scalar::from(3u64), Scalar::from(7u64)];
        assert_eq!(poly_eval(&coeffs, &Scalar::from(2u64)), Scalar::from(17u64));
    }

    #[test]
    fn test_lagrange_coefficient_simple() {
        // For parties {1, 2}: lambda_1(0) = (0-2)/(1-2) = 2
        let lambda = lagrange_coefficient(1, &[1, 2]).unwrap();
        assert_eq!(lambda, Scalar::from(2u64));
    }

    // ── Paillier + Pedersen aux info tests ──────────────────────────────

    #[test]
    fn test_paillier_keypair_generated() {
        let secret = Scalar::from(42u64);
        let kp = generate_paillier_keypair(&secret, 1);
        assert_eq!(kp.p.len(), 32);
        assert_eq!(kp.q.len(), 32);
        assert_eq!(kp.n.len(), 32);
        // Different parties get different keys
        let kp2 = generate_paillier_keypair(&secret, 2);
        assert_ne!(kp.p, kp2.p);
        assert_ne!(kp.q, kp2.q);
    }

    #[test]
    fn test_pedersen_params_generated() {
        let secret = Scalar::from(42u64);
        let pp = generate_pedersen_params(&secret, 1);
        assert_eq!(pp.s.len(), 32);
        assert_eq!(pp.t.len(), 32);
        assert_eq!(pp.n_hat.len(), 32);
    }

    // ── Share data serialization test ───────────────────────────────────

    #[test]
    fn test_cggmp21_share_data_serde_roundtrip() {
        let share = Cggmp21ShareData {
            party_index: 1,
            secret_share: vec![1u8; 32],
            public_shares: vec![vec![2u8; 33], vec![3u8; 33]],
            group_public_key: vec![4u8; 33],
            paillier_sk: vec![5u8; 64],
            paillier_pk: vec![6u8; 32],
            pedersen_params: vec![7u8; 96],
        };

        let bytes = serde_json::to_vec(&share).unwrap();
        let restored: Cggmp21ShareData = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(restored.party_index, 1);
        assert_eq!(restored.secret_share, vec![1u8; 32]);
        assert_eq!(restored.public_shares.len(), 2);
        assert_eq!(restored.group_public_key, vec![4u8; 33]);
        assert!(!restored.paillier_sk.is_empty());
        assert!(!restored.paillier_pk.is_empty());
        assert!(!restored.pedersen_params.is_empty());
    }

    // ── Integration tests using LocalTransport ──────────────────────────

    #[tokio::test]
    async fn test_cggmp21_keygen_2_of_3() {
        use crate::transport::local::LocalTransportNetwork;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        let mut shares = Vec::new();
        for h in handles {
            let share = h.await.unwrap().unwrap();
            assert_eq!(share.scheme, CryptoScheme::Cggmp21Secp256k1);
            shares.push(share);
        }

        // All parties must agree on the group public key
        let gpk = shares[0].group_public_key.as_bytes();
        for share in &shares[1..] {
            assert_eq!(
                share.group_public_key.as_bytes(),
                gpk,
                "all parties must have same group public key"
            );
        }

        // Verify the group public key is a valid secp256k1 point
        let pk = k256::PublicKey::from_sec1_bytes(gpk);
        assert!(pk.is_ok(), "group public key must be a valid SEC1 point");
    }

    #[tokio::test]
    async fn test_cggmp21_keygen_3_of_5() {
        use crate::transport::local::LocalTransportNetwork;

        let config = ThresholdConfig::new(3, 5).unwrap();
        let net = LocalTransportNetwork::new(5);

        let mut handles = Vec::new();
        for i in 1..=5u16 {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        let mut shares = Vec::new();
        for h in handles {
            let share = h.await.unwrap().unwrap();
            shares.push(share);
        }

        // All 5 parties must agree on the group public key
        let gpk = shares[0].group_public_key.as_bytes();
        for share in &shares[1..] {
            assert_eq!(share.group_public_key.as_bytes(), gpk);
        }

        // Verify config is preserved
        assert_eq!(shares[0].config.threshold, 3);
        assert_eq!(shares[0].config.total_parties, 5);
    }

    #[tokio::test]
    async fn test_cggmp21_aux_info_generated() {
        use crate::transport::local::LocalTransportNetwork;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        for h in handles {
            let share = h.await.unwrap().unwrap();
            // Deserialize share data and verify aux info exists
            let data: Cggmp21ShareData = serde_json::from_slice(&share.share_data).unwrap();

            // Secret share must be 32 bytes (secp256k1 scalar)
            assert_eq!(data.secret_share.len(), 32, "secret share must be 32 bytes");

            // Public shares: one per party
            assert_eq!(data.public_shares.len(), 3, "must have 3 public shares");
            for ps in &data.public_shares {
                assert_eq!(ps.len(), 33, "compressed SEC1 point is 33 bytes");
            }

            // Paillier keys must be non-empty
            assert!(!data.paillier_sk.is_empty(), "Paillier SK must exist");
            assert!(!data.paillier_pk.is_empty(), "Paillier PK must exist");

            // Pedersen params must be non-empty
            assert!(
                !data.pedersen_params.is_empty(),
                "Pedersen params must exist"
            );

            // Verify Paillier SK can be deserialized
            let (p, q): (Vec<u8>, Vec<u8>) = serde_json::from_slice(&data.paillier_sk).unwrap();
            assert_eq!(p.len(), 32);
            assert_eq!(q.len(), 32);

            // Verify Pedersen params can be deserialized
            let pp: PedersenParams = serde_json::from_slice(&data.pedersen_params).unwrap();
            assert_eq!(pp.s.len(), 32);
            assert_eq!(pp.t.len(), 32);
            assert_eq!(pp.n_hat.len(), 32);
        }
    }

    #[tokio::test]
    async fn test_cggmp21_share_data_format() {
        use crate::transport::local::LocalTransportNetwork;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        for (idx, h) in handles.into_iter().enumerate() {
            let share = h.await.unwrap().unwrap();
            // Verify share_data can be round-tripped through JSON
            let data: Cggmp21ShareData = serde_json::from_slice(&share.share_data).unwrap();
            let re_serialized = serde_json::to_vec(&data).unwrap();
            let data2: Cggmp21ShareData = serde_json::from_slice(&re_serialized).unwrap();

            assert_eq!(data.party_index, data2.party_index);
            assert_eq!(data.secret_share, data2.secret_share);
            assert_eq!(data.group_public_key, data2.group_public_key);
            assert_eq!(data.public_shares.len(), data2.public_shares.len());

            // Party index should match (1-indexed)
            assert_eq!(data.party_index, (idx + 1) as u16);
        }
    }
}
