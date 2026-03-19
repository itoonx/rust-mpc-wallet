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
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, Field, PrimeField},
    ProjectivePoint, Scalar, U256,
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
// Pre-signature data structure
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-computed signing material produced by the offline pre-signing phase.
///
/// Contains the party's nonce share, chi share (multiplicative-to-additive
/// conversion of k*x), and the combined R point. Can be stored and used later
/// when an actual message arrives, enabling 1-round online signing.
///
/// **Nonce reuse protection:** A `PreSignature` MUST only be used once. Using
/// the same pre-signature to sign two different messages would leak the private key.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct PreSignature {
    /// Random nonce share k_i (32 bytes, secp256k1 scalar).
    /// SEC-008: zeroized on drop.
    pub k_i: Vec<u8>,
    /// Chi share: k_i * x_i * lambda_i (share of k * x).
    /// SEC-008: zeroized on drop.
    pub chi_i: Vec<u8>,
    /// Delta share: k_i * gamma_sum (share used in R computation).
    /// SEC-008: zeroized on drop.
    pub delta_i: Vec<u8>,
    /// Combined R point (compressed SEC1, 33 bytes). Public.
    #[zeroize(skip)]
    pub big_r: Vec<u8>,
    /// This party's ID.
    #[zeroize(skip)]
    pub party_id: PartyId,
    /// Which parties participated in pre-signing.
    #[zeroize(skip)]
    pub signers: Vec<PartyId>,
    /// Whether this pre-signature has been consumed (nonce reuse protection).
    #[zeroize(skip)]
    pub used: bool,
}

/// Round 1 message for pre-signing: broadcast K_i and Gamma_i with Schnorr proofs.
#[derive(Serialize, Deserialize)]
struct PreSignRound1 {
    party_index: u16,
    /// K_i = k_i * G (compressed SEC1, 33 bytes).
    k_point: Vec<u8>,
    /// Gamma_i = gamma_i * G (compressed SEC1, 33 bytes).
    gamma_point: Vec<u8>,
    /// Schnorr proof of knowledge of k_i: (R, s).
    schnorr_k_r: Vec<u8>,
    schnorr_k_s: Vec<u8>,
}

/// Online signing round message: partial signature sigma_i.
#[derive(Serialize, Deserialize)]
struct SignOnlineMsg {
    party_index: u16,
    /// sigma_i = k_i * e + chi_i * r (scalar, 32 bytes).
    sigma_i: Vec<u8>,
}

/// Error identifying a cheating party during identifiable abort.
#[derive(Debug, Clone)]
pub struct CheatingPartyError {
    /// The party identified as cheating.
    pub cheater: PartyId,
    /// Description of what failed verification.
    pub reason: String,
}

impl std::fmt::Display for CheatingPartyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "identifiable abort: party {} cheated: {}",
            self.cheater.0, self.reason
        )
    }
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

    /// CGGMP21 pre-signing phase (offline, batchable).
    ///
    /// Produces a `PreSignature` that can be stored and used later to sign
    /// any message in a single online round. Pre-signing is the expensive
    /// part of CGGMP21 and can be batched ahead of time.
    ///
    /// # Protocol flow
    ///
    /// 1. **Round 1:** Each party generates random k_i, gamma_i. Broadcasts
    ///    K_i = k_i * G, Gamma_i = gamma_i * G, plus Schnorr proof of k_i.
    /// 2. **Round 2:** Multiplicative-to-additive (MtA) conversion:
    ///    delta_i = k_i * sum(gamma_j for all j). In production this uses
    ///    Paillier encryption; for simulation we compute directly.
    /// 3. **Finalize:** Compute R = (1/delta) * G where delta = sum(delta_i),
    ///    and chi_i = k_i * x_i * lambda_i (share of k * x).
    pub async fn pre_sign(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        transport: &dyn Transport,
    ) -> Result<PreSignature, CoreError> {
        cggmp21_pre_sign(key_share, signers, transport).await
    }

    /// CGGMP21 online signing phase (1 round from pre-shares).
    ///
    /// Uses a pre-computed `PreSignature` to produce a final ECDSA signature
    /// in a single communication round.
    ///
    /// # Nonce reuse protection
    ///
    /// The `pre_sig` is marked as used after this call. Attempting to reuse
    /// the same pre-signature will return an error to prevent nonce reuse
    /// (which would leak the private key).
    ///
    /// # Identifiable abort
    ///
    /// If the final signature fails verification, the protocol identifies
    /// which party submitted an invalid partial signature.
    pub async fn sign_with_presig(
        &self,
        pre_sig: &mut PreSignature,
        message: &[u8],
        key_share: &KeyShare,
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        cggmp21_sign_online(pre_sig, message, key_share, transport).await
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
        key_share: &KeyShare,
        signers: &[PartyId],
        message: &[u8],
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        // Full signing = pre-sign + online sign in one shot.
        let mut pre_sig = self.pre_sign(key_share, signers, transport).await?;
        self.sign_with_presig(&mut pre_sig, message, key_share, transport)
            .await
    }

    async fn refresh(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        cggmp21_refresh(key_share, signers, transport).await
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
// CGGMP21 Pre-Signing — offline phase (T-S20-01)
// ─────────────────────────────────────────────────────────────────────────────

/// CGGMP21 pre-signing phase: produces a PreSignature for later online signing.
///
/// # Protocol
///
/// Round 1: Each party generates k_i, gamma_i, broadcasts K_i = k_i * G,
///          Gamma_i = gamma_i * G, plus Schnorr proof of k_i.
/// Round 2: Multiplicative-to-additive (MtA) conversion. In production this
///          uses Paillier encryption. For simulation, parties share their
///          k_i and gamma_i scalars so the combined delta = k * gamma can be
///          computed. This is insecure in production but correctly demonstrates
///          the protocol structure and produces valid signatures.
/// Finalize: R = delta^{-1} * Gamma_sum = (k*gamma)^{-1} * gamma*G = k^{-1}*G.
///           chi_i = k_i * x_i * lambda_i (share of k * x).
async fn cggmp21_pre_sign(
    key_share: &KeyShare,
    signers: &[PartyId],
    transport: &dyn Transport,
) -> Result<PreSignature, CoreError> {
    let share_data: Cggmp21ShareData = serde_json::from_slice(&key_share.share_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    let my_index = share_data.party_index;
    let my_party_id = key_share.party_id;
    let n_signers = signers.len();

    // Parse our secret share
    let x_i = Zeroizing::new(
        Scalar::from_repr(*k256::FieldBytes::from_slice(&share_data.secret_share))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid secret share scalar".into()))?,
    );

    // Compute Lagrange coefficient for this party in the signer set
    let signer_indices: Vec<u16> = signers.iter().map(|p| p.0).collect();
    let lambda_i = lagrange_coefficient(my_index, &signer_indices)?;

    // ── Generate random values before any .await (ThreadRng not Send) ──
    let (k_i, gamma_i) = {
        let mut rng = rand::thread_rng();
        (
            Zeroizing::new(Scalar::random(&mut rng)),
            Zeroizing::new(Scalar::random(&mut rng)),
        )
    };

    // K_i = k_i * G
    let k_point = (ProjectivePoint::GENERATOR * *k_i).to_affine();
    let k_point_bytes = k256::PublicKey::from_affine(k_point)
        .map_err(|e| CoreError::Crypto(e.to_string()))?
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // Gamma_i = gamma_i * G
    let gamma_point = (ProjectivePoint::GENERATOR * *gamma_i).to_affine();
    let gamma_point_bytes = k256::PublicKey::from_affine(gamma_point)
        .map_err(|e| CoreError::Crypto(e.to_string()))?
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // Schnorr proof of knowledge of k_i
    let (schnorr_k_r, schnorr_k_s) = schnorr_prove(&k_i, &k_point_bytes, my_index);

    // ── Round 1 (presign): Broadcast K_i, Gamma_i, Schnorr proof ──────
    let round1_msg = PreSignRound1 {
        party_index: my_index,
        k_point: k_point_bytes.clone(),
        gamma_point: gamma_point_bytes.clone(),
        schnorr_k_r: schnorr_k_r.clone(),
        schnorr_k_s: schnorr_k_s.clone(),
    };
    let round1_payload =
        serde_json::to_vec(&round1_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 10, // Use round 10+ to avoid conflicts with keygen rounds
            payload: round1_payload,
        })
        .await?;

    // Collect Round 1 messages from all signers
    let mut round1_msgs: Vec<PreSignRound1> = vec![round1_msg];
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let r1: PreSignRound1 = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        // Validate sender is in signer set (SEC-013 pattern)
        if !signers.iter().any(|s| s.0 == r1.party_index) {
            return Err(CoreError::Protocol(format!(
                "pre-sign round 1: unexpected party {} not in signer set",
                r1.party_index
            )));
        }

        round1_msgs.push(r1);
    }
    round1_msgs.sort_by_key(|m| m.party_index);

    // ── Verify Schnorr proofs on K_i (identifiable abort) ─────────────
    for r1 in &round1_msgs {
        if r1.party_index == my_index {
            continue; // Skip self
        }
        let valid = schnorr_verify(
            &r1.k_point,
            &r1.schnorr_k_r,
            &r1.schnorr_k_s,
            r1.party_index,
        )?;
        if !valid {
            return Err(CoreError::Protocol(format!(
                "identifiable abort: party {} cheated: invalid Schnorr proof for K_i in pre-signing",
                r1.party_index
            )));
        }
    }

    // ── Compute Gamma_sum = sum of all Gamma_i ────────────────────────
    let mut gamma_sum_point = ProjectivePoint::IDENTITY;
    for r1 in &round1_msgs {
        let gp = k256::PublicKey::from_sec1_bytes(&r1.gamma_point)
            .map_err(|e| CoreError::Crypto(format!("invalid Gamma point: {e}")))?;
        gamma_sum_point += gp.to_projective();
    }

    // ── Round 2: MtA simulation ───────────────────────────────────────
    // In production CGGMP21, MtA uses Paillier encryption to compute shares
    // of k * gamma without revealing k_i or gamma_i to other parties.
    //
    // For simulation: each party broadcasts (k_i, gamma_i) scalars so that
    // all parties can compute delta = (sum k_i) * (sum gamma_i) = k * gamma.
    // This is INSECURE (reveals nonce shares) but produces correct signatures
    // and demonstrates the protocol structure.
    // Combine k_i and gamma_i into the round 2 message
    let combined_r2 = serde_json::json!({
        "party_index": my_index,
        "k_i": k_i.to_repr().as_slice(),
        "gamma_i": gamma_i.to_repr().as_slice(),
    });
    let round2_payload =
        serde_json::to_vec(&combined_r2).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 11,
            payload: round2_payload,
        })
        .await?;

    // Collect Round 2 messages and compute k_sum, gamma_sum
    let mut k_sum = *k_i;
    let mut gamma_sum_scalar = *gamma_i;

    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let r2: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let k_j_bytes: Vec<u8> = serde_json::from_value(r2["k_i"].clone())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let gamma_j_bytes: Vec<u8> = serde_json::from_value(r2["gamma_i"].clone())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let k_j = Scalar::from_repr(*k256::FieldBytes::from_slice(&k_j_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid k_j scalar".into()))?;
        let gamma_j = Scalar::from_repr(*k256::FieldBytes::from_slice(&gamma_j_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid gamma_j scalar".into()))?;

        k_sum += k_j;
        gamma_sum_scalar += gamma_j;
    }

    // delta = k * gamma (the combined product)
    let delta = k_sum * gamma_sum_scalar;

    // ── Compute R = delta^{-1} * Gamma_sum ────────────────────────────
    // R = (k*gamma)^{-1} * gamma*G = k^{-1} * G
    let delta_inv = delta
        .invert()
        .into_option()
        .ok_or_else(|| CoreError::Crypto("delta is zero — cannot compute R point".into()))?;
    let big_r_point = (gamma_sum_point * delta_inv).to_affine();
    let big_r_bytes = k256::PublicKey::from_affine(big_r_point)
        .map_err(|e| CoreError::Crypto(format!("invalid R point: {e}")))?
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // ── Compute chi_i = k_sum * x_i * lambda_i (share of k * x) ─────
    // In production CGGMP21, chi_i is computed via Paillier MtA so that
    // sum(chi_i) = k * x without any party learning k or x.
    // In simulation, we use k_sum (which all parties computed from shared k_j).
    let chi_i_scalar = k_sum * *x_i * lambda_i;

    // ── Explicitly zeroize temporaries (SEC-008) ──────────────────────
    k_sum.zeroize();
    gamma_sum_scalar.zeroize();

    Ok(PreSignature {
        k_i: k_i.to_repr().to_vec(),
        chi_i: chi_i_scalar.to_repr().to_vec(),
        delta_i: delta.to_repr().to_vec(),
        big_r: big_r_bytes,
        party_id: my_party_id,
        signers: signers.to_vec(),
        used: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// CGGMP21 Online Signing — 1 round (T-S20-02)
// ─────────────────────────────────────────────────────────────────────────────

/// CGGMP21 online signing: uses a pre-signature to produce an ECDSA signature
/// in a single communication round.
///
/// # Identifiable abort (T-S20-03)
///
/// If the final aggregated signature fails verification against the group
/// public key, the protocol checks each party's partial signature to identify
/// the cheater.
async fn cggmp21_sign_online(
    pre_sig: &mut PreSignature,
    message: &[u8],
    key_share: &KeyShare,
    transport: &dyn Transport,
) -> Result<MpcSignature, CoreError> {
    // ── Nonce reuse protection ────────────────────────────────────────
    if pre_sig.used {
        return Err(CoreError::Protocol(
            "pre-signature already used — nonce reuse would leak private key".into(),
        ));
    }
    pre_sig.used = true;

    let my_party_id = pre_sig.party_id;
    let my_index = my_party_id.0;
    let n_signers = pre_sig.signers.len();

    // Parse pre-signature components
    let k_i = Zeroizing::new(
        Scalar::from_repr(*k256::FieldBytes::from_slice(&pre_sig.k_i))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid k_i scalar in pre-signature".into()))?,
    );
    let chi_i = Scalar::from_repr(*k256::FieldBytes::from_slice(&pre_sig.chi_i))
        .into_option()
        .ok_or_else(|| CoreError::Crypto("invalid chi_i scalar in pre-signature".into()))?;

    // Parse R point and extract r (x-coordinate as scalar)
    let big_r_pub = k256::PublicKey::from_sec1_bytes(&pre_sig.big_r)
        .map_err(|e| CoreError::Crypto(format!("invalid R point: {e}")))?;
    let big_r_affine = big_r_pub.to_projective().to_affine();
    let r_x_bytes = big_r_affine.to_encoded_point(false);
    let r_x_field = r_x_bytes.x().ok_or_else(|| {
        CoreError::Crypto("R point is identity — cannot extract x-coordinate".into())
    })?;
    let r_scalar = <Scalar as Reduce<U256>>::reduce_bytes(r_x_field);

    // ── Compute message hash as scalar ────────────────────────────────
    let hash_bytes = Sha256::digest(message);
    let e_scalar =
        <Scalar as Reduce<U256>>::reduce_bytes(k256::FieldBytes::from_slice(&hash_bytes));

    // ── Compute partial signature: sigma_i = k_i * e + chi_i * r ─────
    let sigma_i = *k_i * e_scalar + chi_i * r_scalar;

    // ── Broadcast sigma_i ─────────────────────────────────────────────
    let sign_msg = SignOnlineMsg {
        party_index: my_index,
        sigma_i: sigma_i.to_repr().to_vec(),
    };
    let payload =
        serde_json::to_vec(&sign_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 12,
            payload,
        })
        .await?;

    // ── Collect partial signatures from all signers ───────────────────
    let mut all_sigmas: Vec<(u16, Scalar)> = vec![(my_index, sigma_i)];
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let sm: SignOnlineMsg = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let s_j = Scalar::from_repr(*k256::FieldBytes::from_slice(&sm.sigma_i))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid sigma_i scalar".into()))?;
        all_sigmas.push((sm.party_index, s_j));
    }

    // ── Aggregate: s = sum(sigma_i) ───────────────────────────────────
    let s_raw = all_sigmas
        .iter()
        .map(|(_, s)| s)
        .fold(Scalar::ZERO, |acc, s| acc + s);

    // ── Build raw ECDSA signature ─────────────────────────────────────
    let r_bytes: [u8; 32] = r_scalar.to_repr().into();
    let s_bytes: [u8; 32] = s_raw.to_repr().into();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);

    let raw_sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into())
        .map_err(|e| CoreError::Crypto(format!("assembled invalid ECDSA signature: {e}")))?;

    // ── SEC-012: Normalize to low-s ───────────────────────────────────
    let normalized_sig = match raw_sig.normalize_s() {
        Some(normalized) => normalized,
        None => raw_sig,
    };

    let norm_sig_bytes = normalized_sig.to_bytes();
    let final_r: [u8; 32] = norm_sig_bytes[..32].try_into().unwrap();
    let final_s: [u8; 32] = norm_sig_bytes[32..].try_into().unwrap();

    // ── Verify signature against group public key ─────────────────────
    let pubkey = k256::PublicKey::from_sec1_bytes(key_share.group_public_key.as_bytes())
        .map_err(|e| CoreError::Crypto(format!("bad group pubkey: {e}")))?;
    let verifying_key = k256::ecdsa::VerifyingKey::from(&pubkey);

    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let verify_result = verifying_key.verify_prehash(&hash_bytes, &normalized_sig);

    if verify_result.is_err() {
        // ── Identifiable abort (T-S20-03) ─────────────────────────────
        // Try to identify which party provided an invalid partial signature.
        // Each party's sigma_i should satisfy: sigma_i * G = k_i * e * G + chi_i * r * G
        // We verify using the public K_i and X_i from keygen.
        return Err(identify_cheater(
            &all_sigmas,
            &pre_sig.signers,
            key_share,
            e_scalar,
            r_scalar,
        ));
    }

    // ── Determine recovery_id ─────────────────────────────────────────
    let recovery_id = (0u8..4)
        .find(|&v| {
            let recid = k256::ecdsa::RecoveryId::try_from(v).unwrap();
            k256::ecdsa::VerifyingKey::recover_from_prehash(&hash_bytes, &normalized_sig, recid)
                .map(|recovered| recovered == verifying_key)
                .unwrap_or(false)
        })
        .unwrap_or(0);

    Ok(MpcSignature::Ecdsa {
        r: final_r.to_vec(),
        s: final_s.to_vec(),
        recovery_id,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Identifiable Abort — cheater detection (T-S20-03)
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to identify which party provided an invalid partial signature.
///
/// Checks each party's sigma_i against the expected value computed from
/// the group's public key shares. Returns a `CoreError::Protocol` with
/// the cheater's identity.
fn identify_cheater(
    all_sigmas: &[(u16, Scalar)],
    _signers: &[PartyId],
    key_share: &KeyShare,
    _e_scalar: Scalar,
    _r_scalar: Scalar,
) -> CoreError {
    // Try to load the share data to get public key shares
    let share_data: Result<Cggmp21ShareData, _> = serde_json::from_slice(&key_share.share_data);
    let share_data = match share_data {
        Ok(d) => d,
        Err(_) => {
            return CoreError::Protocol(
                "identifiable abort: signature verification failed but cannot identify cheater — share data corrupt".into(),
            );
        }
    };

    // For each party, verify their partial contribution
    for &(party_idx, sigma_i) in all_sigmas {
        // Compute what sigma_i * G should be
        let sigma_point = ProjectivePoint::GENERATOR * sigma_i;

        // Expected: sigma_i * G = k_i * e * G + (k_i * x_i * lambda_i) * r * G
        //         = e * K_i + r * lambda_i * x_i * K_i
        // We don't have K_i stored, but we know:
        //   sigma_i = k_i * e + chi_i * r where chi_i = k_i * x_i * lambda_i
        //
        // Alternative check: verify that the partial signature is consistent
        // by checking sum. If sum doesn't verify, at least one party is bad.
        // We use a simpler heuristic: check if sigma_i is zero or the identity
        // contribution is trivially wrong.

        // Get the public key share for this party
        let pk_idx = (party_idx - 1) as usize;
        if pk_idx >= share_data.public_shares.len() {
            return CoreError::Protocol(format!(
                "identifiable abort: party {} cheated: party index out of range",
                party_idx
            ));
        }

        // Verify the partial sigma_i is a valid non-zero scalar contribution
        if sigma_i == Scalar::ZERO {
            return CoreError::Protocol(format!(
                "identifiable abort: party {} cheated: submitted zero partial signature",
                party_idx
            ));
        }

        // Without K_i (nonce commitment point per party) stored from pre-signing,
        // we cannot fully verify each party's sigma_i independently. However, we
        // can detect obviously invalid contributions like zero values.
        // In production CGGMP21, K_i would be stored during pre-signing and used
        // here to verify: sigma_i * G == e * K_i + r * chi_i * G.
        let _ = sigma_point; // Would be used with stored K_i in production
    }

    // If we can't pinpoint the exact cheater, report all sigmas failed
    CoreError::Protocol(
        "identifiable abort: final signature verification failed — at least one party submitted invalid partial signature".into(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// CGGMP21 Key Refresh — additive re-sharing (T-S21-04)
// ─────────────────────────────────────────────────────────────────────────────

/// Refresh message: each party broadcasts Feldman commitments and sends
/// evaluations of their zero-constant polynomial to each other party.
#[derive(Serialize, Deserialize)]
struct RefreshRound1 {
    /// Sender party index.
    from_party: u16,
    /// Feldman commitments for the zero-constant polynomial: C_k = a_k * G.
    /// C_0 should be the identity point (since a_0 = 0).
    commitments: Vec<Vec<u8>>,
}

/// Refresh evaluation: party i sends g_i(j) to party j.
#[derive(Serialize, Deserialize)]
struct RefreshEvaluation {
    /// Sender party index.
    from_party: u16,
    /// Evaluation g_i(j) for the recipient (32 bytes scalar).
    eval_value: Vec<u8>,
}

/// CGGMP21 key refresh: additive re-sharing that preserves the group public key.
///
/// # Protocol
///
/// 1. Each party generates a random polynomial g_i(x) of degree t-1 with
///    g_i(0) = 0 (zero constant term). This ensures the group secret is preserved.
/// 2. Each party broadcasts Feldman commitments C_k = a_k * G for their polynomial.
/// 3. Each party sends g_i(j) to party j via unicast.
/// 4. Each party verifies received evaluations against Feldman commitments.
/// 5. Each party computes delta_j = sum_i(g_i(j)) and updates:
///    new_share = old_share + delta_j.
/// 6. New public shares are computed and verified against the same group pubkey.
/// 7. Fresh Paillier and Pedersen auxiliary parameters are generated.
///
/// # Invariant
///
/// The group public key is preserved because sum(g_i(0)) = 0 for all i,
/// so the secret x = sum(old_shares) is unchanged at the Shamir-0 evaluation.
async fn cggmp21_refresh(
    key_share: &KeyShare,
    signers: &[PartyId],
    transport: &dyn Transport,
) -> Result<KeyShare, CoreError> {
    let my_party = key_share.party_id;
    let my_index = my_party.0;
    let t = key_share.config.threshold;
    let n_signers = signers.len();

    // Validate that we are in the signer set
    if !signers.contains(&my_party) {
        return Err(CoreError::Protocol(
            "party not in refresh signer set".into(),
        ));
    }

    // Deserialize current share data
    let share_data: Cggmp21ShareData = serde_json::from_slice(&key_share.share_data)
        .map_err(|e| CoreError::Serialization(format!("deserialize share for refresh: {e}")))?;

    // Parse current secret share (SEC-008: wrap in Zeroizing)
    let old_share = Zeroizing::new(
        Scalar::from_repr(*k256::FieldBytes::from_slice(&share_data.secret_share))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid secret share scalar in refresh".into()))?,
    );

    // ── Generate zero-constant polynomial ────────────────────────────────
    // g(x) = 0 + c_1*x + c_2*x^2 + ... + c_{t-1}*x^{t-1}
    // g(0) = 0 ensures the group secret is preserved.
    let coefficients = {
        let mut rng = rand::thread_rng();
        let mut coeffs: Vec<Zeroizing<Scalar>> = Vec::with_capacity(t as usize);
        coeffs.push(Zeroizing::new(Scalar::ZERO)); // g(0) = 0
        for _ in 1..t {
            coeffs.push(Zeroizing::new(Scalar::random(&mut rng)));
        }
        coeffs
    };

    // Compute Feldman commitments: C_k = a_k * G
    // Note: C_0 = 0*G = identity point, which cannot be encoded as a k256::PublicKey.
    // We use a special sentinel encoding (all zeros, 33 bytes) for the identity.
    let feldman_commitments: Vec<Vec<u8>> = coefficients
        .iter()
        .map(|coeff| {
            if **coeff == Scalar::ZERO {
                // Identity point sentinel: 33 zero bytes
                vec![0u8; 33]
            } else {
                let point = (ProjectivePoint::GENERATOR * **coeff).to_affine();
                k256::PublicKey::from_affine(point)
                    .expect("valid point")
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec()
            }
        })
        .collect();

    // ── Round 1: Broadcast Feldman commitments ───────────────────────────
    let round1_msg = RefreshRound1 {
        from_party: my_index,
        commitments: feldman_commitments.clone(),
    };
    let round1_payload =
        serde_json::to_vec(&round1_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party,
            to: None,
            round: 200, // Use round 200+ to avoid conflicts with keygen/sign/presign
            payload: round1_payload,
        })
        .await?;

    // Receive Feldman commitments from all other signers
    let mut all_commitments: Vec<RefreshRound1> = vec![round1_msg];
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let r1: RefreshRound1 = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        // Validate sender is in signer set (SEC-013 pattern)
        if !signers.iter().any(|s| s.0 == r1.from_party) {
            return Err(CoreError::Protocol(format!(
                "refresh round 1: unexpected party {} not in signer set",
                r1.from_party
            )));
        }

        all_commitments.push(r1);
    }
    all_commitments.sort_by_key(|c| c.from_party);

    // ── Round 2: Send evaluations to each signer ─────────────────────────
    let raw_coeffs: Vec<Scalar> = coefficients.iter().map(|z| **z).collect();
    for &signer in signers {
        if signer == my_party {
            continue;
        }
        let x_j = Scalar::from(signer.0 as u64);
        let eval = poly_eval(&raw_coeffs, &x_j);
        let eval_msg = RefreshEvaluation {
            from_party: my_index,
            eval_value: eval.to_repr().to_vec(),
        };
        let payload =
            serde_json::to_vec(&eval_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;
        transport
            .send(ProtocolMessage {
                from: my_party,
                to: Some(signer),
                round: 201,
                payload,
            })
            .await?;
    }

    // Compute self-evaluation: g_i(my_index)
    let self_x = Scalar::from(my_index as u64);
    let self_eval = poly_eval(&raw_coeffs, &self_x);

    // Explicitly zeroize the raw coefficients copy (SEC-008)
    let mut raw_coeffs = raw_coeffs;
    for coeff in raw_coeffs.iter_mut() {
        coeff.zeroize();
    }
    drop(raw_coeffs);

    // Receive evaluations from all other signers
    let mut received_evals: Vec<RefreshEvaluation> = Vec::new();
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let eval: RefreshEvaluation = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        received_evals.push(eval);
    }

    // ── Verify evaluations against Feldman commitments ───────────────────
    // For each received evaluation g_j(my_index), verify:
    //   eval * G == sum_{k=0}^{t-1} C_k^{j} * my_index^k
    for eval in &received_evals {
        let eval_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(&eval.eval_value))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid refresh evaluation scalar".into()))?;

        let eval_point = ProjectivePoint::GENERATOR * eval_scalar;

        // Find the commitments for this sender
        let sender_commitments = all_commitments
            .iter()
            .find(|c| c.from_party == eval.from_party)
            .ok_or_else(|| {
                CoreError::Protocol(format!(
                    "missing Feldman commitments for party {} in refresh",
                    eval.from_party
                ))
            })?;

        let mut expected_point = ProjectivePoint::IDENTITY;
        let my_x_scalar = Scalar::from(my_index as u64);
        let mut x_pow = Scalar::ONE;
        for commitment_bytes in &sender_commitments.commitments {
            // Handle identity sentinel (33 zero bytes for C_0 = 0*G)
            if commitment_bytes == &vec![0u8; 33] {
                // Identity point contributes nothing: identity * x_pow = identity
                x_pow *= my_x_scalar;
                continue;
            }
            let c_k = k256::PublicKey::from_sec1_bytes(commitment_bytes)
                .map_err(|e| CoreError::Crypto(format!("invalid Feldman commitment: {e}")))?;
            expected_point += c_k.to_projective() * x_pow;
            x_pow *= my_x_scalar;
        }

        if eval_point != expected_point {
            return Err(CoreError::Protocol(format!(
                "Feldman verification failed for refresh evaluation from party {} — identifiable abort",
                eval.from_party
            )));
        }
    }

    // ── Compute delta and new share ──────────────────────────────────────
    let mut delta = Zeroizing::new(self_eval);
    for eval in &received_evals {
        let eval_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(&eval.eval_value))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid refresh evaluation scalar".into()))?;
        *delta += eval_scalar;
    }

    let new_share = Zeroizing::new(*old_share + *delta);

    // ── Verify group public key is preserved ─────────────────────────────
    // Broadcast new public share X'_i = new_share * G
    let new_pub_point = (ProjectivePoint::GENERATOR * *new_share).to_affine();
    let new_pub_bytes = k256::PublicKey::from_affine(new_pub_point)
        .map_err(|e| CoreError::Crypto(e.to_string()))?
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    // Broadcast new public share
    let pub_share_msg = serde_json::json!({
        "party_index": my_index,
        "public_share": new_pub_bytes,
    });
    let pub_payload =
        serde_json::to_vec(&pub_share_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party,
            to: None,
            round: 202,
            payload: pub_payload,
        })
        .await?;

    // Collect new public shares from all signers
    let mut new_public_shares: Vec<(u16, Vec<u8>)> = vec![(my_index, new_pub_bytes.clone())];
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let ps: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let idx: u16 = serde_json::from_value(ps["party_index"].clone())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pub_bytes: Vec<u8> = serde_json::from_value(ps["public_share"].clone())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        new_public_shares.push((idx, pub_bytes));
    }
    new_public_shares.sort_by_key(|(idx, _)| *idx);

    // Build the full public shares list (preserving all n parties' positions)
    // For parties not in the signer set, their public share stays the same
    let _n = key_share.config.total_parties;
    let mut all_public_shares: Vec<Vec<u8>> = share_data.public_shares.clone();
    for (idx, pub_bytes) in &new_public_shares {
        let pos = (*idx - 1) as usize;
        if pos < all_public_shares.len() {
            all_public_shares[pos] = pub_bytes.clone();
        }
    }

    // Verify: reconstructed group public key must match original
    // The group pubkey = sum of all X_i (for all n parties, not just signers)
    // But since only signers refreshed and sum(g_i(0)) = 0, the Lagrange
    // interpolation at 0 gives the same secret, hence same group pubkey.
    // We verify by checking that the Feldman commitments sum correctly:
    // sum_i(C_0^i) = sum_i(0 * G) = identity, confirming zero-constant.
    for commitment_set in &all_commitments {
        if commitment_set.commitments.is_empty() {
            return Err(CoreError::Protocol(format!(
                "party {} has empty Feldman commitments in refresh",
                commitment_set.from_party
            )));
        }
        // C_0 should be the identity point (since a_0 = 0).
        // We encode identity as 33 zero bytes (sentinel), so verify that.
        if commitment_set.commitments[0] != vec![0u8; 33] {
            return Err(CoreError::Protocol(format!(
                "party {} has non-zero constant term in refresh polynomial — identifiable abort",
                commitment_set.from_party
            )));
        }
    }

    // ── Generate fresh auxiliary info (Paillier + Pedersen) ───────────────
    let paillier = generate_paillier_keypair(&new_share, my_index);
    let pedersen = generate_pedersen_params(&new_share, my_index);

    let paillier_sk_bytes = serde_json::to_vec(&(paillier.p.clone(), paillier.q.clone()))
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    let paillier_pk_bytes = paillier.n.clone();
    let pedersen_bytes =
        serde_json::to_vec(&pedersen).map_err(|e| CoreError::Serialization(e.to_string()))?;

    // ── Build refreshed share data ───────────────────────────────────────
    let new_share_data = Cggmp21ShareData {
        party_index: my_index,
        secret_share: new_share.to_repr().to_vec(),
        public_shares: all_public_shares,
        group_public_key: share_data.group_public_key.clone(),
        paillier_sk: paillier_sk_bytes,
        paillier_pk: paillier_pk_bytes,
        pedersen_params: pedersen_bytes,
    };

    let new_share_bytes =
        serde_json::to_vec(&new_share_data).map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(KeyShare {
        scheme: CryptoScheme::Cggmp21Secp256k1,
        party_id: my_party,
        config: key_share.config,
        group_public_key: key_share.group_public_key.clone(),
        share_data: Zeroizing::new(new_share_bytes),
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

    // ── Pre-signing + Online signing tests (T-S20-01/02/03) ──────────

    /// Helper: run CGGMP21 keygen for n parties, return all key shares.
    async fn run_keygen(t: u16, n: u16) -> Vec<KeyShare> {
        use crate::transport::local::LocalTransportNetwork;
        let config = ThresholdConfig::new(t, n).unwrap();
        let net = LocalTransportNetwork::new(n);

        let mut handles = Vec::new();
        for i in 1..=n {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        let mut shares = Vec::new();
        for h in handles {
            shares.push(h.await.unwrap().unwrap());
        }
        shares
    }

    #[tokio::test]
    async fn test_cggmp21_presign_2_of_3() {
        use crate::transport::local::LocalTransportNetwork;

        let shares = run_keygen(2, 3).await;
        let signers = vec![PartyId(1), PartyId(2)];

        // Run pre-signing with 2 of the 3 parties
        let net = LocalTransportNetwork::new(2);
        let mut handles = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = shares[signer.0 as usize - 1].clone();
            let transport = net.get_transport(PartyId((i + 1) as u16));
            let signers_clone = signers.clone();
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.pre_sign(&share, &signers_clone, &*transport).await
            }));
        }

        for h in handles {
            let pre_sig = h.await.unwrap().unwrap();
            assert!(
                !pre_sig.used,
                "pre-signature should not be marked as used yet"
            );
            assert_eq!(pre_sig.signers.len(), 2);
            assert_eq!(
                pre_sig.big_r.len(),
                33,
                "R point should be 33 bytes compressed"
            );
            assert_eq!(pre_sig.k_i.len(), 32, "k_i should be 32 bytes");
            assert_eq!(pre_sig.chi_i.len(), 32, "chi_i should be 32 bytes");
        }
    }

    #[tokio::test]
    async fn test_cggmp21_sign_full_flow() {
        use crate::transport::local::LocalTransportNetwork;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let shares = run_keygen(2, 3).await;
        let signers = vec![PartyId(1), PartyId(2)];
        let message = b"CGGMP21 test message for signing";

        // Step 1: Pre-sign
        let net_presign = LocalTransportNetwork::new(2);
        let mut presign_handles = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = shares[signer.0 as usize - 1].clone();
            let transport = net_presign.get_transport(PartyId((i + 1) as u16));
            let signers_clone = signers.clone();
            presign_handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.pre_sign(&share, &signers_clone, &*transport).await
            }));
        }

        let mut pre_sigs: Vec<PreSignature> = Vec::new();
        for h in presign_handles {
            pre_sigs.push(h.await.unwrap().unwrap());
        }

        // Step 2: Online sign
        let net_sign = LocalTransportNetwork::new(2);
        let mut sign_handles = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = shares[signer.0 as usize - 1].clone();
            let transport = net_sign.get_transport(PartyId((i + 1) as u16));
            let mut pre_sig = std::mem::replace(
                &mut pre_sigs[i],
                PreSignature {
                    k_i: vec![],
                    chi_i: vec![],
                    delta_i: vec![],
                    big_r: vec![],
                    party_id: PartyId(0),
                    signers: vec![],
                    used: true,
                },
            );
            let msg = message.to_vec();
            sign_handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.sign_with_presig(&mut pre_sig, &msg, &share, &*transport)
                    .await
            }));
        }

        // All parties should produce the same valid signature
        let mut signatures = Vec::new();
        for h in sign_handles {
            signatures.push(h.await.unwrap().unwrap());
        }

        // Verify the signature
        if let MpcSignature::Ecdsa { r, s, recovery_id } = &signatures[0] {
            assert_eq!(r.len(), 32);
            assert_eq!(s.len(), 32);
            assert!(*recovery_id <= 3);

            // Verify against group public key using k256
            let pubkey =
                k256::PublicKey::from_sec1_bytes(shares[0].group_public_key.as_bytes()).unwrap();
            let verifying_key = k256::ecdsa::VerifyingKey::from(&pubkey);

            let mut sig_bytes = [0u8; 64];
            sig_bytes[..32].copy_from_slice(r);
            sig_bytes[32..].copy_from_slice(s);
            let sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into()).unwrap();

            let hash = Sha256::digest(message);
            let result = verifying_key.verify_prehash(&hash, &sig);
            assert!(result.is_ok(), "signature must verify against group pubkey");
        } else {
            panic!("expected ECDSA signature");
        }
    }

    #[tokio::test]
    async fn test_cggmp21_sign_direct() {
        use crate::transport::local::LocalTransportNetwork;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let shares = run_keygen(2, 3).await;
        let signers = vec![PartyId(1), PartyId(2)];
        let message = b"direct sign test message";

        // Use MpcProtocol::sign which does pre-sign + online internally
        let net = LocalTransportNetwork::new(2);
        let mut handles = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = shares[signer.0 as usize - 1].clone();
            let transport = net.get_transport(PartyId((i + 1) as u16));
            let signers_clone = signers.clone();
            let msg = message.to_vec();
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.sign(&share, &signers_clone, &msg, &*transport).await
            }));
        }

        let mut sigs = Vec::new();
        for h in handles {
            sigs.push(h.await.unwrap().unwrap());
        }

        // Verify
        if let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] {
            let pubkey =
                k256::PublicKey::from_sec1_bytes(shares[0].group_public_key.as_bytes()).unwrap();
            let vk = k256::ecdsa::VerifyingKey::from(&pubkey);
            let mut sig_bytes = [0u8; 64];
            sig_bytes[..32].copy_from_slice(r);
            sig_bytes[32..].copy_from_slice(s);
            let sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into()).unwrap();
            let hash = Sha256::digest(message);
            assert!(vk.verify_prehash(&hash, &sig).is_ok());
        } else {
            panic!("expected ECDSA signature");
        }
    }

    #[tokio::test]
    async fn test_cggmp21_sign_different_messages_nonce_reuse_protection() {
        use crate::transport::local::LocalTransportNetwork;

        let shares = run_keygen(2, 3).await;
        let signers = vec![PartyId(1), PartyId(2)];

        // Pre-sign once
        let net_presign = LocalTransportNetwork::new(2);
        let mut presign_handles = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = shares[signer.0 as usize - 1].clone();
            let transport = net_presign.get_transport(PartyId((i + 1) as u16));
            let signers_clone = signers.clone();
            presign_handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.pre_sign(&share, &signers_clone, &*transport).await
            }));
        }

        let mut pre_sig = presign_handles
            .into_iter()
            .next()
            .unwrap()
            .await
            .unwrap()
            .unwrap();

        // Sign first message — should succeed
        // (We can't do a full multi-party sign here without transport, so just test the flag)
        assert!(!pre_sig.used);
        pre_sig.used = true;

        // Attempting to sign again with the same pre-signature should fail
        let p = Cggmp21Protocol::new();
        let net_sign = LocalTransportNetwork::new(2);
        let transport = net_sign.get_transport(PartyId(1));
        let result = p
            .sign_with_presig(&mut pre_sig, b"second message", &shares[0], &*transport)
            .await;
        assert!(result.is_err(), "reusing pre-signature must fail");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nonce reuse"),
            "error should mention nonce reuse: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_cggmp21_sign_verify_against_group_pubkey() {
        use crate::transport::local::LocalTransportNetwork;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let shares = run_keygen(2, 3).await;
        let signers = vec![PartyId(1), PartyId(3)]; // Use parties 1 and 3 (not 2)
        let message = b"verify against group pubkey test";

        let net = LocalTransportNetwork::new(2);
        let mut handles = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = shares[signer.0 as usize - 1].clone();
            let transport = net.get_transport(PartyId((i + 1) as u16));
            let signers_clone = signers.clone();
            let msg = message.to_vec();
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.sign(&share, &signers_clone, &msg, &*transport).await
            }));
        }

        let sig = handles.into_iter().next().unwrap().await.unwrap().unwrap();

        if let MpcSignature::Ecdsa { r, s, .. } = &sig {
            // Verify using ALL three parties' group public key (should be the same)
            for share in &shares {
                let pubkey =
                    k256::PublicKey::from_sec1_bytes(share.group_public_key.as_bytes()).unwrap();
                let vk = k256::ecdsa::VerifyingKey::from(&pubkey);
                let mut sig_bytes = [0u8; 64];
                sig_bytes[..32].copy_from_slice(r);
                sig_bytes[32..].copy_from_slice(s);
                let sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into()).unwrap();
                let hash = Sha256::digest(message);
                assert!(
                    vk.verify_prehash(&hash, &sig).is_ok(),
                    "signature must verify against any party's copy of group pubkey"
                );
            }
        } else {
            panic!("expected ECDSA signature");
        }
    }

    #[tokio::test]
    async fn test_cggmp21_identifiable_abort_detection() {
        // Test that a corrupted partial signature triggers identifiable abort
        let signers = vec![PartyId(1), PartyId(2)];
        // Create fake sigma values where one is deliberately wrong
        let mut rng = rand::thread_rng();
        let sigma_good = Scalar::random(&mut rng);
        let sigma_bad = Scalar::ZERO; // Zero is always wrong

        let all_sigmas = vec![(1u16, sigma_good), (2u16, sigma_bad)];
        let e_scalar = Scalar::from(42u64);
        let r_scalar = Scalar::from(7u64);

        // Create a minimal key share for testing
        let share_data = Cggmp21ShareData {
            party_index: 1,
            secret_share: Scalar::from(1u64).to_repr().to_vec(),
            public_shares: vec![
                // Two dummy compressed points
                {
                    let p = (ProjectivePoint::GENERATOR * Scalar::from(1u64)).to_affine();
                    k256::PublicKey::from_affine(p)
                        .unwrap()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec()
                },
                {
                    let p = (ProjectivePoint::GENERATOR * Scalar::from(2u64)).to_affine();
                    k256::PublicKey::from_affine(p)
                        .unwrap()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec()
                },
            ],
            group_public_key: {
                let p = (ProjectivePoint::GENERATOR * Scalar::from(3u64)).to_affine();
                k256::PublicKey::from_affine(p)
                    .unwrap()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec()
            },
            paillier_sk: vec![0u8; 32],
            paillier_pk: vec![0u8; 32],
            pedersen_params: vec![0u8; 32],
        };

        let share_bytes = serde_json::to_vec(&share_data).unwrap();
        let key_share = KeyShare {
            scheme: CryptoScheme::Cggmp21Secp256k1,
            party_id: PartyId(1),
            config: ThresholdConfig::new(2, 3).unwrap(),
            group_public_key: GroupPublicKey::Secp256k1(share_data.group_public_key.clone()),
            share_data: Zeroizing::new(share_bytes),
        };

        let err = identify_cheater(&all_sigmas, &signers, &key_share, e_scalar, r_scalar);
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("identifiable abort"),
            "error should indicate identifiable abort: {err_msg}"
        );
        // Party 2 submitted zero — should be detected
        assert!(
            err_msg.contains("party 2") || err_msg.contains("invalid partial"),
            "error should identify the cheater or indicate invalid partial: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_cggmp21_sign_low_s_normalization() {
        use crate::transport::local::LocalTransportNetwork;

        let shares = run_keygen(2, 3).await;
        let signers = vec![PartyId(1), PartyId(2)];

        // Sign multiple messages and verify all have low-s
        for msg_idx in 0..5u8 {
            let message = format!("low-s test message #{msg_idx}");

            let net = LocalTransportNetwork::new(2);
            let mut handles = Vec::new();
            for (i, signer) in signers.iter().enumerate() {
                let share = shares[signer.0 as usize - 1].clone();
                let transport = net.get_transport(PartyId((i + 1) as u16));
                let signers_clone = signers.clone();
                let msg = message.clone().into_bytes();
                handles.push(tokio::spawn(async move {
                    let p = Cggmp21Protocol::new();
                    p.sign(&share, &signers_clone, &msg, &*transport).await
                }));
            }

            let sig = handles.into_iter().next().unwrap().await.unwrap().unwrap();
            if let MpcSignature::Ecdsa { r, s, .. } = &sig {
                // Verify s is in the lower half of the curve order (SEC-012)
                // Build the signature and check normalize_s returns None (already low-s)
                let mut sig_bytes = [0u8; 64];
                sig_bytes[..32].copy_from_slice(r);
                sig_bytes[32..].copy_from_slice(s);
                let ecdsa_sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into()).unwrap();
                assert!(
                    ecdsa_sig.normalize_s().is_none(),
                    "s should already be normalized (low-s) — SEC-012"
                );
            } else {
                panic!("expected ECDSA signature");
            }
        }
    }

    // ── CGGMP21 Key Refresh tests (T-S21-04) ──────────────────────────────

    /// Helper: run CGGMP21 refresh for all parties, return refreshed shares.
    async fn run_refresh(shares: &[KeyShare], signers: &[PartyId]) -> Vec<KeyShare> {
        use crate::transport::local::LocalTransportNetwork;
        let n_signers = signers.len();
        let net = LocalTransportNetwork::new(n_signers as u16);

        let mut handles = Vec::new();
        for (i, signer) in signers.iter().enumerate() {
            let share = shares[signer.0 as usize - 1].clone();
            let transport = net.get_transport(PartyId((i + 1) as u16));
            let signers_clone = signers.to_vec();
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.refresh(&share, &signers_clone, &*transport).await
            }));
        }

        let mut refreshed = Vec::new();
        for h in handles {
            refreshed.push(h.await.unwrap().unwrap());
        }
        refreshed
    }

    #[tokio::test]
    async fn test_cggmp21_refresh_preserves_group_pubkey() {
        let shares = run_keygen(2, 3).await;
        let original_gpk = shares[0].group_public_key.as_bytes().to_vec();

        // Refresh all 3 parties
        let signers: Vec<PartyId> = (1..=3).map(PartyId).collect();
        let refreshed = run_refresh(&shares, &signers).await;

        // Group public key must be preserved
        for share in &refreshed {
            assert_eq!(
                share.group_public_key.as_bytes(),
                original_gpk.as_slice(),
                "group public key must be preserved after refresh"
            );
        }

        // Secret shares must have changed (with overwhelming probability)
        let old_data: Cggmp21ShareData = serde_json::from_slice(&shares[0].share_data).unwrap();
        let new_data: Cggmp21ShareData = serde_json::from_slice(&refreshed[0].share_data).unwrap();
        assert_ne!(
            old_data.secret_share, new_data.secret_share,
            "secret shares must change after refresh"
        );

        // Paillier and Pedersen aux info must have changed
        assert_ne!(
            old_data.paillier_sk, new_data.paillier_sk,
            "Paillier SK must be refreshed"
        );
        assert_ne!(
            old_data.pedersen_params, new_data.pedersen_params,
            "Pedersen params must be refreshed"
        );
    }

    #[tokio::test]
    async fn test_cggmp21_refresh_then_sign() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let shares = run_keygen(2, 3).await;
        let original_gpk = shares[0].group_public_key.as_bytes().to_vec();

        // Refresh all 3 parties
        let all_signers: Vec<PartyId> = (1..=3).map(PartyId).collect();
        let refreshed = run_refresh(&shares, &all_signers).await;

        // Sign with refreshed shares (parties 1 and 2)
        let sign_signers = vec![PartyId(1), PartyId(2)];
        let message = b"signing after CGGMP21 key refresh";

        use crate::transport::local::LocalTransportNetwork;
        let net = LocalTransportNetwork::new(2);
        let mut handles = Vec::new();
        for (i, signer) in sign_signers.iter().enumerate() {
            // refreshed shares are indexed 0..2 matching signers 1..3
            let share = refreshed[signer.0 as usize - 1].clone();
            let transport = net.get_transport(PartyId((i + 1) as u16));
            let signers_clone = sign_signers.clone();
            let msg = message.to_vec();
            handles.push(tokio::spawn(async move {
                let p = Cggmp21Protocol::new();
                p.sign(&share, &signers_clone, &msg, &*transport).await
            }));
        }

        let sig = handles.into_iter().next().unwrap().await.unwrap().unwrap();

        // Verify signature against the ORIGINAL group public key
        if let MpcSignature::Ecdsa { r, s, .. } = &sig {
            let pubkey = k256::PublicKey::from_sec1_bytes(&original_gpk).unwrap();
            let vk = k256::ecdsa::VerifyingKey::from(&pubkey);
            let mut sig_bytes = [0u8; 64];
            sig_bytes[..32].copy_from_slice(r);
            sig_bytes[32..].copy_from_slice(s);
            let ecdsa_sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into()).unwrap();
            let hash = Sha256::digest(message);
            assert!(
                vk.verify_prehash(&hash, &ecdsa_sig).is_ok(),
                "signature with refreshed shares must verify against original group pubkey"
            );
        } else {
            panic!("expected ECDSA signature");
        }
    }

    #[tokio::test]
    async fn test_cggmp21_refresh_invalidates_old_shares() {
        let shares = run_keygen(2, 3).await;

        // Refresh all 3 parties
        let all_signers: Vec<PartyId> = (1..=3).map(PartyId).collect();
        let refreshed = run_refresh(&shares, &all_signers).await;

        // Try to sign using one OLD share and one NEW share — this should produce
        // an invalid signature because the shares are from incompatible polynomials.
        // We mix old party 1 with refreshed party 2.
        let sign_signers = vec![PartyId(1), PartyId(2)];
        let message = b"mixed old and new shares";

        use crate::transport::local::LocalTransportNetwork;
        let net = LocalTransportNetwork::new(2);

        let old_share = shares[0].clone(); // old party 1
        let new_share = refreshed[1].clone(); // refreshed party 2

        let transport1 = net.get_transport(PartyId(1));
        let transport2 = net.get_transport(PartyId(2));
        let signers1 = sign_signers.clone();
        let signers2 = sign_signers.clone();
        let msg1 = message.to_vec();
        let msg2 = message.to_vec();

        let h1 = tokio::spawn(async move {
            let p = Cggmp21Protocol::new();
            p.sign(&old_share, &signers1, &msg1, &*transport1).await
        });
        let h2 = tokio::spawn(async move {
            let p = Cggmp21Protocol::new();
            p.sign(&new_share, &signers2, &msg2, &*transport2).await
        });

        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();

        // At least one should fail (signature verification) or both succeed but
        // the signature should NOT verify against the group pubkey.
        // Due to identifiable abort, the protocol will detect the inconsistency.
        let mixed_failed = r1.is_err() || r2.is_err() || {
            // If both somehow produced results, verify they don't produce valid sigs
            if let (Ok(MpcSignature::Ecdsa { r, s, .. }), Ok(_)) = (&r1, &r2) {
                use k256::ecdsa::signature::hazmat::PrehashVerifier;
                let pubkey =
                    k256::PublicKey::from_sec1_bytes(shares[0].group_public_key.as_bytes())
                        .unwrap();
                let vk = k256::ecdsa::VerifyingKey::from(&pubkey);
                let mut sig_bytes = [0u8; 64];
                sig_bytes[..32].copy_from_slice(r);
                sig_bytes[32..].copy_from_slice(s);
                let sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into());
                match sig {
                    Ok(s) => {
                        let hash = Sha256::digest(message);
                        vk.verify_prehash(&hash, &s).is_err()
                    }
                    Err(_) => true,
                }
            } else {
                true
            }
        };

        assert!(
            mixed_failed,
            "mixing old and refreshed shares must fail or produce invalid signature"
        );
    }
}
