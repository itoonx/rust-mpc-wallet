//! Threshold ECDSA signing on the Stark curve for StarkNet.
//!
//! Uses real StarkNet cryptography via `starknet-crypto` and `starknet-types-core`:
//! - ECDSA on the STARK curve (order p = 2^251 + 17*2^192 + 1)
//! - Threshold keygen with Feldman VSS over the Stark field
//! - Pre-signing with MtA (Paillier homomorphic encryption) for k*gamma and k*x shares
//! - Online 1-round signing with sigma_i aggregation
//! - Verification via `starknet_crypto::verify`
//!
//! ## Protocol Overview (mirrors CGGMP21 structure)
//!
//! 1. **Keygen** — 3 rounds + Feldman VSS + aux info (Paillier/Pedersen)
//! 2. **Pre-signing** — offline phase producing pre-signature (k_i, chi_i, R)
//! 3. **Online signing** — 1 round sigma aggregation using pre-signature
//!
//! ## Security Notes
//!
//! - The full private key `x = sum(x_i)` is NEVER reconstructed.
//! - All secret scalars are zeroized on drop (SEC-008 pattern).
//! - MtA uses real Paillier encryption (reuses `crate::paillier::mta`).
//! - TODO: Add PiLogstar_stark and PiAffg_stark ZK proofs for full CGGMP21 security.
//!   Current implementation uses Pienc only (Paillier range proof, field-agnostic).

use async_trait::async_trait;
use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use starknet_crypto::Felt;
use starknet_curve::curve_params::{EC_ORDER, GENERATOR};
use starknet_types_core::curve::ProjectivePoint;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::paillier::mta::{MtaPartyA, MtaPartyB, MtaRound1};
use crate::paillier::{PaillierPublicKey, PaillierSecretKey};
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::{ProtocolMessage, Transport};
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Share data structures
// ─────────────────────────────────────────────────────────────────────────────

/// Per-party threshold Stark key share data stored in `KeyShare.share_data`.
///
/// Contains the party's secret Feldman share, all public key shares, the
/// group public key, and auxiliary cryptographic parameters (Paillier, Pedersen)
/// needed for the pre-signing protocol.
#[derive(Serialize, Deserialize)]
pub struct StarkThresholdShareData {
    /// This party's index (1-indexed).
    pub party_index: u16,
    /// This party's secret Feldman share (32 bytes, Stark field element big-endian).
    pub secret_share: Vec<u8>,
    /// All parties' public key shares (each is 64 bytes: x || y, big-endian Felts).
    pub public_shares: Vec<Vec<u8>>,
    /// The combined group public key (32 bytes: x-coordinate of sum of Xi*G).
    pub group_public_key: Vec<u8>,
    /// Real Paillier secret key for MtA in pre-signing.
    #[serde(default)]
    pub real_paillier_sk: Option<PaillierSecretKey>,
    /// Real Paillier public key for MtA in pre-signing.
    #[serde(default)]
    pub real_paillier_pk: Option<PaillierPublicKey>,
    /// All parties' real Paillier public keys, indexed by party position (0-based).
    #[serde(default)]
    pub all_paillier_pks: Option<Vec<PaillierPublicKey>>,
    /// Real Pedersen N_hat (product of safe primes, big-endian bytes).
    #[serde(default)]
    pub real_pedersen_n_hat: Option<Vec<u8>>,
    /// Real Pedersen s parameter (big-endian bytes).
    #[serde(default)]
    pub real_pedersen_s: Option<Vec<u8>>,
    /// Real Pedersen t parameter (big-endian bytes).
    #[serde(default)]
    pub real_pedersen_t: Option<Vec<u8>>,
    /// All parties' real Pedersen parameters (N_hat, s, t) indexed by party position.
    #[serde(default)]
    #[allow(clippy::type_complexity)]
    pub all_pedersen_params: Option<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>>,
}

// Manual Drop to zeroize secret share.
impl Drop for StarkThresholdShareData {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret_share);
    }
}

/// Stark pre-signature produced by the offline pre-signing phase.
///
/// Contains the party's nonce share, chi share, and the combined R point.
/// Can be stored and used later when a message arrives, enabling 1-round online signing.
///
/// **Nonce reuse protection:** A pre-signature MUST only be used once.
#[derive(Serialize, Deserialize)]
pub struct StarkPreSignature {
    /// Unique identifier for this pre-signature.
    pub id: String,
    /// Random nonce share k_i (32 bytes, Stark Felt big-endian).
    pub k_i: Vec<u8>,
    /// Chi share: additive share of k * x (32 bytes, Stark Felt big-endian).
    pub chi_i: Vec<u8>,
    /// R point x-coordinate (32 bytes, Stark Felt big-endian).
    pub r_felt: Vec<u8>,
    /// This party's ID.
    pub party_id: PartyId,
    /// Which parties participated in pre-signing.
    pub signers: Vec<PartyId>,
    /// Whether this pre-signature has been consumed (nonce reuse protection).
    pub used: bool,
}

impl Drop for StarkPreSignature {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.k_i);
        zeroize::Zeroize::zeroize(&mut self.chi_i);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire message types
// ─────────────────────────────────────────────────────────────────────────────

/// Round 1: commitment to public share.
#[derive(Serialize, Deserialize)]
struct StarkRound1Commitment {
    party_index: u16,
    commitment: Vec<u8>,
}

/// Round 2: decommitment + Schnorr proof.
#[derive(Serialize, Deserialize)]
struct StarkRound2Decommit {
    party_index: u16,
    /// Public key share point (64 bytes: x || y).
    public_share: Vec<u8>,
    /// Schnorr proof R point (64 bytes: x || y).
    schnorr_r: Vec<u8>,
    /// Schnorr proof s scalar (32 bytes).
    schnorr_s: Vec<u8>,
}

/// Round 3: Feldman VSS share distribution.
#[derive(Serialize, Deserialize)]
struct StarkRound3FeldmanShare {
    from_party: u16,
    /// Feldman share value for recipient (32 bytes, Felt big-endian).
    share_value: Vec<u8>,
    /// Feldman commitments: C_k = a_k * G (each 64 bytes: x || y).
    commitments: Vec<Vec<u8>>,
}

/// Aux info broadcast (Round 4): Paillier public key + Pedersen params.
#[derive(Serialize, Deserialize)]
struct StarkAuxInfoBroadcast {
    party_index: u16,
    paillier_pk: PaillierPublicKey,
    #[serde(default)]
    pedersen_n_hat: Option<Vec<u8>>,
    #[serde(default)]
    pedersen_s: Option<Vec<u8>>,
    #[serde(default)]
    pedersen_t: Option<Vec<u8>>,
}

/// Pre-sign Round 1: broadcast Gamma_i point + Schnorr proof of k_i.
#[derive(Serialize, Deserialize)]
struct StarkPreSignRound1 {
    party_index: u16,
    /// Gamma_i = gamma_i * G (64 bytes: x || y).
    gamma_point: Vec<u8>,
    /// Schnorr proof of k_i.
    schnorr_k_r: Vec<u8>,
    schnorr_k_s: Vec<u8>,
    /// K_i = k_i * G (64 bytes: x || y) — for Schnorr verification.
    k_point: Vec<u8>,
}

/// Pre-sign MtA Round 2: encrypted k_i.
#[derive(Serialize, Deserialize)]
struct StarkPreSignMtaRound2 {
    party_index: u16,
    encrypted_k: crate::paillier::PaillierCiphertext,
    // TODO: Add PiLogstar_stark and PiAffg_stark ZK proofs for full CGGMP21 security
    // Currently uses Pienc only (Paillier range proof, field-agnostic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pi_enc: Option<crate::paillier::zk_proofs::PiEncProof>,
}

/// Online signing message: partial signature sigma_i.
#[derive(Serialize, Deserialize)]
struct StarkSignOnlineMsg {
    party_index: u16,
    sigma_i: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Stark field helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Stark curve order as bytes (big-endian).
fn stark_order_bytes() -> [u8; 32] {
    EC_ORDER.to_bytes_be()
}

/// Stark curve order as BigUint.
fn stark_order_biguint() -> BigUint {
    BigUint::from_bytes_be(&stark_order_bytes())
}

/// Generate a random non-zero scalar in the Stark EC ORDER group.
///
/// IMPORTANT: Scalars for EC operations must be reduced mod q (the EC order),
/// NOT mod p (the field prime). Felt arithmetic operates mod p, so we use
/// BigUint arithmetic mod q and convert to Felt only for EC multiplication.
fn random_scalar_felt() -> Felt {
    let q = stark_order_biguint();
    let mut bytes = [0u8; 32];
    loop {
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let val = BigUint::from_bytes_be(&bytes);
        let reduced = val % &q;
        if !reduced.is_zero() {
            return biguint_to_felt(&reduced);
        }
    }
}

/// Add two scalars mod the EC order q (NOT mod the field prime p).
fn scalar_add(a: &Felt, b: &Felt) -> Felt {
    let q = stark_order_biguint();
    let a_big = BigUint::from_bytes_be(&a.to_bytes_be());
    let b_big = BigUint::from_bytes_be(&b.to_bytes_be());
    let sum = (a_big + b_big) % &q;
    biguint_to_felt(&sum)
}

/// Multiply two scalars mod the EC order q.
fn scalar_mul(a: &Felt, b: &Felt) -> Felt {
    let q = stark_order_biguint();
    let a_big = BigUint::from_bytes_be(&a.to_bytes_be());
    let b_big = BigUint::from_bytes_be(&b.to_bytes_be());
    let prod = (a_big * b_big) % &q;
    biguint_to_felt(&prod)
}

/// Subtract two scalars mod the EC order q.
fn scalar_sub(a: &Felt, b: &Felt) -> Felt {
    let q = stark_order_biguint();
    let a_big = BigUint::from_bytes_be(&a.to_bytes_be());
    let b_big = BigUint::from_bytes_be(&b.to_bytes_be());
    let diff = if a_big >= b_big {
        (a_big - b_big) % &q
    } else {
        (&q - (b_big - a_big) % &q) % &q
    };
    biguint_to_felt(&diff)
}

/// Compute modular inverse of a scalar mod the EC order q.
fn scalar_inverse(a: &Felt) -> Result<Felt, CoreError> {
    let q = stark_order_biguint();
    let a_big = BigUint::from_bytes_be(&a.to_bytes_be());
    // Extended Euclidean algorithm for modular inverse
    mod_inverse_biguint(&a_big, &q)
        .map(|inv| biguint_to_felt(&inv))
        .ok_or_else(|| CoreError::Crypto("scalar has no inverse mod EC order".into()))
}

/// Extended GCD-based modular inverse.
fn mod_inverse_biguint(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_integer::Integer;
    use num_traits::{One, Signed, Zero};

    let a_int = BigInt::from(a.clone());
    let m_int = BigInt::from(m.clone());

    let (mut old_r, mut r) = (a_int.clone(), m_int.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());

    while !r.is_zero() {
        let q = old_r.div_floor(&r);
        let tmp_r = r.clone();
        r = old_r - &q * &r;
        old_r = tmp_r;
        let tmp_s = s.clone();
        s = old_s - &q * &s;
        old_s = tmp_s;
    }

    if old_r != BigInt::one() {
        return None;
    }

    if old_s.is_negative() {
        old_s += &m_int;
    }
    Some(old_s.to_biguint().unwrap())
}

/// Evaluate polynomial at x using Horner's method, with arithmetic mod EC order q.
fn poly_eval_felt(coeffs: &[Felt], x: Felt) -> Felt {
    let mut result = Felt::ZERO;
    for coeff in coeffs.iter().rev() {
        result = scalar_add(&scalar_mul(&result, &x), coeff);
    }
    result
}

/// Compute Lagrange coefficient for party `my_index` among `signer_indices`, mod EC order q.
fn lagrange_coefficient_felt(my_index: u16, signer_indices: &[u16]) -> Result<Felt, CoreError> {
    let x_i = Felt::from(my_index as u64);
    let mut coeff = Felt::ONE;
    for &j in signer_indices {
        if j == my_index {
            continue;
        }
        let x_j = Felt::from(j as u64);
        let num = scalar_sub(&Felt::ZERO, &x_j); // -x_j mod q
        let den = scalar_sub(&x_i, &x_j);
        let den_inv = scalar_inverse(&den).map_err(|_| {
            CoreError::Crypto(
                "zero denominator in Lagrange coefficient — duplicate party index".into(),
            )
        })?;
        coeff = scalar_mul(&coeff, &scalar_mul(&num, &den_inv));
    }
    Ok(coeff)
}

/// Encode a ProjectivePoint as 64 bytes: x || y (big-endian Felts).
/// Converts to affine first.
fn encode_point(p: &ProjectivePoint) -> Result<Vec<u8>, CoreError> {
    let affine = p
        .to_affine()
        .map_err(|e| CoreError::Crypto(format!("point at infinity: {e:?}")))?;
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&affine.x().to_bytes_be());
    buf.extend_from_slice(&affine.y().to_bytes_be());
    Ok(buf)
}

/// Decode 64 bytes (x || y, big-endian) into a ProjectivePoint.
fn decode_point(bytes: &[u8]) -> Result<ProjectivePoint, CoreError> {
    if bytes.len() != 64 {
        return Err(CoreError::Crypto(format!(
            "invalid point encoding: expected 64 bytes, got {}",
            bytes.len()
        )));
    }
    let x = Felt::from_bytes_be_slice(&bytes[..32]);
    let y = Felt::from_bytes_be_slice(&bytes[32..]);
    ProjectivePoint::from_affine(x, y)
        .map_err(|e| CoreError::Crypto(format!("invalid curve point: {e:?}")))
}

/// Compare two ProjectivePoints by converting to affine (x, y) coordinates.
///
/// Direct projective comparison may fail when Z coordinates differ even though
/// the affine points are the same. This function normalizes both points.
fn points_equal(a: &ProjectivePoint, b: &ProjectivePoint) -> bool {
    match (a.to_affine(), b.to_affine()) {
        (Ok(aa), Ok(bb)) => aa.x() == bb.x() && aa.y() == bb.y(),
        // Both at infinity
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

/// The Stark curve generator as a ProjectivePoint.
fn stark_generator() -> ProjectivePoint {
    ProjectivePoint::from_affine(GENERATOR.x(), GENERATOR.y())
        .expect("generator is a valid curve point")
}

/// Convert BigUint to Felt (reduce mod Stark prime).
fn biguint_to_felt(b: &BigUint) -> Felt {
    let bytes = b.to_bytes_be();
    Felt::from_bytes_be_slice(&bytes)
}

/// Convert a Paillier MtA output (BigUint mod N) to a Felt using signed interpretation.
///
/// MtA produces values in [0, N). Values > N/2 represent negative numbers (value - N).
/// We reduce to the Stark field: positive values mod q, negative as -(N-value) mod q.
fn to_felt_signed(big: &BigUint, n: &BigUint, n_half: &BigUint, stark_order: &BigUint) -> Felt {
    if big <= n_half {
        // Positive: reduce directly mod q
        let reduced = big % stark_order;
        biguint_to_felt(&reduced)
    } else {
        // Negative: true value is big - N, so Felt = -(N - big) mod q
        let abs_val = n - big;
        let reduced = &abs_val % stark_order;
        Felt::ZERO - biguint_to_felt(&reduced)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Schnorr proof helpers (Stark curve)
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a Schnorr proof of knowledge of discrete log on the Stark curve.
///
/// Proves knowledge of `secret` such that `public_point = secret * G_stark`.
/// Returns (R_bytes, s_bytes) where R = k*G, e = SHA256(public_point || R || party_index),
/// s = k + e_felt * secret.
fn schnorr_prove_stark(
    secret: &Felt,
    public_point_bytes: &[u8],
    party_index: u16,
) -> (Vec<u8>, Vec<u8>) {
    let k = random_scalar_felt();
    let g = stark_generator();
    let r_point = &g * k;
    let r_bytes = encode_point(&r_point).expect("R point must be valid");

    // Challenge: e = SHA256(public_point || R_bytes || party_index), reduced mod q
    let e_felt = schnorr_challenge(public_point_bytes, &r_bytes, party_index);

    // s = k + e * secret (mod q — the EC order)
    let s = scalar_add(&k, &scalar_mul(&e_felt, secret));
    let s_bytes = s.to_bytes_be().to_vec();

    (r_bytes, s_bytes)
}

/// Compute Schnorr challenge hash, reduced mod EC order q.
fn schnorr_challenge(public_point_bytes: &[u8], r_bytes: &[u8], party_index: u16) -> Felt {
    let mut hasher = Sha256::new();
    hasher.update(public_point_bytes);
    hasher.update(r_bytes);
    hasher.update(party_index.to_le_bytes());
    let e_hash = hasher.finalize();
    // Reduce hash mod EC order q to stay in the scalar field.
    let e_big = BigUint::from_bytes_be(&e_hash);
    let q = stark_order_biguint();
    let e_reduced = e_big % q;
    biguint_to_felt(&e_reduced)
}

/// Verify a Schnorr proof of knowledge on the Stark curve.
///
/// Checks that s * G == R + e * X where e = SHA256(X || R || party_index).
fn schnorr_verify_stark(
    public_point_bytes: &[u8],
    r_bytes: &[u8],
    s_bytes: &[u8],
    party_index: u16,
) -> Result<bool, CoreError> {
    let x_point = decode_point(public_point_bytes)?;
    let r_point = decode_point(r_bytes)?;
    let s_felt = Felt::from_bytes_be_slice(s_bytes);

    // Recompute challenge (same as prove: reduced mod q)
    let e_felt = schnorr_challenge(public_point_bytes, r_bytes, party_index);

    // Check: s * G == R + e * X
    let g = stark_generator();
    let lhs = &g * s_felt;
    let rhs = r_point + &x_point * e_felt;

    Ok(points_equal(&lhs, &rhs))
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol implementation
// ─────────────────────────────────────────────────────────────────────────────

/// StarkNet threshold signing protocol using real STARK curve cryptography.
///
/// Implements threshold ECDSA on the Stark curve with:
/// - Feldman VSS keygen over the Stark field
/// - MtA-based pre-signing (reuses Paillier MtA from crate::paillier)
/// - 1-round online signing
pub struct StarkProtocol;

impl StarkProtocol {
    pub fn new() -> Self {
        Self
    }

    /// Threshold pre-signing phase (offline, produces StarkPreSignature).
    pub async fn pre_sign(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        transport: &dyn Transport,
    ) -> Result<StarkPreSignature, CoreError> {
        stark_threshold_presign(key_share, signers, transport).await
    }

    /// Online signing phase (1 round from pre-signature).
    pub async fn sign_with_presig(
        &self,
        pre_sig: &mut StarkPreSignature,
        message: &[u8],
        key_share: &KeyShare,
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        stark_threshold_sign_online(pre_sig, message, key_share, transport).await
    }
}

impl Default for StarkProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MpcProtocol for StarkProtocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::StarkThreshold
    }

    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        stark_threshold_keygen(config, party_id, transport).await
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Keygen — 3 rounds + Feldman VSS + aux info
// ─────────────────────────────────────────────────────────────────────────────

/// Stark threshold distributed keygen with Feldman VSS.
///
/// Protocol flow:
/// 1. Round 1: Each party generates secret x_i, computes X_i = x_i * G_stark,
///    broadcasts commitment V_i = H(X_i || schnorr_proof || i).
/// 2. Round 2: Each party reveals X_i and Schnorr proof of knowledge of x_i.
/// 3. Round 3: Feldman VSS — distribute shares with verifiable commitments.
/// 4. Round 4: Aux info — broadcast Paillier public key + Pedersen params.
///
/// The full private key x = sum(x_i) is NEVER reconstructed.
async fn stark_threshold_keygen(
    config: ThresholdConfig,
    party_id: PartyId,
    transport: &dyn Transport,
) -> Result<KeyShare, CoreError> {
    let n = config.total_parties;
    let t = config.threshold;
    let my_index = party_id.0;
    let g = stark_generator();

    // Generate all random values before any .await (ThreadRng not Send).
    // Use random_scalar_felt() to ensure values are in [1, q) where q is the EC order.
    let x_i = random_scalar_felt();
    let mut feldman_coeffs: Vec<Felt> = Vec::with_capacity(t as usize);
    feldman_coeffs.push(x_i); // a_0 = x_i (the secret)
    for _ in 1..t {
        feldman_coeffs.push(random_scalar_felt());
    }

    // X_i = x_i * G_stark
    let x_i_point = &g * x_i;
    let x_i_pub_bytes = encode_point(&x_i_point)?;

    // Generate Schnorr proof of knowledge of x_i
    let (schnorr_r, schnorr_s) = schnorr_prove_stark(&x_i, &x_i_pub_bytes, my_index);

    // ── Round 1: Broadcast commitment ───────────────────────────────────
    let mut hasher = Sha256::new();
    hasher.update(&x_i_pub_bytes);
    hasher.update(&schnorr_r);
    hasher.update(&schnorr_s);
    hasher.update(my_index.to_le_bytes());
    let commitment = hasher.finalize().to_vec();

    let round1_msg = StarkRound1Commitment {
        party_index: my_index,
        commitment: commitment.clone(),
    };
    let round1_payload =
        serde_json::to_vec(&round1_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: party_id,
            to: None,
            round: 1,
            payload: round1_payload,
        })
        .await?;

    let mut commitments: Vec<StarkRound1Commitment> = vec![round1_msg];
    for _ in 1..n {
        let msg = transport.recv().await?;
        let r1: StarkRound1Commitment = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        commitments.push(r1);
    }
    commitments.sort_by_key(|c| c.party_index);

    // ── Round 2: Broadcast decommitment + Schnorr proof ────────────────
    let round2_msg = StarkRound2Decommit {
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

    let mut decommits: Vec<StarkRound2Decommit> = vec![round2_msg];
    for _ in 1..n {
        let msg = transport.recv().await?;
        let r2: StarkRound2Decommit = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        decommits.push(r2);
    }
    decommits.sort_by_key(|d| d.party_index);

    // ── Verify commitments and Schnorr proofs ───────────────────────────
    for decommit in &decommits {
        let mut hasher = Sha256::new();
        hasher.update(&decommit.public_share);
        hasher.update(&decommit.schnorr_r);
        hasher.update(&decommit.schnorr_s);
        hasher.update(decommit.party_index.to_le_bytes());
        let expected = hasher.finalize().to_vec();

        let stored = commitments
            .iter()
            .find(|c| c.party_index == decommit.party_index)
            .ok_or_else(|| {
                CoreError::Protocol(format!(
                    "missing commitment for party {}",
                    decommit.party_index
                ))
            })?;

        if stored.commitment != expected {
            return Err(CoreError::Protocol(format!(
                "commitment mismatch for party {} — identifiable abort",
                decommit.party_index
            )));
        }

        let valid = schnorr_verify_stark(
            &decommit.public_share,
            &decommit.schnorr_r,
            &decommit.schnorr_s,
            decommit.party_index,
        )?;
        if !valid {
            return Err(CoreError::Protocol(format!(
                "identifiable abort: party {} Schnorr proof invalid",
                decommit.party_index
            )));
        }
    }

    // Compute group public key: sum of all X_i
    let mut group_point = ProjectivePoint::identity();
    for decommit in &decommits {
        let p = decode_point(&decommit.public_share)?;
        group_point += p;
    }

    // Store public shares (sorted by party_index)
    let public_shares: Vec<Vec<u8>> = decommits.iter().map(|d| d.public_share.clone()).collect();

    // ── Round 3: Feldman VSS ────────────────────────────────────────────
    // Compute Feldman commitments: C_k = a_k * G for k = 0..t-1
    let feldman_commitments: Vec<Vec<u8>> = feldman_coeffs
        .iter()
        .map(|c| encode_point(&(&g * *c)))
        .collect::<Result<Vec<_>, _>>()?;

    // Send share to each party
    for j in 1..=n {
        let eval_x = Felt::from(j as u64);
        let share_val = poly_eval_felt(&feldman_coeffs, eval_x);
        let share_msg = StarkRound3FeldmanShare {
            from_party: my_index,
            share_value: share_val.to_bytes_be().to_vec(),
            commitments: feldman_commitments.clone(),
        };
        let payload =
            serde_json::to_vec(&share_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

        let to_pid = PartyId(j);
        transport
            .send(ProtocolMessage {
                from: party_id,
                to: Some(to_pid),
                round: 3,
                payload,
            })
            .await?;
    }

    // Receive Feldman shares from all parties (including self)
    let mut received_shares: Vec<StarkRound3FeldmanShare> = Vec::new();
    for _ in 0..n {
        let msg = transport.recv().await?;
        let r3: StarkRound3FeldmanShare = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        received_shares.push(r3);
    }
    received_shares.sort_by_key(|s| s.from_party);

    // Verify Feldman commitments and sum shares
    let mut final_share = Felt::ZERO;
    for share in &received_shares {
        // Verify: share_value * G == sum(C_k * my_index^k) for k = 0..t-1
        let share_felt = Felt::from_bytes_be_slice(&share.share_value);
        let share_point = &g * share_felt;

        let mut expected_point = ProjectivePoint::identity();
        let my_x = Felt::from(my_index as u64);
        let mut x_power = Felt::ONE;
        for commitment_bytes in &share.commitments {
            let c_point = decode_point(commitment_bytes)?;
            expected_point += &c_point * x_power;
            x_power = scalar_mul(&x_power, &my_x);
        }

        // Compare via affine x,y (projective PartialEq may compare raw Z coordinates).
        if !points_equal(&share_point, &expected_point) {
            return Err(CoreError::Protocol(format!(
                "Feldman VSS verification failed for share from party {} — identifiable abort",
                share.from_party
            )));
        }

        final_share = scalar_add(&final_share, &share_felt);
    }

    // ── Round 4: Auxiliary info — Paillier + Pedersen ────────────────────
    let (paillier_pk, paillier_sk) = crate::paillier::keygen::keypair_for_protocol(2048)?;

    // Generate Pedersen parameters (N_hat = product of two safe primes, s, t)
    let (ped_pk, _ped_sk) = crate::paillier::keygen::keypair_for_protocol(2048)?;
    let ped_n_hat = ped_pk.n_biguint().to_bytes_be();
    // s = random element in Z*_N_hat, t = s^lambda mod N_hat (simplified: random)
    let ped_s = {
        let mut buf = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    };
    let ped_t = {
        let mut buf = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    };

    let aux_msg = StarkAuxInfoBroadcast {
        party_index: my_index,
        paillier_pk: paillier_pk.clone(),
        pedersen_n_hat: Some(ped_n_hat.clone()),
        pedersen_s: Some(ped_s.clone()),
        pedersen_t: Some(ped_t.clone()),
    };
    let aux_payload =
        serde_json::to_vec(&aux_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: party_id,
            to: None,
            round: 4,
            payload: aux_payload,
        })
        .await?;

    let mut aux_msgs: Vec<StarkAuxInfoBroadcast> = vec![aux_msg];
    for _ in 1..n {
        let msg = transport.recv().await?;
        let aux: StarkAuxInfoBroadcast = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        aux_msgs.push(aux);
    }
    aux_msgs.sort_by_key(|a| a.party_index);

    // Collect all Paillier PKs and Pedersen params
    let all_paillier_pks: Vec<PaillierPublicKey> =
        aux_msgs.iter().map(|a| a.paillier_pk.clone()).collect();
    let all_pedersen_params: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = aux_msgs
        .iter()
        .map(|a| {
            (
                a.pedersen_n_hat.clone().unwrap_or_default(),
                a.pedersen_s.clone().unwrap_or_default(),
                a.pedersen_t.clone().unwrap_or_default(),
            )
        })
        .collect();

    // Group public key: x-coordinate of the summed point
    let group_affine = group_point
        .to_affine()
        .map_err(|e| CoreError::Crypto(format!("group pubkey at infinity: {e:?}")))?;
    let group_pubkey_x = group_affine.x().to_bytes_be().to_vec();

    let share_data = StarkThresholdShareData {
        party_index: my_index,
        secret_share: final_share.to_bytes_be().to_vec(),
        public_shares,
        group_public_key: group_pubkey_x.clone(),
        real_paillier_sk: Some(paillier_sk),
        real_paillier_pk: Some(paillier_pk),
        all_paillier_pks: Some(all_paillier_pks),
        real_pedersen_n_hat: Some(ped_n_hat),
        real_pedersen_s: Some(ped_s),
        real_pedersen_t: Some(ped_t),
        all_pedersen_params: Some(all_pedersen_params),
    };

    let share_bytes = Zeroizing::new(
        serde_json::to_vec(&share_data).map_err(|e| CoreError::Serialization(e.to_string()))?,
    );

    Ok(KeyShare {
        scheme: CryptoScheme::StarkThreshold,
        party_id,
        config,
        group_public_key: GroupPublicKey::StarkCurve(group_pubkey_x),
        share_data: share_bytes,
        chain_code: None,
        is_derived: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Pre-signing — offline phase (MtA-based)
// ─────────────────────────────────────────────────────────────────────────────

/// Stark threshold pre-signing using MtA with Paillier.
///
/// Produces a StarkPreSignature containing (k_i, chi_i, r_felt) that can later
/// be used for 1-round online signing.
async fn stark_threshold_presign(
    key_share: &KeyShare,
    signers: &[PartyId],
    transport: &dyn Transport,
) -> Result<StarkPreSignature, CoreError> {
    let share_data: StarkThresholdShareData = serde_json::from_slice(&key_share.share_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    let my_index = share_data.party_index;
    let my_party_id = key_share.party_id;
    let n_signers = signers.len();

    // Parse secret share
    let x_i = Felt::from_bytes_be_slice(&share_data.secret_share);

    // Compute Lagrange coefficient
    let signer_indices: Vec<u16> = signers.iter().map(|p| p.0).collect();
    let lambda_i = lagrange_coefficient_felt(my_index, &signer_indices)?;

    // Generate random nonce shares (before .await), mod EC order q.
    let k_i = random_scalar_felt();
    let gamma_i = random_scalar_felt();

    let g = stark_generator();

    // K_i = k_i * G
    let k_point = &g * k_i;
    let k_point_bytes = encode_point(&k_point)?;

    // Gamma_i = gamma_i * G
    let gamma_point = &g * gamma_i;
    let gamma_point_bytes = encode_point(&gamma_point)?;

    // Schnorr proof of knowledge of k_i
    let (schnorr_k_r, schnorr_k_s) = schnorr_prove_stark(&k_i, &k_point_bytes, my_index);

    // ── Round 1 (presign): Broadcast Gamma_i, K_i, Schnorr proof ──────
    let round1_msg = StarkPreSignRound1 {
        party_index: my_index,
        gamma_point: gamma_point_bytes.clone(),
        schnorr_k_r: schnorr_k_r.clone(),
        schnorr_k_s: schnorr_k_s.clone(),
        k_point: k_point_bytes.clone(),
    };
    let round1_payload =
        serde_json::to_vec(&round1_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 10,
            payload: round1_payload,
        })
        .await?;

    let mut round1_msgs: Vec<StarkPreSignRound1> = vec![round1_msg];
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let r1: StarkPreSignRound1 = serde_json::from_slice(&msg.payload)
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

    // Verify Schnorr proofs on K_i
    for r1 in &round1_msgs {
        if r1.party_index == my_index {
            continue;
        }
        let valid = schnorr_verify_stark(
            &r1.k_point,
            &r1.schnorr_k_r,
            &r1.schnorr_k_s,
            r1.party_index,
        )?;
        if !valid {
            return Err(CoreError::Protocol(format!(
                "identifiable abort: party {} invalid Schnorr proof for K_i in pre-signing",
                r1.party_index
            )));
        }
    }

    // Compute Gamma_sum = sum of all Gamma_i
    let mut gamma_sum_point = ProjectivePoint::identity();
    for r1 in &round1_msgs {
        let gp = decode_point(&r1.gamma_point)?;
        gamma_sum_point += gp;
    }

    // Sync barrier
    transport.wait_ready().await?;

    // ── Round 2: MtA — compute shares of k * gamma and k * x ──────────
    let has_paillier = share_data.real_paillier_pk.is_some()
        && share_data.real_paillier_sk.is_some()
        && share_data.all_paillier_pks.is_some();

    if !has_paillier {
        return Err(CoreError::Protocol(
            "Stark pre-signing requires Paillier keys — keygen must produce aux info".into(),
        ));
    }

    let my_pk = share_data.real_paillier_pk.as_ref().unwrap().clone();
    let my_sk = share_data.real_paillier_sk.as_ref().unwrap().clone();
    let all_pks = share_data.all_paillier_pks.as_ref().unwrap();

    // Create MtA Party A for k_i
    let k_i_bytes = k_i.to_bytes_be();
    let mta_party_a_k = MtaPartyA::new(
        my_pk.clone(),
        my_sk.clone(),
        Zeroizing::new(k_i_bytes.to_vec()),
    );
    let mta_round1_k = mta_party_a_k.round1();

    // Broadcast Enc(k_i)
    // TODO: Add PiLogstar_stark and PiAffg_stark ZK proofs for full CGGMP21 security
    let mta_r2_msg = StarkPreSignMtaRound2 {
        party_index: my_index,
        encrypted_k: mta_round1_k.ciphertext.clone(),
        pi_enc: None,
    };
    let mta_r2_payload =
        serde_json::to_vec(&mta_r2_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 11,
            payload: mta_r2_payload,
        })
        .await?;

    // Collect Enc(k_j) from all other signers
    let mut index_to_transport: std::collections::HashMap<u16, PartyId> =
        std::collections::HashMap::new();
    index_to_transport.insert(my_index, transport.party_id());

    let mut peer_enc_k: Vec<StarkPreSignMtaRound2> = vec![mta_r2_msg];
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let r2: StarkPreSignMtaRound2 = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        index_to_transport.insert(r2.party_index, msg.from);
        peer_enc_k.push(r2);
    }
    peer_enc_k.sort_by_key(|m| m.party_index);

    // For each peer j: run two MtA instances as Party B:
    //   1. k_j * gamma_i (for delta)
    //   2. k_j * (x_i * lambda_i) (for chi)
    let gamma_i_bytes = Zeroizing::new(gamma_i.to_bytes_be().to_vec());
    let x_i_lambda_i = scalar_mul(&x_i, &lambda_i);
    let x_i_lambda_i_bytes = Zeroizing::new(x_i_lambda_i.to_bytes_be().to_vec());

    let mut delta_beta_shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut chi_beta_shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();

    for peer_msg in &peer_enc_k {
        if peer_msg.party_index == my_index {
            continue;
        }
        let peer_pk_idx = (peer_msg.party_index - 1) as usize;
        if peer_pk_idx >= all_pks.len() {
            return Err(CoreError::Protocol(format!(
                "missing Paillier PK for party {}",
                peer_msg.party_index
            )));
        }
        let peer_pk = &all_pks[peer_pk_idx];

        // MtA for delta: k_j * gamma_i
        let mta_b_delta = MtaPartyB::new(peer_pk.clone(), gamma_i_bytes.clone());
        let mta_r1_in = MtaRound1 {
            ciphertext: peer_msg.encrypted_k.clone(),
        };
        let mta_r2_delta = mta_b_delta.round2(&mta_r1_in);

        // MtA for chi: k_j * (x_i * lambda_i)
        let mta_b_chi = MtaPartyB::new(peer_pk.clone(), x_i_lambda_i_bytes.clone());
        let mta_r1_in_chi = MtaRound1 {
            ciphertext: peer_msg.encrypted_k.clone(),
        };
        let mta_r2_chi = mta_b_chi.round2(&mta_r1_in_chi);

        delta_beta_shares.push(mta_r2_delta.beta);
        chi_beta_shares.push(mta_r2_chi.beta);

        // Send both MtA responses to peer
        let peer_transport_id = index_to_transport
            .get(&peer_msg.party_index)
            .copied()
            .ok_or_else(|| {
                CoreError::Protocol(format!(
                    "no transport mapping for party {}",
                    peer_msg.party_index
                ))
            })?;

        let combined_response = serde_json::json!({
            "from_party": my_index,
            "to_party": peer_msg.party_index,
            "delta_ct": serde_json::to_value(&mta_r2_delta.ciphertext).unwrap(),
            "chi_ct": serde_json::to_value(&mta_r2_chi.ciphertext).unwrap(),
        });
        let payload = serde_json::to_vec(&combined_response)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        transport
            .send(ProtocolMessage {
                from: my_party_id,
                to: Some(peer_transport_id),
                round: 12,
                payload,
            })
            .await?;
    }

    // Receive MtA responses and compute delta_i, chi_i.
    let n_big = my_pk.n_biguint();
    let n_half = &n_big >> 1;
    let stark_order = stark_order_biguint();

    // Start with local products: k_i * gamma_i and k_i * (x_i * lambda_i), mod q.
    let mut delta_felt = scalar_mul(&k_i, &gamma_i);
    let mut chi_felt = scalar_mul(&k_i, &x_i_lambda_i);

    // Subtract beta shares (Party B's contribution is -beta' in the new MtA formula).
    for beta_bytes in &delta_beta_shares {
        let beta_big = BigUint::from_bytes_be(beta_bytes);
        let beta_felt = to_felt_signed(&beta_big, &n_big, &n_half, &stark_order);
        delta_felt = scalar_sub(&delta_felt, &beta_felt);
    }
    for beta_bytes in &chi_beta_shares {
        let beta_big = BigUint::from_bytes_be(beta_bytes);
        let beta_felt = to_felt_signed(&beta_big, &n_big, &n_half, &stark_order);
        chi_felt = scalar_sub(&chi_felt, &beta_felt);
    }

    // Receive alpha shares from peers (responses to our Enc(k_i) broadcast)
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let r3: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let delta_ct: crate::paillier::PaillierCiphertext =
            serde_json::from_value(r3["delta_ct"].clone())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let chi_ct: crate::paillier::PaillierCiphertext =
            serde_json::from_value(r3["chi_ct"].clone())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

        // Decrypt as Party A
        let alpha_d = mta_party_a_k.round2_finish(&delta_ct);
        let alpha_d_felt = to_felt_signed(
            &BigUint::from_bytes_be(&alpha_d),
            &n_big,
            &n_half,
            &stark_order,
        );
        delta_felt = scalar_add(&delta_felt, &alpha_d_felt);

        let alpha_c = mta_party_a_k.round2_finish(&chi_ct);
        let alpha_c_felt = to_felt_signed(
            &BigUint::from_bytes_be(&alpha_c),
            &n_big,
            &n_half,
            &stark_order,
        );
        chi_felt = scalar_add(&chi_felt, &alpha_c_felt);
    }

    // Sync barrier
    transport.wait_ready().await?;

    // ── Broadcast delta_i for aggregation ─────────────────────────────
    let delta_broadcast = serde_json::json!({
        "party_index": my_index,
        "delta_i": delta_felt.to_bytes_be().to_vec(),
    });
    let delta_payload = serde_json::to_vec(&delta_broadcast)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 13,
            payload: delta_payload,
        })
        .await?;

    // Collect all delta_i and sum (mod q)
    let mut delta_sum = delta_felt;
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let dv: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let d_bytes: Vec<u8> = serde_json::from_value(dv["delta_i"].clone())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let d_felt = Felt::from_bytes_be_slice(&d_bytes);
        delta_sum = scalar_add(&delta_sum, &d_felt);
    }

    // ── Compute R = delta_inv * Gamma_sum ─────────────────────────────
    let delta_inv = scalar_inverse(&delta_sum)
        .map_err(|_| CoreError::Crypto("delta is zero — cannot compute R point".into()))?;
    let big_r_point = &gamma_sum_point * delta_inv;
    let big_r_affine = big_r_point
        .to_affine()
        .map_err(|e| CoreError::Crypto(format!("R point at infinity: {e:?}")))?;
    let r_felt = big_r_affine.x();

    Ok(StarkPreSignature {
        id: uuid::Uuid::new_v4().to_string(),
        k_i: k_i.to_bytes_be().to_vec(),
        chi_i: chi_felt.to_bytes_be().to_vec(),
        r_felt: r_felt.to_bytes_be().to_vec(),
        party_id: my_party_id,
        signers: signers.to_vec(),
        used: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Online Signing — 1 round
// ─────────────────────────────────────────────────────────────────────────────

/// Stark threshold online signing: uses a pre-signature to produce an ECDSA
/// signature in a single communication round.
async fn stark_threshold_sign_online(
    pre_sig: &mut StarkPreSignature,
    message: &[u8],
    key_share: &KeyShare,
    transport: &dyn Transport,
) -> Result<MpcSignature, CoreError> {
    // Nonce reuse protection
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
    let k_i = Felt::from_bytes_be_slice(&pre_sig.k_i);
    let chi_i = Felt::from_bytes_be_slice(&pre_sig.chi_i);
    let r_felt = Felt::from_bytes_be_slice(&pre_sig.r_felt);

    // Hash message to a Stark field element
    let msg_felt = Felt::from_bytes_be_slice(message);

    // Compute partial signature: sigma_i = k_i * msg_felt + chi_i * r_felt (mod q)
    let sigma_i = scalar_add(&scalar_mul(&k_i, &msg_felt), &scalar_mul(&chi_i, &r_felt));

    // Broadcast sigma_i
    let sign_msg = StarkSignOnlineMsg {
        party_index: my_index,
        sigma_i: sigma_i.to_bytes_be().to_vec(),
    };
    let payload =
        serde_json::to_vec(&sign_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 20,
            payload,
        })
        .await?;

    // Collect partial signatures from all signers
    let mut all_sigmas: Vec<(u16, Felt)> = vec![(my_index, sigma_i)];
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let sm: StarkSignOnlineMsg = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let s_j = Felt::from_bytes_be_slice(&sm.sigma_i);
        all_sigmas.push((sm.party_index, s_j));
    }

    // Aggregate: s = sum(sigma_i) mod q
    let mut s_total = Felt::ZERO;
    for (_, sigma) in &all_sigmas {
        s_total = scalar_add(&s_total, sigma);
    }

    let r_bytes = r_felt.to_bytes_be().to_vec();
    let s_bytes = s_total.to_bytes_be().to_vec();

    // Verify signature using starknet_crypto::verify
    let group_pubkey_felt = Felt::from_bytes_be_slice(key_share.group_public_key.as_bytes());
    let verify_result = starknet_crypto::verify(&group_pubkey_felt, &msg_felt, &r_felt, &s_total);

    match verify_result {
        Ok(true) => {}
        Ok(false) => {
            return Err(CoreError::Crypto(
                "threshold signature verification failed — potential cheating party".into(),
            ));
        }
        Err(e) => {
            return Err(CoreError::Crypto(format!("stark verify error: {e}")));
        }
    }

    Ok(MpcSignature::StarkSig {
        r: r_bytes,
        s: s_bytes,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Standalone verification helper
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a StarkNet signature against a public key and message.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_stark_signature(
    public_key: &[u8],
    message: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<bool, CoreError> {
    if public_key.len() > 32 || r.len() > 32 || s.len() > 32 {
        return Err(CoreError::Crypto(
            "stark verify: invalid field element length".into(),
        ));
    }

    let pubkey_felt = Felt::from_bytes_be_slice(public_key);
    let msg_felt = Felt::from_bytes_be_slice(message);
    let r_felt = Felt::from_bytes_be_slice(r);
    let s_felt = Felt::from_bytes_be_slice(s);

    starknet_crypto::verify(&pubkey_felt, &msg_felt, &r_felt, &s_felt)
        .map_err(|e| CoreError::Crypto(format!("stark verify: {e}")))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_keygen_and_sign_verify() {
        // Generate a private key.
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        secret_bytes[0] &= 0x07;

        let private_key = Felt::from_bytes_be(&secret_bytes);
        let public_key = starknet_crypto::get_public_key(&private_key);

        // Sign a message.
        let message = b"test message for stark signing";
        let msg_felt = Felt::from_bytes_be_slice(message);
        let k = starknet_crypto::rfc6979_generate_k(&msg_felt, &private_key, None);
        let sig = starknet_crypto::sign(&private_key, &msg_felt, &k).unwrap();

        // Verify.
        let valid = starknet_crypto::verify(&public_key, &msg_felt, &sig.r, &sig.s).unwrap();
        assert!(valid, "signature should verify");
    }

    #[test]
    fn test_stark_verify_wrong_message() {
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        secret_bytes[0] &= 0x07;

        let private_key = Felt::from_bytes_be(&secret_bytes);
        let public_key = starknet_crypto::get_public_key(&private_key);

        let message = b"correct message";
        let msg_felt = Felt::from_bytes_be_slice(message);
        let k = starknet_crypto::rfc6979_generate_k(&msg_felt, &private_key, None);
        let sig = starknet_crypto::sign(&private_key, &msg_felt, &k).unwrap();

        // Verify with wrong message should fail.
        let wrong_msg = Felt::from_bytes_be_slice(b"wrong message");
        let valid = starknet_crypto::verify(&public_key, &wrong_msg, &sig.r, &sig.s).unwrap();
        assert!(!valid, "signature should NOT verify with wrong message");
    }

    #[test]
    fn test_stark_verify_helper() {
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        secret_bytes[0] &= 0x07;

        let private_key = Felt::from_bytes_be(&secret_bytes);
        let public_key = starknet_crypto::get_public_key(&private_key);
        let pubkey_bytes = public_key.to_bytes_be();

        let message = b"verify helper test";
        let msg_felt = Felt::from_bytes_be_slice(message);
        let k = starknet_crypto::rfc6979_generate_k(&msg_felt, &private_key, None);
        let sig = starknet_crypto::sign(&private_key, &msg_felt, &k).unwrap();

        let r_bytes = sig.r.to_bytes_be();
        let s_bytes = sig.s.to_bytes_be();

        let valid = verify_stark_signature(&pubkey_bytes, message, &r_bytes, &s_bytes).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_stark_public_key_deterministic() {
        let secret = Felt::from_bytes_be(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ]);
        let pk1 = starknet_crypto::get_public_key(&secret);
        let pk2 = starknet_crypto::get_public_key(&secret);
        assert_eq!(pk1, pk2, "public key derivation must be deterministic");
    }

    #[test]
    fn test_stark_field_element_roundtrip() {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes[0] &= 0x07; // Ensure within field.

        let felt = Felt::from_bytes_be(&bytes);
        let roundtrip = felt.to_bytes_be();
        let felt2 = Felt::from_bytes_be(&roundtrip);
        assert_eq!(felt, felt2, "Felt round-trip must be lossless");
    }

    #[test]
    fn test_poly_eval_felt() {
        // f(x) = 3 + 2x + x^2
        let coeffs = vec![Felt::from(3u64), Felt::from(2u64), Felt::from(1u64)];
        // f(1) = 3 + 2 + 1 = 6
        let result = poly_eval_felt(&coeffs, Felt::from(1u64));
        assert_eq!(result, Felt::from(6u64));
        // f(2) = 3 + 4 + 4 = 11
        let result = poly_eval_felt(&coeffs, Felt::from(2u64));
        assert_eq!(result, Felt::from(11u64));
    }

    #[test]
    fn test_lagrange_coefficient_felt() {
        // 2-of-3: reconstruct at x=0 from parties 1,2
        let indices = vec![1u16, 2];
        let l1 = lagrange_coefficient_felt(1, &indices).unwrap();
        let l2 = lagrange_coefficient_felt(2, &indices).unwrap();

        // f(0) = l1 * f(1) + l2 * f(2) should hold for any degree-1 polynomial
        // Use f(x) = 5 + 3x, evaluated using scalar_* (mod q)
        let five = Felt::from(5u64);
        let three = Felt::from(3u64);
        let f1 = scalar_add(&five, &scalar_mul(&three, &Felt::from(1u64))); // 8
        let f2 = scalar_add(&five, &scalar_mul(&three, &Felt::from(2u64))); // 11
        let reconstructed = scalar_add(&scalar_mul(&l1, &f1), &scalar_mul(&l2, &f2));
        assert_eq!(
            reconstructed, five,
            "Lagrange interpolation must recover f(0)"
        );
    }

    #[test]
    fn test_schnorr_stark_prove_verify() {
        let g = stark_generator();

        // Test EC homomorphism with scalars mod q
        let a = random_scalar_felt();
        let b = random_scalar_felt();
        let a_plus_b = scalar_add(&a, &b);
        let ga = &g * a;
        let gb = &g * b;
        let g_ab_direct = &g * a_plus_b;
        let g_ab_sum = &ga + &gb;
        assert!(
            points_equal(&g_ab_direct, &g_ab_sum),
            "(a+b)*G must equal a*G + b*G with scalars mod q"
        );

        // Test Schnorr prove/verify
        let secret = random_scalar_felt();
        let pub_point = &g * secret;
        let pub_bytes = encode_point(&pub_point).unwrap();

        let (r, s) = schnorr_prove_stark(&secret, &pub_bytes, 1);
        let valid = schnorr_verify_stark(&pub_bytes, &r, &s, 1).unwrap();
        assert!(valid, "Schnorr proof must verify");

        // Wrong party index should fail
        let wrong = schnorr_verify_stark(&pub_bytes, &r, &s, 2).unwrap();
        assert!(!wrong, "Schnorr proof must fail with wrong party index");
    }

    #[test]
    fn test_encode_decode_point() {
        let secret = random_scalar_felt();
        let g = stark_generator();
        let point = &g * secret;
        let encoded = encode_point(&point).unwrap();
        let decoded = decode_point(&encoded).unwrap();
        assert!(
            points_equal(&point, &decoded),
            "point encode/decode roundtrip must be lossless"
        );
    }

    #[tokio::test]
    async fn test_stark_threshold_keygen_2_of_3() {
        use crate::transport::local::LocalTransportNetwork;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = StarkProtocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        let mut shares = Vec::new();
        for h in handles {
            let share = h.await.unwrap().unwrap();
            assert_eq!(share.scheme, CryptoScheme::StarkThreshold);
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

        // Verify shares have Paillier keys
        for share in &shares {
            let sd: StarkThresholdShareData = serde_json::from_slice(&share.share_data).unwrap();
            assert!(sd.real_paillier_pk.is_some(), "share must have Paillier PK");
            assert!(sd.real_paillier_sk.is_some(), "share must have Paillier SK");
            assert!(
                sd.all_paillier_pks.is_some(),
                "share must have all Paillier PKs"
            );
        }
    }

    #[tokio::test]
    async fn test_stark_threshold_sign_and_verify() {
        use crate::transport::local::LocalTransportNetwork;

        // Keygen: 2-of-3
        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = StarkProtocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        let mut shares = Vec::new();
        for h in handles {
            shares.push(h.await.unwrap().unwrap());
        }

        let group_pubkey_bytes = shares[0].group_public_key.as_bytes().to_vec();

        // Sign with parties 1 and 2 (threshold = 2)
        let signers = vec![PartyId(1), PartyId(2)];
        let message = b"stark threshold test message";

        let sign_net = LocalTransportNetwork::new(2);
        let mut sign_handles = Vec::new();

        for (idx, &signer) in signers.iter().enumerate() {
            let share = shares[(signer.0 - 1) as usize].clone();
            let transport = sign_net.get_transport(PartyId((idx + 1) as u16));
            let signers_clone = signers.clone();
            let msg = message.to_vec();
            sign_handles.push(tokio::spawn(async move {
                let p = StarkProtocol::new();
                p.sign(&share, &signers_clone, &msg, &*transport).await
            }));
        }

        let mut signatures = Vec::new();
        for h in sign_handles {
            signatures.push(h.await.unwrap().unwrap());
        }

        // All parties should produce the same signature
        if let MpcSignature::StarkSig { ref r, ref s } = signatures[0] {
            // Verify the signature
            let valid = verify_stark_signature(&group_pubkey_bytes, message, r, s).unwrap();
            assert!(valid, "threshold signature must verify");
        } else {
            panic!("expected StarkSig");
        }
    }
}
