//! # GG20 Threshold ECDSA Protocol
//!
//! This module provides two implementations selectable by feature flag:
//!
//! ## `gg20-distributed` (default — ON by default)
//!
//! Distributed ECDSA signing using **additive share arithmetic**.  The full
//! private key scalar is **never assembled** at any point during signing.
//!
//! ### Mathematical basis
//!
//! **Keygen (trusted dealer):**
//!
//! 1. The dealer (Party 1) generates private key `x` and splits it into
//!    Shamir shares `(i, f(i))` where `f` is a degree-(t-1) polynomial with
//!    `f(0) = x`.
//! 2. Party `i` receives **only** its own Shamir share value `f(i)`.
//!    The full secret `x` is never sent or stored.
//!
//! **Signing (distributed):**
//!
//! 1. Each party `i` in the signing set first computes its Lagrange coefficient
//!    `λ_i` from the actual signer set.  This turns their Shamir share into
//!    an additive share: `x_i_add = λ_i · f(i)` where `Σ x_i_add = x`.
//! 2. Party 1 (coordinator) draws an ephemeral nonce `k ∈ Z_n`, computes
//!    `R = k·G`, extracts `r = R.x mod n`, and computes `k_inv = k⁻¹ mod n`.
//! 3. Party 1 broadcasts `(r, k_inv)` to all other signers.
//! 4. Each party `i` computes its **partial signature contribution**:
//!    `s_i = x_i_add · r · k_inv  mod n`.
//! 5. Each party sends `s_i` to the coordinator (Party 1).
//! 6. The coordinator assembles: `s = hash · k_inv + Σ s_i  mod n`.
//!
//! **Correctness:**
//! ```text
//! s = hash · k_inv + Σ (x_i_add · r · k_inv)
//!   = k_inv · (hash + r · Σ x_i_add)
//!   = k_inv · (hash + r · x)
//! ```
//!
//! **Note:** The coordinator currently controls nonce generation. A future
//! enhancement will use Paillier MtA-based distributed nonce (see
//! `crate::paillier::mta`) to eliminate this trust assumption.
//!
//! ## `gg20-simulation` (OFF by default — INSECURE — backward compat only)
//!
//! Reconstructs the full private key via Lagrange interpolation during signing.
//! Completely negates the MPC security guarantee.  Gated behind the
//! `gg20-simulation` feature which is **disabled by default** (SEC-001).

use crate::error::CoreError;
use crate::paillier::zk_proofs::{prove_pifac, prove_pimod, verify_pifac, verify_pimod};
use crate::paillier::{PaillierPublicKey, PaillierSecretKey};
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::{ProtocolMessage, Transport};
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Common imports
// ─────────────────────────────────────────────────────────────────────────────

use async_trait::async_trait;
use k256::{
    elliptic_curve::{Field, PrimeField},
    ProjectivePoint, Scalar,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use zeroize::{ZeroizeOnDrop, Zeroizing};

// ─────────────────────────────────────────────────────────────────────────────
// Shared key-share data structure
// ─────────────────────────────────────────────────────────────────────────────

/// Per-party key share data stored in `KeyShare.share_data`.
///
/// Holds the raw Shamir share value `f(i)` (the y-coordinate of the polynomial
/// evaluated at the party's x-coordinate).  The Lagrange coefficient `λ_i` is
/// NOT pre-computed here — it is derived at signing time from the actual signer
/// set, enabling any valid threshold subset to sign.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct Gg20ShareData {
    /// This party's x-coordinate (1-indexed party number).
    x: u16,
    /// This party's Shamir share value `f(x)` as 32 bytes big-endian scalar.
    y: Vec<u8>,
    /// Real Paillier secret key (Sprint 28, optional for backward compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    real_paillier_sk: Option<PaillierSecretKey>,
    /// Real Paillier public key (Sprint 28, optional for backward compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    real_paillier_pk: Option<PaillierPublicKey>,
    /// All parties' verified Paillier public keys (Sprint 28).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    all_paillier_pks: Option<Vec<PaillierPublicKey>>,
    /// Real Pedersen N_hat (product of safe primes, big-endian bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    real_pedersen_n_hat: Option<Vec<u8>>,
    /// Real Pedersen s parameter (big-endian bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    real_pedersen_s: Option<Vec<u8>>,
    /// Real Pedersen t parameter (big-endian bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    real_pedersen_t: Option<Vec<u8>>,
    /// All parties' real Pedersen parameters (N_hat, s, t) indexed by party position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    #[allow(clippy::type_complexity)]
    all_pedersen_params: Option<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>>,
}

impl Gg20ShareData {
    /// Returns true if this share has real Paillier keys AND Pedersen params
    /// for MtA-based distributed nonce signing.
    fn has_real_aux_info(&self) -> bool {
        self.real_paillier_pk.is_some()
            && self.real_paillier_sk.is_some()
            && self.all_paillier_pks.is_some()
            && self.real_pedersen_n_hat.is_some()
            && self.real_pedersen_s.is_some()
            && self.real_pedersen_t.is_some()
            && self.all_pedersen_params.is_some()
    }
}

/// Default Paillier key size for production (secure, ~10s with glass_pumpkin).
/// In test mode, `keypair_for_protocol()` ignores this and returns a cached 512-bit keypair.
const GG20_PAILLIER_BITS: usize = 2048;

/// GG20 auxiliary info broadcast (Paillier PK + ZK proofs).
#[derive(Serialize, Deserialize)]
struct Gg20AuxInfoBroadcast {
    party_index: u16,
    paillier_pk: PaillierPublicKey,
    pimod_proof: crate::paillier::zk_proofs::PimodProof,
    pifac_proof: crate::paillier::zk_proofs::PifacProof,
    #[serde(default)]
    pedersen_n_hat: Option<Vec<u8>>,
    #[serde(default)]
    pedersen_s: Option<Vec<u8>>,
    #[serde(default)]
    pedersen_t: Option<Vec<u8>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Polynomial and Shamir helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate polynomial at `x`: `f(x) = c[0] + c[1]·x + c[2]·x² + …`
fn poly_eval(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    let mut result = Scalar::ZERO;
    let mut x_pow = Scalar::ONE;
    for coeff in coefficients {
        result += coeff * &x_pow;
        x_pow *= x;
    }
    result
}

/// Shamir secret sharing: split `secret` into `total` shares with threshold `t`.
///
/// Returns `(i, f(i))` for `i = 1..=total` where `f(0) = secret`.
fn shamir_split(secret: &Scalar, threshold: u16, total: u16) -> Vec<(u16, Scalar)> {
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

/// Compute the Lagrange basis coefficient `λ_i(0)` for party `i`
/// given the full set of participating party x-coordinates.
///
/// `λ_i(0) = ∏_{j≠i} (0 - x_j) / (x_i - x_j)  mod n`
/// Delegates to [`super::common::lagrange_coefficient`].
fn lagrange_coefficient(party_index: u16, all_parties: &[u16]) -> Result<Scalar, CoreError> {
    super::common::lagrange_coefficient(party_index, all_parties)
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulation-only: Lagrange interpolation (INSECURE — reconstructs full key)
// ─────────────────────────────────────────────────────────────────────────────

/// Lagrange interpolation at x=0 to reconstruct the secret.
///
/// # SECURITY: SIMULATION ONLY
/// This assembles the full private key in one scalar. Never called outside
/// the `gg20-simulation` feature gate.
#[cfg(feature = "gg20-simulation")]
fn lagrange_interpolate(shares: &[(u16, Scalar)]) -> Scalar {
    let mut result = Scalar::ZERO;
    for (i, &(x_i, ref y_i)) in shares.iter().enumerate() {
        let x_i_s = Scalar::from(x_i as u64);
        let mut basis = Scalar::ONE;
        for (j, &(x_j, _)) in shares.iter().enumerate() {
            if i != j {
                let x_j_s = Scalar::from(x_j as u64);
                let num = Scalar::ZERO - x_j_s;
                let den = x_i_s - x_j_s;
                let den_inv = den.invert();
                assert!(
                    bool::from(den_inv.is_some()),
                    "zero denominator in Lagrange"
                );
                basis *= num * den_inv.unwrap();
            }
        }
        result += *y_i * basis;
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Public struct
// ─────────────────────────────────────────────────────────────────────────────

/// GG20 threshold ECDSA protocol.
///
/// - Default (`gg20-distributed` ON): signing never reconstructs the private key.
/// - `gg20-simulation` ON: Lagrange reconstruction used (insecure, backward compat).
pub struct Gg20Protocol;

impl Gg20Protocol {
    /// Create a new `Gg20Protocol` instance.
    ///
    /// The struct is zero-sized; all signing state lives in the [`crate::protocol::KeyShare`]
    /// passed to [`crate::protocol::MpcProtocol::sign`]. By default the distributed
    /// (non-reconstructing) signing path is used. The insecure Lagrange-reconstruction
    /// simulation path requires the `gg20-simulation` feature flag, which is **off by default**.
    pub fn new() -> Self {
        Self
    }
}

impl Default for Gg20Protocol {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MpcProtocol impl — dispatches to distributed or simulation
// ─────────────────────────────────────────────────────────────────────────────

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
        #[cfg(feature = "gg20-simulation")]
        {
            simulation_keygen(config, party_id, transport).await
        }

        #[cfg(not(feature = "gg20-simulation"))]
        {
            distributed_keygen(config, party_id, transport).await
        }
    }

    async fn sign(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        message: &[u8],
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        #[cfg(feature = "gg20-simulation")]
        {
            simulation_sign(key_share, signers, message, transport).await
        }

        #[cfg(not(feature = "gg20-simulation"))]
        {
            // Sprint 28b: Always use MtA-based signing with mandatory ZK proofs.
            // Legacy shares without real Paillier + Pedersen keys are rejected inside
            // distributed_sign_mta() (line 812 check).
            distributed_sign_mta(key_share, signers, message, transport).await
        }
    }

    async fn refresh(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        distributed_refresh(key_share, signers, transport).await
    }

    async fn reshare(
        &self,
        key_share: &KeyShare,
        old_signers: &[PartyId],
        new_config: ThresholdConfig,
        new_parties: &[PartyId],
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        distributed_reshare(key_share, old_signers, new_config, new_parties, transport).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DISTRIBUTED keygen — no key reconstruction (SEC-001 fix)
// ─────────────────────────────────────────────────────────────────────────────

/// Keygen using trusted-dealer model with Shamir secret sharing.
///
/// Each party receives only its own Shamir share value `f(i)`.  The full
/// private key scalar `x = f(0)` is never transmitted — it is erased from
/// the dealer's memory after the shares are sent.
///
/// Lagrange coefficients are computed at signing time from the actual signer
/// set, not pre-computed here.  This allows any valid t-subset to sign.
#[cfg(not(feature = "gg20-simulation"))]
async fn distributed_keygen(
    config: ThresholdConfig,
    party_id: PartyId,
    transport: &dyn Transport,
) -> Result<KeyShare, CoreError> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    // ── Phase 1: Shamir share distribution ──────────────────────────────
    let (share_data_base, group_pubkey_bytes) = if party_id == PartyId(1) {
        // ── Dealer: all scalar work before first .await ───────────────────
        let secret = Zeroizing::new(Scalar::random(&mut rand::thread_rng()));

        let public_point = (ProjectivePoint::GENERATOR * *secret).to_affine();
        let public_key = k256::PublicKey::from_affine(public_point)
            .map_err(|e| CoreError::Crypto(e.to_string()))?;
        let group_pubkey_bytes = public_key.to_encoded_point(true).as_bytes().to_vec();

        let shamir_shares = shamir_split(&secret, config.threshold, config.total_parties);

        let mut messages: Vec<(PartyId, Vec<u8>)> = Vec::new();
        let mut my_share_data: Option<Gg20ShareData> = None;

        for &(x, ref y) in &shamir_shares {
            let sd = Gg20ShareData {
                x,
                y: y.to_repr().to_vec(),
                real_paillier_sk: None,
                real_paillier_pk: None,
                all_paillier_pks: None,
                real_pedersen_n_hat: None,
                real_pedersen_s: None,
                real_pedersen_t: None,
                all_pedersen_params: None,
            };
            let share_bytes =
                serde_json::to_vec(&sd).map_err(|e| CoreError::Serialization(e.to_string()))?;
            let msg_payload = serde_json::to_vec(&(share_bytes, group_pubkey_bytes.clone()))
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

            let target = PartyId(x);
            if target == party_id {
                my_share_data = Some(sd);
            } else {
                messages.push((target, msg_payload));
            }
        }

        for (target, payload) in messages {
            transport
                .send(ProtocolMessage {
                    from: party_id,
                    to: Some(target),
                    round: 1,
                    payload,
                })
                .await?;
        }

        let sd = my_share_data
            .ok_or_else(|| CoreError::Crypto("party 1 missing in share list".into()))?;
        (sd, group_pubkey_bytes)
    } else {
        let msg = transport.recv().await?;
        let (share_bytes, group_pubkey_bytes): (Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let sd: Gg20ShareData = serde_json::from_slice(&share_bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        (sd, group_pubkey_bytes)
    };

    // ── Per-round sync barrier (L-012 fix): ensure all parties have completed
    //    Phase 1 before anyone starts Phase 2 broadcasts ──────────────────────
    transport.wait_ready().await?;

    // ── Phase 2: Paillier key generation + ZK proof exchange (Sprint 28) ──
    let (real_pk, real_sk) = crate::paillier::keygen::keypair_for_protocol(GG20_PAILLIER_BITS)?;

    let p_big = BigUint::from_bytes_be(&real_sk.p);
    let q_big = BigUint::from_bytes_be(&real_sk.q);
    let n_big = real_pk.n_biguint();

    let pimod_proof = prove_pimod(&n_big, &p_big, &q_big);
    let pifac_proof = prove_pifac(&n_big, &p_big, &q_big);

    // Generate real Pedersen parameters for ZK proofs
    let (ped_n_hat, ped_s, ped_t) =
        crate::paillier::zk_proofs::pedersen_params_for_protocol(GG20_PAILLIER_BITS);

    let aux_msg = Gg20AuxInfoBroadcast {
        party_index: party_id.0,
        paillier_pk: real_pk.clone(),
        pimod_proof,
        pifac_proof,
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
            round: 2,
            payload: aux_payload,
        })
        .await?;

    let n = config.total_parties;
    let mut all_aux: Vec<Gg20AuxInfoBroadcast> = vec![aux_msg];
    for _ in 1..n {
        let msg = transport.recv().await?;
        let aux: Gg20AuxInfoBroadcast = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        all_aux.push(aux);
    }
    all_aux.sort_by_key(|a| a.party_index);

    for aux in &all_aux {
        if aux.party_index == party_id.0 {
            continue;
        }
        let peer_n = aux.paillier_pk.n_biguint();
        if !verify_pimod(&peer_n, &aux.pimod_proof) {
            return Err(CoreError::Protocol(format!(
                "GG20: Πmod proof failed for party {}",
                aux.party_index
            )));
        }
        if !verify_pifac(&peer_n, &aux.pifac_proof) {
            return Err(CoreError::Protocol(format!(
                "GG20: Πfac proof failed for party {}",
                aux.party_index
            )));
        }
    }

    let all_paillier_pks: Vec<PaillierPublicKey> =
        all_aux.iter().map(|a| a.paillier_pk.clone()).collect();
    let all_pedersen: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = all_aux
        .iter()
        .map(|a| {
            (
                a.pedersen_n_hat.clone().unwrap_or_default(),
                a.pedersen_s.clone().unwrap_or_default(),
                a.pedersen_t.clone().unwrap_or_default(),
            )
        })
        .collect();

    // Build final share data with Paillier keys + Pedersen params
    let final_share_data = Gg20ShareData {
        x: share_data_base.x,
        y: share_data_base.y.clone(),
        real_paillier_sk: Some(real_sk),
        real_paillier_pk: Some(real_pk),
        all_paillier_pks: Some(all_paillier_pks),
        real_pedersen_n_hat: Some(ped_n_hat),
        real_pedersen_s: Some(ped_s),
        real_pedersen_t: Some(ped_t),
        all_pedersen_params: Some(all_pedersen),
    };

    let share_bytes = serde_json::to_vec(&final_share_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    // BIP32: generate random chain code for HD derivation support
    let mut chain_code = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut chain_code);

    Ok(KeyShare {
        scheme: CryptoScheme::Gg20Ecdsa,
        party_id,
        config,
        group_public_key: GroupPublicKey::Secp256k1(group_pubkey_bytes),
        share_data: zeroize::Zeroizing::new(share_bytes),
        chain_code: Some(chain_code),
        is_derived: false,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// MtA-BASED DISTRIBUTED signing — no coordinator trust (DEC-017 fix)
// ─────────────────────────────────────────────────────────────────────────────

/// Distributed ECDSA signing using MtA-based distributed nonce.
///
/// Unlike `distributed_sign()` which trusts Party 1 to generate nonce k,
/// this version has each party contribute k_i shares via Paillier MtA.
/// No single party learns the full nonce. Requires real Paillier + Pedersen keys.
///
/// ## Protocol
///
/// 1. Each party samples k_i, γ_i and broadcasts K_i = k_i·G, Γ_i = γ_i·G
/// 2. MtA computes shares of δ = k·γ and χ = k·x (with Πenc + Πlog* + Πaff-g)
/// 3. Broadcast δ_i, aggregate δ = Σ δ_i
/// 4. R = δ⁻¹ · Γ_sum = k⁻¹·G, extract r = R.x
/// 5. Each party: σ_i = k_i·m + χ_i·r, broadcast and aggregate s = Σ σ_i
///
/// ## Correctness
///
/// s = Σ σ_i = m·k + r·k·x = k·(m + xr)
/// R = k⁻¹·G → verify: s⁻¹·(mG + rQ) = k⁻¹·G = R ✓
#[allow(clippy::too_many_lines)]
async fn distributed_sign_mta(
    key_share: &KeyShare,
    signers: &[PartyId],
    message: &[u8],
    transport: &dyn Transport,
) -> Result<MpcSignature, CoreError> {
    use crate::paillier::mta::{MtaPartyA, MtaPartyB, MtaRound1};
    use crate::paillier::zk_proofs::{PiAffgPublicInput, PiEncPublicInput, PiLogStarPublicInput};
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::Digest;

    let my_party_id = key_share.party_id;
    let share_data_copy = key_share.share_data.clone();
    let share_data: Gg20ShareData = serde_json::from_slice(&share_data_copy)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    if !share_data.has_real_aux_info() {
        return Err(CoreError::Protocol(
            "GG20 MtA signing requires real Paillier + Pedersen keys (run key refresh)".into(),
        ));
    }

    let my_pk = share_data.real_paillier_pk.as_ref().unwrap().clone();
    let my_sk = share_data.real_paillier_sk.as_ref().unwrap().clone();
    let all_pks = share_data.all_paillier_pks.as_ref().unwrap();
    let ped_n_hat = share_data.real_pedersen_n_hat.as_ref().unwrap();
    let ped_s = share_data.real_pedersen_s.as_ref().unwrap();
    let ped_t = share_data.real_pedersen_t.as_ref().unwrap();

    let my_index = share_data.x;
    let n_signers = signers.len();
    let signer_indices: Vec<u16> = signers.iter().map(|p| p.0).collect();

    // Compute Lagrange coefficient and additive share
    let shamir_y = Zeroizing::new(
        Scalar::from_repr(*k256::FieldBytes::from_slice(&share_data.y))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid Shamir share scalar".into()))?,
    );
    let lambda_i = lagrange_coefficient(my_index, &signer_indices)?;
    let x_i_add = Zeroizing::new(lambda_i * *shamir_y);

    // ── Round 1: Broadcast K_i, Gamma_i ─────────────────────────────────
    let k_i = Zeroizing::new(Scalar::random(&mut rand::thread_rng()));
    let gamma_i = Zeroizing::new(Scalar::random(&mut rand::thread_rng()));

    let k_point = (ProjectivePoint::GENERATOR * *k_i).to_affine();
    let k_point_bytes = k256::PublicKey::from_affine(k_point)
        .map_err(|e| CoreError::Crypto(format!("k_point: {e}")))?
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let gamma_point = (ProjectivePoint::GENERATOR * *gamma_i).to_affine();
    let gamma_point_bytes = k256::PublicKey::from_affine(gamma_point)
        .map_err(|e| CoreError::Crypto(format!("gamma_point: {e}")))?
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let round1_payload = serde_json::to_vec(&serde_json::json!({
        "party_index": my_index,
        "k_point": k_point_bytes,
        "gamma_point": gamma_point_bytes,
    }))
    .map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 30,
            payload: round1_payload,
        })
        .await?;

    // Collect Round 1 from all signers
    let mut round1_msgs: Vec<serde_json::Value> = Vec::new();
    round1_msgs.push(serde_json::json!({
        "party_index": my_index,
        "k_point": k_point_bytes,
        "gamma_point": gamma_point_bytes,
    }));
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let v: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        round1_msgs.push(v);
    }

    // Compute Gamma_sum = Σ Gamma_i
    let mut gamma_sum_point = ProjectivePoint::IDENTITY;
    for r1 in &round1_msgs {
        let gp_bytes: Vec<u8> = serde_json::from_value(r1["gamma_point"].clone())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let gp = k256::PublicKey::from_sec1_bytes(&gp_bytes)
            .map_err(|e| CoreError::Crypto(format!("invalid Gamma point: {e}")))?;
        gamma_sum_point += gp.to_projective();
    }

    // ── Per-round sync barrier (L-012 fix)
    transport.wait_ready().await?;

    // ── Round 2: MtA for delta (k*gamma) and chi (k*x) ─────────────────
    let mta_party_a_k = MtaPartyA::new(
        my_pk.clone(),
        my_sk.clone(),
        Zeroizing::new(k_i.to_repr().to_vec()),
    );
    let mta_witness = mta_party_a_k.round1_with_witness();
    let mta_round1_k = mta_witness.message;

    // Generate Πenc + Πlog* proofs
    let pi_enc_public = PiEncPublicInput {
        pk_n: my_pk.n.clone(),
        pk_n_squared: my_pk.n_squared.clone(),
        ciphertext: mta_round1_k.ciphertext.data.clone(),
        n_hat: ped_n_hat.clone(),
        s: ped_s.clone(),
        t: ped_t.clone(),
        session_id: key_share.group_public_key.as_bytes().to_vec(),
        prover_index: my_index,
    };
    let m_big = BigUint::from_bytes_be(&mta_witness.plaintext_m);
    let r_big = BigUint::from_bytes_be(&mta_witness.randomness_r);
    let pi_enc = crate::paillier::zk_proofs::prove_pienc(&m_big, &r_big, &pi_enc_public);

    let pi_logstar_public = PiLogStarPublicInput {
        pk_n: my_pk.n.clone(),
        pk_n_squared: my_pk.n_squared.clone(),
        ciphertext: mta_round1_k.ciphertext.data.clone(),
        x_commitment: k_point_bytes.clone(),
        n_hat: ped_n_hat.clone(),
        s: ped_s.clone(),
        t: ped_t.clone(),
        session_id: key_share.group_public_key.as_bytes().to_vec(),
        prover_index: my_index,
    };
    let pi_logstar =
        crate::paillier::zk_proofs::prove_pilogstar(&m_big, &r_big, &pi_logstar_public);

    // Broadcast Enc(k_i) + proofs
    let mta_r2_payload = serde_json::to_vec(&serde_json::json!({
        "party_index": my_index,
        "encrypted_k": serde_json::to_value(&mta_round1_k.ciphertext).unwrap(),
        "pi_enc": serde_json::to_value(&pi_enc).unwrap(),
        "pi_logstar": serde_json::to_value(&pi_logstar).unwrap(),
        "k_point": k_point_bytes,
    }))
    .map_err(|e| CoreError::Serialization(e.to_string()))?;

    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 31,
            payload: mta_r2_payload,
        })
        .await?;

    // Collect Enc(k_j) from peers
    let mut peer_enc_k: Vec<serde_json::Value> = Vec::new();
    peer_enc_k.push(serde_json::json!({
        "party_index": my_index,
        "encrypted_k": serde_json::to_value(&mta_round1_k.ciphertext).unwrap(),
    }));
    let mut index_to_transport: std::collections::HashMap<u16, PartyId> =
        std::collections::HashMap::new();
    index_to_transport.insert(my_index, my_party_id);

    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let v: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let peer_idx = v["party_index"].as_u64().unwrap_or(0) as u16;
        index_to_transport.insert(peer_idx, msg.from);

        // Verify Πenc + Πlog* from peer (MANDATORY since Sprint 28b)
        let peer_pk_idx = (peer_idx - 1) as usize;
        let peer_pk = &all_pks[peer_pk_idx];

        let pi_enc_peer: crate::paillier::zk_proofs::PiEncProof =
            serde_json::from_value(v["pi_enc"].clone()).map_err(|e| {
                CoreError::Protocol(format!(
                    "missing or invalid Πenc proof from party {} — all parties must provide ZK proofs: {}",
                    peer_idx, e
                ))
            })?;
        let enc_ct: crate::paillier::PaillierCiphertext =
            serde_json::from_value(v["encrypted_k"].clone())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pub_input = PiEncPublicInput {
            pk_n: peer_pk.n.clone(),
            pk_n_squared: peer_pk.n_squared.clone(),
            ciphertext: enc_ct.data.clone(),
            n_hat: ped_n_hat.clone(),
            s: ped_s.clone(),
            t: ped_t.clone(),
            session_id: key_share.group_public_key.as_bytes().to_vec(),
            prover_index: peer_idx,
        };
        if !crate::paillier::zk_proofs::verify_pienc(&pi_enc_peer, &pub_input) {
            return Err(CoreError::Protocol(format!(
                "GG20 MtA: Πenc failed for party {} — identifiable abort",
                peer_idx
            )));
        }

        let pi_ls: crate::paillier::zk_proofs::PiLogStarProof =
            serde_json::from_value(v["pi_logstar"].clone()).map_err(|e| {
                CoreError::Protocol(format!(
                    "missing or invalid Πlog* proof from party {} — all parties must provide ZK proofs: {}",
                    peer_idx, e
                ))
            })?;
        let kp_bytes: Vec<u8> = serde_json::from_value(v["k_point"].clone()).map_err(|e| {
            CoreError::Protocol(format!(
                "missing K_i point from party {} — required for Πlog* verification: {}",
                peer_idx, e
            ))
        })?;
        let enc_ct2: crate::paillier::PaillierCiphertext =
            serde_json::from_value(v["encrypted_k"].clone())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pub_input2 = PiLogStarPublicInput {
            pk_n: peer_pk.n.clone(),
            pk_n_squared: peer_pk.n_squared.clone(),
            ciphertext: enc_ct2.data.clone(),
            x_commitment: kp_bytes,
            n_hat: ped_n_hat.clone(),
            s: ped_s.clone(),
            t: ped_t.clone(),
            session_id: key_share.group_public_key.as_bytes().to_vec(),
            prover_index: peer_idx,
        };
        if !crate::paillier::zk_proofs::verify_pilogstar(&pi_ls, &pub_input2) {
            return Err(CoreError::Protocol(format!(
                "GG20 MtA: Πlog* failed for party {} — identifiable abort",
                peer_idx
            )));
        }

        peer_enc_k.push(v);
    }
    peer_enc_k.sort_by_key(|v| v["party_index"].as_u64().unwrap_or(0));

    // MtA as Party B for each peer's Enc(k_j)
    let gamma_i_bytes = Zeroizing::new(gamma_i.to_repr().to_vec());
    let x_i_add_bytes = Zeroizing::new(x_i_add.to_repr().to_vec());

    let mut delta_beta_shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut chi_beta_shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();

    for peer_v in &peer_enc_k {
        let peer_idx = peer_v["party_index"].as_u64().unwrap_or(0) as u16;
        if peer_idx == my_index {
            continue;
        }
        let peer_pk_idx = (peer_idx - 1) as usize;
        let peer_pk = &all_pks[peer_pk_idx];

        let enc_k: crate::paillier::PaillierCiphertext =
            serde_json::from_value(peer_v["encrypted_k"].clone())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

        // MtA for delta: k_j * gamma_i
        let mta_b_delta = MtaPartyB::new(peer_pk.clone(), gamma_i_bytes.clone());
        let mta_r1_in = MtaRound1 {
            ciphertext: enc_k.clone(),
        };
        let mta_w_delta = mta_b_delta.round2_with_witness(&mta_r1_in);

        // MtA for chi: k_j * x_i_add
        let mta_b_chi = MtaPartyB::new(peer_pk.clone(), x_i_add_bytes.clone());
        let mta_r1_chi = MtaRound1 {
            ciphertext: enc_k.clone(),
        };
        let mta_w_chi = mta_b_chi.round2_with_witness(&mta_r1_chi);

        // Generate Πaff-g proofs
        let beta_d = BigUint::from_bytes_be(&mta_w_delta.result.beta);
        let rho_d = BigUint::from_bytes_be(&mta_w_delta.rho_y);
        let pi_affg_d = crate::paillier::zk_proofs::prove_piaffg(
            &BigUint::from_bytes_be(&gamma_i_bytes),
            &beta_d,
            &rho_d,
            &PiAffgPublicInput {
                pk_n0: peer_pk.n.clone(),
                pk_n0_squared: peer_pk.n_squared.clone(),
                c: enc_k.data.clone(),
                d: mta_w_delta.result.ciphertext.data.clone(),
                n_hat: ped_n_hat.clone(),
                s: ped_s.clone(),
                t: ped_t.clone(),
                x_commitment: gamma_point_bytes.clone(),
                session_id: key_share.group_public_key.as_bytes().to_vec(),
                prover_index: my_index,
            },
        );

        let beta_c = BigUint::from_bytes_be(&mta_w_chi.result.beta);
        let rho_c = BigUint::from_bytes_be(&mta_w_chi.rho_y);
        let x_i_add_point = crate::paillier::zk_proofs::pilogstar_point_commitment(
            &BigUint::from_bytes_be(&x_i_add_bytes),
        );
        let pi_affg_c = crate::paillier::zk_proofs::prove_piaffg(
            &BigUint::from_bytes_be(&x_i_add_bytes),
            &beta_c,
            &rho_c,
            &PiAffgPublicInput {
                pk_n0: peer_pk.n.clone(),
                pk_n0_squared: peer_pk.n_squared.clone(),
                c: enc_k.data.clone(),
                d: mta_w_chi.result.ciphertext.data.clone(),
                n_hat: ped_n_hat.clone(),
                s: ped_s.clone(),
                t: ped_t.clone(),
                x_commitment: x_i_add_point.clone(),
                session_id: key_share.group_public_key.as_bytes().to_vec(),
                prover_index: my_index,
            },
        );

        delta_beta_shares.push(mta_w_delta.result.beta);
        chi_beta_shares.push(mta_w_chi.result.beta);

        // Send MtA responses + Πaff-g proofs to peer
        let peer_transport_id = index_to_transport.get(&peer_idx).copied().ok_or_else(|| {
            CoreError::Protocol(format!("no transport mapping for party {}", peer_idx))
        })?;
        let response = serde_json::json!({
            "from_party": my_index,
            "delta_ct": serde_json::to_value(&mta_w_delta.result.ciphertext).unwrap(),
            "chi_ct": serde_json::to_value(&mta_w_chi.result.ciphertext).unwrap(),
            "pi_affg_delta": serde_json::to_value(&pi_affg_d).unwrap(),
            "pi_affg_chi": serde_json::to_value(&pi_affg_c).unwrap(),
            "gamma_point": gamma_point_bytes,
            "x_i_add_point": x_i_add_point,
        });
        let payload =
            serde_json::to_vec(&response).map_err(|e| CoreError::Serialization(e.to_string()))?;
        transport
            .send(ProtocolMessage {
                from: my_party_id,
                to: Some(peer_transport_id),
                round: 32,
                payload,
            })
            .await?;
    }

    // Aggregate delta and chi
    let n_big = my_pk.n_biguint();
    let n_half = &n_big >> 1;
    let secp_order = BigUint::from_bytes_be(&super::common::secp256k1_order_bytes());

    let mut delta_scalar = *k_i * *gamma_i;
    let mut chi_scalar = *k_i * *x_i_add;

    // Subtract beta shares (MtA formula: alpha - beta = a*b)
    for beta_bytes in &delta_beta_shares {
        delta_scalar -= crate::protocol::common::to_scalar_signed(
            &BigUint::from_bytes_be(beta_bytes),
            &n_big,
            &n_half,
            &secp_order,
        );
    }
    for beta_bytes in &chi_beta_shares {
        chi_scalar -= crate::protocol::common::to_scalar_signed(
            &BigUint::from_bytes_be(beta_bytes),
            &n_big,
            &n_half,
            &secp_order,
        );
    }

    // Receive alpha shares from peers
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

        // Extract peer party index for ZK proof verification
        let peer_idx = r3["from_party"].as_u64().unwrap_or(0) as u16;

        // Verify Πaff-g proofs (MANDATORY since Sprint 28b)
        let pi_d_val = r3
            .get("pi_affg_delta")
            .filter(|v| !v.is_null())
            .ok_or_else(|| {
                CoreError::Protocol(
                    "missing Πaff-g (delta) proof — all parties must provide ZK proofs".into(),
                )
            })?;
        let pi_d: crate::paillier::zk_proofs::PiAffgProof =
            serde_json::from_value(pi_d_val.clone())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
        // Extract peer's Gamma_j point (gamma_j * G) from round 3 message
        let peer_gamma_point: Vec<u8> =
            serde_json::from_value(r3["gamma_point"].clone()).map_err(|e| {
                CoreError::Protocol(format!(
                    "missing gamma_point from party {} for Πaff-g delta verification: {}",
                    peer_idx, e
                ))
            })?;
        let verify_pub_d = PiAffgPublicInput {
            pk_n0: my_pk.n.clone(),
            pk_n0_squared: my_pk.n_squared.clone(),
            c: mta_round1_k.ciphertext.data.clone(),
            d: delta_ct.data.clone(),
            n_hat: ped_n_hat.clone(),
            s: ped_s.clone(),
            t: ped_t.clone(),
            x_commitment: peer_gamma_point,
            session_id: key_share.group_public_key.as_bytes().to_vec(),
            prover_index: peer_idx,
        };
        if !crate::paillier::zk_proofs::verify_piaffg(&pi_d, &verify_pub_d) {
            return Err(CoreError::Protocol(
                "GG20 MtA: Πaff-g (delta) verification failed — identifiable abort".into(),
            ));
        }

        let pi_c_val = r3
            .get("pi_affg_chi")
            .filter(|v| !v.is_null())
            .ok_or_else(|| {
                CoreError::Protocol(
                    "missing Πaff-g (chi) proof — all parties must provide ZK proofs".into(),
                )
            })?;
        let pi_c: crate::paillier::zk_proofs::PiAffgProof =
            serde_json::from_value(pi_c_val.clone())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
        // Extract peer's X_j point (x_j_add * G) from round 3 message
        let peer_x_i_add_point: Vec<u8> = serde_json::from_value(r3["x_i_add_point"].clone())
            .map_err(|e| {
                CoreError::Protocol(format!(
                    "missing x_i_add_point from party {} for Πaff-g chi verification: {}",
                    peer_idx, e
                ))
            })?;
        let verify_pub_c = PiAffgPublicInput {
            pk_n0: my_pk.n.clone(),
            pk_n0_squared: my_pk.n_squared.clone(),
            c: mta_round1_k.ciphertext.data.clone(),
            d: chi_ct.data.clone(),
            n_hat: ped_n_hat.clone(),
            s: ped_s.clone(),
            t: ped_t.clone(),
            x_commitment: peer_x_i_add_point,
            session_id: key_share.group_public_key.as_bytes().to_vec(),
            prover_index: peer_idx,
        };
        if !crate::paillier::zk_proofs::verify_piaffg(&pi_c, &verify_pub_c) {
            return Err(CoreError::Protocol(
                "GG20 MtA: Πaff-g (chi) verification failed — identifiable abort".into(),
            ));
        }

        let alpha_d = mta_party_a_k.round2_finish(&delta_ct);
        delta_scalar += crate::protocol::common::to_scalar_signed(
            &BigUint::from_bytes_be(&alpha_d),
            &n_big,
            &n_half,
            &secp_order,
        );

        let alpha_c = mta_party_a_k.round2_finish(&chi_ct);
        chi_scalar += crate::protocol::common::to_scalar_signed(
            &BigUint::from_bytes_be(&alpha_c),
            &n_big,
            &n_half,
            &secp_order,
        );
    }

    // ── Per-round sync barrier (L-012 fix)
    transport.wait_ready().await?;

    // ── Round 3: Broadcast delta_i, aggregate ────────────────────────────
    let delta_payload = serde_json::to_vec(&serde_json::json!({
        "party_index": my_index,
        "delta_i": delta_scalar.to_repr().as_slice(),
    }))
    .map_err(|e| CoreError::Serialization(e.to_string()))?;
    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 33,
            payload: delta_payload,
        })
        .await?;

    let mut delta_sum = delta_scalar;
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let v: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let delta_j_bytes: Vec<u8> = serde_json::from_value(v["delta_i"].clone())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let delta_j = Scalar::from_repr(*k256::FieldBytes::from_slice(&delta_j_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid delta scalar from peer".into()))?;
        delta_sum += delta_j;
    }

    // ── Compute R = δ⁻¹ · Γ_sum = k⁻¹·G ────────────────────────────────
    let delta_inv = delta_sum
        .invert()
        .into_option()
        .ok_or_else(|| CoreError::Crypto("delta sum is zero — protocol abort".into()))?;

    let big_r_point = (gamma_sum_point * delta_inv).to_affine();
    let big_r_bytes = big_r_point.to_bytes();

    // Extract r = R.x mod n
    let r_x_bytes: [u8; 32] = big_r_bytes[1..33]
        .try_into()
        .map_err(|_| CoreError::Crypto("failed to extract R.x".into()))?;
    let r_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(&r_x_bytes))
        .into_option()
        .ok_or_else(|| CoreError::Crypto("R.x does not reduce to valid scalar".into()))?;

    // ── Per-round sync barrier (L-012 fix)
    transport.wait_ready().await?;

    // ── Round 4: Online signing — σ_i = k_i·m + χ_i·r ──────────────────
    let hash_bytes = sha2::Sha256::digest(message);
    use k256::elliptic_curve::ops::Reduce;
    use k256::U256;
    let m_scalar =
        <Scalar as Reduce<U256>>::reduce_bytes(k256::FieldBytes::from_slice(&hash_bytes));

    let sigma_i = *k_i * m_scalar + chi_scalar * r_scalar;

    let sigma_payload = serde_json::to_vec(&serde_json::json!({
        "party_index": my_index,
        "sigma_i": sigma_i.to_repr().as_slice(),
    }))
    .map_err(|e| CoreError::Serialization(e.to_string()))?;
    transport
        .send(ProtocolMessage {
            from: my_party_id,
            to: None,
            round: 34,
            payload: sigma_payload,
        })
        .await?;

    let mut s_sum = sigma_i;
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let v: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let sigma_j_bytes: Vec<u8> = serde_json::from_value(v["sigma_i"].clone())
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let sigma_j = Scalar::from_repr(*k256::FieldBytes::from_slice(&sigma_j_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid sigma scalar from peer".into()))?;
        s_sum += sigma_j;
    }

    // s = Σ σ_i = k·(m + xr)
    let s = s_sum;

    // ── Build and normalize signature ────────────────────────────────────
    let r_bytes_arr: [u8; 32] = r_scalar.to_repr().into();
    let s_bytes_arr: [u8; 32] = s.to_repr().into();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes_arr);
    sig_bytes[32..].copy_from_slice(&s_bytes_arr);

    let raw_sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into())
        .map_err(|e| CoreError::Crypto(format!("invalid ECDSA signature: {e}")))?;

    // Low-s normalization (SEC-012 / EIP-2)
    let normalized_sig = match raw_sig.normalize_s() {
        Some(n) => n,
        None => raw_sig,
    };

    let norm_bytes = normalized_sig.to_bytes();
    let final_r: [u8; 32] = norm_bytes[..32].try_into().unwrap();
    let final_s: [u8; 32] = norm_bytes[32..].try_into().unwrap();

    // Determine recovery_id
    let pubkey = k256::PublicKey::from_sec1_bytes(key_share.group_public_key.as_bytes())
        .map_err(|e| CoreError::Crypto(format!("bad group pubkey: {e}")))?;
    let verifying_key = k256::ecdsa::VerifyingKey::from(&pubkey);

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
// DISTRIBUTED key refresh — proactive re-sharing (Epic H1)
// ─────────────────────────────────────────────────────────────────────────────

/// Proactive key refresh for GG20 distributed ECDSA.
///
/// Each participating party generates a random degree-(t-1) polynomial `g_i(x)`
/// with `g_i(0) = 0`, evaluates it at every other party's x-coordinate, and
/// exchanges evaluations via transport.  Each party then adds the aggregated
/// delta to its existing Shamir share:
///
/// ```text
/// delta_j = Σ_i g_i(j)      (sum of all parties' evaluations at j)
/// s'_j    = s_j + delta_j    (new share)
/// ```
///
/// **Invariant:** The group public key `Q = x·G` is unchanged because
/// `Σ_i g_i(0) = 0` for all parties' polynomials.
///
/// # Protocol rounds
///
/// **Round 100** — Each party sends `g_i(j)` to party `j` (unicast).
/// **Receive** — Each party collects evaluations from all other parties.
/// **Local** — Each party adds `delta_j` to its Shamir share scalar.
async fn distributed_refresh(
    key_share: &KeyShare,
    signers: &[PartyId],
    transport: &dyn Transport,
) -> Result<KeyShare, CoreError> {
    let my_party = key_share.party_id;
    let t = key_share.config.threshold;

    // Validate that we are in the signer set.
    if !signers.contains(&my_party) {
        return Err(CoreError::Protocol(
            "party not in refresh signer set".into(),
        ));
    }

    // Deserialize our current Shamir share.
    let share_data_copy = key_share.share_data.clone();
    let my_share: Gg20ShareData = serde_json::from_slice(&share_data_copy)
        .map_err(|e| CoreError::Serialization(format!("deserialize share for refresh: {e}")))?;

    // SEC-008 FIX: wrap share scalar in Zeroizing.
    let old_y = Zeroizing::new(
        Scalar::from_repr(*k256::FieldBytes::from_slice(&my_share.y))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid Shamir share scalar in refresh".into()))?,
    );

    // Generate random polynomial g(x) with g(0) = 0, degree t-1.
    // Coefficients: [0, c_1, c_2, ..., c_{t-1}]
    // Note: rng is scoped in a block so it does not live across an await point
    // (ThreadRng is !Send).
    let coefficients = {
        let mut rng = rand::thread_rng();
        let mut coeffs = Vec::with_capacity(t as usize);
        coeffs.push(Scalar::ZERO); // g(0) = 0 — preserves the secret
        for _ in 1..t {
            coeffs.push(Scalar::random(&mut rng));
        }
        coeffs
    };

    // Evaluate g(j) for each other signer j and send via unicast.
    for &signer in signers {
        if signer == my_party {
            continue;
        }
        let x_j = Scalar::from(signer.0 as u64);
        let eval = poly_eval(&coefficients, &x_j);

        let msg = ProtocolMessage {
            from: my_party,
            to: Some(signer),
            round: 100, // high round number to distinguish refresh from keygen/sign
            payload: eval.to_repr().to_vec(),
        };
        transport.send(msg).await?;
    }

    // Evaluate g(my_x) for self.
    let self_x = Scalar::from(my_share.x as u64);
    let self_eval = poly_eval(&coefficients, &self_x);

    // Receive evaluations from all other signers and sum into delta.
    let mut delta = self_eval;
    for &signer in signers {
        if signer == my_party {
            continue;
        }
        let msg = transport.recv().await?;
        let eval_bytes: [u8; 32] = msg.payload.as_slice().try_into().map_err(|_| {
            CoreError::Protocol("invalid refresh evaluation size (expected 32 bytes)".into())
        })?;
        let eval = Scalar::from_repr(*k256::FieldBytes::from_slice(&eval_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid scalar in refresh evaluation".into()))?;
        delta += eval;
    }

    // Compute new share: s'_j = s_j + delta_j
    let new_y = *old_y + delta;

    // Build new Gg20ShareData with updated share value, same x-coordinate.
    // Preserve existing Paillier keys from old share (refresh doesn't change them).
    let new_share_data = Gg20ShareData {
        x: my_share.x,
        y: new_y.to_repr().to_vec(),
        real_paillier_sk: my_share.real_paillier_sk.clone(),
        real_paillier_pk: my_share.real_paillier_pk.clone(),
        all_paillier_pks: my_share.all_paillier_pks.clone(),
        real_pedersen_n_hat: my_share.real_pedersen_n_hat.clone(),
        real_pedersen_s: my_share.real_pedersen_s.clone(),
        real_pedersen_t: my_share.real_pedersen_t.clone(),
        all_pedersen_params: my_share.all_pedersen_params.clone(),
    };
    let new_share_bytes = serde_json::to_vec(&new_share_data)
        .map_err(|e| CoreError::Serialization(format!("serialize refreshed share: {e}")))?;

    Ok(KeyShare {
        scheme: key_share.scheme,
        party_id: my_party,
        config: key_share.config,
        group_public_key: key_share.group_public_key.clone(),
        share_data: Zeroizing::new(new_share_bytes),
        chain_code: key_share.chain_code,
        is_derived: key_share.is_derived,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// DISTRIBUTED key resharing — change threshold / add-remove parties (Epic H2)
// ─────────────────────────────────────────────────────────────────────────────

/// Key resharing for GG20 distributed ECDSA.
///
/// Allows changing the threshold configuration (t,n) while preserving the group
/// public key. Old parties re-share their existing shares to a new set of
/// parties using new Shamir polynomials.
///
/// # Mathematical basis
///
/// Each old party `i` in the signing set holds Shamir share `f(i)`. They first
/// compute their Lagrange-weighted additive share `x_i = lambda_i * f(i)` where
/// `sum(x_i) = x` (the secret key).
///
/// Each old party generates a new degree-(t_new-1) polynomial `g_i` with
/// `g_i(0) = x_i` (their additive share as the constant term). They evaluate
/// `g_i(j)` for each new party `j` and send via transport.
///
/// Each new party `j` sums the evaluations: `s'_j = sum_i(g_i(j))`.
///
/// **Correctness:**
/// ```text
/// At x=0: sum_i(g_i(0)) = sum_i(x_i) = x  (the original secret)
/// ```
/// So the new shares `s'_j` are valid Shamir shares of the same secret `x`
/// under the new polynomial `G(x) = sum_i(g_i(x))` of degree `t_new - 1`.
///
/// The group public key `Q = x * G` is unchanged.
///
/// # Protocol rounds
///
/// **Round 200** — Each old party sends `g_i(j)` to new party `j` (unicast).
/// **Receive** — Each new party collects evaluations from all old parties.
/// **Local** — Each new party sums evaluations to get its new Shamir share.
///
/// # Participant roles
///
/// - Old parties (in `old_signers`): generate polynomials and send evaluations.
///   Must have at least `old_threshold` parties to reconstruct the secret.
/// - New parties (in `new_parties`): receive evaluations and compute new shares.
/// - A party can be in both sets (e.g., party 1 stays across resharing).
async fn distributed_reshare(
    key_share: &KeyShare,
    old_signers: &[PartyId],
    new_config: ThresholdConfig,
    new_parties: &[PartyId],
    transport: &dyn Transport,
) -> Result<KeyShare, CoreError> {
    let my_party = key_share.party_id;
    let is_old = old_signers.contains(&my_party);
    let is_new = new_parties.contains(&my_party);

    if !is_old && !is_new {
        return Err(CoreError::Protocol(
            "party is neither in old signers nor new parties for reshare".into(),
        ));
    }

    // Validate old signers meet the old threshold.
    if (old_signers.len() as u16) < key_share.config.threshold {
        return Err(CoreError::Protocol(format!(
            "reshare requires at least {} old signers, got {}",
            key_share.config.threshold,
            old_signers.len()
        )));
    }

    // ── Old party: compute additive share and send evaluations to new parties ──
    if is_old {
        // Deserialize our current Shamir share.
        let share_data_copy = key_share.share_data.clone();
        let my_share: Gg20ShareData = serde_json::from_slice(&share_data_copy)
            .map_err(|e| CoreError::Serialization(format!("deserialize share for reshare: {e}")))?;

        // SEC-008 FIX: wrap secret-derived scalars in Zeroizing.
        let shamir_y = Zeroizing::new(
            Scalar::from_repr(*k256::FieldBytes::from_slice(&my_share.y))
                .into_option()
                .ok_or_else(|| {
                    CoreError::Crypto("invalid Shamir share scalar in reshare".into())
                })?,
        );

        // Compute Lagrange coefficient for our party in the old signer set.
        let old_indices: Vec<u16> = old_signers.iter().map(|p| p.0).collect();
        let lambda_i = lagrange_coefficient(my_share.x, &old_indices)?;

        // Additive share: x_i = lambda_i * f(i), where sum(x_i) = x.
        // SEC-008 FIX: x_i is zeroized on drop.
        let x_i = Zeroizing::new(lambda_i * *shamir_y);

        // Generate new polynomial g_i of degree (t_new - 1) with g_i(0) = x_i.
        let t_new = new_config.threshold;
        let coefficients = {
            let mut rng = rand::thread_rng();
            let mut coeffs = Vec::with_capacity(t_new as usize);
            coeffs.push(*x_i); // g_i(0) = x_i (our additive share)
            for _ in 1..t_new {
                coeffs.push(Scalar::random(&mut rng));
            }
            coeffs
        };

        // Evaluate g_i(j) for each new party j and send via unicast.
        for &new_party in new_parties {
            let x_j = Scalar::from(new_party.0 as u64);
            let eval = poly_eval(&coefficients, &x_j);

            let msg = ProtocolMessage {
                from: my_party,
                to: Some(new_party),
                round: 200, // high round number to distinguish reshare
                payload: eval.to_repr().to_vec(),
            };
            transport.send(msg).await?;
        }
    }

    // ── New party: receive evaluations from all old parties and sum ──
    if is_new {
        let mut new_share_scalar = Scalar::ZERO;

        // Collect evaluations from all old signers.
        for _old_idx in 0..old_signers.len() {
            let msg = transport.recv().await?;
            let eval_bytes: [u8; 32] = msg.payload.as_slice().try_into().map_err(|_| {
                CoreError::Protocol("invalid reshare evaluation size (expected 32 bytes)".into())
            })?;
            let eval = Scalar::from_repr(*k256::FieldBytes::from_slice(&eval_bytes))
                .into_option()
                .ok_or_else(|| CoreError::Crypto("invalid scalar in reshare evaluation".into()))?;
            new_share_scalar += eval;
        }

        // ── Per-round sync barrier: ensure all new parties have received evaluations
        transport.wait_ready().await?;

        // ── Aux info exchange: generate Paillier keys + Pedersen params + ZK proofs ──
        // Same pattern as distributed_keygen Phase 2 (Sprint 28).
        // Without this, reshared shares cannot participate in MtA-based signing.
        let (real_pk, real_sk) = crate::paillier::keygen::keypair_for_protocol(GG20_PAILLIER_BITS)?;

        let p_big = BigUint::from_bytes_be(&real_sk.p);
        let q_big = BigUint::from_bytes_be(&real_sk.q);
        let n_big = real_pk.n_biguint();

        let pimod_proof = prove_pimod(&n_big, &p_big, &q_big);
        let pifac_proof = prove_pifac(&n_big, &p_big, &q_big);

        let (ped_n_hat, ped_s, ped_t) =
            crate::paillier::zk_proofs::pedersen_params_for_protocol(GG20_PAILLIER_BITS);

        let aux_msg = Gg20AuxInfoBroadcast {
            party_index: my_party.0,
            paillier_pk: real_pk.clone(),
            pimod_proof,
            pifac_proof,
            pedersen_n_hat: Some(ped_n_hat.clone()),
            pedersen_s: Some(ped_s.clone()),
            pedersen_t: Some(ped_t.clone()),
        };
        let aux_payload =
            serde_json::to_vec(&aux_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;

        transport
            .send(ProtocolMessage {
                from: my_party,
                to: None,
                round: 201,
                payload: aux_payload,
            })
            .await?;

        let n_new = new_config.total_parties;
        let mut all_aux: Vec<Gg20AuxInfoBroadcast> = vec![aux_msg];
        for _ in 1..n_new {
            let msg = transport.recv().await?;
            let aux: Gg20AuxInfoBroadcast = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            all_aux.push(aux);
        }
        all_aux.sort_by_key(|a| a.party_index);

        // Verify Πmod + Πfac proofs from each peer
        for aux in &all_aux {
            if aux.party_index == my_party.0 {
                continue;
            }
            let peer_n = aux.paillier_pk.n_biguint();
            if !verify_pimod(&peer_n, &aux.pimod_proof) {
                return Err(CoreError::Protocol(format!(
                    "GG20 reshare: Πmod proof failed for party {}",
                    aux.party_index
                )));
            }
            if !verify_pifac(&peer_n, &aux.pifac_proof) {
                return Err(CoreError::Protocol(format!(
                    "GG20 reshare: Πfac proof failed for party {}",
                    aux.party_index
                )));
            }
        }

        let all_paillier_pks: Vec<PaillierPublicKey> =
            all_aux.iter().map(|a| a.paillier_pk.clone()).collect();
        let all_pedersen: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = all_aux
            .iter()
            .map(|a| {
                (
                    a.pedersen_n_hat.clone().unwrap_or_default(),
                    a.pedersen_s.clone().unwrap_or_default(),
                    a.pedersen_t.clone().unwrap_or_default(),
                )
            })
            .collect();

        // Build final share data with Paillier keys + Pedersen params
        let new_share_data = Gg20ShareData {
            x: my_party.0,
            y: new_share_scalar.to_repr().to_vec(),
            real_paillier_sk: Some(real_sk),
            real_paillier_pk: Some(real_pk),
            all_paillier_pks: Some(all_paillier_pks),
            real_pedersen_n_hat: Some(ped_n_hat),
            real_pedersen_s: Some(ped_s),
            real_pedersen_t: Some(ped_t),
            all_pedersen_params: Some(all_pedersen),
        };
        let new_share_bytes = serde_json::to_vec(&new_share_data)
            .map_err(|e| CoreError::Serialization(format!("serialize reshared share: {e}")))?;

        Ok(KeyShare {
            scheme: key_share.scheme,
            party_id: my_party,
            config: new_config,
            group_public_key: key_share.group_public_key.clone(),
            share_data: Zeroizing::new(new_share_bytes),
            chain_code: key_share.chain_code,
            is_derived: key_share.is_derived,
        })
    } else {
        // Old-only party: does not receive a new share. Return a dummy key share
        // indicating this party is no longer part of the group.
        // In practice, the caller should discard this share.
        Err(CoreError::Protocol(
            "old-only party does not receive a new share after reshare".into(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SIMULATION keygen (gg20-simulation feature only — INSECURE backward compat)
// ─────────────────────────────────────────────────────────────────────────────

/// Simulation keygen: Shamir secret sharing, raw share values distributed.
///
/// # SECURITY: SIMULATION ONLY
/// During `simulation_sign`, all parties broadcast their raw Shamir shares and
/// reconstruct the full private key via Lagrange interpolation.
#[cfg(feature = "gg20-simulation")]
async fn simulation_keygen(
    config: ThresholdConfig,
    party_id: PartyId,
    transport: &dyn Transport,
) -> Result<KeyShare, CoreError> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    if party_id == PartyId(1) {
        // SEC-008 FIX: wrap dealer secret in Zeroizing.
        let secret = Zeroizing::new(Scalar::random(&mut rand::thread_rng()));
        let public_point = (ProjectivePoint::GENERATOR * *secret).to_affine();
        let public_key = k256::PublicKey::from_affine(public_point)
            .map_err(|e| CoreError::Crypto(e.to_string()))?;
        let uncompressed = public_key.to_encoded_point(false);
        let compressed = public_key.to_encoded_point(true);
        let group_pubkey_bytes = compressed.as_bytes().to_vec();
        let group_pubkey_uncompressed = uncompressed.as_bytes().to_vec();
        let shares = shamir_split(&secret, config.threshold, config.total_parties);

        let mut messages = Vec::new();
        for &(x, ref y) in &shares {
            let target = PartyId(x);
            if target == party_id {
                continue;
            }
            let share_data = Gg20ShareData {
                x,
                y: y.to_repr().to_vec(),
                real_paillier_sk: None,
                real_paillier_pk: None,
                all_paillier_pks: None,
                real_pedersen_n_hat: None,
                real_pedersen_s: None,
                real_pedersen_t: None,
                all_pedersen_params: None,
            };
            let payload = serde_json::to_vec(&share_data)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let msg_data = serde_json::to_vec(&(
                payload.clone(),
                group_pubkey_bytes.clone(),
                group_pubkey_uncompressed.clone(),
            ))
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
            messages.push((target, msg_data));
        }

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

        let my_share = shares.iter().find(|(x, _)| *x == 1).unwrap();
        let share_data = Gg20ShareData {
            x: my_share.0,
            y: my_share.1.to_repr().to_vec(),
            real_paillier_sk: None,
            real_paillier_pk: None,
            all_paillier_pks: None,
        };

        Ok(KeyShare {
            scheme: CryptoScheme::Gg20Ecdsa,
            party_id,
            config,
            group_public_key: GroupPublicKey::Secp256k1(group_pubkey_bytes),
            // SEC-004 root fix (T-S4-00/T-S4-01): wrap in Zeroizing
            share_data: zeroize::Zeroizing::new(
                serde_json::to_vec(&share_data)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?,
            ),
            chain_code: None,
            is_derived: false,
        })
    } else {
        let msg = transport.recv().await?;
        let (share_bytes, group_pubkey_bytes, _uncompressed): (Vec<u8>, Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let _: Gg20ShareData = serde_json::from_slice(&share_bytes)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        Ok(KeyShare {
            scheme: CryptoScheme::Gg20Ecdsa,
            party_id,
            config,
            group_public_key: GroupPublicKey::Secp256k1(group_pubkey_bytes),
            // SEC-004 root fix (T-S4-00/T-S4-01): wrap in Zeroizing
            share_data: zeroize::Zeroizing::new(share_bytes),
            chain_code: None,
            is_derived: false,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SIMULATION signing (gg20-simulation feature only — INSECURE backward compat)
// ─────────────────────────────────────────────────────────────────────────────

/// Simulation signing: broadcasts raw Shamir shares, reconstructs full key.
///
/// # SECURITY: SIMULATION ONLY — reconstructs full private key.
#[cfg(feature = "gg20-simulation")]
async fn simulation_sign(
    key_share: &KeyShare,
    signers: &[PartyId],
    message: &[u8],
    transport: &dyn Transport,
) -> Result<MpcSignature, CoreError> {
    use k256::SecretKey;

    // SEC-004 root fix (T-S4-00): share_data is now Zeroizing<Vec<u8>>.
    // Cloning produces another Zeroizing<Vec<u8>> — no double-wrap needed.
    let share_data_copy = key_share.share_data.clone();
    let my_share: Gg20ShareData = serde_json::from_slice(&share_data_copy)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    let my_y = Scalar::from_repr(*k256::FieldBytes::from_slice(&my_share.y))
        .into_option()
        .ok_or_else(|| CoreError::Crypto("invalid share scalar".into()))?;

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

    let mut collected_shares: Vec<(u16, Scalar)> = vec![(my_share.x, my_y)];
    for _ in 0..(signers.len() - 1) {
        let msg = transport.recv().await?;
        let (x, y_bytes): (u16, Vec<u8>) = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let y = Scalar::from_repr(*k256::FieldBytes::from_slice(&y_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid share from peer".into()))?;
        collected_shares.push((x, y));
    }

    // ⚠️ SECURITY: SIMULATION ONLY — reconstructs full private key.
    // SEC-008 FIX: wrap the reconstructed secret scalar in Zeroizing so it is
    // wiped from memory as soon as signing completes.
    let secret = Zeroizing::new(lagrange_interpolate(&collected_shares));

    let secret_key =
        SecretKey::from_bytes(&secret.to_repr()).map_err(|e| CoreError::Crypto(e.to_string()))?;
    let signing_key = k256::ecdsa::SigningKey::from(secret_key);

    use k256::ecdsa::signature::Signer;
    let sig: k256::ecdsa::Signature = signing_key.sign(message);

    let r = sig.r().to_bytes().to_vec();
    let s = sig.s().to_bytes().to_vec();

    let verifying_key = signing_key.verifying_key();
    let recovery_id = (0u8..2)
        .find(|&v| {
            let recid = k256::ecdsa::RecoveryId::try_from(v).unwrap();
            k256::ecdsa::VerifyingKey::recover_from_prehash(
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

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that Σ (λ_i · f(i)) = x for signing set {1, 2}.
    ///
    /// This is the core correctness property of the distributed protocol:
    /// the additive shares sum to the secret without any party having to
    /// assemble the full `x`.
    #[test]
    fn test_additive_shares_sum_to_secret_subset_12() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let shamir_shares = shamir_split(&secret, 2, 3);
        let signing_set = vec![1u16, 2u16];

        let mut sum = Scalar::ZERO;
        for &(x, ref y) in &shamir_shares {
            if signing_set.contains(&x) {
                let lambda = lagrange_coefficient(x, &signing_set).unwrap();
                sum += lambda * y;
            }
        }
        assert_eq!(
            secret, sum,
            "additive shares for set {{1,2}} must sum to secret"
        );
    }

    /// Verify the same property for signing set {1, 3} and {2, 3}.
    #[test]
    fn test_additive_shares_sum_to_secret_all_subsets() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let shamir_shares = shamir_split(&secret, 2, 3);

        for signing_set in [vec![1u16, 2u16], vec![1, 3], vec![2, 3]] {
            let mut sum = Scalar::ZERO;
            for &(x, ref y) in &shamir_shares {
                if signing_set.contains(&x) {
                    let lambda = lagrange_coefficient(x, &signing_set).unwrap();
                    sum += lambda * y;
                }
            }
            assert_eq!(
                secret, sum,
                "additive shares for set {signing_set:?} must sum to secret"
            );
        }
    }

    /// Verify polynomial evaluation for degree-0 and degree-1 cases.
    #[test]
    fn test_poly_eval_degree0() {
        let c = Scalar::from(7u64);
        assert_eq!(poly_eval(&[c], &Scalar::from(3u64)), c);
    }

    #[test]
    fn test_poly_eval_degree1() {
        // f(x) = 1 + 2x  =>  f(3) = 7
        let coeffs = [Scalar::from(1u64), Scalar::from(2u64)];
        assert_eq!(poly_eval(&coeffs, &Scalar::from(3u64)), Scalar::from(7u64));
    }

    /// Simulation: Shamir split + Lagrange reconstruction roundtrip.
    #[cfg(feature = "gg20-simulation")]
    #[test]
    fn test_shamir_roundtrip() {
        let mut rng = rand::thread_rng();
        let secret = Scalar::random(&mut rng);
        let shares = shamir_split(&secret, 2, 3);

        let reconstructed = lagrange_interpolate(&shares[..2]);
        assert_eq!(secret, reconstructed);

        let reconstructed2 = lagrange_interpolate(&[shares[0], shares[2]]);
        assert_eq!(secret, reconstructed2);

        let reconstructed3 = lagrange_interpolate(&[shares[1], shares[2]]);
        assert_eq!(secret, reconstructed3);
    }

    // ── Sprint 28: GG20 Paillier key tests ──────────────────────────────

    #[cfg(not(feature = "gg20-simulation"))]
    #[tokio::test]
    async fn test_gg20_keygen_with_paillier() {
        use crate::transport::local::LocalTransportNetwork;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = Gg20Protocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        for h in handles {
            let share = h.await.unwrap().unwrap();
            let data: Gg20ShareData = serde_json::from_slice(&share.share_data).unwrap();

            // Real Paillier keys must be present in new keygen
            assert!(
                data.real_paillier_pk.is_some(),
                "GG20 keygen must generate real Paillier PK"
            );
            assert!(
                data.real_paillier_sk.is_some(),
                "GG20 keygen must generate real Paillier SK"
            );
            assert!(
                data.all_paillier_pks.is_some(),
                "GG20 keygen must store all parties' Paillier PKs"
            );

            let all_pks = data.all_paillier_pks.as_ref().unwrap();
            assert_eq!(all_pks.len(), 3, "must have 3 Paillier PKs");
        }
    }

    #[cfg(not(feature = "gg20-simulation"))]
    #[tokio::test]
    async fn test_gg20_paillier_proof_verification() {
        use crate::paillier::zk_proofs::{prove_pifac, prove_pimod, verify_pifac, verify_pimod};
        use crate::transport::local::LocalTransportNetwork;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);

        let mut handles = Vec::new();
        for i in 1..=3u16 {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            handles.push(tokio::spawn(async move {
                let p = Gg20Protocol::new();
                p.keygen(config, pid, &*transport).await
            }));
        }

        for h in handles {
            let share = h.await.unwrap().unwrap();
            let data: Gg20ShareData = serde_json::from_slice(&share.share_data).unwrap();
            let pk = data.real_paillier_pk.as_ref().unwrap();
            let sk = data.real_paillier_sk.as_ref().unwrap();

            // Verify the stored key produces valid ZK proofs
            let p = num_bigint::BigUint::from_bytes_be(&sk.p);
            let q = num_bigint::BigUint::from_bytes_be(&sk.q);
            let n = pk.n_biguint();

            let pimod = prove_pimod(&n, &p, &q);
            assert!(
                verify_pimod(&n, &pimod),
                "Πmod must verify for GG20 Paillier key"
            );

            let pifac = prove_pifac(&n, &p, &q);
            assert!(
                verify_pifac(&n, &pifac),
                "Πfac must verify for GG20 Paillier key"
            );
        }
    }
}
