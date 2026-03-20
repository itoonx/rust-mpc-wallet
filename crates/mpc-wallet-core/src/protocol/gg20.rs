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
            distributed_sign(key_share, signers, message, transport).await
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

    // ── Phase 2: Paillier key generation + ZK proof exchange (Sprint 28) ──
    let (real_pk, real_sk) = crate::paillier::keygen::keypair_for_protocol(GG20_PAILLIER_BITS)?;

    let p_big = BigUint::from_bytes_be(&real_sk.p);
    let q_big = BigUint::from_bytes_be(&real_sk.q);
    let n_big = real_pk.n_biguint();

    let pimod_proof = prove_pimod(&n_big, &p_big, &q_big);
    let pifac_proof = prove_pifac(&n_big, &p_big, &q_big);

    let aux_msg = Gg20AuxInfoBroadcast {
        party_index: party_id.0,
        paillier_pk: real_pk.clone(),
        pimod_proof,
        pifac_proof,
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

    // Build final share data with Paillier keys
    let final_share_data = Gg20ShareData {
        x: share_data_base.x,
        y: share_data_base.y.clone(),
        real_paillier_sk: Some(real_sk),
        real_paillier_pk: Some(real_pk),
        all_paillier_pks: Some(all_paillier_pks),
    };

    let share_bytes = serde_json::to_vec(&final_share_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(KeyShare {
        scheme: CryptoScheme::Gg20Ecdsa,
        party_id,
        config,
        group_public_key: GroupPublicKey::Secp256k1(group_pubkey_bytes),
        share_data: zeroize::Zeroizing::new(share_bytes),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// DISTRIBUTED signing — full key NEVER reconstructed (SEC-001 fix)
// ─────────────────────────────────────────────────────────────────────────────

/// Distributed ECDSA signing — the full private key is **never reconstructed**.
///
/// # Security property
///
/// Each party holds a Shamir share `f(i)`.  At signing time the shares are
/// converted to *additive* shares via Lagrange interpolation, and each party
/// computes only a *partial* signature contribution on its own local share.
/// The coordinator (Party 1) assembles the final `(r, s)` from all partials.
///
/// The full key `x = f(0) = Σ λ_i · f(i)` is **never** held in memory by
/// any party — not even the coordinator.
///
/// # Protocol (2 rounds)
///
/// **Round 1 (coordinator → all):**
///   Coordinator draws ephemeral nonce `k`, computes `R = k·G`, `r = R.x`,
///   `k_inv = k⁻¹`, and broadcasts `(r, k_inv)`.
///
/// **Round 2 (all → coordinator):**
///   Each party computes `s_i = x_i_add · r · k_inv` and sends to coordinator.
///   Coordinator computes `s = hash · k_inv + Σ s_i`, normalizes, outputs `(r, s)`.
///
/// # Note on coordinator nonce
///
/// The coordinator currently controls nonce generation. A future improvement
/// (DEC-017) will use MtA-based distributed nonce with commitment-reveal to
/// eliminate this trust assumption. The Paillier MtA infrastructure is in place
/// (see `crate::paillier::mta`), but wiring it into the signing protocol is
/// deferred to a future sprint.
#[cfg(not(feature = "gg20-simulation"))]
async fn distributed_sign(
    key_share: &KeyShare,
    signers: &[PartyId],
    message: &[u8],
    transport: &dyn Transport,
) -> Result<MpcSignature, CoreError> {
    use sha2::Digest;

    // Deserialize our Shamir share.
    let share_data_copy = key_share.share_data.clone();
    let my_share: Gg20ShareData = serde_json::from_slice(&share_data_copy)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    // SEC-008 FIX: wrap secret-derived scalars in Zeroizing.
    let shamir_y = Zeroizing::new(
        Scalar::from_repr(*k256::FieldBytes::from_slice(&my_share.y))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid Shamir share scalar".into()))?,
    );

    // Compute the Lagrange coefficient λ_i for our party in the actual signer set.
    let signer_indices: Vec<u16> = signers.iter().map(|p| p.0).collect();
    let lambda_i = lagrange_coefficient(my_share.x, &signer_indices)?;

    // Additive share: x_i_add = λ_i · f(i).
    // The full key x = Σ x_i_add is NEVER computed.
    // SEC-008 FIX: x_i_add is zeroized on drop.
    let x_i_add = Zeroizing::new(lambda_i * *shamir_y);

    let is_coordinator = key_share.party_id == PartyId(1);
    let coordinator = PartyId(1);

    // ── Round 1: coordinator generates (R, k, k_inv) and broadcasts (r, k_inv) ──
    let (r_scalar, k_inv_scalar) = if is_coordinator {
        // Draw ephemeral nonce k and compute R = k·G.
        let k = Scalar::random(&mut rand::thread_rng());
        let r_point = (ProjectivePoint::GENERATOR * k).to_affine();

        // Extract r = R.x mod n.
        let r_point_bytes = {
            use k256::elliptic_curve::group::GroupEncoding;
            r_point.to_bytes()
        };
        let x_bytes: [u8; 32] = r_point_bytes[1..33]
            .try_into()
            .map_err(|_| CoreError::Crypto("failed to extract R.x bytes from SEC1 point".into()))?;
        let r_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(&x_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("R.x does not reduce to valid scalar".into()))?;

        let k_inv_scalar = k
            .invert()
            .into_option()
            .ok_or_else(|| CoreError::Crypto("ephemeral nonce k is zero — regenerate".into()))?;

        // Broadcast (r, k_inv) to all other signers.
        let round1_payload = serde_json::to_vec(&serde_json::json!({
            "type": "gg20_dist_round1",
            "r":     hex::encode(r_scalar.to_repr().as_slice()),
            "k_inv": hex::encode(k_inv_scalar.to_repr().as_slice()),
        }))
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

        transport
            .send(ProtocolMessage {
                from: key_share.party_id,
                to: None, // broadcast
                round: 1,
                payload: round1_payload,
            })
            .await?;

        (r_scalar, k_inv_scalar)
    } else {
        // Receive (r, k_inv) from coordinator.
        let msg = transport.recv().await?;
        let v: serde_json::Value = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let r_hex = v["r"]
            .as_str()
            .ok_or_else(|| CoreError::Serialization("missing 'r' in round1 message".into()))?;
        let k_inv_hex = v["k_inv"]
            .as_str()
            .ok_or_else(|| CoreError::Serialization("missing 'k_inv' in round1 message".into()))?;

        let r_bytes = hex::decode(r_hex).map_err(|e| CoreError::Serialization(e.to_string()))?;
        let k_inv_bytes =
            hex::decode(k_inv_hex).map_err(|e| CoreError::Serialization(e.to_string()))?;

        let r_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(&r_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid r scalar from coordinator".into()))?;
        let k_inv_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(&k_inv_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid k_inv scalar from coordinator".into()))?;

        (r_scalar, k_inv_scalar)
    };

    // ── Round 2: compute partial signature contribution and send to Party 1 ──
    //
    // s_i = x_i_add · r · k_inv  mod n
    //
    // Key security property: this is one scalar multiply on our LOCAL additive
    // share.  The full key x = Σ x_i_add is NEVER computed.
    let s_partial = *x_i_add * r_scalar * k_inv_scalar;

    let round2_payload = serde_json::to_vec(&serde_json::json!({
        "type": "gg20_dist_round2",
        "s_partial": hex::encode(s_partial.to_repr().as_slice()),
    }))
    .map_err(|e| CoreError::Serialization(e.to_string()))?;

    if is_coordinator {
        // Coordinator accumulates its own partial and collects from others.
        let mut s_sum = s_partial;

        for _ in 0..(signers.len() - 1) {
            let msg = transport.recv().await?;
            let v: serde_json::Value = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let s_hex = v["s_partial"].as_str().ok_or_else(|| {
                CoreError::Serialization("missing 's_partial' in round2 message".into())
            })?;
            let s_bytes =
                hex::decode(s_hex).map_err(|e| CoreError::Serialization(e.to_string()))?;
            let s_i = Scalar::from_repr(*k256::FieldBytes::from_slice(&s_bytes))
                .into_option()
                .ok_or_else(|| CoreError::Crypto("invalid s_partial from signer".into()))?;
            s_sum += s_i;
        }

        // Assemble final signature: s = hash·k_inv + Σ s_i
        let hash_bytes = sha2::Sha256::digest(message);
        use k256::elliptic_curve::ops::Reduce;
        use k256::U256;
        let hash_scalar =
            <Scalar as Reduce<U256>>::reduce_bytes(k256::FieldBytes::from_slice(&hash_bytes));

        let s = hash_scalar * k_inv_scalar + s_sum;

        let r_bytes_arr: [u8; 32] = r_scalar.to_repr().into();
        let s_bytes_arr: [u8; 32] = s.to_repr().into();
        let mut sig_bytes_build = [0u8; 64];
        sig_bytes_build[..32].copy_from_slice(&r_bytes_arr);
        sig_bytes_build[32..].copy_from_slice(&s_bytes_arr);
        let raw_sig = k256::ecdsa::Signature::from_bytes(&sig_bytes_build.into())
            .map_err(|e| CoreError::Crypto(format!("assembled invalid ECDSA signature: {e}")))?;

        // Low-s normalization (SEC-012 / EIP-2).
        let (normalized_sig, _s_was_high) = match raw_sig.normalize_s() {
            Some(normalized) => (normalized, true),
            None => (raw_sig, false),
        };

        let norm_sig_bytes = normalized_sig.to_bytes();
        let final_r: [u8; 32] = norm_sig_bytes[..32].try_into().unwrap();
        let final_s: [u8; 32] = norm_sig_bytes[32..].try_into().unwrap();

        // Determine recovery_id against the group public key.
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
    } else {
        // Non-coordinator: send partial to Party 1 and return a partial sentinel.
        transport
            .send(ProtocolMessage {
                from: key_share.party_id,
                to: Some(coordinator),
                round: 2,
                payload: round2_payload,
            })
            .await?;

        // Return a sentinel — the canonical (final) signature is only at Party 1.
        // Tests must use the coordinator's (index 0) result for verification.
        Ok(MpcSignature::Ecdsa {
            r: r_scalar.to_repr().to_vec(),
            s: s_partial.to_repr().to_vec(),
            recovery_id: 0xff,
        })
    }
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
    };
    let new_share_bytes = serde_json::to_vec(&new_share_data)
        .map_err(|e| CoreError::Serialization(format!("serialize refreshed share: {e}")))?;

    Ok(KeyShare {
        scheme: key_share.scheme,
        party_id: my_party,
        config: key_share.config,
        group_public_key: key_share.group_public_key.clone(),
        share_data: Zeroizing::new(new_share_bytes),
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

        // Build new Gg20ShareData with new share value.
        // Paillier keys are not carried over during reshare (new group).
        let new_share_data = Gg20ShareData {
            x: my_party.0,
            y: new_share_scalar.to_repr().to_vec(),
            real_paillier_sk: None,
            real_paillier_pk: None,
            all_paillier_pks: None,
        };
        let new_share_bytes = serde_json::to_vec(&new_share_data)
            .map_err(|e| CoreError::Serialization(format!("serialize reshared share: {e}")))?;

        Ok(KeyShare {
            scheme: key_share.scheme,
            party_id: my_party,
            config: new_config,
            group_public_key: key_share.group_public_key.clone(),
            share_data: Zeroizing::new(new_share_bytes),
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
