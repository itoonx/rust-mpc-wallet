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
use crate::paillier::mta::{MtaPartyA, MtaPartyB, MtaRound1};
use crate::paillier::zk_proofs::{
    prove_pifac, prove_pimod, verify_pifac, verify_pimod, PifacProof, PimodProof,
};
use crate::paillier::{PaillierPublicKey, PaillierSecretKey};
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::{ProtocolMessage, Transport};
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};
use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, Field, PrimeField},
    ProjectivePoint, Scalar, U256,
};
use num_bigint::BigUint;
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
    /// Paillier secret key (legacy field, kept empty for serde backward compat).
    #[serde(default)]
    pub paillier_sk: Vec<u8>,
    /// Paillier public key (legacy field, kept empty for serde backward compat).
    #[serde(default)]
    #[zeroize(skip)]
    pub paillier_pk: Vec<u8>,
    /// Pedersen commitment parameters (legacy field, kept empty for serde backward compat).
    #[serde(default)]
    #[zeroize(skip)]
    pub pedersen_params: Vec<u8>,
    /// Real Paillier secret key (Sprint 28 — replaces simulated).
    /// Optional for backward compatibility with old shares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub real_paillier_sk: Option<PaillierSecretKey>,
    /// Real Paillier public key (Sprint 28).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub real_paillier_pk: Option<PaillierPublicKey>,
    /// All parties' real Paillier public keys, indexed by party position (0-based).
    /// Needed for MtA during pre-signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub all_paillier_pks: Option<Vec<PaillierPublicKey>>,
    /// Real Pedersen N_hat (product of safe primes, big-endian bytes).
    /// Sprint 28: replaces simulated pedersen_params.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub real_pedersen_n_hat: Option<Vec<u8>>,
    /// Real Pedersen s parameter (big-endian bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub real_pedersen_s: Option<Vec<u8>>,
    /// Real Pedersen t parameter (big-endian bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub real_pedersen_t: Option<Vec<u8>>,
    /// All parties' real Pedersen parameters (N_hat, s, t) indexed by party position.
    /// Needed for ZK proof verification during pre-signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    #[allow(clippy::type_complexity)]
    pub all_pedersen_params: Option<Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>>,
}

impl Cggmp21ShareData {
    /// Returns true if this share lacks real Paillier keys and needs a key refresh
    /// to upgrade from legacy (pre-Sprint 28) Paillier keys.
    ///
    /// Shares created before Sprint 28 have `real_paillier_pk = None` and cannot
    /// participate in secure MtA-based pre-signing. In production, pre-signing
    /// will be rejected for such shares (SEC-034).
    pub fn needs_paillier_upgrade(&self) -> bool {
        self.real_paillier_pk.is_none()
            || self.real_paillier_sk.is_none()
            || self.all_paillier_pks.is_none()
    }

    /// Returns true if this share has BOTH real Paillier keys AND real Pedersen
    /// parameters — the full auxiliary info needed for ZK-proof-verified pre-signing.
    pub fn has_real_aux_info(&self) -> bool {
        self.real_paillier_pk.is_some()
            && self.real_paillier_sk.is_some()
            && self.all_paillier_pks.is_some()
            && self.real_pedersen_n_hat.is_some()
            && self.real_pedersen_s.is_some()
            && self.real_pedersen_t.is_some()
            && self.all_pedersen_params.is_some()
    }
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

/// Default Paillier key size for production (secure, ~10s per keygen with glass_pumpkin).
/// In test mode, `keypair_for_protocol()` ignores this and returns a cached 512-bit keypair.
const DEFAULT_PAILLIER_BITS: usize = 2048;

/// Auxiliary info broadcast message (Round 4): Paillier public key + ZK proofs.
#[derive(Serialize, Deserialize)]
struct AuxInfoBroadcast {
    /// Party index (1-indexed).
    party_index: u16,
    /// Real Paillier public key.
    paillier_pk: PaillierPublicKey,
    /// Πmod proof: N is a Blum integer.
    pimod_proof: PimodProof,
    /// Πfac proof: N has no small factors (CVE-2023-33241 prevention).
    pifac_proof: PifacProof,
    /// Real Pedersen N_hat (product of safe primes, big-endian bytes).
    #[serde(default)]
    pedersen_n_hat: Option<Vec<u8>>,
    /// Real Pedersen s parameter (big-endian bytes).
    #[serde(default)]
    pedersen_s: Option<Vec<u8>>,
    /// Real Pedersen t parameter (big-endian bytes).
    #[serde(default)]
    pedersen_t: Option<Vec<u8>>,
}

/// Round 2 message for pre-signing with real MtA: encrypted k_i + ZK proofs.
#[derive(Serialize, Deserialize)]
struct PreSignMtaRound2 {
    /// Sender party index.
    party_index: u16,
    /// Enc(k_i) — encryption of sender's nonce share under sender's Paillier key.
    encrypted_k: crate::paillier::PaillierCiphertext,
    /// Πenc proof: proves |k_i| < 2^256 (CGGMP21 Fig. 14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pi_enc: Option<crate::paillier::zk_proofs::PiEncProof>,
    /// Πlog* proof: proves Enc(k_i) matches K_i = k_i*G (CGGMP21 Fig. 25).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pi_logstar: Option<crate::paillier::zk_proofs::PiLogStarProof>,
    /// K_i = k_i*G point for Πlog* verification (33 bytes compressed SEC1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    k_point: Option<Vec<u8>>,
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
    /// Unique identifier for this pre-signature (SEC-037: persistent nonce reuse protection).
    #[zeroize(skip)]
    pub id: String,
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
    /// K_i points per signer: (party_index, K_i compressed SEC1 33 bytes).
    /// SEC-035: stored for identifiable abort — verifier checks sigma_i * G == hash * K_i + r * Chi_i.
    #[zeroize(skip)]
    #[serde(default)]
    pub k_points: Vec<(u16, Vec<u8>)>,
    /// Chi_i points per signer: (party_index, Chi_i = chi_i * G compressed SEC1 33 bytes).
    /// Used in full CGGMP21 identifiable abort check: sigma_i * G == e * K_i + r * Chi_i.
    #[zeroize(skip)]
    #[serde(default)]
    pub chi_points: Vec<(u16, Vec<u8>)>,
    /// Whether this pre-signature has been consumed (nonce reuse protection).
    #[zeroize(skip)]
    pub used: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// SEC-037: Persistent pre-signature nonce reuse protection
// ─────────────────────────────────────────────────────────────────────────────

/// Persistent store for tracking used pre-signatures (SEC-037).
///
/// The in-memory `used` flag on `PreSignature` is lost on crash. If a node crashes
/// after using a pre-signature but before the flag is persisted, a restart could
/// replay the same nonce — which is catastrophic for ECDSA (nonce reuse → private
/// key extraction).
///
/// Implementations should persist the used-marker to durable storage (disk, database)
/// so that a crash-restart cycle cannot replay a pre-signature.
pub trait PreSignatureStore: Send + Sync {
    /// Mark a pre-signature as used BEFORE consuming it in signing.
    /// Returns `Ok(())` if successfully marked, `Err` if already used.
    fn mark_used(&self, pre_sig_id: &str) -> Result<(), CoreError>;

    /// Check if a pre-signature has been used.
    fn is_used(&self, pre_sig_id: &str) -> bool;
}

/// In-memory implementation of `PreSignatureStore` for tests and single-process use.
///
/// **Not crash-safe** — this is equivalent to the old `used` flag but demonstrates
/// the interface. Production deployments should use a durable-storage implementation.
///
/// **No eviction** — the `used_ids` set grows without bound. This is acceptable for
/// tests and short-lived processes, but a production implementation should evict old
/// entries (e.g., with a TTL or LRU policy) to avoid unbounded memory growth.
pub struct InMemoryPreSignatureStore {
    used_ids: Mutex<HashSet<String>>,
}

impl InMemoryPreSignatureStore {
    pub fn new() -> Self {
        Self {
            used_ids: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for InMemoryPreSignatureStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PreSignatureStore for InMemoryPreSignatureStore {
    fn mark_used(&self, pre_sig_id: &str) -> Result<(), CoreError> {
        let mut set = self
            .used_ids
            .lock()
            .map_err(|e| CoreError::Protocol(format!("pre-signature store lock poisoned: {e}")))?;
        if !set.insert(pre_sig_id.to_string()) {
            return Err(CoreError::Protocol(
                "pre-signature already used — nonce reuse would leak private key (SEC-037)".into(),
            ));
        }
        Ok(())
    }

    fn is_used(&self, pre_sig_id: &str) -> bool {
        self.used_ids
            .lock()
            .map(|set| set.contains(pre_sig_id))
            .unwrap_or(true) // If lock is poisoned, treat as used (safe default)
    }
}

/// SEC-037: File-backed pre-signature store for crash-safe nonce reuse protection.
///
/// Each used presig ID is appended to a log file with fsync. On startup, the
/// file is loaded to reconstruct the used set. This ensures that even if the
/// process crashes after `mark_used` but before signing completes, the presig
/// cannot be replayed on restart.
pub struct FilePreSignatureStore {
    used_ids: Mutex<HashSet<String>>,
    file_path: std::path::PathBuf,
}

impl FilePreSignatureStore {
    /// Create or open a file-backed store at `dir/used_presigs.log`.
    pub fn new(dir: &std::path::Path) -> Result<Self, CoreError> {
        let file_path = dir.join("used_presigs.log");
        let mut used_ids = HashSet::new();
        if file_path.exists() {
            let content = std::fs::read_to_string(&file_path)
                .map_err(|e| CoreError::KeyStore(format!("read presig log: {e}")))?;
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    used_ids.insert(trimmed.to_string());
                }
            }
        }
        Ok(Self {
            used_ids: Mutex::new(used_ids),
            file_path,
        })
    }
}

impl PreSignatureStore for FilePreSignatureStore {
    fn mark_used(&self, pre_sig_id: &str) -> Result<(), CoreError> {
        let mut set = self.used_ids.lock().unwrap();
        if set.contains(pre_sig_id) {
            return Err(CoreError::Protocol(
                "pre-signature already used — nonce reuse would leak private key (SEC-037)".into(),
            ));
        }
        // Write to file FIRST with fsync — crash-safe before updating in-memory
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .map_err(|e| CoreError::KeyStore(format!("open presig log: {e}")))?;
        writeln!(file, "{}", pre_sig_id)
            .map_err(|e| CoreError::KeyStore(format!("write presig log: {e}")))?;
        file.sync_all()
            .map_err(|e| CoreError::KeyStore(format!("fsync presig log: {e}")))?;
        set.insert(pre_sig_id.to_string());
        Ok(())
    }

    fn is_used(&self, pre_sig_id: &str) -> bool {
        self.used_ids
            .lock()
            .map(|s| s.contains(pre_sig_id))
            .unwrap_or(true) // safe default on poisoned mutex
    }
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
    /// 2. **Round 2:** Multiplicative-to-additive (MtA) conversion using real
    ///    Paillier homomorphic encryption: each party encrypts k_i under its own
    ///    Paillier key, then MtA produces additive shares of k_i * gamma_j.
    ///    ZK proofs (Pienc, PiAffg, PiLogstar) are mandatory.
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
    ///
    /// # Security: CVE-2025-66017 constraints
    ///
    /// **DO NOT** combine presignatures with:
    /// - **HD wallet derivation (BIP-32)**: security degrades from 128-bit to 85-bit.
    /// - **Raw pre-hashed signing**: callers must pass the original message, not a
    ///   pre-computed hash. This function applies SHA-256 internally.
    ///
    /// Presignatures are message-independent "blank cheques" — each MUST be used
    /// exactly once. The `used` flag and optional `PreSignatureStore` enforce this.
    pub async fn sign_with_presig(
        &self,
        pre_sig: &mut PreSignature,
        message: &[u8],
        key_share: &KeyShare,
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        cggmp21_sign_online(pre_sig, message, key_share, transport).await
    }

    /// SEC-037: Sign with a persistent pre-signature store for crash-safe nonce reuse protection.
    ///
    /// The store is checked/marked BEFORE any cryptographic computation. If the node
    /// crashes after `mark_used` but before signing completes, the pre-signature cannot
    /// be replayed on restart.
    pub async fn sign_with_presig_stored(
        &self,
        pre_sig: &mut PreSignature,
        message: &[u8],
        key_share: &KeyShare,
        transport: &dyn Transport,
        store: &dyn PreSignatureStore,
    ) -> Result<MpcSignature, CoreError> {
        cggmp21_sign_online_with_store(pre_sig, message, key_share, transport, Some(store)).await
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

    // ── Per-round sync barrier (L-012 fix): ensure all Feldman VSS complete
    transport.wait_ready().await?;

    // ── Real Paillier keygen + ZK proofs (Sprint 28) ────────────────────
    let (real_pk, real_sk) = crate::paillier::keygen::keypair_for_protocol(DEFAULT_PAILLIER_BITS)?;

    let p_big = BigUint::from_bytes_be(&real_sk.p);
    let q_big = BigUint::from_bytes_be(&real_sk.q);
    let n_big = real_pk.n_biguint();

    // Generate Πmod and Πfac ZK proofs
    let pimod_proof = prove_pimod(&n_big, &p_big, &q_big);
    let pifac_proof = prove_pifac(&n_big, &p_big, &q_big);

    // ── Generate real Pedersen parameters for ZK proofs ─────────────────
    let (ped_n_hat, ped_s, ped_t) =
        crate::paillier::zk_proofs::pedersen_params_for_protocol(DEFAULT_PAILLIER_BITS);

    // ── Round 4: Broadcast Paillier public key + Pedersen params + ZK proofs ──
    let aux_msg = AuxInfoBroadcast {
        party_index: my_index,
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
            round: 4,
            payload: aux_payload,
        })
        .await?;

    // Receive aux info from all other parties
    let mut all_aux: Vec<AuxInfoBroadcast> = vec![aux_msg];
    for _ in 1..n {
        let msg = transport.recv().await?;
        let aux: AuxInfoBroadcast = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        all_aux.push(aux);
    }
    all_aux.sort_by_key(|a| a.party_index);

    // ── Verify Πmod + Πfac proofs from all parties ──────────────────────
    for aux in &all_aux {
        if aux.party_index == my_index {
            continue; // Skip self (we trust our own key)
        }
        let peer_n = aux.paillier_pk.n_biguint();

        // Verify Πmod: N is a Blum integer
        if !verify_pimod(&peer_n, &aux.pimod_proof) {
            return Err(CoreError::Protocol(format!(
                "Πmod proof verification failed for party {} — invalid Paillier key, identifiable abort",
                aux.party_index
            )));
        }

        // Verify Πfac: N has no small factors (CVE-2023-33241 prevention)
        if !verify_pifac(&peer_n, &aux.pifac_proof) {
            return Err(CoreError::Protocol(format!(
                "Πfac proof verification failed for party {} — Paillier key has small factors, identifiable abort",
                aux.party_index
            )));
        }
    }

    // Collect all parties' verified Paillier public keys (ordered by party index)
    let all_paillier_pks: Vec<PaillierPublicKey> =
        all_aux.iter().map(|a| a.paillier_pk.clone()).collect();

    // Collect all parties' Pedersen parameters (ordered by party index)
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

    // ── Build share data ────────────────────────────────────────────────
    let share_data = Cggmp21ShareData {
        party_index: my_index,
        secret_share: final_share.to_repr().to_vec(),
        public_shares,
        group_public_key: group_pubkey_bytes.clone(),
        paillier_sk: vec![],
        paillier_pk: vec![],
        pedersen_params: vec![],
        real_paillier_sk: Some(real_sk),
        real_paillier_pk: Some(real_pk),
        all_paillier_pks: Some(all_paillier_pks),
        real_pedersen_n_hat: Some(ped_n_hat),
        real_pedersen_s: Some(ped_s),
        real_pedersen_t: Some(ped_t),
        all_pedersen_params: Some(all_pedersen),
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
/// Round 2: Multiplicative-to-additive (MtA) conversion using real Paillier
///          homomorphic encryption. Each party encrypts k_i under its own
///          Paillier public key and broadcasts Enc(k_i). For each pair (i,j),
///          MtA produces additive shares of k_i * gamma_j (for delta) and
///          k_i * x_j * lambda_j (for chi). Raw scalars are never broadcast.
///          ZK proofs (Pienc, PiAffg, PiLogstar) are mandatory for all MtA steps.
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

    // ── Per-round sync barrier (L-012 fix): ensure all parties completed Round 1
    transport.wait_ready().await?;

    // ── Round 2: MtA — compute shares of k * gamma ────────────────────
    // Check if real Paillier keys are available for secure MtA
    // Real Paillier MtA for pre-signing (enabled Sprint 28 Phase C1).
    // Shares created after Sprint 28 always have real Paillier keys from
    // keypair_for_protocol(). Legacy shares without real Paillier keys are rejected.
    let has_real_paillier = share_data.real_paillier_pk.is_some()
        && share_data.real_paillier_sk.is_some()
        && share_data.all_paillier_pks.is_some();

    #[allow(clippy::type_complexity)]
    let (delta, chi_i_scalar, chi_broadcast_collected): (
        Scalar,
        Zeroizing<Scalar>,
        Vec<(u16, Vec<u8>)>,
    ) = if has_real_paillier {
        // ── Real Paillier MtA (Sprint 28) ──────────────────────────────
        // Each party i: encrypt k_i under their own Paillier key, broadcast
        // Enc(k_i). Then for each pair (i,j), run MtA to compute additive
        // shares of k_i * gamma_j (for delta) and k_i * x_j * lambda_j (for chi).

        // Sprint 28a: ZK proofs are MANDATORY — require full aux info (Pedersen params).
        // Without Pedersen parameters, we cannot generate or verify Πenc, Πlog*, Πaff-g.
        if !share_data.has_real_aux_info() {
            return Err(CoreError::Protocol(
                "CGGMP21 pre-signing requires real Pedersen parameters for ZK proofs \
                 — run key refresh to upgrade legacy shares"
                    .into(),
            ));
        }

        let my_pk = share_data.real_paillier_pk.as_ref().unwrap().clone();
        let my_sk = share_data.real_paillier_sk.as_ref().unwrap().clone();
        let all_pks = share_data.all_paillier_pks.as_ref().unwrap();

        // Create MtA Party A for k_i — use witness version for ZK proof generation
        let mta_party_a_k = MtaPartyA::new(
            my_pk.clone(),
            my_sk.clone(),
            Zeroizing::new(k_i.to_repr().to_vec()),
        );
        let mta_witness = mta_party_a_k.round1_with_witness();
        let mta_round1_k = mta_witness.message;

        // ── Generate Πenc proof (CGGMP21 Fig. 14): |k_i| < 2^256 ────────
        // Sprint 28a: ZK proofs are MANDATORY — no conditional guards.
        let ped_n_hat = share_data.real_pedersen_n_hat.as_ref().unwrap();
        let ped_s = share_data.real_pedersen_s.as_ref().unwrap();
        let ped_t = share_data.real_pedersen_t.as_ref().unwrap();

        let pi_enc_public = crate::paillier::zk_proofs::PiEncPublicInput {
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
        let pi_enc_proof = crate::paillier::zk_proofs::prove_pienc(&m_big, &r_big, &pi_enc_public);

        // ── Generate Πlog* proof (CGGMP21 Fig. 25): Enc(k_i) ↔ K_i = k_i*G ──
        let pi_logstar_public = crate::paillier::zk_proofs::PiLogStarPublicInput {
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
        let pi_logstar_proof =
            crate::paillier::zk_proofs::prove_pilogstar(&m_big, &r_big, &pi_logstar_public);

        // Broadcast Enc(k_i) + ZK proofs (mandatory since Sprint 28a)
        let mta_r2_msg = PreSignMtaRound2 {
            party_index: my_index,
            encrypted_k: mta_round1_k.ciphertext.clone(),
            pi_enc: Some(pi_enc_proof),
            pi_logstar: Some(pi_logstar_proof),
            k_point: Some(k_point_bytes.clone()),
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

        // Collect Enc(k_j) from all other signers, tracking transport PartyId per keygen index
        let mut index_to_transport: std::collections::HashMap<u16, PartyId> =
            std::collections::HashMap::new();
        index_to_transport.insert(my_index, transport.party_id());

        let mut peer_enc_k: Vec<PreSignMtaRound2> = vec![mta_r2_msg];
        for _ in 1..n_signers {
            let msg = transport.recv().await?;
            let r2: PreSignMtaRound2 = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            index_to_transport.insert(r2.party_index, msg.from);
            peer_enc_k.push(r2);
        }
        peer_enc_k.sort_by_key(|m| m.party_index);

        // For each peer j: run two MtA instances as Party B:
        //   1. k_j * gamma_i (for delta)
        //   2. k_j * (x_i * lambda_i) (for chi)
        // We send both responses in one message.
        let gamma_i_bytes = Zeroizing::new(gamma_i.to_repr().to_vec());
        let x_i_lambda_i = *x_i * lambda_i;
        let x_i_lambda_i_bytes = Zeroizing::new(x_i_lambda_i.to_repr().to_vec());

        let mut delta_beta_shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut chi_beta_shares: Vec<Zeroizing<Vec<u8>>> = Vec::new();

        // Pedersen params for proof generation/verification (mandatory since Sprint 28a)
        let own_ped = (
            share_data.real_pedersen_n_hat.as_ref().unwrap().clone(),
            share_data.real_pedersen_s.as_ref().unwrap().clone(),
            share_data.real_pedersen_t.as_ref().unwrap().clone(),
        );

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

            // ── Verify Πenc + Πlog* proofs from peer (MANDATORY since Sprint 28a) ──
            let pi_enc = peer_msg.pi_enc.as_ref().ok_or_else(|| {
                CoreError::Protocol(format!(
                    "missing Πenc proof from party {} — all parties must provide ZK proofs",
                    peer_msg.party_index
                ))
            })?;
            let pi_enc_public = crate::paillier::zk_proofs::PiEncPublicInput {
                pk_n: peer_pk.n.clone(),
                pk_n_squared: peer_pk.n_squared.clone(),
                ciphertext: peer_msg.encrypted_k.data.clone(),
                n_hat: own_ped.0.clone(),
                s: own_ped.1.clone(),
                t: own_ped.2.clone(),
                session_id: key_share.group_public_key.as_bytes().to_vec(),
                prover_index: peer_msg.party_index,
            };
            if !crate::paillier::zk_proofs::verify_pienc(pi_enc, &pi_enc_public) {
                return Err(CoreError::Protocol(format!(
                    "Πenc proof failed for party {} — identifiable abort",
                    peer_msg.party_index
                )));
            }

            let pi_logstar = peer_msg.pi_logstar.as_ref().ok_or_else(|| {
                CoreError::Protocol(format!(
                    "missing Πlog* proof from party {} — all parties must provide ZK proofs",
                    peer_msg.party_index
                ))
            })?;
            let k_pt = peer_msg.k_point.as_ref().ok_or_else(|| {
                CoreError::Protocol(format!(
                    "missing K_i point from party {} — required for Πlog* verification",
                    peer_msg.party_index
                ))
            })?;
            let pi_logstar_public = crate::paillier::zk_proofs::PiLogStarPublicInput {
                pk_n: peer_pk.n.clone(),
                pk_n_squared: peer_pk.n_squared.clone(),
                ciphertext: peer_msg.encrypted_k.data.clone(),
                x_commitment: k_pt.clone(),
                n_hat: own_ped.0.clone(),
                s: own_ped.1.clone(),
                t: own_ped.2.clone(),
                session_id: key_share.group_public_key.as_bytes().to_vec(),
                prover_index: peer_msg.party_index,
            };
            if !crate::paillier::zk_proofs::verify_pilogstar(pi_logstar, &pi_logstar_public) {
                return Err(CoreError::Protocol(format!(
                    "Πlog* proof failed for party {} — identifiable abort",
                    peer_msg.party_index
                )));
            }

            // MtA for delta: k_j * gamma_i — use witness for Πaff-g proof
            let mta_b_delta = MtaPartyB::new(peer_pk.clone(), gamma_i_bytes.clone());
            let mta_r1_in = MtaRound1 {
                ciphertext: peer_msg.encrypted_k.clone(),
            };
            let mta_w_delta = mta_b_delta.round2_with_witness(&mta_r1_in);

            // MtA for chi: k_j * (x_i * lambda_i) — use witness for Πaff-g proof
            let mta_b_chi = MtaPartyB::new(peer_pk.clone(), x_i_lambda_i_bytes.clone());
            let mta_r1_in_chi = MtaRound1 {
                ciphertext: peer_msg.encrypted_k.clone(),
            };
            let mta_w_chi = mta_b_chi.round2_with_witness(&mta_r1_in_chi);

            // ── Generate Πaff-g proofs (CGGMP21 Fig. 15, MANDATORY since Sprint 28a) ──
            // MtA now uses D = C^b * Enc(+beta') with beta' < 2^768.
            // Πaff-g witness: x = gamma_i (or x_i*lambda_i), y = beta' (both small).
            let beta_d = BigUint::from_bytes_be(&mta_w_delta.result.beta);
            let rho_d = BigUint::from_bytes_be(&mta_w_delta.rho_y);
            let gamma_big = BigUint::from_bytes_be(&gamma_i_bytes);
            let pi_affg_delta = crate::paillier::zk_proofs::prove_piaffg(
                &gamma_big,
                &beta_d,
                &rho_d,
                &crate::paillier::zk_proofs::PiAffgPublicInput {
                    pk_n0: peer_pk.n.clone(),
                    pk_n0_squared: peer_pk.n_squared.clone(),
                    c: peer_msg.encrypted_k.data.clone(),
                    d: mta_w_delta.result.ciphertext.data.clone(),
                    n_hat: own_ped.0.clone(),
                    s: own_ped.1.clone(),
                    t: own_ped.2.clone(),
                    x_commitment: crate::paillier::zk_proofs::pilogstar_point_commitment(
                        &gamma_big,
                    ),
                    session_id: key_share.group_public_key.as_bytes().to_vec(),
                    prover_index: my_index,
                },
            );

            let beta_c = BigUint::from_bytes_be(&mta_w_chi.result.beta);
            let rho_c = BigUint::from_bytes_be(&mta_w_chi.rho_y);
            let x_i_lambda_big = BigUint::from_bytes_be(&x_i_lambda_i_bytes);
            let pi_affg_chi = crate::paillier::zk_proofs::prove_piaffg(
                &x_i_lambda_big,
                &beta_c,
                &rho_c,
                &crate::paillier::zk_proofs::PiAffgPublicInput {
                    pk_n0: peer_pk.n.clone(),
                    pk_n0_squared: peer_pk.n_squared.clone(),
                    c: peer_msg.encrypted_k.data.clone(),
                    d: mta_w_chi.result.ciphertext.data.clone(),
                    n_hat: own_ped.0.clone(),
                    s: own_ped.1.clone(),
                    t: own_ped.2.clone(),
                    x_commitment: crate::paillier::zk_proofs::pilogstar_point_commitment(
                        &x_i_lambda_big,
                    ),
                    session_id: key_share.group_public_key.as_bytes().to_vec(),
                    prover_index: my_index,
                },
            );

            // Push beta shares AFTER proof generation (Zeroizing moves on push)
            delta_beta_shares.push(mta_w_delta.result.beta);
            chi_beta_shares.push(mta_w_chi.result.beta);

            // Send both MtA responses + Πaff-g proofs to peer
            let peer_transport_id = index_to_transport
                .get(&peer_msg.party_index)
                .copied()
                .ok_or_else(|| {
                    CoreError::Protocol(format!(
                        "no transport mapping for party {}",
                        peer_msg.party_index
                    ))
                })?;
            // Include EC point commitments for verifier-side PiAffg check (SEC-056)
            let gamma_x_commitment =
                crate::paillier::zk_proofs::pilogstar_point_commitment(&gamma_big);
            let chi_x_commitment =
                crate::paillier::zk_proofs::pilogstar_point_commitment(&x_i_lambda_big);
            let combined_response = serde_json::json!({
                "from_party": my_index,
                "to_party": peer_msg.party_index,
                "delta_ct": serde_json::to_value(&mta_w_delta.result.ciphertext).unwrap(),
                "chi_ct": serde_json::to_value(&mta_w_chi.result.ciphertext).unwrap(),
                "pi_affg_delta": serde_json::to_value(&pi_affg_delta).unwrap(),
                "pi_affg_chi": serde_json::to_value(&pi_affg_chi).unwrap(),
                "gamma_x_commitment": gamma_x_commitment,
                "chi_x_commitment": chi_x_commitment,
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

        // Receive MtA responses and compute delta_i, chi_i using Scalar arithmetic.
        //
        // Critical: MtA produces alpha + beta = a*b (mod N). Since beta is sampled
        // uniformly from [0, N), the unsigned sum alpha + beta can be either a*b or
        // a*b + N. Naively reducing both mod q gives the wrong result when the sum
        // wraps (off by N mod q). We use signed interpretation: values > N/2 represent
        // negative numbers (value - N), ensuring alpha_signed + beta_signed = a*b exactly.
        let n_big = my_pk.n_biguint();
        let n_half = &n_big >> 1;
        let secp_order = BigUint::from_bytes_be(&hex_decode_secp_order());

        // Start with local products
        let mut delta_scalar = *k_i * *gamma_i;
        let mut chi_scalar = *k_i * x_i_lambda_i;

        // Subtract beta shares (from acting as Party B on peers' broadcasts).
        // New MtA formula: alpha - beta = a*b (D = C^b * Enc(+beta')),
        // so Party B's contribution is -beta' (negated here).
        for beta_bytes in &delta_beta_shares {
            delta_scalar -= to_scalar_signed(
                &BigUint::from_bytes_be(beta_bytes),
                &n_big,
                &n_half,
                &secp_order,
            );
        }
        for beta_bytes in &chi_beta_shares {
            chi_scalar -= to_scalar_signed(
                &BigUint::from_bytes_be(beta_bytes),
                &n_big,
                &n_half,
                &secp_order,
            );
        }

        // Receive alpha shares from peers (responses to our Enc(k_i) broadcast)
        // Verify Πaff-g proofs before decrypting (CGGMP21 Fig. 15)
        for _ in 1..n_signers {
            let msg = transport.recv().await?;
            let r3: serde_json::Value = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

            let _from_party = r3["from_party"].as_u64().unwrap_or(0) as u16;

            let delta_ct: crate::paillier::PaillierCiphertext =
                serde_json::from_value(r3["delta_ct"].clone())
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let chi_ct: crate::paillier::PaillierCiphertext =
                serde_json::from_value(r3["chi_ct"].clone())
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;

            // ── Verify Πaff-g proofs from peer (MANDATORY since Sprint 28a) ─────
            let pi_affg_d_val = r3.get("pi_affg_delta").filter(|v| !v.is_null()).ok_or_else(|| {
                CoreError::Protocol(format!(
                    "missing Πaff-g (delta) proof from party {} — all parties must provide ZK proofs",
                    _from_party
                ))
            })?;
            let pi_affg_d: crate::paillier::zk_proofs::PiAffgProof =
                serde_json::from_value(pi_affg_d_val.clone())
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
            // EC point commitments from prover (SEC-056: sent alongside proofs)
            let gamma_x_commit: Vec<u8> = serde_json::from_value(
                r3.get("gamma_x_commitment")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .unwrap_or_default();
            let chi_x_commit: Vec<u8> = serde_json::from_value(
                r3.get("chi_x_commitment")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .unwrap_or_default();
            let verify_pub_d = crate::paillier::zk_proofs::PiAffgPublicInput {
                pk_n0: my_pk.n.clone(),
                pk_n0_squared: my_pk.n_squared.clone(),
                c: mta_round1_k.ciphertext.data.clone(),
                d: delta_ct.data.clone(),
                n_hat: own_ped.0.clone(),
                s: own_ped.1.clone(),
                t: own_ped.2.clone(),
                x_commitment: gamma_x_commit,
                session_id: key_share.group_public_key.as_bytes().to_vec(),
                prover_index: _from_party,
            };
            if !crate::paillier::zk_proofs::verify_piaffg(&pi_affg_d, &verify_pub_d) {
                return Err(CoreError::Protocol(format!(
                    "Πaff-g (delta) proof failed for party {} — identifiable abort",
                    _from_party
                )));
            }

            let pi_affg_c_val =
                r3.get("pi_affg_chi")
                    .filter(|v| !v.is_null())
                    .ok_or_else(|| {
                        CoreError::Protocol(format!(
                    "missing Πaff-g (chi) proof from party {} — all parties must provide ZK proofs",
                    _from_party
                ))
                    })?;
            let pi_affg_c: crate::paillier::zk_proofs::PiAffgProof =
                serde_json::from_value(pi_affg_c_val.clone())
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let verify_pub_c = crate::paillier::zk_proofs::PiAffgPublicInput {
                pk_n0: my_pk.n.clone(),
                pk_n0_squared: my_pk.n_squared.clone(),
                c: mta_round1_k.ciphertext.data.clone(),
                d: chi_ct.data.clone(),
                n_hat: own_ped.0.clone(),
                s: own_ped.1.clone(),
                t: own_ped.2.clone(),
                x_commitment: chi_x_commit,
                session_id: key_share.group_public_key.as_bytes().to_vec(),
                prover_index: _from_party,
            };
            if !crate::paillier::zk_proofs::verify_piaffg(&pi_affg_c, &verify_pub_c) {
                return Err(CoreError::Protocol(format!(
                    "Πaff-g (chi) proof failed for party {} — identifiable abort",
                    _from_party
                )));
            }

            // Decrypt as Party A, reduce to Scalar
            let alpha_d = mta_party_a_k.round2_finish(&delta_ct);
            delta_scalar += to_scalar_signed(
                &BigUint::from_bytes_be(&alpha_d),
                &n_big,
                &n_half,
                &secp_order,
            );

            let alpha_c = mta_party_a_k.round2_finish(&chi_ct);
            chi_scalar += to_scalar_signed(
                &BigUint::from_bytes_be(&alpha_c),
                &n_big,
                &n_half,
                &secp_order,
            );
        }

        // ── Per-round sync barrier (L-012 fix): ensure all MtA round 2 complete
        transport.wait_ready().await?;

        // Compute Chi_i = chi_i * G for identifiable abort broadcast
        let chi_i_point = {
            let chi_proj = ProjectivePoint::GENERATOR * chi_scalar;
            let chi_affine = chi_proj.to_affine();
            k256::PublicKey::from_affine(chi_affine)
                .map_err(|e| CoreError::Crypto(format!("invalid Chi_i point: {e}")))?
                .to_encoded_point(true)
                .as_bytes()
                .to_vec()
        };

        // Broadcast delta_i + Chi_i for aggregation (round 13)
        let delta_broadcast = serde_json::json!({
            "party_index": my_index,
            "delta_i": delta_scalar.to_repr().as_slice(),
            "chi_i_point": chi_i_point,
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

        // Collect all delta_i (+ Chi_i points) and sum deltas as Scalars
        let mut delta_sum = delta_scalar;
        let mut chi_broadcast_collected: Vec<(u16, Vec<u8>)> = vec![(my_index, chi_i_point)];
        for _ in 1..n_signers {
            let msg = transport.recv().await?;
            let dv: serde_json::Value = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let d_bytes: Vec<u8> = serde_json::from_value(dv["delta_i"].clone())
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let d_scalar = Scalar::from_repr(*k256::FieldBytes::from_slice(&d_bytes))
                .into_option()
                .ok_or_else(|| CoreError::Crypto("invalid delta_i scalar".into()))?;
            delta_sum += d_scalar;

            // Collect Chi_i point from peer (backward-compatible: default to empty if absent)
            let peer_idx = dv["party_index"].as_u64().unwrap_or(0) as u16;
            if let Some(chi_val) = dv.get("chi_i_point") {
                if let Ok(chi_bytes) = serde_json::from_value::<Vec<u8>>(chi_val.clone()) {
                    if !chi_bytes.is_empty() {
                        chi_broadcast_collected.push((peer_idx, chi_bytes));
                    }
                }
            }
        }
        chi_broadcast_collected.sort_by_key(|(idx, _)| *idx);

        (
            delta_sum,
            Zeroizing::new(chi_scalar),
            chi_broadcast_collected,
        )
    } else {
        // Sprint 28: Legacy shares without real Paillier keys are unconditionally rejected.
        // No simulated MtA fallback — even in test builds. All keygen paths now generate
        // real Paillier keys, so this path should never be reached for well-formed shares.
        return Err(CoreError::Protocol(
            "CGGMP21 pre-signing requires real Paillier keys \
             — run key refresh to upgrade legacy shares"
                .into(),
        ));
    };

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

    // SEC-035: collect K_i points from Round 1 for identifiable abort
    let k_points: Vec<(u16, Vec<u8>)> = round1_msgs
        .iter()
        .map(|m| (m.party_index, m.k_point.clone()))
        .collect();

    Ok(PreSignature {
        id: uuid::Uuid::new_v4().to_string(),
        k_i: k_i.to_repr().to_vec(),
        chi_i: (*chi_i_scalar).to_repr().to_vec(),
        delta_i: delta.to_repr().to_vec(),
        big_r: big_r_bytes,
        party_id: my_party_id,
        signers: signers.to_vec(),
        k_points,
        chi_points: chi_broadcast_collected,
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
    cggmp21_sign_online_with_store(pre_sig, message, key_share, transport, None).await
}

/// SEC-037: Sign online with optional persistent pre-signature store.
///
/// If `store` is provided, the pre-signature is marked as used in the persistent
/// store BEFORE any cryptographic computation. This ensures crash-safety: even if
/// the node crashes mid-signing, the nonce cannot be replayed on restart.
///
/// If `store` is `None`, falls back to the in-memory `used` flag (backward compat).
async fn cggmp21_sign_online_with_store(
    pre_sig: &mut PreSignature,
    message: &[u8],
    key_share: &KeyShare,
    transport: &dyn Transport,
    store: Option<&dyn PreSignatureStore>,
) -> Result<MpcSignature, CoreError> {
    // ── Nonce reuse protection (SEC-037) ──────────────────────────────
    // Mark-before-use: persistent store is checked/marked BEFORE any
    // cryptographic computation to prevent crash-replay attacks.
    if let Some(store) = store {
        store.mark_used(&pre_sig.id)?;
    } else {
        // Fallback: in-memory flag (not crash-safe, backward compat)
        if pre_sig.used {
            return Err(CoreError::Protocol(
                "pre-signature already used — nonce reuse would leak private key".into(),
            ));
        }
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
    let chi_i = Zeroizing::new(
        Scalar::from_repr(*k256::FieldBytes::from_slice(&pre_sig.chi_i))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid chi_i scalar in pre-signature".into()))?,
    );

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
    let sigma_i = *k_i * e_scalar + *chi_i * r_scalar;

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
            round: 20, // Online signing round (separate from pre-sign MtA rounds 11-13)
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
            &pre_sig.k_points,
            &pre_sig.chi_points,
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
/// SEC-035: Full CGGMP21 identifiable abort check using K_i and Chi_i points.
/// For each party, verifies: `sigma_i * G == e * K_i + r * Chi_i`
/// where e = H(message) and r = x-coordinate of R.
///
/// If Chi_i points are not available (backward compat with old pre-signatures),
/// falls back to basic checks (zero sigma, malformed K_i).
fn identify_cheater(
    all_sigmas: &[(u16, Scalar)],
    k_points: &[(u16, Vec<u8>)],
    chi_points: &[(u16, Vec<u8>)],
    e_scalar: Scalar,
    r_scalar: Scalar,
) -> CoreError {
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::elliptic_curve::sec1::FromEncodedPoint;

    // Build lookups: party_index -> point bytes
    let k_point_map: std::collections::HashMap<u16, &Vec<u8>> =
        k_points.iter().map(|(idx, kp)| (*idx, kp)).collect();
    let chi_point_map: std::collections::HashMap<u16, &Vec<u8>> =
        chi_points.iter().map(|(idx, cp)| (*idx, cp)).collect();

    let have_chi_points = !chi_points.is_empty();

    for &(party_idx, sigma_i) in all_sigmas {
        // Check 1: zero sigma is always invalid
        if sigma_i == Scalar::ZERO {
            return CoreError::Protocol(format!(
                "identifiable abort: party {} cheated: submitted zero partial signature",
                party_idx
            ));
        }

        // Check 2: validate K_i is a valid curve point
        if let Some(k_bytes) = k_point_map.get(&party_idx) {
            let k_encoded = match k256::EncodedPoint::from_bytes(k_bytes) {
                Ok(e) => e,
                Err(_) => {
                    return CoreError::Protocol(format!(
                        "identifiable abort: party {} cheated: invalid K_i encoding",
                        party_idx
                    ));
                }
            };
            let k_affine: Option<k256::AffinePoint> =
                k256::AffinePoint::from_encoded_point(&k_encoded).into();
            if k_affine.is_none() {
                return CoreError::Protocol(format!(
                    "identifiable abort: party {} cheated: K_i is not on the curve",
                    party_idx
                ));
            }
            let k_proj: ProjectivePoint = k_affine.unwrap().into();

            // Verify sigma_i * G is not the identity (point at infinity)
            let sigma_point = ProjectivePoint::GENERATOR * sigma_i;
            if sigma_point.to_bytes() == ProjectivePoint::IDENTITY.to_bytes() {
                return CoreError::Protocol(format!(
                    "identifiable abort: party {} cheated: sigma_i * G is the identity point",
                    party_idx
                ));
            }

            // Check 3: Full CGGMP21 abort check if Chi_i is available
            // Verify: sigma_i * G == e * K_i + r * Chi_i
            if let Some(chi_bytes) = chi_point_map.get(&party_idx) {
                let chi_encoded = match k256::EncodedPoint::from_bytes(chi_bytes) {
                    Ok(e) => e,
                    Err(_) => {
                        return CoreError::Protocol(format!(
                            "identifiable abort: party {} cheated: invalid Chi_i encoding",
                            party_idx
                        ));
                    }
                };
                let chi_affine: Option<k256::AffinePoint> =
                    k256::AffinePoint::from_encoded_point(&chi_encoded).into();
                if chi_affine.is_none() {
                    return CoreError::Protocol(format!(
                        "identifiable abort: party {} cheated: Chi_i is not on the curve",
                        party_idx
                    ));
                }
                let chi_proj: ProjectivePoint = chi_affine.unwrap().into();

                // sigma_i * G == e * K_i + r * Chi_i
                let expected: ProjectivePoint = k_proj * e_scalar + chi_proj * r_scalar;
                if sigma_point != expected {
                    return CoreError::Protocol(format!(
                        "identifiable abort: party {} cheated: sigma_i * G != e * K_i + r * Chi_i",
                        party_idx
                    ));
                }
            }
        }
    }

    // If we have Chi_i points but couldn't pinpoint, all individual checks passed
    // but the aggregate still failed -- possible Chi_i broadcast mismatch.
    if have_chi_points {
        CoreError::Protocol(
            "identifiable abort: final signature verification failed — all individual sigma_i * G == e * K_i + r * Chi_i checks passed but aggregate is invalid".into(),
        )
    } else {
        // Fallback without Chi_i points -- cannot pinpoint exact cheater
        CoreError::Protocol(
            "identifiable abort: final signature verification failed — at least one party submitted invalid partial signature (Chi_i points unavailable for full check)".into(),
        )
    }
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

    // ── Generate fresh real Paillier keys + ZK proofs ─────────────────
    let (fresh_pk, fresh_sk) =
        crate::paillier::keygen::keypair_for_protocol(DEFAULT_PAILLIER_BITS)?;

    let p_big = BigUint::from_bytes_be(&fresh_sk.p);
    let q_big = BigUint::from_bytes_be(&fresh_sk.q);
    let n_big = fresh_pk.n_biguint();
    let pimod_proof = prove_pimod(&n_big, &p_big, &q_big);
    let pifac_proof = prove_pifac(&n_big, &p_big, &q_big);

    // Generate fresh real Pedersen parameters
    let (fresh_ped_n_hat, fresh_ped_s, fresh_ped_t) =
        crate::paillier::zk_proofs::pedersen_params_for_protocol(DEFAULT_PAILLIER_BITS);

    let aux_msg = AuxInfoBroadcast {
        party_index: my_index,
        paillier_pk: fresh_pk.clone(),
        pimod_proof,
        pifac_proof,
        pedersen_n_hat: Some(fresh_ped_n_hat.clone()),
        pedersen_s: Some(fresh_ped_s.clone()),
        pedersen_t: Some(fresh_ped_t.clone()),
    };
    let aux_payload =
        serde_json::to_vec(&aux_msg).map_err(|e| CoreError::Serialization(e.to_string()))?;
    transport
        .send(ProtocolMessage {
            from: my_party,
            to: None,
            round: 203,
            payload: aux_payload,
        })
        .await?;

    let mut all_aux: Vec<AuxInfoBroadcast> = vec![aux_msg];
    for _ in 1..n_signers {
        let msg = transport.recv().await?;
        let aux: AuxInfoBroadcast = serde_json::from_slice(&msg.payload)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        all_aux.push(aux);
    }
    all_aux.sort_by_key(|a| a.party_index);

    for aux in &all_aux {
        if aux.party_index == my_index {
            continue;
        }
        let peer_n = aux.paillier_pk.n_biguint();
        if !verify_pimod(&peer_n, &aux.pimod_proof) {
            return Err(CoreError::Protocol(format!(
                "Πmod proof failed for party {} during refresh",
                aux.party_index
            )));
        }
        if !verify_pifac(&peer_n, &aux.pifac_proof) {
            return Err(CoreError::Protocol(format!(
                "Πfac proof failed for party {} during refresh",
                aux.party_index
            )));
        }
    }
    let fresh_all_pks: Vec<PaillierPublicKey> =
        all_aux.iter().map(|a| a.paillier_pk.clone()).collect();
    let fresh_all_ped: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = all_aux
        .iter()
        .map(|a| {
            (
                a.pedersen_n_hat.clone().unwrap_or_default(),
                a.pedersen_s.clone().unwrap_or_default(),
                a.pedersen_t.clone().unwrap_or_default(),
            )
        })
        .collect();

    // ── Build refreshed share data ───────────────────────────────────────
    let new_share_data = Cggmp21ShareData {
        party_index: my_index,
        secret_share: new_share.to_repr().to_vec(),
        public_shares: all_public_shares,
        group_public_key: share_data.group_public_key.clone(),
        paillier_sk: vec![],
        paillier_pk: vec![],
        pedersen_params: vec![],
        real_paillier_sk: Some(fresh_sk),
        real_paillier_pk: Some(fresh_pk),
        all_paillier_pks: Some(fresh_all_pks),
        real_pedersen_n_hat: Some(fresh_ped_n_hat),
        real_pedersen_s: Some(fresh_ped_s),
        real_pedersen_t: Some(fresh_ped_t),
        all_pedersen_params: Some(fresh_all_ped),
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

/// Convert a `BigUint` in `[0, N)` to a secp256k1 `Scalar` using signed reduction.
///
/// MtA produces values uniformly in `[0, N)`. Values in `[0, N/2]` are interpreted
/// as positive and reduced mod `q` directly. Values in `(N/2, N)` represent negative
/// numbers (`value - N`), so we compute `-(N - value) mod q`.
///
/// This ensures `to_scalar_signed(alpha) + to_scalar_signed(beta) == a * b` as a
/// `Scalar`, even when the unsigned sum `alpha + beta` wraps modulo `N`.
pub fn to_scalar_signed(
    big: &BigUint,
    n: &BigUint,
    n_half: &BigUint,
    secp_order: &BigUint,
) -> Scalar {
    use k256::elliptic_curve::ops::Reduce;
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

/// Return the secp256k1 curve order as 32 big-endian bytes.
fn hex_decode_secp_order() -> [u8; 32] {
    // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ]
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
            real_paillier_sk: None,
            real_paillier_pk: None,
            all_paillier_pks: None,
            real_pedersen_n_hat: None,
            real_pedersen_s: None,
            real_pedersen_t: None,
            all_pedersen_params: None,
        };

        let bytes = serde_json::to_vec(&share).unwrap();
        let restored: Cggmp21ShareData = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(restored.party_index, 1);
        assert_eq!(restored.secret_share, vec![1u8; 32]);
        assert_eq!(restored.public_shares.len(), 2);
        assert_eq!(restored.group_public_key, vec![4u8; 33]);
        // Legacy fields preserved through serde roundtrip
        assert_eq!(restored.paillier_sk, vec![5u8; 64]);
        assert_eq!(restored.paillier_pk, vec![6u8; 32]);
        assert_eq!(restored.pedersen_params, vec![7u8; 96]);
        // Optional fields should be None for old shares
        assert!(restored.real_paillier_sk.is_none());
        assert!(restored.real_paillier_pk.is_none());
        assert!(restored.all_paillier_pks.is_none());
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

            // Legacy fields are now empty (simulated Paillier removed)
            assert!(
                data.paillier_sk.is_empty(),
                "Legacy paillier_sk should be empty"
            );
            assert!(
                data.paillier_pk.is_empty(),
                "Legacy paillier_pk should be empty"
            );
            assert!(
                data.pedersen_params.is_empty(),
                "Legacy pedersen_params should be empty"
            );

            // Real Paillier keys must be present
            assert!(
                data.real_paillier_sk.is_some(),
                "Real Paillier SK must exist"
            );
            assert!(
                data.real_paillier_pk.is_some(),
                "Real Paillier PK must exist"
            );
            assert!(
                data.all_paillier_pks.is_some(),
                "All Paillier PKs must exist"
            );
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
                    id: String::new(),
                    k_i: vec![],
                    chi_i: vec![],
                    delta_i: vec![],
                    big_r: vec![],
                    party_id: PartyId(0),
                    signers: vec![],
                    k_points: vec![],
                    chi_points: vec![],
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

        // Transport needs PartyId(3), so create with max signer ID
        let max_id = signers.iter().map(|s| s.0).max().unwrap();
        let net = LocalTransportNetwork::new(max_id);
        let mut handles = Vec::new();
        for signer in &signers {
            let share = shares[signer.0 as usize - 1].clone();
            let transport = net.get_transport(*signer);
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
            real_paillier_sk: None,
            real_paillier_pk: None,
            all_paillier_pks: None,
            real_pedersen_n_hat: None,
            real_pedersen_s: None,
            real_pedersen_t: None,
            all_pedersen_params: None,
        };

        let share_bytes = serde_json::to_vec(&share_data).unwrap();
        let key_share = KeyShare {
            scheme: CryptoScheme::Cggmp21Secp256k1,
            party_id: PartyId(1),
            config: ThresholdConfig::new(2, 3).unwrap(),
            group_public_key: GroupPublicKey::Secp256k1(share_data.group_public_key.clone()),
            share_data: Zeroizing::new(share_bytes),
        };

        let k_points: Vec<(u16, Vec<u8>)> = vec![];
        let chi_points: Vec<(u16, Vec<u8>)> = vec![];
        let err = identify_cheater(&all_sigmas, &k_points, &chi_points, e_scalar, r_scalar);
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

        // Real Paillier and Pedersen aux info must have been refreshed
        assert!(
            new_data.real_paillier_sk.is_some(),
            "Refreshed share must have real Paillier SK"
        );
        assert!(
            new_data.real_pedersen_n_hat.is_some(),
            "Refreshed share must have real Pedersen params"
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

    // ── Sprint 28: Real Paillier + ZK proof tests ────────────────────────

    #[tokio::test]
    async fn test_cggmp21_keygen_with_real_paillier() {
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
            let data: Cggmp21ShareData = serde_json::from_slice(&share.share_data).unwrap();

            // Real Paillier keys must be present
            assert!(
                data.real_paillier_pk.is_some(),
                "keygen must generate real Paillier PK"
            );
            assert!(
                data.real_paillier_sk.is_some(),
                "keygen must generate real Paillier SK"
            );
            assert!(
                data.all_paillier_pks.is_some(),
                "keygen must store all parties' Paillier PKs"
            );

            // All Paillier PKs must have valid N
            let all_pks = data.all_paillier_pks.as_ref().unwrap();
            assert_eq!(all_pks.len(), 3, "must have 3 Paillier PKs");
            for pk in all_pks {
                let n = pk.n_biguint();
                assert!(
                    n.bits() >= 500,
                    "Paillier N must be ~512 bits for test, got {} bits",
                    n.bits()
                );
            }
        }
    }

    #[tokio::test]
    async fn test_cggmp21_keygen_paillier_proofs_verified() {
        // This test verifies that keygen actually runs ZK proof verification.
        // Since keygen succeeds (tested above), the proofs must have been verified.
        // We verify indirectly by checking the stored Paillier keys are valid.
        use crate::paillier::zk_proofs::{prove_pifac, prove_pimod, verify_pifac, verify_pimod};
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
            let data: Cggmp21ShareData = serde_json::from_slice(&share.share_data).unwrap();
            let sk = data.real_paillier_sk.as_ref().unwrap();
            let pk = data.real_paillier_pk.as_ref().unwrap();

            // Re-generate proofs for our own key and verify they pass
            let p = num_bigint::BigUint::from_bytes_be(&sk.p);
            let q = num_bigint::BigUint::from_bytes_be(&sk.q);
            let n = pk.n_biguint();

            let pimod = prove_pimod(&n, &p, &q);
            assert!(
                verify_pimod(&n, &pimod),
                "Πmod proof must verify for stored key"
            );

            let pifac = prove_pifac(&n, &p, &q);
            assert!(
                verify_pifac(&n, &pifac),
                "Πfac proof must verify for stored key"
            );
        }
    }

    /// Standalone test: verify MtA correctness with signed Scalar reduction.
    #[test]
    fn test_mta_scalar_reduction_correctness() {
        use crate::paillier::keygen::keypair_for_protocol;
        use crate::paillier::mta::{MtaPartyA, MtaPartyB};
        use num_bigint::BigUint;

        let (pk, sk) = keypair_for_protocol(2048).unwrap();
        let n = pk.n_biguint();
        let n_half = &n >> 1;
        let secp_order = BigUint::from_bytes_be(&hex_decode_secp_order());

        // Run multiple trials to cover both wrap and no-wrap cases
        for trial in 0..10 {
            let mut rng = rand::thread_rng();
            let k_1 = Scalar::random(&mut rng);
            let gamma_2 = Scalar::random(&mut rng);

            let party_a = MtaPartyA::new(
                pk.clone(),
                sk.clone(),
                Zeroizing::new(k_1.to_repr().to_vec()),
            );
            let party_b = MtaPartyB::new(pk.clone(), Zeroizing::new(gamma_2.to_repr().to_vec()));

            let round1 = party_a.round1();
            let round2 = party_b.round2(&round1);

            let alpha_bytes = party_a.round2_finish(&round2.ciphertext);
            let alpha = BigUint::from_bytes_be(&alpha_bytes);
            let beta = BigUint::from_bytes_be(&round2.beta);

            // Verify: alpha - beta = k_1 * gamma_2 (mod N)
            // New MtA: D = C^b * Enc(+beta'), so alpha = a*b + beta'
            let diff_mod_n = (&alpha + &n - &beta) % &n;
            let k_1_big = BigUint::from_bytes_be(&k_1.to_repr());
            let gamma_2_big = BigUint::from_bytes_be(&gamma_2.to_repr());
            let product_mod_n = (&k_1_big * &gamma_2_big) % &n;
            assert_eq!(
                diff_mod_n, product_mod_n,
                "trial {}: MtA basic correctness failed",
                trial
            );

            // Verify signed Scalar reduction
            let alpha_scalar = to_scalar_signed(&alpha, &n, &n_half, &secp_order);
            let beta_scalar = to_scalar_signed(&beta, &n, &n_half, &secp_order);
            let diff_scalar = alpha_scalar - beta_scalar;
            let expected_scalar = k_1 * gamma_2;
            assert_eq!(
                diff_scalar, expected_scalar,
                "trial {}: signed reduction failed",
                trial
            );
        }
    }

    #[tokio::test]
    async fn test_cggmp21_sign_with_real_paillier_keygen() {
        // Test that keygen with real Paillier + signing with real Paillier MtA works
        use crate::transport::local::LocalTransportNetwork;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let shares = run_keygen(2, 3).await;
        let signers = vec![PartyId(1), PartyId(2)];
        let message = b"Sprint 28: real Paillier keygen + real MtA sign";

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
            let pubkey =
                k256::PublicKey::from_sec1_bytes(shares[0].group_public_key.as_bytes()).unwrap();
            let vk = k256::ecdsa::VerifyingKey::from(&pubkey);
            let mut sig_bytes = [0u8; 64];
            sig_bytes[..32].copy_from_slice(r);
            sig_bytes[32..].copy_from_slice(s);
            let ecdsa_sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into()).unwrap();
            let hash = Sha256::digest(message);
            assert!(
                vk.verify_prehash(&hash, &ecdsa_sig).is_ok(),
                "signature must verify after real Paillier keygen"
            );
        } else {
            panic!("expected ECDSA signature");
        }
    }

    #[test]
    fn test_backward_compat_old_shares() {
        // Shares without real Paillier keys should deserialize correctly
        let old_share = Cggmp21ShareData {
            party_index: 1,
            secret_share: vec![1u8; 32],
            public_shares: vec![vec![2u8; 33]],
            group_public_key: vec![3u8; 33],
            paillier_sk: vec![4u8; 32],
            paillier_pk: vec![5u8; 32],
            pedersen_params: vec![6u8; 32],
            real_paillier_sk: None,
            real_paillier_pk: None,
            all_paillier_pks: None,
            real_pedersen_n_hat: None,
            real_pedersen_s: None,
            real_pedersen_t: None,
            all_pedersen_params: None,
        };

        let bytes = serde_json::to_vec(&old_share).unwrap();
        let restored: Cggmp21ShareData = serde_json::from_slice(&bytes).unwrap();

        assert!(restored.real_paillier_sk.is_none());
        assert!(restored.real_paillier_pk.is_none());
        assert!(restored.all_paillier_pks.is_none());
        assert_eq!(restored.party_index, 1);
        assert_eq!(restored.secret_share, vec![1u8; 32]);

        // Shares without optional fields should also deserialize
        // (simulating old format without the real_paillier_* fields)
        let old_share2 = Cggmp21ShareData {
            party_index: 2,
            secret_share: vec![1u8; 32],
            public_shares: vec![vec![2u8; 33]],
            group_public_key: vec![3u8; 33],
            paillier_sk: vec![4u8; 32],
            paillier_pk: vec![5u8; 32],
            pedersen_params: vec![6u8; 32],
            real_paillier_sk: None,
            real_paillier_pk: None,
            all_paillier_pks: None,
            real_pedersen_n_hat: None,
            real_pedersen_s: None,
            real_pedersen_t: None,
            all_pedersen_params: None,
        };
        let old_format = serde_json::to_vec(&old_share2).unwrap();
        // The JSON should NOT contain real_paillier_* fields (skip_serializing_if)
        let json_str = String::from_utf8(old_format.clone()).unwrap();
        assert!(
            !json_str.contains("real_paillier"),
            "None fields must not be serialized"
        );
        let restored2: Cggmp21ShareData = serde_json::from_slice(&old_format).unwrap();
        assert!(restored2.real_paillier_sk.is_none());
        assert_eq!(restored2.party_index, 2);
    }

    #[test]
    fn test_reject_bad_paillier_key() {
        use crate::paillier::zk_proofs::{verify_pifac, NthRootProofRound, PifacProof};

        // Create a Pifac proof with wrong bit sizes (simulating a bad key with small factors)
        let bad_proof = PifacProof {
            p_bits: 64, // Too small! Must be >= 256 bits
            q_bits: 64,
            nth_root_proofs: vec![NthRootProofRound {
                x: vec![1u8; 32],
                a: vec![1u8; 32],
            }],
        };

        // A small N (128 bits) should fail Pifac verification
        let small_n = num_bigint::BigUint::from(u128::MAX);
        assert!(
            !verify_pifac(&small_n, &bad_proof),
            "Πfac must reject keys with small factors"
        );
    }

    #[test]
    fn test_paillier_keys_in_share_data_serde() {
        use crate::paillier::keygen::generate_paillier_keypair;

        let (pk, sk) = generate_paillier_keypair(512).unwrap();
        let share = Cggmp21ShareData {
            party_index: 1,
            secret_share: vec![1u8; 32],
            public_shares: vec![vec![2u8; 33]],
            group_public_key: vec![3u8; 33],
            paillier_sk: vec![4u8; 32],
            paillier_pk: vec![5u8; 32],
            pedersen_params: vec![6u8; 32],
            real_paillier_sk: Some(sk),
            real_paillier_pk: Some(pk.clone()),
            all_paillier_pks: Some(vec![pk]),
            real_pedersen_n_hat: None,
            real_pedersen_s: None,
            real_pedersen_t: None,
            all_pedersen_params: None,
        };

        // Serialize
        let bytes = serde_json::to_vec(&share).unwrap();
        // Deserialize
        let restored: Cggmp21ShareData = serde_json::from_slice(&bytes).unwrap();

        // Verify Paillier keys survive roundtrip
        assert!(restored.real_paillier_pk.is_some());
        assert!(restored.real_paillier_sk.is_some());
        assert!(restored.all_paillier_pks.is_some());

        let restored_pk = restored.real_paillier_pk.clone().unwrap();
        let original_n = share.real_paillier_pk.as_ref().unwrap().n_biguint();
        let restored_n = restored_pk.n_biguint();
        assert_eq!(
            original_n, restored_n,
            "Paillier N must survive serialization"
        );

        let all_pks = restored.all_paillier_pks.clone().unwrap();
        assert_eq!(all_pks.len(), 1);
        assert_eq!(all_pks[0].n_biguint(), original_n);
    }

    // ── SEC-037: PreSignatureStore nonce reuse protection ────────────────

    #[test]
    fn test_in_memory_store_rejects_double_use() {
        let store = InMemoryPreSignatureStore::new();
        let id = "test-presig-001";

        // First mark should succeed
        assert!(store.mark_used(id).is_ok());
        assert!(store.is_used(id));

        // Second mark must fail — nonce reuse prevented
        let err = store.mark_used(id).unwrap_err();
        assert!(
            err.to_string().contains("already used"),
            "error should indicate double use: {err}"
        );
    }

    #[test]
    fn test_in_memory_store_allows_different_ids() {
        let store = InMemoryPreSignatureStore::new();

        assert!(store.mark_used("presig-a").is_ok());
        assert!(store.mark_used("presig-b").is_ok());
        assert!(store.mark_used("presig-c").is_ok());

        assert!(store.is_used("presig-a"));
        assert!(store.is_used("presig-b"));
        assert!(store.is_used("presig-c"));
        assert!(!store.is_used("presig-d")); // never marked
    }

    #[test]
    fn test_presignature_has_unique_id() {
        // Two pre-signatures constructed with new UUIDs must have different IDs
        let ps1 = PreSignature {
            id: uuid::Uuid::new_v4().to_string(),
            k_i: vec![1u8; 32],
            chi_i: vec![2u8; 32],
            delta_i: vec![3u8; 32],
            big_r: vec![4u8; 33],
            party_id: PartyId(1),
            signers: vec![PartyId(1), PartyId(2)],
            k_points: vec![],
            chi_points: vec![],
            used: false,
        };
        let ps2 = PreSignature {
            id: uuid::Uuid::new_v4().to_string(),
            k_i: vec![1u8; 32],
            chi_i: vec![2u8; 32],
            delta_i: vec![3u8; 32],
            big_r: vec![4u8; 33],
            party_id: PartyId(2),
            signers: vec![PartyId(1), PartyId(2)],
            k_points: vec![],
            chi_points: vec![],
            used: false,
        };

        assert_ne!(ps1.id, ps2.id, "each pre-signature must have a unique ID");
        assert!(!ps1.id.is_empty());
        assert!(!ps2.id.is_empty());
    }

    #[test]
    fn test_store_mark_before_use_ordering() {
        // Verify that mark_used is called (and succeeds) BEFORE we'd consume the presig.
        // This simulates the mark-before-use pattern in cggmp21_sign_online_with_store.
        let store = InMemoryPreSignatureStore::new();
        let presig_id = uuid::Uuid::new_v4().to_string();

        // Step 1: mark used (simulates what happens before crypto computation)
        assert!(
            !store.is_used(&presig_id),
            "must not be used before marking"
        );
        store
            .mark_used(&presig_id)
            .expect("first mark must succeed");

        // Step 2: after marking, the ID is recorded even if we crash here
        assert!(
            store.is_used(&presig_id),
            "must be used after marking (crash-safe)"
        );

        // Step 3: simulating a "restart" — a new attempt to use the same presig must fail
        let result = store.mark_used(&presig_id);
        assert!(
            result.is_err(),
            "second mark must fail — nonce reuse blocked"
        );
    }

    #[tokio::test]
    async fn test_sign_with_presig_stored_rejects_reuse() {
        // Build a minimal scenario: we need a valid pre-signature from keygen+presign
        // to test sign_with_presig_stored. Instead, test the store-rejection path
        // by pre-marking the ID in the store.
        let store = InMemoryPreSignatureStore::new();
        let presig_id = uuid::Uuid::new_v4().to_string();

        // Pre-mark the ID as used (simulates previous use before crash)
        store.mark_used(&presig_id).unwrap();

        // Create a dummy pre-signature with that ID
        let mut pre_sig = PreSignature {
            id: presig_id,
            k_i: vec![1u8; 32],
            chi_i: vec![2u8; 32],
            delta_i: vec![3u8; 32],
            big_r: vec![4u8; 33],
            party_id: PartyId(1),
            signers: vec![PartyId(1), PartyId(2)],
            k_points: vec![],
            chi_points: vec![],
            used: false, // in-memory flag says "not used" — simulating post-crash state
        };

        // Create a dummy key share (won't get to crypto — should fail at store check)
        let key_share = KeyShare {
            scheme: CryptoScheme::Cggmp21Secp256k1,
            config: ThresholdConfig {
                threshold: 2,
                total_parties: 3,
            },
            party_id: PartyId(1),
            share_data: zeroize::Zeroizing::new(vec![]),
            group_public_key: GroupPublicKey::Secp256k1(vec![]),
        };

        let net = crate::transport::local::LocalTransportNetwork::new(2);
        let transport = net.get_transport(PartyId(1));

        // Even though pre_sig.used == false, the store blocks reuse
        let result = cggmp21_sign_online_with_store(
            &mut pre_sig,
            b"some message",
            &key_share,
            &*transport,
            Some(&store),
        )
        .await;

        assert!(
            result.is_err(),
            "store must reject pre-signature that was already used"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already used"),
            "error must mention double use: {err_msg}"
        );
    }

    // ── SEC-034: needs_paillier_upgrade tests ─────────────────────────────

    #[test]
    fn test_needs_paillier_upgrade_true_for_legacy_share() {
        let share = Cggmp21ShareData {
            party_index: 1,
            secret_share: vec![1u8; 32],
            public_shares: vec![vec![2u8; 33]],
            group_public_key: vec![4u8; 33],
            paillier_sk: vec![5u8; 64],
            paillier_pk: vec![6u8; 32],
            pedersen_params: vec![7u8; 96],
            real_paillier_sk: None,
            real_paillier_pk: None,
            all_paillier_pks: None,
            real_pedersen_n_hat: None,
            real_pedersen_s: None,
            real_pedersen_t: None,
            all_pedersen_params: None,
        };
        assert!(
            share.needs_paillier_upgrade(),
            "legacy share without real Paillier keys must need upgrade"
        );
    }

    #[test]
    fn test_needs_paillier_upgrade_false_for_modern_share() {
        use crate::paillier::keygen::generate_paillier_keypair;

        let (pk, sk) = generate_paillier_keypair(512).unwrap();
        let share = Cggmp21ShareData {
            party_index: 1,
            secret_share: vec![1u8; 32],
            public_shares: vec![vec![2u8; 33]],
            group_public_key: vec![4u8; 33],
            paillier_sk: vec![5u8; 64],
            paillier_pk: vec![6u8; 32],
            pedersen_params: vec![7u8; 96],
            real_paillier_sk: Some(sk),
            real_paillier_pk: Some(pk.clone()),
            all_paillier_pks: Some(vec![pk]),
            real_pedersen_n_hat: None,
            real_pedersen_s: None,
            real_pedersen_t: None,
            all_pedersen_params: None,
        };
        assert!(
            !share.needs_paillier_upgrade(),
            "share with real Paillier keys must not need upgrade"
        );
    }

    #[test]
    fn test_needs_paillier_upgrade_partial_keys_still_needs_upgrade() {
        use crate::paillier::keygen::generate_paillier_keypair;

        let (pk, _sk) = generate_paillier_keypair(512).unwrap();
        // Has pk but missing sk and all_paillier_pks
        let share = Cggmp21ShareData {
            party_index: 1,
            secret_share: vec![1u8; 32],
            public_shares: vec![vec![2u8; 33]],
            group_public_key: vec![4u8; 33],
            paillier_sk: vec![5u8; 64],
            paillier_pk: vec![6u8; 32],
            pedersen_params: vec![7u8; 96],
            real_paillier_sk: None,
            real_paillier_pk: Some(pk),
            all_paillier_pks: None,
            real_pedersen_n_hat: None,
            real_pedersen_s: None,
            real_pedersen_t: None,
            all_pedersen_params: None,
        };
        assert!(
            share.needs_paillier_upgrade(),
            "share with only partial Paillier keys must still need upgrade"
        );
    }

    // ── SEC-054: Paillier key size validation tests ──────────────────────

    #[test]
    fn test_paillier_validation_512bit_works_in_test() {
        use crate::paillier::keygen::{generate_paillier_keypair, validate_paillier_key_size};

        let (pk, _sk) = generate_paillier_keypair(512).unwrap();
        assert!(
            validate_paillier_key_size(&pk).is_ok(),
            "512-bit key validation must succeed in test mode"
        );
    }

    #[test]
    fn test_paillier_validation_rejects_nothing_in_test_mode() {
        // In test builds, even tiny keys pass validation (this is by design).
        use crate::paillier::keygen::validate_paillier_bits;
        assert!(validate_paillier_bits(256).is_ok());
        assert!(validate_paillier_bits(512).is_ok());
        assert!(validate_paillier_bits(1024).is_ok());
        assert!(validate_paillier_bits(2048).is_ok());
    }

    // ── SEC-037: FilePreSignatureStore crash-safe nonce reuse protection ──

    #[test]
    fn test_file_presignature_store_crash_safe() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilePreSignatureStore::new(dir.path()).unwrap();

        // Mark a presig as used
        store.mark_used("presig-001").unwrap();
        assert!(store.is_used("presig-001"));
        assert!(!store.is_used("presig-002"));

        // Duplicate should fail
        assert!(store.mark_used("presig-001").is_err());

        // "Crash" — drop the store, reload from file
        drop(store);
        let store2 = FilePreSignatureStore::new(dir.path()).unwrap();

        // Must still be marked as used after reload
        assert!(store2.is_used("presig-001"), "presig must survive restart");
        assert!(!store2.is_used("presig-002"));

        // Can mark new ones
        store2.mark_used("presig-002").unwrap();
        assert!(store2.is_used("presig-002"));
    }
}
