use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use frost_secp256k1_tr as frost;
use k256::elliptic_curve::{Field, PrimeField};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::CoreError;
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::{ProtocolMessage, Transport};
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

/// FROST threshold Schnorr protocol adapter for secp256k1 (Taproot).
pub struct FrostSecp256k1TrProtocol;

impl FrostSecp256k1TrProtocol {
    /// Create a new `FrostSecp256k1TrProtocol` instance.
    ///
    /// The struct is zero-sized; all state lives in the [`crate::protocol::KeyShare`]
    /// passed to [`crate::protocol::MpcProtocol::sign`].
    pub fn new() -> Self {
        Self
    }
}

impl Default for FrostSecp256k1TrProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal serializable wrapper for share data stored in KeyShare.share_data
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct FrostSecp256k1ShareData {
    key_package: Vec<u8>,
    pubkey_package: Vec<u8>,
}

fn party_to_identifier(party: PartyId) -> Result<frost::Identifier, CoreError> {
    frost::Identifier::try_from(party.0)
        .map_err(|e| CoreError::Protocol(format!("invalid party id for FROST: {e}")))
}

/// SEC-013 FIX: Validate that `msg.from` is in the expected set of parties.
///
/// **Trust boundary:** The transport layer (SignedEnvelope in NatsTransport)
/// cryptographically verifies sender identity via Ed25519 signatures and
/// monotonic sequence numbers (SEC-007). This check is a defense-in-depth
/// measure ensuring the self-reported `from` field matches a party we
/// expect in the protocol, preventing a compromised-but-authenticated peer
/// from injecting messages for a party ID it does not own.
fn validate_sender(
    msg: &crate::transport::ProtocolMessage,
    expected: &HashSet<PartyId>,
) -> Result<(), CoreError> {
    if !expected.contains(&msg.from) {
        return Err(CoreError::Protocol(format!(
            "FROST: unexpected sender party {} — not in expected set",
            msg.from.0
        )));
    }
    Ok(())
}

#[async_trait]
impl MpcProtocol for FrostSecp256k1TrProtocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::FrostSecp256k1Tr
    }

    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        let my_id = party_to_identifier(party_id)?;

        // SEC-013 FIX: build expected peer set for `from` field validation in keygen.
        let expected_keygen_peers: HashSet<PartyId> = (1..=config.total_parties)
            .filter(|&p| PartyId(p) != party_id)
            .map(PartyId)
            .collect();

        // === Round 1: Generate and broadcast round1 packages ===
        // Do RNG work in a block so rng is dropped before .await
        let (round1_secret, round1_bytes) = {
            let mut rng = rand::thread_rng();
            let (round1_secret, round1_package) =
                frost::keys::dkg::part1(my_id, config.total_parties, config.threshold, &mut rng)
                    .map_err(|e| CoreError::Protocol(format!("FROST DKG part1: {e}")))?;

            let round1_bytes = serde_json::to_vec(&round1_package)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            (round1_secret, round1_bytes)
        };

        // Broadcast our round1 package
        transport
            .send(ProtocolMessage {
                from: party_id,
                to: None,
                round: 1,
                payload: round1_bytes,
            })
            .await?;

        // Collect round1 packages from all other parties
        let mut round1_packages: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
            BTreeMap::new();
        for _ in 0..(config.total_parties - 1) {
            let msg = transport.recv().await?;
            // SEC-013 FIX: validate sender is an expected keygen participant.
            validate_sender(&msg, &expected_keygen_peers)?;
            let pkg: frost::keys::dkg::round1::Package = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let from_id = party_to_identifier(msg.from)?;
            round1_packages.insert(from_id, pkg);
        }

        // === Round 2: Generate and unicast round2 packages ===
        let (round2_secret, round2_messages) = {
            let (round2_secret, round2_packages) =
                frost::keys::dkg::part2(round1_secret, &round1_packages)
                    .map_err(|e| CoreError::Protocol(format!("FROST DKG part2: {e}")))?;

            // Pre-serialize all round2 messages
            let mut messages = Vec::new();
            for (target_id, pkg) in &round2_packages {
                let target_party = (1..=config.total_parties)
                    .find(|&p| {
                        frost::Identifier::try_from(p)
                            .map(|id| id == *target_id)
                            .unwrap_or(false)
                    })
                    .ok_or_else(|| CoreError::Protocol("cannot map identifier to party".into()))?;

                let pkg_bytes =
                    serde_json::to_vec(pkg).map_err(|e| CoreError::Serialization(e.to_string()))?;
                messages.push((target_party, pkg_bytes));
            }
            (round2_secret, messages)
        };

        // Send round2 packages to each peer
        for (target_party, pkg_bytes) in round2_messages {
            transport
                .send(ProtocolMessage {
                    from: party_id,
                    to: Some(PartyId(target_party)),
                    round: 2,
                    payload: pkg_bytes,
                })
                .await?;
        }

        // Collect round2 packages from all other parties
        let mut round2_received: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package> =
            BTreeMap::new();
        for _ in 0..(config.total_parties - 1) {
            let msg = transport.recv().await?;
            // SEC-013 FIX: validate sender is an expected keygen participant.
            validate_sender(&msg, &expected_keygen_peers)?;
            let pkg: frost::keys::dkg::round2::Package = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let from_id = party_to_identifier(msg.from)?;
            round2_received.insert(from_id, pkg);
        }

        // === Round 3: Derive key package ===
        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(&round2_secret, &round1_packages, &round2_received)
                .map_err(|e| CoreError::Protocol(format!("FROST DKG part3: {e}")))?;

        // Extract the group verifying key
        let verifying_key = pubkey_package.verifying_key();
        let vk_bytes = verifying_key
            .serialize()
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        // Serialize key_package and pubkey_package for storage
        let key_pkg_bytes = serde_json::to_vec(&key_package)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pubkey_pkg_bytes = serde_json::to_vec(&pubkey_package)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let share_data = FrostSecp256k1ShareData {
            key_package: key_pkg_bytes,
            pubkey_package: pubkey_pkg_bytes,
        };

        Ok(KeyShare {
            scheme: CryptoScheme::FrostSecp256k1Tr,
            party_id,
            config,
            group_public_key: GroupPublicKey::Secp256k1(vk_bytes),
            // SEC-004 root fix (T-S4-00): wrap in Zeroizing so key bytes are wiped on drop
            share_data: zeroize::Zeroizing::new(
                serde_json::to_vec(&share_data)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?,
            ),
            chain_code: None,
            is_derived: false,
        })
    }

    /// Reshare key shares to a new threshold configuration.
    ///
    /// For FROST Secp256k1-tr, resharing runs a fresh DKG with the new configuration.
    /// **Note:** Unlike GG20, FROST reshare generates a new group public key
    /// because the FROST DKG API does not expose a mechanism to constrain the
    /// group secret to a pre-existing value. All new parties must participate.
    async fn reshare(
        &self,
        key_share: &KeyShare,
        _old_signers: &[PartyId],
        new_config: ThresholdConfig,
        _new_parties: &[PartyId],
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        // For FROST, reshare = new DKG with new config.
        // The group key will change (FROST limitation — no secret injection in DKG).
        let party_id = key_share.party_id;
        self.keygen(new_config, party_id, transport).await
    }

    async fn sign(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        message: &[u8],
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        // Deserialize stored data.
        // SEC-004 root fix (T-S4-00): share_data is now Zeroizing<Vec<u8>>.
        // Cloning produces another Zeroizing<Vec<u8>> — no double-wrap needed.
        // The deserialized FrostSecp256k1ShareData also derives ZeroizeOnDrop.
        let share_data_copy = key_share.share_data.clone();
        let share_data: FrostSecp256k1ShareData = serde_json::from_slice(&share_data_copy)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let key_package: frost::keys::KeyPackage = serde_json::from_slice(&share_data.key_package)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pubkey_package: frost::keys::PublicKeyPackage =
            serde_json::from_slice(&share_data.pubkey_package)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let my_id = party_to_identifier(key_share.party_id)?;

        // SEC-013 FIX: build expected signer set for `from` field validation.
        let expected_peers: HashSet<PartyId> = signers
            .iter()
            .copied()
            .filter(|&p| p != key_share.party_id)
            .collect();

        // === Round 1: Generate nonces and commitments ===
        // Do RNG work in a block so rng is dropped before .await
        let (nonces, commitments, commit_bytes) = {
            let mut rng = rand::thread_rng();
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            let commit_bytes = serde_json::to_vec(&commitments)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            (nonces, commitments, commit_bytes)
        };

        // Broadcast commitments
        transport
            .send(ProtocolMessage {
                from: key_share.party_id,
                to: None,
                round: 1,
                payload: commit_bytes,
            })
            .await?;

        // Collect commitments from other signers
        let mut all_commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
            BTreeMap::new();
        all_commitments.insert(my_id, commitments);

        for _ in 0..(signers.len() - 1) {
            let msg = transport.recv().await?;
            // SEC-013 FIX: validate sender is an expected signer.
            validate_sender(&msg, &expected_peers)?;
            let their_commitments: frost::round1::SigningCommitments =
                serde_json::from_slice(&msg.payload)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let from_id = party_to_identifier(msg.from)?;
            all_commitments.insert(from_id, their_commitments);
        }

        // === Round 2: Create signing package and generate signature share ===
        let signing_package = frost::SigningPackage::new(all_commitments, message);
        let sig_share = frost::round2::sign(&signing_package, &nonces, &key_package)
            .map_err(|e| CoreError::Protocol(format!("FROST sign round2: {e}")))?;

        // Broadcast signature share
        let share_bytes =
            serde_json::to_vec(&sig_share).map_err(|e| CoreError::Serialization(e.to_string()))?;
        transport
            .send(ProtocolMessage {
                from: key_share.party_id,
                to: None,
                round: 2,
                payload: share_bytes,
            })
            .await?;

        // Collect signature shares
        let mut all_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> =
            BTreeMap::new();
        all_shares.insert(my_id, sig_share);

        for _ in 0..(signers.len() - 1) {
            let msg = transport.recv().await?;
            // SEC-013 FIX: validate sender is an expected signer.
            validate_sender(&msg, &expected_peers)?;
            let their_share: frost::round2::SignatureShare =
                serde_json::from_slice(&msg.payload)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let from_id = party_to_identifier(msg.from)?;
            all_shares.insert(from_id, their_share);
        }

        // Aggregate into final signature
        let signature = frost::aggregate(&signing_package, &all_shares, &pubkey_package)
            .map_err(|e| CoreError::Protocol(format!("FROST aggregate: {e}")))?;

        let sig_bytes = signature
            .serialize()
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);

        Ok(MpcSignature::Schnorr {
            signature: sig_array,
        })
    }

    /// Proactive key share refresh using additive re-sharing on secp256k1.
    ///
    /// Each party generates a random degree-(t-1) polynomial g(x) with g(0) = 0
    /// (ensuring the group secret is unchanged). Parties exchange evaluations
    /// g_j(i) via round 100, sum the received deltas, and add to their current
    /// signing share. New verifying shares are broadcast on round 101 so each
    /// party can rebuild the `PublicKeyPackage`.
    ///
    /// The group public key is preserved because Σ g_j(0) = 0 for all j.
    async fn refresh(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        let _ = signers;
        let config = key_share.config;
        let party_id = key_share.party_id;
        let my_id = party_to_identifier(party_id)?;

        // SEC-013 FIX: build expected peer set for `from` field validation in refresh.
        let expected_refresh_peers: HashSet<PartyId> = (1..=config.total_parties)
            .filter(|&p| PartyId(p) != party_id)
            .map(PartyId)
            .collect();

        // Deserialize current key package and pubkey package
        let share_data_copy = key_share.share_data.clone();
        let share_data: FrostSecp256k1ShareData = serde_json::from_slice(&share_data_copy)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let key_package: frost::keys::KeyPackage = serde_json::from_slice(&share_data.key_package)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pubkey_package: frost::keys::PublicKeyPackage =
            serde_json::from_slice(&share_data.pubkey_package)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

        // Extract current signing share scalar via serialize → k256::Scalar
        let current_share_bytes = key_package.signing_share().serialize();
        let current_scalar =
            k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&current_share_bytes))
                .into_option()
                .ok_or_else(|| CoreError::Crypto("invalid signing share scalar".into()))?;

        // === Generate refresh polynomial g(x) with g(0) = 0 ===
        // Coefficients: [0, c1, c2, ..., c_{t-1}] — degree t-1 polynomial
        let evaluations = {
            let mut rng = rand::thread_rng();
            let mut coefficients = vec![k256::Scalar::ZERO]; // g(0) = 0
            for _ in 1..config.threshold {
                coefficients.push(k256::Scalar::random(&mut rng));
            }

            // Evaluate g at each party's index
            let mut evals: Vec<(u16, Vec<u8>)> = Vec::new();
            for p in 1..=config.total_parties {
                let x = k256::Scalar::from(p as u64);
                let y = poly_eval_k256(&coefficients, &x);
                evals.push((p, y.to_repr().to_vec()));
            }
            evals
        };

        // === Round 100: send g(j) to each party j ===
        let mut my_eval_from_self = None;
        for (target_party, eval_bytes) in &evaluations {
            if *target_party == party_id.0 {
                my_eval_from_self = Some(eval_bytes.clone());
                continue;
            }
            let payload = serde_json::to_vec(eval_bytes)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            transport
                .send(ProtocolMessage {
                    from: party_id,
                    to: Some(PartyId(*target_party)),
                    round: 100,
                    payload,
                })
                .await?;
        }

        // Accumulate delta: start with our own polynomial's evaluation at our index
        let my_eval_bytes = my_eval_from_self
            .ok_or_else(|| CoreError::Protocol("missing self-evaluation".into()))?;
        let mut delta = k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&my_eval_bytes))
            .into_option()
            .ok_or_else(|| CoreError::Crypto("invalid self-evaluation scalar".into()))?;

        // Collect evaluations from all other parties
        for _ in 0..(config.total_parties - 1) {
            let msg = transport.recv().await?;
            // SEC-013 FIX: validate sender is an expected refresh participant.
            validate_sender(&msg, &expected_refresh_peers)?;
            let eval_bytes: Vec<u8> = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let eval_scalar = k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&eval_bytes))
                .into_option()
                .ok_or_else(|| CoreError::Crypto("invalid peer evaluation scalar".into()))?;
            delta += eval_scalar;
        }

        // === Compute new signing share ===
        let new_scalar = current_scalar + delta;
        let new_share_bytes = new_scalar.to_repr();

        // Create new SigningShare via deserialization
        let new_signing_share = frost::keys::SigningShare::deserialize(new_share_bytes.as_slice())
            .map_err(|e| CoreError::Protocol(format!("SigningShare deserialize: {e}")))?;

        // Compute new verifying share: G * new_scalar (compressed SEC1 point)
        let new_vs_point = (k256::ProjectivePoint::GENERATOR * new_scalar).to_affine();
        let new_vs_compressed = {
            use k256::elliptic_curve::group::GroupEncoding;
            new_vs_point.to_bytes()
        };
        let new_verifying_share = frost::keys::VerifyingShare::deserialize(&new_vs_compressed)
            .map_err(|e| CoreError::Protocol(format!("VerifyingShare deserialize: {e}")))?;

        // === Round 101: broadcast new verifying share so all can rebuild PublicKeyPackage ===
        let vs_bytes = new_verifying_share
            .serialize()
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let vs_payload =
            serde_json::to_vec(&vs_bytes).map_err(|e| CoreError::Serialization(e.to_string()))?;
        transport
            .send(ProtocolMessage {
                from: party_id,
                to: None,
                round: 101,
                payload: vs_payload,
            })
            .await?;

        // Collect verifying shares from all parties (including ourselves)
        let mut new_verifying_shares: BTreeMap<frost::Identifier, frost::keys::VerifyingShare> =
            BTreeMap::new();
        new_verifying_shares.insert(my_id, new_verifying_share);

        for _ in 0..(config.total_parties - 1) {
            let msg = transport.recv().await?;
            // SEC-013 FIX: validate sender is an expected refresh participant.
            validate_sender(&msg, &expected_refresh_peers)?;
            let peer_vs_bytes: Vec<u8> = serde_json::from_slice(&msg.payload)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let peer_vs =
                frost::keys::VerifyingShare::deserialize(&peer_vs_bytes).map_err(|e| {
                    CoreError::Protocol(format!("peer VerifyingShare deserialize: {e}"))
                })?;
            let from_id = party_to_identifier(msg.from)?;
            new_verifying_shares.insert(from_id, peer_vs);
        }

        // Build new KeyPackage and PublicKeyPackage
        // The verifying key (group public key) stays the same
        let verifying_key = *pubkey_package.verifying_key();

        let new_key_package = frost::keys::KeyPackage::new(
            *key_package.identifier(),
            new_signing_share,
            new_verifying_share,
            verifying_key,
            *key_package.min_signers(),
        );

        let new_pubkey_package =
            frost::keys::PublicKeyPackage::new(new_verifying_shares, verifying_key);

        // Serialize and return new KeyShare
        let key_pkg_bytes = serde_json::to_vec(&new_key_package)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pubkey_pkg_bytes = serde_json::to_vec(&new_pubkey_package)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let new_share_data = FrostSecp256k1ShareData {
            key_package: key_pkg_bytes,
            pubkey_package: pubkey_pkg_bytes,
        };

        let vk_bytes = verifying_key
            .serialize()
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        Ok(KeyShare {
            scheme: CryptoScheme::FrostSecp256k1Tr,
            party_id,
            config,
            group_public_key: GroupPublicKey::Secp256k1(vk_bytes),
            share_data: zeroize::Zeroizing::new(
                serde_json::to_vec(&new_share_data)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?,
            ),
            chain_code: None,
            is_derived: false,
        })
    }
}

/// Evaluate polynomial at `x`: `f(x) = c[0] + c[1]·x + c[2]·x² + …` (secp256k1 scalar)
fn poly_eval_k256(coefficients: &[k256::Scalar], x: &k256::Scalar) -> k256::Scalar {
    let mut result = k256::Scalar::ZERO;
    let mut x_pow = k256::Scalar::ONE;
    for coeff in coefficients {
        result += coeff * &x_pow;
        x_pow *= x;
    }
    result
}
