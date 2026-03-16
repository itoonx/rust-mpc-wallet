use std::collections::BTreeMap;

use async_trait::async_trait;
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroizing, ZeroizeOnDrop};

use crate::error::CoreError;
use crate::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use crate::transport::{ProtocolMessage, Transport};
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

/// FROST threshold EdDSA protocol adapter for Ed25519.
pub struct FrostEd25519Protocol;

impl FrostEd25519Protocol {
    /// Create a new `FrostEd25519Protocol` instance.
    ///
    /// The struct is zero-sized; all state lives in the [`crate::protocol::KeyShare`]
    /// passed to [`crate::protocol::MpcProtocol::sign`].
    pub fn new() -> Self {
        Self
    }
}

impl Default for FrostEd25519Protocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal serializable wrapper for share data stored in KeyShare.share_data
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct FrostEd25519ShareData {
    key_package: Vec<u8>,
    pubkey_package: Vec<u8>,
}

fn party_to_identifier(party: PartyId) -> Result<frost::Identifier, CoreError> {
    frost::Identifier::try_from(party.0)
        .map_err(|e| CoreError::Protocol(format!("invalid party id for FROST: {e}")))
}

#[async_trait]
impl MpcProtocol for FrostEd25519Protocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::FrostEd25519
    }

    async fn keygen(
        &self,
        config: ThresholdConfig,
        party_id: PartyId,
        transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        let my_id = party_to_identifier(party_id)?;

        // === Round 1: Generate and broadcast round1 packages ===
        let (round1_secret, round1_bytes) = {
            let mut rng = rand::thread_rng();
            let (round1_secret, round1_package) = frost::keys::dkg::part1(
                my_id,
                config.total_parties,
                config.threshold,
                &mut rng,
            )
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
            let pkg: frost::keys::dkg::round1::Package =
                serde_json::from_slice(&msg.payload)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let from_id = party_to_identifier(msg.from)?;
            round1_packages.insert(from_id, pkg);
        }

        // === Round 2: Generate and unicast round2 packages ===
        let (round2_secret, round2_messages) = {
            let (round2_secret, round2_packages) =
                frost::keys::dkg::part2(round1_secret, &round1_packages)
                    .map_err(|e| CoreError::Protocol(format!("FROST DKG part2: {e}")))?;

            let mut messages = Vec::new();
            for (target_id, pkg) in &round2_packages {
                let target_party = (1..=config.total_parties)
                    .find(|&p| {
                        frost::Identifier::try_from(p)
                            .map(|id| id == *target_id)
                            .unwrap_or(false)
                    })
                    .ok_or_else(|| {
                        CoreError::Protocol("cannot map identifier to party".into())
                    })?;

                let pkg_bytes = serde_json::to_vec(pkg)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
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
            let pkg: frost::keys::dkg::round2::Package =
                serde_json::from_slice(&msg.payload)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
            let from_id = party_to_identifier(msg.from)?;
            round2_received.insert(from_id, pkg);
        }

        // === Round 3: Derive key package ===
        let (key_package, pubkey_package) =
            frost::keys::dkg::part3(&round2_secret, &round1_packages, &round2_received)
                .map_err(|e| CoreError::Protocol(format!("FROST DKG part3: {e}")))?;

        // Extract the group verifying key as Ed25519 public key bytes (32 bytes)
        let verifying_key = pubkey_package.verifying_key();
        let vk_bytes = verifying_key
            .serialize()
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        // Serialize key_package and pubkey_package for storage
        let key_pkg_bytes = serde_json::to_vec(&key_package)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pubkey_pkg_bytes = serde_json::to_vec(&pubkey_package)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let share_data = FrostEd25519ShareData {
            key_package: key_pkg_bytes,
            pubkey_package: pubkey_pkg_bytes,
        };

        Ok(KeyShare {
            scheme: CryptoScheme::FrostEd25519,
            party_id,
            config,
            group_public_key: GroupPublicKey::Ed25519(vk_bytes),
            share_data: serde_json::to_vec(&share_data)
                .map_err(|e| CoreError::Serialization(e.to_string()))?,
        })
    }

    async fn sign(
        &self,
        key_share: &KeyShare,
        signers: &[PartyId],
        message: &[u8],
        transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        // Deserialize stored data.
        // SEC-004 partial fix: wrap the share_data clone in Zeroizing so the raw
        // bytes are zeroed on drop.  The deserialized FrostEd25519ShareData also
        // derives ZeroizeOnDrop, ensuring key material bytes are erased after use.
        let share_data_copy = Zeroizing::new(key_share.share_data.clone());
        let share_data: FrostEd25519ShareData =
            serde_json::from_slice(&share_data_copy)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let key_package: frost::keys::KeyPackage =
            serde_json::from_slice(&share_data.key_package)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;
        let pubkey_package: frost::keys::PublicKeyPackage =
            serde_json::from_slice(&share_data.pubkey_package)
                .map_err(|e| CoreError::Serialization(e.to_string()))?;

        let my_id = party_to_identifier(key_share.party_id)?;

        // === Round 1: Generate nonces and commitments ===
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
        let share_bytes = serde_json::to_vec(&sig_share)
            .map_err(|e| CoreError::Serialization(e.to_string()))?;
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

        Ok(MpcSignature::EdDsa {
            signature: sig_array,
        })
    }
}
