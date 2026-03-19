//! MPC Orchestrator — gateway delegates keygen/sign to distributed MPC nodes via NATS.
//!
//! The gateway holds ZERO key shares. It only stores metadata (group_id, label,
//! scheme, group_pubkey) and coordinates ceremonies by publishing requests on NATS
//! control channels and collecting responses.
//!
//! # Architecture (DEC-015)
//! ```text
//! Gateway (this orchestrator)
//!   │ NATS control channels
//!   ├── Node 1 (share 1 only)
//!   ├── Node 2 (share 2 only)
//!   └── Node 3 (share 3 only)
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_nats::Client as NatsClient;
use ed25519_dalek::SigningKey;
use futures::StreamExt;
use tokio::sync::RwLock;

use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};
use mpc_wallet_core::rpc;
use mpc_wallet_core::types::{CryptoScheme, ThresholdConfig};

/// Wallet metadata stored by the gateway (NO key shares).
#[derive(Clone, Debug)]
pub struct WalletMetadata {
    pub group_id: String,
    pub label: String,
    pub scheme: CryptoScheme,
    pub config: ThresholdConfig,
    pub group_public_key: GroupPublicKey,
    pub created_at: u64,
    pub frozen: bool,
}

/// MPC Orchestrator — delegates to distributed nodes, holds no shares.
#[derive(Clone)]
pub struct MpcOrchestrator {
    /// NATS client for publishing control messages. None in local-only mode.
    nats: Option<Arc<NatsClient>>,
    /// Wallet metadata (group_id → metadata). NO key shares.
    wallets: Arc<RwLock<HashMap<String, WalletMetadata>>>,
    /// Timeout for waiting for node responses.
    ceremony_timeout: Duration,
    /// Ed25519 signing key for control plane message authentication (SEC-026).
    /// All control messages are signed before publishing on NATS.
    signing_key: Option<SigningKey>,
}

impl Default for MpcOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl MpcOrchestrator {
    /// Create an orchestrator without NATS (for unit tests).
    /// Keygen/sign operations will fail — only metadata operations work.
    pub fn new() -> Self {
        Self {
            nats: None,
            wallets: Arc::new(RwLock::new(HashMap::new())),
            ceremony_timeout: Duration::from_secs(60),
            signing_key: None,
        }
    }

    /// Create an orchestrator connected to NATS (production).
    pub async fn connect(nats_url: &str) -> Result<Self, mpc_wallet_core::error::CoreError> {
        let nats = async_nats::connect(nats_url).await.map_err(|e| {
            mpc_wallet_core::error::CoreError::Transport(format!("NATS connect: {e}"))
        })?;

        tracing::info!(url = %nats_url, "MPC orchestrator connected to NATS");

        Ok(Self {
            nats: Some(Arc::new(nats)),
            wallets: Arc::new(RwLock::new(HashMap::new())),
            ceremony_timeout: Duration::from_secs(60),
            signing_key: None,
        })
    }

    /// Create an orchestrator connected to NATS with an Ed25519 signing key (SEC-026).
    ///
    /// All control plane messages (keygen/sign/freeze) will be signed with this key.
    /// MPC nodes verify the signature against the corresponding public key before
    /// processing any control message.
    pub async fn connect_with_key(
        nats_url: &str,
        signing_key: SigningKey,
    ) -> Result<Self, mpc_wallet_core::error::CoreError> {
        let nats = async_nats::connect(nats_url).await.map_err(|e| {
            mpc_wallet_core::error::CoreError::Transport(format!("NATS connect: {e}"))
        })?;

        tracing::info!(
            url = %nats_url,
            gateway_pubkey = %hex::encode(signing_key.verifying_key().as_bytes()),
            "MPC orchestrator connected to NATS with signing key (SEC-026)"
        );

        Ok(Self {
            nats: Some(Arc::new(nats)),
            wallets: Arc::new(RwLock::new(HashMap::new())),
            ceremony_timeout: Duration::from_secs(60),
            signing_key: Some(signing_key),
        })
    }

    /// Get the NATS client, or return an error if not connected.
    fn nats(&self) -> Result<&NatsClient, mpc_wallet_core::error::CoreError> {
        self.nats.as_ref().map(|n| n.as_ref()).ok_or_else(|| {
            mpc_wallet_core::error::CoreError::Transport(
                "MPC orchestrator: NATS not connected (local-only mode)".into(),
            )
        })
    }

    /// Wrap a serialized payload in a `SignedControlMessage` if a signing key is configured.
    /// Returns the final bytes to publish on NATS.
    fn wrap_payload(&self, payload: &[u8]) -> Result<Vec<u8>, mpc_wallet_core::error::CoreError> {
        match &self.signing_key {
            Some(key) => {
                let signed = rpc::sign_control_message(payload, key);
                serde_json::to_vec(&signed)
                    .map_err(|e| mpc_wallet_core::error::CoreError::Serialization(e.to_string()))
            }
            None => Ok(payload.to_vec()),
        }
    }

    /// Initiate distributed keygen via NATS.
    ///
    /// Publishes `KeygenRequest` to all nodes, waits for `KeygenResponse` from each,
    /// verifies all agree on group public key, stores metadata (NO shares).
    pub async fn keygen(
        &self,
        group_id: String,
        label: String,
        scheme: CryptoScheme,
        threshold: u16,
        total_parties: u16,
    ) -> Result<WalletMetadata, mpc_wallet_core::error::CoreError> {
        let session_id = uuid::Uuid::new_v4().to_string();

        // Generate Ed25519 keys for each party's envelope signing.
        // In production, nodes have persistent keys — this is for session-scoped keys.
        let peer_keys: Vec<rpc::PeerKeyEntry> = (1..=total_parties)
            .map(|i| {
                let mut bytes = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
                let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
                rpc::PeerKeyEntry {
                    party_id: i,
                    verifying_key_hex: hex::encode(key.verifying_key().as_bytes()),
                }
            })
            .collect();

        // Include the NATS URL so nodes know where to connect for protocol transport
        let nats_url = self
            .nats
            .as_ref()
            .map(|_| "nats://127.0.0.1:4222".to_string()); // TODO: pass actual URL from config

        let request = rpc::KeygenRequest {
            group_id: group_id.clone(),
            label: label.clone(),
            scheme: scheme.to_string(),
            threshold,
            total_parties,
            session_id,
            peer_keys,
            nats_url,
        };

        // Use NATS request-reply: create an inbox, subscribe to it, then publish
        // with reply set to the inbox. Nodes respond to the inbox directly.
        // This eliminates the subscribe-before-publish timing issue.
        let nats = self.nats()?;
        let inbox = nats.new_inbox();
        let mut reply_sub = nats.subscribe(inbox.clone()).await.map_err(|e| {
            mpc_wallet_core::error::CoreError::Transport(format!("subscribe inbox: {e}"))
        })?;

        let subject = rpc::keygen_subject(&group_id);
        let raw_payload = serde_json::to_vec(&request)
            .map_err(|e| mpc_wallet_core::error::CoreError::Serialization(e.to_string()))?;
        let payload = self.wrap_payload(&raw_payload)?;
        nats.publish_with_reply(subject, inbox, payload.into())
            .await
            .map_err(|e| mpc_wallet_core::error::CoreError::Transport(format!("publish: {e}")))?;

        tracing::info!(group_id = %group_id, "keygen request published (signed), waiting for {total_parties} responses");

        // Collect responses from all nodes
        let mut responses: Vec<rpc::KeygenResponse> = Vec::new();
        let deadline = tokio::time::Instant::now() + self.ceremony_timeout;

        while responses.len() < total_parties as usize {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(mpc_wallet_core::error::CoreError::Protocol(format!(
                    "keygen timeout: got {}/{total_parties} responses",
                    responses.len()
                )));
            }

            match tokio::time::timeout(remaining, reply_sub.next()).await {
                Ok(Some(msg)) => {
                    if let Ok(resp) = serde_json::from_slice::<rpc::KeygenResponse>(&msg.payload) {
                        if !resp.success {
                            return Err(mpc_wallet_core::error::CoreError::Protocol(format!(
                                "node {} keygen failed: {}",
                                resp.party_id,
                                resp.error.unwrap_or_default()
                            )));
                        }
                        tracing::debug!(party_id = resp.party_id, "keygen response received");
                        responses.push(resp);
                    }
                }
                Ok(None) => {
                    return Err(mpc_wallet_core::error::CoreError::Transport(
                        "NATS subscription closed during keygen".into(),
                    ));
                }
                Err(_) => {
                    return Err(mpc_wallet_core::error::CoreError::Protocol(format!(
                        "keygen timeout: got {}/{total_parties} responses",
                        responses.len()
                    )));
                }
            }
        }

        // Verify all nodes agree on group public key
        let gpk_hex = &responses[0].group_pubkey_hex;
        for resp in &responses[1..] {
            if resp.group_pubkey_hex != *gpk_hex {
                return Err(mpc_wallet_core::error::CoreError::Protocol(
                    "keygen: nodes disagree on group public key".into(),
                ));
            }
        }

        // Parse group public key
        let gpk_bytes = hex::decode(gpk_hex).map_err(|e| {
            mpc_wallet_core::error::CoreError::Serialization(format!("gpk hex: {e}"))
        })?;

        // Determine GroupPublicKey variant based on scheme
        let group_public_key = match scheme {
            CryptoScheme::Gg20Ecdsa
            | CryptoScheme::FrostSecp256k1Tr
            | CryptoScheme::Cggmp21Secp256k1 => GroupPublicKey::Secp256k1(gpk_bytes),
            CryptoScheme::FrostEd25519 => GroupPublicKey::Ed25519(gpk_bytes),
            _ => GroupPublicKey::Secp256k1(gpk_bytes),
        };

        let config = ThresholdConfig::new(threshold, total_parties)
            .map_err(|e| mpc_wallet_core::error::CoreError::InvalidConfig(e.to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = WalletMetadata {
            group_id: group_id.clone(),
            label,
            scheme,
            config,
            group_public_key,
            created_at: now,
            frozen: false,
        };

        // Store metadata only (NO shares)
        self.wallets
            .write()
            .await
            .insert(group_id.clone(), metadata.clone());

        tracing::info!(
            group_id = %group_id,
            gpk = &gpk_hex[..16],
            parties = total_parties,
            "keygen complete — metadata stored (NO shares in gateway)"
        );

        Ok(metadata)
    }

    /// Request distributed signing via NATS.
    ///
    /// Publishes `SignRequest` with SignAuthorization to signer nodes,
    /// waits for coordinator's response with the final signature.
    pub async fn sign(
        &self,
        group_id: &str,
        message: &[u8],
        sign_authorization_json: &str,
    ) -> Result<MpcSignature, mpc_wallet_core::error::CoreError> {
        // Check metadata (frozen state, existence)
        let metadata = {
            let wallets = self.wallets.read().await;
            wallets.get(group_id).cloned().ok_or_else(|| {
                mpc_wallet_core::error::CoreError::NotFound(format!("wallet {group_id} not found"))
            })?
        };

        if metadata.frozen {
            return Err(mpc_wallet_core::error::CoreError::KeyFrozen(format!(
                "wallet {group_id} is frozen"
            )));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let threshold = metadata.config.threshold;

        // Select first t parties as signers (coordinator = Party 1)
        let signer_ids: Vec<u16> = (1..=threshold).collect();

        // Generate session peer keys for signing
        let peer_keys: Vec<rpc::PeerKeyEntry> = signer_ids
            .iter()
            .map(|&i| {
                let mut bytes = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
                let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
                rpc::PeerKeyEntry {
                    party_id: i,
                    verifying_key_hex: hex::encode(key.verifying_key().as_bytes()),
                }
            })
            .collect();

        // Include the NATS URL so nodes know where to connect for protocol transport
        let nats_url = self
            .nats
            .as_ref()
            .map(|_| "nats://127.0.0.1:4222".to_string()); // TODO: pass actual URL from config

        let request = rpc::SignRequest {
            group_id: group_id.to_string(),
            message_hex: hex::encode(message),
            signer_ids: signer_ids.clone(),
            session_id,
            peer_keys,
            sign_authorization: sign_authorization_json.to_string(),
            nats_url,
        };

        // Use NATS request-reply: create an inbox, subscribe to it, then publish
        // with reply set to the inbox. Eliminates timing issues.
        let nats = self.nats()?;
        let inbox = nats.new_inbox();
        let mut reply_sub = nats.subscribe(inbox.clone()).await.map_err(|e| {
            mpc_wallet_core::error::CoreError::Transport(format!("subscribe inbox: {e}"))
        })?;

        let subject = rpc::sign_subject(group_id);
        let raw_payload = serde_json::to_vec(&request)
            .map_err(|e| mpc_wallet_core::error::CoreError::Serialization(e.to_string()))?;
        let payload = self.wrap_payload(&raw_payload)?;
        nats.publish_with_reply(subject, inbox, payload.into())
            .await
            .map_err(|e| mpc_wallet_core::error::CoreError::Transport(format!("publish: {e}")))?;

        tracing::info!(
            group_id = %group_id,
            signers = ?signer_ids,
            "sign request published, waiting for responses"
        );

        // Wait for coordinator's response (Party 1 has the complete signature)
        let deadline = tokio::time::Instant::now() + self.ceremony_timeout;
        let mut coordinator_sig: Option<MpcSignature> = None;

        let expected_responses = signer_ids.len();
        let mut received = 0;

        while received < expected_responses {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, reply_sub.next()).await {
                Ok(Some(msg)) => {
                    if let Ok(resp) = serde_json::from_slice::<rpc::SignResponse>(&msg.payload) {
                        if !resp.success {
                            return Err(mpc_wallet_core::error::CoreError::Protocol(format!(
                                "node {} sign failed: {}",
                                resp.party_id,
                                resp.error.unwrap_or_default()
                            )));
                        }

                        // Coordinator (Party 1) returns the complete signature
                        if resp.party_id == 1 {
                            if let Some(ref sig_json) = resp.signature_json {
                                coordinator_sig = serde_json::from_str(sig_json).ok();
                            }
                        }

                        received += 1;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        coordinator_sig.ok_or_else(|| {
            mpc_wallet_core::error::CoreError::Protocol(
                "sign: coordinator did not return signature".into(),
            )
        })
    }

    /// Publish freeze/unfreeze request to all nodes + update local metadata.
    pub async fn freeze(
        &self,
        group_id: &str,
        freeze: bool,
    ) -> Result<(), mpc_wallet_core::error::CoreError> {
        // Update local metadata
        {
            let mut wallets = self.wallets.write().await;
            let wallet = wallets.get_mut(group_id).ok_or_else(|| {
                mpc_wallet_core::error::CoreError::NotFound(format!("wallet {group_id} not found"))
            })?;
            wallet.frozen = freeze;
        }

        // Publish freeze request to nodes using request-reply for acknowledgment
        let request = rpc::FreezeRequest {
            group_id: group_id.to_string(),
            freeze,
        };
        let subject = rpc::freeze_subject(group_id);
        let raw_payload = serde_json::to_vec(&request)
            .map_err(|e| mpc_wallet_core::error::CoreError::Serialization(e.to_string()))?;
        let payload = self.wrap_payload(&raw_payload)?;
        if let Ok(nats) = self.nats() {
            // Use request() for single-response freeze acknowledgment.
            // Timeout after 10s — freeze is a fast operation.
            match tokio::time::timeout(
                Duration::from_secs(10),
                nats.request(subject, payload.into()),
            )
            .await
            {
                Ok(Ok(msg)) => {
                    if let Ok(resp) = serde_json::from_slice::<rpc::FreezeResponse>(&msg.payload) {
                        if !resp.success {
                            tracing::warn!(
                                group_id = %group_id,
                                "node {} freeze failed: {}",
                                resp.party_id,
                                resp.error.unwrap_or_default()
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(group_id = %group_id, "freeze request error: {e}");
                }
                Err(_) => {
                    tracing::warn!(group_id = %group_id, "freeze request timed out");
                }
            }
        }

        Ok(())
    }

    /// Get wallet metadata (NO shares).
    pub async fn get(&self, group_id: &str) -> Option<WalletMetadata> {
        self.wallets.read().await.get(group_id).cloned()
    }

    /// List all wallet metadata (NO shares).
    pub async fn list(&self) -> Vec<WalletMetadata> {
        self.wallets.read().await.values().cloned().collect()
    }
}
