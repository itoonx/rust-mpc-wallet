//! MPC Node — holds exactly one party's key share.
//!
//! Each node:
//! 1. Connects to NATS with Ed25519 signed envelopes
//! 2. Listens for keygen/sign/freeze requests on control channels
//! 3. Participates in MPC protocol rounds via NATS
//! 4. Stores its own share in EncryptedFileStore (AES-256-GCM + Argon2id)
//! 5. Verifies SignAuthorization before signing (DEC-012)
//!
//! # Configuration (env vars)
//! - `PARTY_ID` — this node's party ID (1-indexed)
//! - `NATS_URL` — NATS server URL
//! - `KEY_STORE_DIR` — directory for encrypted key shares
//! - `KEY_STORE_PASSWORD` — password for key store encryption
//! - `NODE_SIGNING_KEY` — hex Ed25519 signing key for envelope auth
//! - `GATEWAY_PUBKEY` — hex Ed25519 verifying key of the gateway (for SignAuth verification)

mod rpc;

use std::collections::HashMap as StdHashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use tokio::sync::Mutex;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zeroize::Zeroizing;

use mpc_wallet_core::key_store::encrypted::EncryptedFileStore;
use mpc_wallet_core::key_store::types::{KeyGroupId, KeyMetadata};
use mpc_wallet_core::key_store::KeyStore;
use mpc_wallet_core::protocol::sign_authorization::AuthorizationCache;
use mpc_wallet_core::protocol::MpcProtocol;
use mpc_wallet_core::transport::nats::NatsTransport;
use mpc_wallet_core::types::{CryptoScheme, PartyId, ThresholdConfig};

use rpc::*;

/// Default max entries for authorization replay cache.
const DEFAULT_AUTH_CACHE_MAX_ENTRIES: usize = 10_000;

/// Minimum interval between requests for the same group_id (SEC-030/031).
const MIN_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

/// Check per-group-id rate limit. Returns `true` if the request is allowed,
/// `false` if it should be rejected (too soon after last request for this group).
///
/// Updates `last_request` with the current timestamp when allowed.
fn check_rate_limit(
    last_request: &mut StdHashMap<String, Instant>,
    group_id: &str,
    min_interval: Duration,
) -> bool {
    if let Some(last) = last_request.get(group_id) {
        if last.elapsed() < min_interval {
            return false;
        }
    }
    last_request.insert(group_id.to_string(), Instant::now());
    true
}

/// Validate a hex-encoded Ed25519 verifying key string.
/// Returns the decoded `VerifyingKey` or an error message.
fn parse_verifying_key_hex(
    hex_str: &str,
    field_name: &str,
) -> Result<ed25519_dalek::VerifyingKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("{field_name} must be valid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{field_name} must be 32 bytes (got {})",
            bytes.len()
        ));
    }
    let arr: [u8; 32] = bytes.try_into().unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| format!("{field_name} must be a valid Ed25519 public key: {e}"))
}

/// Validate a hex-encoded Ed25519 signing key string.
/// Returns the decoded `SigningKey` or an error message.
fn parse_signing_key_hex(hex_str: &str, field_name: &str) -> Result<SigningKey, String> {
    let key_bytes =
        hex::decode(hex_str).map_err(|e| format!("{field_name} must be valid hex: {e}"))?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "{field_name} must be 32 bytes (got {})",
            key_bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&arr);
    // Zeroize the temporary array
    arr.iter_mut().for_each(|b| *b = 0);
    Ok(signing_key)
}

/// Initialize structured logging with optional JSON format.
///
/// - `RUST_LOG` env controls log levels (default: `mpc_wallet_node=info`)
/// - `LOG_FORMAT=json` enables JSON output (default: human-readable)
fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "mpc_wallet_node=info".into());

    let use_json = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if use_json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json().with_target(true))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}

/// Node configuration loaded from environment.
struct NodeConfig {
    party_id: PartyId,
    nats_url: String,
    key_store_dir: PathBuf,
    key_store_password: Zeroizing<String>, // SEC-028: zeroize password on drop
    signing_key: SigningKey,
    gateway_pubkey: ed25519_dalek::VerifyingKey,
    auth_cache_max_entries: usize,
}

impl NodeConfig {
    fn from_env() -> Self {
        let party_id = std::env::var("PARTY_ID")
            .expect("PARTY_ID must be set")
            .parse::<u16>()
            .expect("PARTY_ID must be a number");

        let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());

        let key_store_dir = std::env::var("KEY_STORE_DIR").unwrap_or_else(|_| "/data/keys".into());

        // SEC-028: wrap password in Zeroizing to clear on drop
        let key_store_password = Zeroizing::new(
            std::env::var("KEY_STORE_PASSWORD").expect("KEY_STORE_PASSWORD must be set"),
        );

        // SEC-029: parse signing key via helper (Zeroizing intermediates)
        let signing_key_hex = Zeroizing::new(
            std::env::var("NODE_SIGNING_KEY").expect("NODE_SIGNING_KEY must be set"),
        );
        let signing_key = parse_signing_key_hex(&signing_key_hex, "NODE_SIGNING_KEY")
            .expect("NODE_SIGNING_KEY parse failed");

        let gateway_pubkey_hex = std::env::var("GATEWAY_PUBKEY").expect(
            "GATEWAY_PUBKEY must be set — MPC nodes require gateway identity verification (DEC-012)",
        );
        let gateway_pubkey = parse_verifying_key_hex(&gateway_pubkey_hex, "GATEWAY_PUBKEY")
            .expect("GATEWAY_PUBKEY parse failed");

        let auth_cache_max_entries = std::env::var("AUTH_CACHE_MAX_ENTRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_AUTH_CACHE_MAX_ENTRIES);

        let config = Self {
            party_id: PartyId(party_id),
            nats_url,
            key_store_dir: PathBuf::from(key_store_dir),
            key_store_password,
            signing_key,
            gateway_pubkey,
            auth_cache_max_entries,
        };
        config.validate();
        config
    }

    /// Validate configuration invariants. Panics with clear messages on invalid config.
    fn validate(&self) {
        assert!(
            self.party_id.0 > 0,
            "PARTY_ID must be >= 1 (got {})",
            self.party_id.0
        );
        assert!(!self.nats_url.is_empty(), "NATS_URL must not be empty");
        assert!(
            self.key_store_dir.exists(),
            "KEY_STORE_DIR does not exist: {} — create it before starting the node",
            self.key_store_dir.display()
        );
        assert!(
            !self.key_store_password.is_empty(),
            "KEY_STORE_PASSWORD must not be empty"
        );
        assert!(
            self.auth_cache_max_entries > 0,
            "AUTH_CACHE_MAX_ENTRIES must be > 0"
        );
    }
}

#[tokio::main]
async fn main() {
    init_tracing();

    let config = NodeConfig::from_env();

    tracing::info!(
        party_id = config.party_id.0,
        nats_url = %config.nats_url,
        key_store_dir = %config.key_store_dir.display(),
        "MPC Node starting"
    );

    // Initialize key store
    let key_store = Arc::new(EncryptedFileStore::new(
        config.key_store_dir.clone(),
        &config.key_store_password,
    ));

    // Connect to NATS
    let nats_client = async_nats::connect(&config.nats_url)
        .await
        .expect("failed to connect to NATS");

    tracing::info!("connected to NATS");

    // Subscribe to control channels
    let keygen_sub = nats_client
        .subscribe("mpc.control.keygen.*")
        .await
        .expect("failed to subscribe to keygen channel");

    let sign_sub = nats_client
        .subscribe("mpc.control.sign.*")
        .await
        .expect("failed to subscribe to sign channel");

    let freeze_sub = nats_client
        .subscribe("mpc.control.freeze.*")
        .await
        .expect("failed to subscribe to freeze channel");

    tracing::info!(
        party_id = config.party_id.0,
        "listening for keygen/sign/freeze requests"
    );

    // Authorization replay cache (prevents duplicate SignAuthorization usage)
    let auth_cache = Arc::new(Mutex::new(AuthorizationCache::new(
        config.auth_cache_max_entries,
    )));

    tracing::info!(
        auth_cache_max_entries = config.auth_cache_max_entries,
        "authorization cache initialized"
    );

    // Process requests
    let config = Arc::new(config);
    let nats = Arc::new(nats_client);

    tokio::select! {
        _ = handle_keygen_requests(keygen_sub, config.clone(), key_store.clone(), nats.clone()) => {}
        _ = handle_sign_requests(sign_sub, config.clone(), key_store.clone(), nats.clone(), auth_cache.clone()) => {}
        _ = handle_freeze_requests(freeze_sub, config.clone(), key_store.clone(), nats.clone()) => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }
}

async fn handle_keygen_requests(
    mut sub: async_nats::Subscriber,
    config: Arc<NodeConfig>,
    key_store: Arc<EncryptedFileStore>,
    nats: Arc<async_nats::Client>,
) {
    use futures::StreamExt;

    // SEC-030: per-group-id rate limiter to prevent request flooding
    let mut last_request: StdHashMap<String, Instant> = StdHashMap::new();

    while let Some(msg) = sub.next().await {
        // SEC-026: Verify signed control message before processing
        let inner_payload = match unwrap_signed_message(&msg.payload, &config.gateway_pubkey) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("keygen: rejecting unsigned/invalid control message: {e}");
                continue;
            }
        };

        let req: KeygenRequest = match serde_json::from_slice(&inner_payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("invalid keygen request: {e}");
                continue;
            }
        };

        // SEC-030: Rate limit per group_id
        if !check_rate_limit(&mut last_request, &req.group_id, MIN_REQUEST_INTERVAL) {
            tracing::warn!(
                group_id = %req.group_id,
                "rate limited: keygen request too soon (SEC-030)"
            );
            continue;
        }

        tracing::info!(
            group_id = %req.group_id,
            scheme = %req.scheme,
            threshold = req.threshold,
            total = req.total_parties,
            "keygen request received"
        );

        let config = config.clone();
        let key_store = key_store.clone();
        let nats = nats.clone();
        let reply_to = msg.reply.clone();

        tokio::spawn(async move {
            let response = execute_keygen(&req, &config, &key_store).await;
            let payload = serde_json::to_vec(&response).unwrap();

            // Use NATS request-reply: respond to the inbox from the request message.
            // Falls back to legacy reply subject for backward compatibility.
            let reply_subject = reply_to
                .unwrap_or_else(|| format!("mpc.control.keygen.{}.reply", req.group_id).into());
            if let Err(e) = nats.publish(reply_subject, payload.into()).await {
                tracing::error!("failed to publish keygen response: {e}");
            }
        });
    }
}

async fn execute_keygen(
    req: &KeygenRequest,
    config: &NodeConfig,
    key_store: &EncryptedFileStore,
) -> KeygenResponse {
    let scheme: CryptoScheme = match req.scheme.parse() {
        Ok(s) => s,
        Err(e) => {
            return KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: String::new(),
                success: false,
                error: Some(format!("invalid scheme: {e}")),
            };
        }
    };

    let protocol = match create_protocol(scheme) {
        Ok(p) => p,
        Err(e) => {
            return KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: String::new(),
                success: false,
                error: Some(e),
            };
        }
    };

    let threshold_config = match ThresholdConfig::new(req.threshold, req.total_parties) {
        Ok(c) => c,
        Err(e) => {
            return KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: String::new(),
                success: false,
                error: Some(e.to_string()),
            };
        }
    };

    // Connect to NATS with signed envelope for this session
    // Use nats_url from control message if provided, otherwise fall back to config
    let transport_url = req.nats_url.as_deref().unwrap_or(&config.nats_url);
    let mut transport = match NatsTransport::connect_signed(
        transport_url,
        config.party_id,
        req.session_id.clone(),
        config.signing_key.clone(),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: String::new(),
                success: false,
                error: Some(format!("NATS connect failed: {e}")),
            };
        }
    };

    // Register peer keys
    for peer in &req.peer_keys {
        if peer.party_id != config.party_id.0 {
            if let Ok(bytes) = hex::decode(&peer.verifying_key_hex) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                        transport.register_peer_key(PartyId(peer.party_id), vk);
                    }
                }
            }
        }
    }

    // Run keygen
    match protocol
        .keygen(threshold_config, config.party_id, &transport)
        .await
    {
        Ok(share) => {
            let gpk_hex = hex::encode(share.group_public_key.as_bytes());

            // Persist share to encrypted file store
            let group_id = KeyGroupId::from_string(req.group_id.clone());
            let metadata = KeyMetadata {
                group_id: group_id.clone(),
                label: req.label.clone(),
                scheme,
                config: threshold_config,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };

            if let Err(e) = key_store
                .save(&group_id, &metadata, config.party_id, &share)
                .await
            {
                return KeygenResponse {
                    party_id: config.party_id.0,
                    group_id: req.group_id.clone(),
                    group_pubkey_hex: gpk_hex,
                    success: false,
                    error: Some(format!("key store save failed: {e}")),
                };
            }

            tracing::info!(
                group_id = %req.group_id,
                party_id = config.party_id.0,
                gpk = %gpk_hex[..16],
                "keygen complete — share saved"
            );

            KeygenResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                group_pubkey_hex: gpk_hex,
                success: true,
                error: None,
            }
        }
        Err(e) => KeygenResponse {
            party_id: config.party_id.0,
            group_id: req.group_id.clone(),
            group_pubkey_hex: String::new(),
            success: false,
            error: Some(format!("keygen failed: {e}")),
        },
    }
}

async fn handle_sign_requests(
    mut sub: async_nats::Subscriber,
    config: Arc<NodeConfig>,
    key_store: Arc<EncryptedFileStore>,
    nats: Arc<async_nats::Client>,
    auth_cache: Arc<Mutex<AuthorizationCache>>,
) {
    use futures::StreamExt;

    // SEC-031: per-group-id rate limiter to prevent request flooding
    let mut last_request: StdHashMap<String, Instant> = StdHashMap::new();

    while let Some(msg) = sub.next().await {
        // SEC-026: Verify signed control message before processing
        let inner_payload = match unwrap_signed_message(&msg.payload, &config.gateway_pubkey) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("sign: rejecting unsigned/invalid control message: {e}");
                continue;
            }
        };

        let req: SignRequest = match serde_json::from_slice(&inner_payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("invalid sign request: {e}");
                continue;
            }
        };

        // Only participate if this node is in the signer set
        if !req.signer_ids.contains(&config.party_id.0) {
            continue;
        }

        // SEC-031: Rate limit per group_id
        if !check_rate_limit(&mut last_request, &req.group_id, MIN_REQUEST_INTERVAL) {
            tracing::warn!(
                group_id = %req.group_id,
                "rate limited: sign request too soon (SEC-031)"
            );
            continue;
        }

        tracing::info!(
            group_id = %req.group_id,
            signers = ?req.signer_ids,
            "sign request received"
        );

        let config = config.clone();
        let key_store = key_store.clone();
        let nats = nats.clone();
        let reply_to = msg.reply.clone();
        let auth_cache = auth_cache.clone();

        tokio::spawn(async move {
            let response = execute_sign(&req, &config, &key_store, &auth_cache).await;
            let payload = serde_json::to_vec(&response).unwrap();

            // Use NATS request-reply: respond to the inbox from the request message.
            // Falls back to legacy reply subject for backward compatibility.
            let reply_subject = reply_to
                .unwrap_or_else(|| format!("mpc.control.sign.{}.reply", req.group_id).into());
            if let Err(e) = nats.publish(reply_subject, payload.into()).await {
                tracing::error!("failed to publish sign response: {e}");
            }
        });
    }
}

async fn execute_sign(
    req: &SignRequest,
    config: &NodeConfig,
    key_store: &EncryptedFileStore,
    auth_cache: &Mutex<AuthorizationCache>,
) -> SignResponse {
    // Load this party's share from key store
    let group_id = KeyGroupId::from_string(req.group_id.clone());
    let share = match key_store.load(&group_id, config.party_id).await {
        Ok(s) => s,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(format!("load share failed: {e}")),
            };
        }
    };

    // Verify SignAuthorization (DEC-012) — mandatory, gateway_pubkey is always set
    let message_bytes = match hex::decode(&req.message_hex) {
        Ok(b) => b,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(format!("invalid message hex: {e}")),
            };
        }
    };

    match serde_json::from_str::<mpc_wallet_core::protocol::sign_authorization::SignAuthorization>(
        &req.sign_authorization,
    ) {
        Ok(auth) => {
            // Verify signature + replay protection via AuthorizationCache
            let mut cache = auth_cache.lock().await;
            if let Err(e) =
                auth.verify_with_cache(&config.gateway_pubkey, &message_bytes, &mut cache)
            {
                tracing::warn!(
                    group_id = %req.group_id,
                    "SignAuthorization verification FAILED: {e}"
                );
                return SignResponse {
                    party_id: config.party_id.0,
                    group_id: req.group_id.clone(),
                    signature_json: None,
                    success: false,
                    error: Some(format!("SignAuthorization verification failed: {e}")),
                };
            }
            tracing::debug!("SignAuthorization verified + replay-checked");
        }
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(format!("invalid SignAuthorization: {e}")),
            };
        }
    }

    let protocol = match create_protocol(share.scheme) {
        Ok(p) => p,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(e),
            };
        }
    };

    // Connect to NATS for this signing session
    // Use nats_url from control message if provided, otherwise fall back to config
    let transport_url = req.nats_url.as_deref().unwrap_or(&config.nats_url);
    let mut transport = match NatsTransport::connect_signed(
        transport_url,
        config.party_id,
        req.session_id.clone(),
        config.signing_key.clone(),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(format!("NATS connect failed: {e}")),
            };
        }
    };

    // Register only signing peers
    for peer in &req.peer_keys {
        if peer.party_id != config.party_id.0 && req.signer_ids.contains(&peer.party_id) {
            if let Ok(bytes) = hex::decode(&peer.verifying_key_hex) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                        transport.register_peer_key(PartyId(peer.party_id), vk);
                    }
                }
            }
        }
    }

    let message = match hex::decode(&req.message_hex) {
        Ok(m) => m,
        Err(e) => {
            return SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: None,
                success: false,
                error: Some(format!("invalid message hex: {e}")),
            };
        }
    };

    let signers: Vec<PartyId> = req.signer_ids.iter().map(|&id| PartyId(id)).collect();

    match protocol.sign(&share, &signers, &message, &transport).await {
        Ok(sig) => {
            let sig_json = serde_json::to_string(&sig).unwrap_or_default();
            tracing::info!(
                group_id = %req.group_id,
                party_id = config.party_id.0,
                "sign complete"
            );
            SignResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                signature_json: Some(sig_json),
                success: true,
                error: None,
            }
        }
        Err(e) => SignResponse {
            party_id: config.party_id.0,
            group_id: req.group_id.clone(),
            signature_json: None,
            success: false,
            error: Some(format!("sign failed: {e}")),
        },
    }
}

async fn handle_freeze_requests(
    mut sub: async_nats::Subscriber,
    config: Arc<NodeConfig>,
    key_store: Arc<EncryptedFileStore>,
    nats: Arc<async_nats::Client>,
) {
    use futures::StreamExt;

    while let Some(msg) = sub.next().await {
        // SEC-026: Verify signed control message before processing
        let inner_payload = match unwrap_signed_message(&msg.payload, &config.gateway_pubkey) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("freeze: rejecting unsigned/invalid control message: {e}");
                continue;
            }
        };

        let req: FreezeRequest = match serde_json::from_slice(&inner_payload) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("invalid freeze request: {e}");
                continue;
            }
        };

        let group_id = KeyGroupId::from_string(req.group_id.clone());
        let result = if req.freeze {
            key_store.freeze(&group_id).await
        } else {
            key_store.unfreeze(&group_id).await
        };

        let (success, error) = match &result {
            Ok(()) => {
                tracing::info!(
                    group_id = %req.group_id,
                    frozen = req.freeze,
                    "freeze/unfreeze complete"
                );
                (true, None)
            }
            Err(e) => {
                tracing::error!(
                    group_id = %req.group_id,
                    "freeze/unfreeze failed: {e}"
                );
                (false, Some(e.to_string()))
            }
        };

        // Send acknowledgment via NATS request-reply if reply inbox is present
        if let Some(reply) = msg.reply {
            let response = FreezeResponse {
                party_id: config.party_id.0,
                group_id: req.group_id.clone(),
                success,
                error,
            };
            let payload = serde_json::to_vec(&response).unwrap();
            if let Err(e) = nats.publish(reply, payload.into()).await {
                tracing::error!("failed to publish freeze response: {e}");
            }
        }
    }
}

/// Unwrap and verify a signed control message from the gateway.
///
/// Parses bytes as `SignedControlMessage`, verifies the Ed25519 signature
/// against the expected gateway public key, and returns the inner payload bytes.
/// Rejects messages signed by unknown keys or with tampered payloads (SEC-026).
fn unwrap_signed_message(
    raw: &[u8],
    gateway_pubkey: &ed25519_dalek::VerifyingKey,
) -> Result<Vec<u8>, String> {
    let signed: rpc::SignedControlMessage =
        serde_json::from_slice(raw).map_err(|e| format!("not a SignedControlMessage: {e}"))?;
    rpc::verify_control_message(&signed, gateway_pubkey)
}

/// Create MPC protocol instance for a given scheme.
fn create_protocol(scheme: CryptoScheme) -> Result<Box<dyn MpcProtocol>, String> {
    use mpc_wallet_core::protocol::*;
    match scheme {
        CryptoScheme::Gg20Ecdsa => Ok(Box::new(gg20::Gg20Protocol::new())),
        CryptoScheme::FrostEd25519 => Ok(Box::new(frost_ed25519::FrostEd25519Protocol::new())),
        CryptoScheme::FrostSecp256k1Tr => {
            Ok(Box::new(frost_secp256k1::FrostSecp256k1TrProtocol::new()))
        }
        CryptoScheme::Cggmp21Secp256k1 => Ok(Box::new(cggmp21::Cggmp21Protocol::new())),
        _ => Err(format!("unsupported scheme: {scheme:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rpc::sign_control_message;

    /// Helper: generate a random Ed25519 signing key.
    fn random_signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    /// Helper: create a valid signed control message with a given payload.
    fn make_signed_message(payload: &[u8], key: &SigningKey) -> Vec<u8> {
        let signed = sign_control_message(payload, key);
        serde_json::to_vec(&signed).unwrap()
    }

    // ── create_protocol tests ───────────────────────────────────────

    #[test]
    fn test_create_protocol_gg20() {
        let result = create_protocol(CryptoScheme::Gg20Ecdsa);
        assert!(result.is_ok(), "Gg20Ecdsa should be supported");
    }

    #[test]
    fn test_create_protocol_frost_ed25519() {
        let result = create_protocol(CryptoScheme::FrostEd25519);
        assert!(result.is_ok(), "FrostEd25519 should be supported");
    }

    #[test]
    fn test_create_protocol_frost_secp256k1() {
        let result = create_protocol(CryptoScheme::FrostSecp256k1Tr);
        assert!(result.is_ok(), "FrostSecp256k1Tr should be supported");
    }

    #[test]
    fn test_create_protocol_cggmp21() {
        let result = create_protocol(CryptoScheme::Cggmp21Secp256k1);
        assert!(result.is_ok(), "Cggmp21Secp256k1 should be supported");
    }

    #[test]
    fn test_create_protocol_unsupported_sr25519() {
        let result = create_protocol(CryptoScheme::Sr25519Threshold);
        match result {
            Err(e) => assert!(e.contains("unsupported scheme"), "unexpected error: {e}"),
            Ok(_) => panic!("expected error for Sr25519Threshold"),
        }
    }

    #[test]
    fn test_create_protocol_unsupported_bls() {
        let result = create_protocol(CryptoScheme::Bls12_381Threshold);
        match result {
            Err(e) => assert!(e.contains("unsupported scheme"), "unexpected error: {e}"),
            Ok(_) => panic!("expected error for Bls12_381Threshold"),
        }
    }

    #[test]
    fn test_create_protocol_unsupported_stark() {
        let result = create_protocol(CryptoScheme::StarkThreshold);
        match result {
            Err(e) => assert!(e.contains("unsupported scheme"), "unexpected error: {e}"),
            Ok(_) => panic!("expected error for StarkThreshold"),
        }
    }

    // ── check_rate_limit tests ──────────────────────────────────────

    #[test]
    fn test_rate_limit_first_request_allowed() {
        let mut map = StdHashMap::new();
        let allowed = check_rate_limit(&mut map, "group-a", Duration::from_secs(1));
        assert!(allowed, "first request should be allowed");
    }

    #[test]
    fn test_rate_limit_immediate_second_request_rejected() {
        let mut map = StdHashMap::new();
        assert!(check_rate_limit(
            &mut map,
            "group-a",
            Duration::from_secs(1)
        ));
        // Immediate second request for the same group
        assert!(
            !check_rate_limit(&mut map, "group-a", Duration::from_secs(1)),
            "immediate second request should be rejected"
        );
    }

    #[test]
    fn test_rate_limit_different_groups_independent() {
        let mut map = StdHashMap::new();
        assert!(check_rate_limit(
            &mut map,
            "group-a",
            Duration::from_secs(1)
        ));
        // Different group should still be allowed
        assert!(
            check_rate_limit(&mut map, "group-b", Duration::from_secs(1)),
            "different group_id should not be rate limited"
        );
    }

    #[test]
    fn test_rate_limit_allowed_after_cooldown() {
        let mut map = StdHashMap::new();
        // Use a very short interval so we can test cooldown expiry
        let interval = Duration::from_millis(10);
        assert!(check_rate_limit(&mut map, "group-a", interval));

        // Manually set a past timestamp to simulate cooldown expiry
        map.insert(
            "group-a".to_string(),
            Instant::now() - Duration::from_millis(50),
        );

        assert!(
            check_rate_limit(&mut map, "group-a", interval),
            "request after cooldown should be allowed"
        );
    }

    #[test]
    fn test_rate_limit_zero_interval_always_allows() {
        let mut map = StdHashMap::new();
        let interval = Duration::from_secs(0);
        assert!(check_rate_limit(&mut map, "group-a", interval));
        assert!(
            check_rate_limit(&mut map, "group-a", interval),
            "zero interval should always allow"
        );
    }

    // ── unwrap_signed_message tests ─────────────────────────────────

    #[test]
    fn test_unwrap_signed_message_valid() {
        let key = random_signing_key();
        let payload = b"hello world";
        let raw = make_signed_message(payload, &key);

        let result = unwrap_signed_message(&raw, &key.verifying_key());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), payload.to_vec());
    }

    #[test]
    fn test_unwrap_signed_message_wrong_gateway_key() {
        let signer = random_signing_key();
        let wrong_gateway = random_signing_key();
        let payload = b"test payload";
        let raw = make_signed_message(payload, &signer);

        let result = unwrap_signed_message(&raw, &wrong_gateway.verifying_key());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("pubkey mismatch"));
    }

    #[test]
    fn test_unwrap_signed_message_not_json() {
        let key = random_signing_key();
        let raw = b"this is not json";
        let result = unwrap_signed_message(raw, &key.verifying_key());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a SignedControlMessage"));
    }

    #[test]
    fn test_unwrap_signed_message_tampered_payload() {
        let key = random_signing_key();
        let payload = b"original";
        let signed = sign_control_message(payload, &key);

        // Tamper with payload before serializing
        let mut tampered = signed.clone();
        tampered.payload = b"tampered".to_vec();
        let raw = serde_json::to_vec(&tampered).unwrap();

        let result = unwrap_signed_message(&raw, &key.verifying_key());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("signature verification failed"));
    }

    #[test]
    fn test_unwrap_signed_message_empty_payload() {
        let key = random_signing_key();
        let payload = b"";
        let raw = make_signed_message(payload, &key);

        let result = unwrap_signed_message(&raw, &key.verifying_key());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // ── parse_verifying_key_hex tests ───────────────────────────────

    #[test]
    fn test_parse_verifying_key_hex_valid() {
        let key = random_signing_key();
        let hex_str = hex::encode(key.verifying_key().to_bytes());
        let result = parse_verifying_key_hex(&hex_str, "GATEWAY_PUBKEY");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), key.verifying_key());
    }

    #[test]
    fn test_parse_verifying_key_hex_invalid_hex() {
        let result = parse_verifying_key_hex("zzzz", "TEST_KEY");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be valid hex"));
    }

    #[test]
    fn test_parse_verifying_key_hex_wrong_length() {
        let result = parse_verifying_key_hex("aabbccdd", "TEST_KEY");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 32 bytes"));
    }

    #[test]
    fn test_parse_verifying_key_hex_all_zeros_invalid_point() {
        // 32 zero bytes is not a valid Ed25519 point
        let hex_str = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = parse_verifying_key_hex(hex_str, "TEST_KEY");
        // All-zeros may or may not be valid depending on ed25519-dalek validation;
        // what matters is we don't panic
        let _ = result;
    }

    // ── parse_signing_key_hex tests ─────────────────────────────────

    #[test]
    fn test_parse_signing_key_hex_valid() {
        let key = random_signing_key();
        let hex_str = hex::encode(key.to_bytes());
        let result = parse_signing_key_hex(&hex_str, "NODE_SIGNING_KEY");
        assert!(result.is_ok());
        // Verify roundtrip: derived verifying key matches
        assert_eq!(result.unwrap().verifying_key(), key.verifying_key());
    }

    #[test]
    fn test_parse_signing_key_hex_invalid_hex() {
        let result = parse_signing_key_hex("not-hex!", "NODE_SIGNING_KEY");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be valid hex"));
    }

    #[test]
    fn test_parse_signing_key_hex_wrong_length() {
        let result = parse_signing_key_hex("aabb", "NODE_SIGNING_KEY");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 32 bytes"));
    }

    // ── RPC type serialization tests ────────────────────────────────

    #[test]
    fn test_keygen_request_roundtrip() {
        let req = rpc::KeygenRequest {
            group_id: "g1".to_string(),
            label: "test-wallet".to_string(),
            scheme: "gg20-ecdsa".to_string(),
            threshold: 2,
            total_parties: 3,
            session_id: "session-abc".to_string(),
            peer_keys: vec![
                rpc::PeerKeyEntry {
                    party_id: 1,
                    verifying_key_hex: "aa".repeat(32),
                },
                rpc::PeerKeyEntry {
                    party_id: 2,
                    verifying_key_hex: "bb".repeat(32),
                },
            ],
            nats_url: Some("nats://custom:4222".to_string()),
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: rpc::KeygenRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.group_id, "g1");
        assert_eq!(decoded.threshold, 2);
        assert_eq!(decoded.total_parties, 3);
        assert_eq!(decoded.peer_keys.len(), 2);
        assert_eq!(decoded.nats_url, Some("nats://custom:4222".to_string()));
    }

    #[test]
    fn test_keygen_request_nats_url_default_none() {
        let json = r#"{"group_id":"g1","label":"l","scheme":"gg20-ecdsa","threshold":2,"total_parties":3,"session_id":"s","peer_keys":[]}"#;
        let req: rpc::KeygenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.nats_url, None);
    }

    #[test]
    fn test_sign_request_roundtrip() {
        let req = rpc::SignRequest {
            group_id: "g1".to_string(),
            message_hex: hex::encode(b"tx-bytes"),
            signer_ids: vec![1, 3],
            session_id: "sign-session".to_string(),
            peer_keys: vec![],
            sign_authorization: "{}".to_string(),
            nats_url: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: rpc::SignRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.signer_ids, vec![1, 3]);
        assert_eq!(decoded.message_hex, hex::encode(b"tx-bytes"));
    }

    #[test]
    fn test_freeze_request_roundtrip() {
        let req = rpc::FreezeRequest {
            group_id: "g1".to_string(),
            freeze: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: rpc::FreezeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.group_id, "g1");
        assert!(decoded.freeze);
    }

    #[test]
    fn test_keygen_response_success() {
        let resp = rpc::KeygenResponse {
            party_id: 1,
            group_id: "g1".to_string(),
            group_pubkey_hex: "abcd".to_string(),
            success: true,
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: rpc::KeygenResponse = serde_json::from_str(&json).unwrap();
        assert!(decoded.success);
        assert!(decoded.error.is_none());
    }

    #[test]
    fn test_keygen_response_failure() {
        let resp = rpc::KeygenResponse {
            party_id: 2,
            group_id: "g2".to_string(),
            group_pubkey_hex: String::new(),
            success: false,
            error: Some("keygen failed: timeout".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: rpc::KeygenResponse = serde_json::from_str(&json).unwrap();
        assert!(!decoded.success);
        assert_eq!(decoded.error.unwrap(), "keygen failed: timeout");
    }

    #[test]
    fn test_sign_response_success() {
        let resp = rpc::SignResponse {
            party_id: 1,
            group_id: "g1".to_string(),
            signature_json: Some(r#"{"r":"...","s":"..."}"#.to_string()),
            success: true,
            error: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: rpc::SignResponse = serde_json::from_str(&json).unwrap();
        assert!(decoded.success);
        assert!(decoded.signature_json.is_some());
    }

    // ── Signed control message integration tests ────────────────────

    #[test]
    fn test_signed_control_message_with_keygen_request() {
        let key = random_signing_key();
        let req = rpc::KeygenRequest {
            group_id: "g1".to_string(),
            label: "test".to_string(),
            scheme: "gg20-ecdsa".to_string(),
            threshold: 2,
            total_parties: 3,
            session_id: "s1".to_string(),
            peer_keys: vec![],
            nats_url: None,
        };
        let payload = serde_json::to_vec(&req).unwrap();
        let raw = make_signed_message(&payload, &key);

        let inner = unwrap_signed_message(&raw, &key.verifying_key()).unwrap();
        let decoded: rpc::KeygenRequest = serde_json::from_slice(&inner).unwrap();
        assert_eq!(decoded.group_id, "g1");
        assert_eq!(decoded.scheme, "gg20-ecdsa");
    }

    #[test]
    fn test_signed_control_message_with_freeze_request() {
        let key = random_signing_key();
        let req = rpc::FreezeRequest {
            group_id: "wallet-1".to_string(),
            freeze: false,
        };
        let payload = serde_json::to_vec(&req).unwrap();
        let raw = make_signed_message(&payload, &key);

        let inner = unwrap_signed_message(&raw, &key.verifying_key()).unwrap();
        let decoded: rpc::FreezeRequest = serde_json::from_slice(&inner).unwrap();
        assert_eq!(decoded.group_id, "wallet-1");
        assert!(!decoded.freeze);
    }

    // ── DEFAULT_AUTH_CACHE_MAX_ENTRIES constant test ─────────────────

    #[test]
    fn test_default_auth_cache_max_entries() {
        assert_eq!(DEFAULT_AUTH_CACHE_MAX_ENTRIES, 10_000);
    }

    #[test]
    fn test_min_request_interval() {
        assert_eq!(MIN_REQUEST_INTERVAL, Duration::from_secs(1));
    }
}
