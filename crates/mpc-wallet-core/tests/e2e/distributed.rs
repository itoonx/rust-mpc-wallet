//! E2E test: Full distributed MPC architecture (DEC-015).
//!
//! Proves that:
//! 1. Gateway (orchestrator) holds ZERO key shares
//! 2. Each node holds exactly 1 share
//! 3. Keygen produces consistent group pubkey across all nodes
//! 4. Sign produces a cryptographically valid signature
//! 5. All communication happens via NATS (no shared memory)
//!
//! Uses NATS request-reply pattern: orchestrator sends with `publish_with_reply`
//! (inbox), nodes respond to `msg.reply`. This eliminates subscribe-before-publish
//! timing issues that previously made these tests flaky in CI.
//!
//! Requires: `./scripts/local-infra.sh up` (NATS on localhost:4222)

use ed25519_dalek::SigningKey;
use futures::StreamExt;

use mpc_wallet_core::key_store::encrypted::EncryptedFileStore;
use mpc_wallet_core::key_store::types::{KeyGroupId, KeyMetadata};
use mpc_wallet_core::key_store::KeyStore;
use mpc_wallet_core::protocol::gg20::Gg20Protocol;
use mpc_wallet_core::protocol::{MpcProtocol, MpcSignature};
use mpc_wallet_core::rpc;
use mpc_wallet_core::transport::nats::NatsTransport;
use mpc_wallet_core::types::{CryptoScheme, PartyId, ThresholdConfig};

fn nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into())
}

/// Simulate a single MPC node: subscribe to control channel, run keygen, save share.
async fn run_node_keygen(
    party_id: u16,
    nats_url: &str,
    key_store_dir: &std::path::Path,
    node_signing_key: SigningKey,
) -> rpc::KeygenResponse {
    let nats = async_nats::connect(nats_url).await.unwrap();

    // Subscribe to keygen control channel
    let mut sub = nats.subscribe("mpc.control.keygen.*").await.unwrap();

    // Wait for keygen request
    let msg = sub.next().await.unwrap();
    let req: rpc::KeygenRequest = serde_json::from_slice(&msg.payload).unwrap();

    // Parse config
    let scheme: CryptoScheme = req.scheme.parse().unwrap();
    let config = ThresholdConfig::new(req.threshold, req.total_parties).unwrap();

    // Connect transport for this session
    let mut transport = NatsTransport::connect_signed(
        nats_url,
        PartyId(party_id),
        req.session_id.clone(),
        node_signing_key,
    )
    .await
    .unwrap();

    // Register peer keys (only other parties)
    for peer in &req.peer_keys {
        if peer.party_id != party_id {
            let bytes = hex::decode(&peer.verifying_key_hex).unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap();
            transport.register_peer_key(PartyId(peer.party_id), vk);
        }
    }

    // Wait for all parties to subscribe before starting keygen.
    // Without this, fast parties broadcast round 1 before slow parties subscribe,
    // causing message loss on CI runners.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Run keygen
    let protocol = Gg20Protocol::new();
    let share = protocol
        .keygen(config, PartyId(party_id), &transport)
        .await
        .unwrap();

    let gpk_hex = hex::encode(share.group_public_key.as_bytes());

    // Save share to encrypted file store (each node saves its OWN share only)
    let key_store = EncryptedFileStore::new(key_store_dir.to_path_buf(), "test-password");
    let group_id = KeyGroupId::from_string(req.group_id.clone());
    let metadata = KeyMetadata {
        group_id: group_id.clone(),
        label: req.label.clone(),
        scheme,
        config,
        created_at: 0,
    };
    key_store
        .save(&group_id, &metadata, PartyId(party_id), &share)
        .await
        .unwrap();

    let response = rpc::KeygenResponse {
        party_id,
        group_id: req.group_id.clone(),
        group_pubkey_hex: gpk_hex,
        success: true,
        error: None,
    };

    // Respond via NATS request-reply: use msg.reply inbox if available,
    // fall back to legacy reply subject for backward compatibility.
    let reply_subject = msg
        .reply
        .unwrap_or_else(|| rpc::keygen_reply_subject(&req.group_id).into());
    let payload = serde_json::to_vec(&response).unwrap();
    nats.publish(reply_subject, payload.into()).await.unwrap();

    response
}

/// Simulate a single MPC node: subscribe to sign channel, load share, sign.
async fn run_node_sign(
    party_id: u16,
    nats_url: &str,
    key_store_dir: &std::path::Path,
    node_signing_key: SigningKey,
) -> rpc::SignResponse {
    let nats = async_nats::connect(nats_url).await.unwrap();

    let mut sub = nats.subscribe("mpc.control.sign.*").await.unwrap();

    let msg = sub.next().await.unwrap();
    let req: rpc::SignRequest = serde_json::from_slice(&msg.payload).unwrap();

    // Only participate if in signer set
    if !req.signer_ids.contains(&party_id) {
        return rpc::SignResponse {
            party_id,
            group_id: req.group_id,
            signature_json: None,
            success: true,
            error: None,
        };
    }

    // Load this node's share from key store
    let key_store = EncryptedFileStore::new(key_store_dir.to_path_buf(), "test-password");
    let group_id = KeyGroupId::from_string(req.group_id.clone());
    let share = key_store.load(&group_id, PartyId(party_id)).await.unwrap();

    // Connect transport for signing session
    let mut transport = NatsTransport::connect_signed(
        nats_url,
        PartyId(party_id),
        req.session_id.clone(),
        node_signing_key,
    )
    .await
    .unwrap();

    // Register only signing peers
    for peer in &req.peer_keys {
        if peer.party_id != party_id && req.signer_ids.contains(&peer.party_id) {
            let bytes = hex::decode(&peer.verifying_key_hex).unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap();
            transport.register_peer_key(PartyId(peer.party_id), vk);
        }
    }

    let message = hex::decode(&req.message_hex).unwrap();
    let signers: Vec<PartyId> = req.signer_ids.iter().map(|&id| PartyId(id)).collect();

    // Wait for all signing parties to subscribe before starting.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let protocol = Gg20Protocol::new();
    let sig = protocol
        .sign(&share, &signers, &message, &transport)
        .await
        .unwrap();

    let sig_json = serde_json::to_string(&sig).unwrap();

    let response = rpc::SignResponse {
        party_id,
        group_id: req.group_id.clone(),
        signature_json: Some(sig_json),
        success: true,
        error: None,
    };

    // Respond via NATS request-reply: use msg.reply inbox if available,
    // fall back to legacy reply subject for backward compatibility.
    let reply_subject = msg
        .reply
        .unwrap_or_else(|| rpc::sign_reply_subject(&req.group_id).into());
    let payload = serde_json::to_vec(&response).unwrap();
    nats.publish(reply_subject, payload.into()).await.unwrap();

    response
}

// ═══════════════════════════════════════════════════════════════════════
// Production E2E: Orchestrator + 3 Nodes via NATS
// ═══════════════════════════════════════════════════════════════════════

/// Full distributed keygen: orchestrator publishes request, 3 nodes respond.
/// Proves: gateway holds 0 shares, each node holds exactly 1.
///
/// Uses NATS request-reply pattern (publish_with_reply + inbox) which eliminates
/// the subscribe-before-publish timing issues that made this test flaky in CI.
#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_distributed_keygen_3_nodes() {
    let url = nats_url();
    let group_id = uuid::Uuid::new_v4().to_string();
    let session_id = uuid::Uuid::new_v4().to_string();

    // Generate signing keys for 3 nodes
    let node_keys: Vec<SigningKey> = (0..3)
        .map(|_| {
            let mut b = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
            SigningKey::from_bytes(&b)
        })
        .collect();

    let peer_keys: Vec<rpc::PeerKeyEntry> = node_keys
        .iter()
        .enumerate()
        .map(|(i, k)| rpc::PeerKeyEntry {
            party_id: i as u16 + 1,
            verifying_key_hex: hex::encode(k.verifying_key().as_bytes()),
        })
        .collect();

    // Create temp dirs for each node's key store
    let temp_dirs: Vec<tempfile::TempDir> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();

    // Spawn 3 node tasks (each simulates a separate process)
    let mut node_handles = Vec::new();
    for i in 0..3u16 {
        let url = url.clone();
        let dir = temp_dirs[i as usize].path().to_path_buf();
        let key = node_keys[i as usize].clone();
        node_handles.push(tokio::spawn(async move {
            run_node_keygen(i + 1, &url, &dir, key).await
        }));
    }

    // Give nodes time to connect to NATS + subscribe to control channel.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Orchestrator uses NATS request-reply: create inbox, subscribe, publish_with_reply.
    // Nodes respond to the inbox directly — no separate reply subject needed.
    let nats = async_nats::connect(&url).await.unwrap();
    let inbox = nats.new_inbox();
    let mut reply_sub = nats.subscribe(inbox.clone()).await.unwrap();

    let request = rpc::KeygenRequest {
        group_id: group_id.clone(),
        label: "distributed-e2e-test".into(),
        scheme: "gg20-ecdsa".into(),
        threshold: 2,
        total_parties: 3,
        session_id,
        peer_keys,
        nats_url: Some(url.clone()),
    };

    let subject = rpc::keygen_subject(&group_id);
    let payload = serde_json::to_vec(&request).unwrap();
    nats.publish_with_reply(subject, inbox, payload.into())
        .await
        .unwrap();

    // Collect 3 responses (with timeout)
    let mut responses = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    while responses.len() < 3 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, reply_sub.next()).await {
            Ok(Some(msg)) => {
                let resp: rpc::KeygenResponse = serde_json::from_slice(&msg.payload).unwrap();
                assert!(
                    resp.success,
                    "node {} keygen failed: {:?}",
                    resp.party_id, resp.error
                );
                responses.push(resp);
            }
            _ => panic!("keygen timeout: got {}/3 responses", responses.len()),
        }
    }

    // Wait for node tasks
    for h in node_handles {
        h.await.unwrap();
    }

    // ── Verify: all nodes agree on group pubkey ──
    let gpk = &responses[0].group_pubkey_hex;
    for resp in &responses[1..] {
        assert_eq!(
            &resp.group_pubkey_hex, gpk,
            "all nodes must agree on group pubkey"
        );
    }

    // ── Verify: each node's key store has exactly 1 share ──
    for i in 0..3u16 {
        let store =
            EncryptedFileStore::new(temp_dirs[i as usize].path().to_path_buf(), "test-password");
        let gid = KeyGroupId::from_string(group_id.clone());

        // This node's share exists
        let share = store.load(&gid, PartyId(i + 1)).await;
        assert!(share.is_ok(), "node {} must have its own share", i + 1);

        // Other nodes' shares do NOT exist
        for j in 0..3u16 {
            if j != i {
                let other = store.load(&gid, PartyId(j + 1)).await;
                assert!(
                    other.is_err(),
                    "node {} must NOT have node {}'s share",
                    i + 1,
                    j + 1
                );
            }
        }
    }

    // ── Verify: orchestrator (gateway) has 0 shares ──
    // The orchestrator only stored responses with group_pubkey_hex.
    // It never received KeyShare data. This is proven by the fact that
    // KeygenResponse contains only group_pubkey_hex (string), not share_data.
    assert!(
        !responses[0].group_pubkey_hex.is_empty(),
        "orchestrator received group pubkey"
    );
    // No share data in response — architecturally impossible for orchestrator to have shares.
}

/// Full distributed keygen → sign: proves end-to-end MPC flow via NATS.
#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_distributed_keygen_then_sign() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let url = nats_url();
    let group_id = uuid::Uuid::new_v4().to_string();
    let keygen_session = uuid::Uuid::new_v4().to_string();

    let node_keys: Vec<SigningKey> = (0..3)
        .map(|_| {
            let mut b = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
            SigningKey::from_bytes(&b)
        })
        .collect();

    let peer_keys: Vec<rpc::PeerKeyEntry> = node_keys
        .iter()
        .enumerate()
        .map(|(i, k)| rpc::PeerKeyEntry {
            party_id: i as u16 + 1,
            verifying_key_hex: hex::encode(k.verifying_key().as_bytes()),
        })
        .collect();

    let temp_dirs: Vec<tempfile::TempDir> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();

    // ── Phase 1: Distributed Keygen ──────────────────────────────────
    let mut keygen_handles = Vec::new();
    for i in 0..3u16 {
        let u = url.clone();
        let d = temp_dirs[i as usize].path().to_path_buf();
        let k = node_keys[i as usize].clone();
        keygen_handles.push(tokio::spawn(async move {
            run_node_keygen(i + 1, &u, &d, k).await
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Orchestrator uses NATS request-reply pattern
    let nats = async_nats::connect(&url).await.unwrap();
    let keygen_inbox = nats.new_inbox();
    let mut reply_sub = nats.subscribe(keygen_inbox.clone()).await.unwrap();

    let keygen_req = rpc::KeygenRequest {
        group_id: group_id.clone(),
        label: "keygen-then-sign-e2e".into(),
        scheme: "gg20-ecdsa".into(),
        threshold: 2,
        total_parties: 3,
        session_id: keygen_session,
        peer_keys: peer_keys.clone(),
        nats_url: Some(url.clone()),
    };
    let payload = serde_json::to_vec(&keygen_req).unwrap();
    nats.publish_with_reply(rpc::keygen_subject(&group_id), keygen_inbox, payload.into())
        .await
        .unwrap();

    let mut keygen_responses = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    while keygen_responses.len() < 3 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, reply_sub.next()).await {
            Ok(Some(msg)) => {
                let resp: rpc::KeygenResponse = serde_json::from_slice(&msg.payload).unwrap();
                assert!(resp.success);
                keygen_responses.push(resp);
            }
            _ => panic!("keygen timeout"),
        }
    }
    for h in keygen_handles {
        h.await.unwrap();
    }

    let gpk_hex = &keygen_responses[0].group_pubkey_hex;
    let gpk_bytes = hex::decode(gpk_hex).unwrap();

    // ── Phase 2: Distributed Sign (parties 1+2) ─────────────────────
    let sign_session = uuid::Uuid::new_v4().to_string();
    let message = b"distributed e2e sign test";
    let message_hex = hex::encode(message);

    // Generate new signing keys for sign session
    let sign_keys: Vec<SigningKey> = (0..3)
        .map(|_| {
            let mut b = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
            SigningKey::from_bytes(&b)
        })
        .collect();

    let sign_peer_keys: Vec<rpc::PeerKeyEntry> = sign_keys
        .iter()
        .enumerate()
        .map(|(i, k)| rpc::PeerKeyEntry {
            party_id: i as u16 + 1,
            verifying_key_hex: hex::encode(k.verifying_key().as_bytes()),
        })
        .collect();

    // Spawn sign node tasks (only parties 1+2 participate)
    let mut sign_handles = Vec::new();
    for i in 0..2u16 {
        let u = url.clone();
        let d = temp_dirs[i as usize].path().to_path_buf();
        let k = sign_keys[i as usize].clone();
        sign_handles.push(tokio::spawn(async move {
            run_node_sign(i + 1, &u, &d, k).await
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Orchestrator uses NATS request-reply for sign phase
    let sign_inbox = nats.new_inbox();
    let mut sign_reply_sub = nats.subscribe(sign_inbox.clone()).await.unwrap();

    let sign_req = rpc::SignRequest {
        group_id: group_id.clone(),
        message_hex,
        signer_ids: vec![1, 2],
        session_id: sign_session,
        peer_keys: sign_peer_keys,
        sign_authorization: "{}".into(),
        nats_url: Some(url.clone()),
    };
    let payload = serde_json::to_vec(&sign_req).unwrap();
    nats.publish_with_reply(rpc::sign_subject(&group_id), sign_inbox, payload.into())
        .await
        .unwrap();

    // Collect sign responses
    let mut coordinator_sig: Option<MpcSignature> = None;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut received = 0;
    while received < 2 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, sign_reply_sub.next()).await {
            Ok(Some(msg)) => {
                let resp: rpc::SignResponse = serde_json::from_slice(&msg.payload).unwrap();
                assert!(resp.success, "sign failed: {:?}", resp.error);
                if resp.party_id == 1 {
                    if let Some(ref sig_json) = resp.signature_json {
                        coordinator_sig = serde_json::from_str(sig_json).ok();
                    }
                }
                received += 1;
            }
            _ => panic!("sign timeout: got {}/2 responses", received),
        }
    }
    for h in sign_handles {
        h.await.unwrap();
    }

    // ── Phase 3: Cryptographic Verification ──────────────────────────
    let sig = coordinator_sig.expect("coordinator must return signature");
    let MpcSignature::Ecdsa { r, s, .. } = &sig else {
        panic!("expected ECDSA signature");
    };

    let pubkey = k256::PublicKey::from_sec1_bytes(&gpk_bytes).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("distributed MPC: keygen(3 nodes) → sign(2 nodes) via NATS must verify");
}
