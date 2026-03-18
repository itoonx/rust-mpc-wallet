//! E2E tests: NATS transport — connectivity, message round-trip, and MPC protocols.
//!
//! Requires: `./scripts/local-infra.sh up` (NATS on localhost:4222)

use super::*;
use mpc_wallet_core::protocol::gg20::Gg20Protocol;
use mpc_wallet_core::protocol::{MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::nats::NatsTransport;
use mpc_wallet_core::transport::{ProtocolMessage, Transport};

fn gg20_factory() -> Box<dyn MpcProtocol> {
    Box::new(Gg20Protocol::new())
}

// ═══════════════════════════════════════════════════════════════════════
// NATS connectivity
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_nats_connect_succeeds() {
    let url = nats_url();
    let key = gen_signing_key();
    let session_id = unique_session_id();

    let transport = NatsTransport::connect_signed(&url, PartyId(1), session_id, key).await;
    assert!(transport.is_ok(), "NATS connect must succeed");
}

#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_nats_connect_wrong_url_fails() {
    let key = gen_signing_key();
    let session_id = unique_session_id();

    let result =
        NatsTransport::connect_signed("nats://127.0.0.1:19999", PartyId(1), session_id, key).await;
    assert!(result.is_err(), "NATS connect to bad URL must fail");
}

// ═══════════════════════════════════════════════════════════════════════
// Single message round-trip (send → recv with SignedEnvelope)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_nats_signed_message_round_trip() {
    let url = nats_url();
    let session_id = unique_session_id();
    let party_keys = PartyKeys::generate(2);

    let sender = party_keys.connect(0, &session_id, &url).await;
    let receiver = party_keys.connect(1, &session_id, &url).await;

    let recv_handle = tokio::spawn(async move { receiver.recv().await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let msg = ProtocolMessage {
        from: PartyId(1),
        to: Some(PartyId(2)),
        round: 1,
        payload: b"hello from party 1".to_vec(),
    };
    sender.send(msg).await.unwrap();

    let received = recv_handle.await.unwrap().unwrap();
    assert_eq!(received.from, PartyId(1));
    assert_eq!(received.round, 1);
    assert_eq!(received.payload, b"hello from party 1");
}

#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_nats_session_isolation() {
    let url = nats_url();
    let party_keys = PartyKeys::generate(2);

    let session_a = unique_session_id();
    let session_b = unique_session_id();

    let sender_a = party_keys.connect(0, &session_a, &url).await;
    let receiver_b = party_keys.connect(1, &session_b, &url).await;

    let recv_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), receiver_b.recv()).await
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    sender_a
        .send(ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: b"session A message".to_vec(),
        })
        .await
        .unwrap();

    let result = recv_handle.await.unwrap();
    assert!(
        result.is_err(),
        "session B must NOT receive session A's message"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// MPC keygen via NATS
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_nats_keygen_gg20_2of3() {
    let url = nats_url();
    let (shares, _party_keys) = nats_keygen(gg20_factory, 2, 3, &url).await;

    assert_eq!(shares.len(), 3);
    let gpk = &shares[0].group_public_key;
    for share in &shares[1..] {
        assert_eq!(
            share.group_public_key.as_bytes(),
            gpk.as_bytes(),
            "all parties must derive same group pubkey via NATS"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// MPC keygen → sign via NATS (full flow with shared PartyKeys)
// ═══════════════════════════════════════════════════════════════════════

/// Direct 2-party sign via NATS (pre-built shares from LocalTransport).
/// Tests the sign protocol over NATS without keygen overhead.
#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_nats_sign_gg20_direct() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use mpc_wallet_core::transport::local::LocalTransportNetwork;

    let url = nats_url();

    // Pre-build shares via LocalTransport (fast, reliable)
    let config = mpc_wallet_core::types::ThresholdConfig::new(2, 3).unwrap();
    let net = LocalTransportNetwork::new(3);
    let mut handles = Vec::new();
    for i in 1..=3 {
        let transport = net.get_transport(PartyId(i));
        let protocol = gg20_factory();
        handles.push(tokio::spawn(async move {
            protocol.keygen(config, PartyId(i), &*transport).await
        }));
    }
    let mut shares = Vec::new();
    for h in handles {
        shares.push(h.await.unwrap().unwrap());
    }

    let gpk = shares[0].group_public_key.as_bytes();
    let message = b"nats direct sign test";

    // Create 2 NATS transports (only signers: Party 1 and 2)
    let sign_session = unique_session_id();
    let key1 = gen_signing_key();
    let key2 = gen_signing_key();
    let vk1 = key1.verifying_key();
    let vk2 = key2.verifying_key();

    // Party 1: register only Party 2 as peer
    let mut t1 = NatsTransport::connect_signed(&url, PartyId(1), sign_session.clone(), key1)
        .await
        .unwrap();
    t1.register_peer_key(PartyId(2), vk2);

    // Party 2: register only Party 1 as peer
    let mut t2 = NatsTransport::connect_signed(&url, PartyId(2), sign_session.clone(), key2)
        .await
        .unwrap();
    t2.register_peer_key(PartyId(1), vk1);

    let share1 = shares[0].clone();
    let share2 = shares[1].clone();
    let signers = vec![PartyId(1), PartyId(2)];
    let s1 = signers.clone();
    let s2 = signers.clone();
    let m1 = message.to_vec();
    let m2 = message.to_vec();

    let h1 = tokio::spawn(async move {
        let protocol = Gg20Protocol::new();
        protocol.sign(&share1, &s1, &m1, &t1).await
    });

    let h2 = tokio::spawn(async move {
        let protocol = Gg20Protocol::new();
        protocol.sign(&share2, &s2, &m2, &t2).await
    });

    let result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let sig1 = h1.await.unwrap()?;
        let _sig2 = h2.await.unwrap()?;
        Ok::<_, mpc_wallet_core::error::CoreError>(sig1)
    })
    .await
    .expect("sign timed out — check NATS broadcast support");

    let sig = result.expect("sign protocol error");

    let MpcSignature::Ecdsa { r, s, .. } = &sig else {
        panic!("expected ECDSA");
    };

    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("GG20 ECDSA signed via NATS must verify");
}

// ═══════════════════════════════════════════════════════════════════════
// Multi-node simulation: keygen (3 nodes) + sign (2 nodes) via NATS
// ═══════════════════════════════════════════════════════════════════════
// TODO: This test hangs when keygen + sign run in sequence within one test.
// Individual keygen and sign tests pass independently.
// Needs investigation: likely NATS connection/subscription lifecycle issue
// when previous tasks' transports are dropped and new ones created.

#[tokio::test]
#[ignore = "requires NATS — hangs in sequence, see TODO above"]
async fn test_multi_node_keygen_sign_isolated() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let url = nats_url();

    // Pre-shared keys (simulates out-of-band key exchange before session)
    let party_keys = PartyKeys::generate(3);

    // ── Phase 1: Keygen ──────────────────────────────────────────────
    // Each "node" connects independently to NATS, runs keygen, returns share via channel.
    let keygen_session = unique_session_id();
    let config = mpc_wallet_core::types::ThresholdConfig::new(2, 3).unwrap();

    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<(usize, mpc_wallet_core::protocol::KeyShare)>(3);

    for i in 0..3usize {
        let pkeys = party_keys.clone();
        let sid = keygen_session.clone();
        let nats = url.clone();
        let sender = tx.clone();

        // Each task is an isolated "node" — no shared state except NATS messages
        tokio::spawn(async move {
            let transport = pkeys.connect(i, &sid, &nats).await;
            let protocol = Gg20Protocol::new();
            let share = protocol
                .keygen(config, PartyId(i as u16 + 1), &transport)
                .await
                .expect("keygen failed");
            sender.send((i, share)).await.unwrap();
        });
    }
    drop(tx); // close sender so rx terminates

    // Collect shares (simulates each node saving to its own disk)
    let mut shares = vec![None; 3];
    while let Some((idx, share)) = rx.recv().await {
        shares[idx] = Some(share);
    }
    let shares: Vec<_> = shares.into_iter().map(|s| s.unwrap()).collect();

    // Verify all nodes agree on group pubkey
    let gpk = shares[0].group_public_key.as_bytes();
    for share in &shares[1..] {
        assert_eq!(share.group_public_key.as_bytes(), gpk);
    }

    // ── Phase 2: Sign ────────────────────────────────────────────────
    // Only nodes 0 and 1 participate (2-of-3 threshold)
    let sign_session = unique_session_id();
    let message = b"multi-node isolated sign test";
    let signers = vec![PartyId(1), PartyId(2)];

    let (sig_tx, mut sig_rx) =
        tokio::sync::mpsc::channel::<(usize, mpc_wallet_core::protocol::MpcSignature)>(2);

    let signer_indices = [0usize, 1];
    for &idx in &signer_indices {
        let share = shares[idx].clone();
        let pkeys = party_keys.clone();
        let sid = sign_session.clone();
        let nats = url.clone();
        let s = signers.clone();
        let m = message.to_vec();
        let sender = sig_tx.clone();
        let peers = signer_indices.to_vec();

        tokio::spawn(async move {
            let transport = pkeys.connect_with_peers(idx, &peers, &sid, &nats).await;
            let protocol = Gg20Protocol::new();
            let sig = protocol
                .sign(&share, &s, &m, &transport)
                .await
                .expect("sign failed");
            sender.send((idx, sig)).await.unwrap();
        });
    }
    drop(sig_tx);

    let mut sigs = vec![None; 3]; // index by party_index
    while let Some((idx, sig)) = sig_rx.recv().await {
        sigs[idx] = Some(sig);
    }

    // ── Phase 3: Verify ──────────────────────────────────────────────
    // Coordinator is Party 1 (index 0) — has the complete signature
    let coordinator_sig = sigs[0]
        .as_ref()
        .expect("coordinator (Party 1) must return signature");
    let MpcSignature::Ecdsa { r, s, .. } = coordinator_sig else {
        panic!("expected ECDSA");
    };

    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("multi-node MPC: keygen→sign via NATS must verify");
}
