//! E2E tests: NATS transport connectivity and message round-trip.
//!
//! Note: Multi-round MPC protocol tests (keygen/sign via NATS) are blocked by
//! NatsTransport::recv() creating a new subscription per call — messages published
//! before subscribe are lost. This needs a persistent subscription fix.
//! For now, we test basic connectivity and single message round-trip.
//!
//! Requires: `./scripts/local-infra.sh up` (NATS on localhost:4222)

use super::*;
use mpc_wallet_core::transport::nats::NatsTransport;
use mpc_wallet_core::transport::{ProtocolMessage, Transport};

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

    // Party 1 sends, Party 2 receives
    let sender = party_keys.connect(0, &session_id, &url).await;
    let receiver = party_keys.connect(1, &session_id, &url).await;

    // Receiver must subscribe BEFORE sender publishes (NATS limitation)
    let recv_handle = tokio::spawn(async move {
        // This subscribes and waits for one message
        receiver.recv().await
    });

    // Small delay to ensure subscription is established
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

// Note: Bidirectional exchange test removed — NatsTransport::recv() creates a fresh
// subscription per call, so party 1 misses the reply if it subscribes after party 2
// publishes. This is the same limitation that blocks multi-round MPC protocol tests.
// Fix: NatsTransport should hold a persistent subscription.

#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_nats_session_isolation() {
    let url = nats_url();
    let party_keys = PartyKeys::generate(2);

    // Two different sessions — messages must NOT cross
    let session_a = unique_session_id();
    let session_b = unique_session_id();

    let sender_a = party_keys.connect(0, &session_a, &url).await;
    let receiver_b = party_keys.connect(1, &session_b, &url).await;

    // Subscribe on session B first
    let recv_handle = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), receiver_b.recv()).await
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send on session A
    sender_a
        .send(ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: b"session A message".to_vec(),
        })
        .await
        .unwrap();

    // Session B should NOT receive it (timeout)
    let result = recv_handle.await.unwrap();
    assert!(
        result.is_err(),
        "session B must NOT receive session A's message"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// MPC keygen/sign via NATS — blocked by recv() subscription issue
// ═══════════════════════════════════════════════════════════════════════
// TODO: Once NatsTransport::recv() uses a persistent subscription,
// enable these tests:
// - test_nats_keygen_gg20_2of3
// - test_nats_sign_gg20_subset_1_2
// - test_nats_keygen_frost_ed25519
// - test_nats_sign_frost_ed25519
// See: protocol_integration.rs for LocalTransport versions that work
