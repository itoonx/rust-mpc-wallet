//! E2E tests: NATS transport — connectivity, message round-trip, and MPC protocols.
//!
//! Requires: `./scripts/local-infra.sh up` (NATS on localhost:4222)

use super::*;
use mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol;
use mpc_wallet_core::protocol::gg20::Gg20Protocol;
use mpc_wallet_core::protocol::{MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::nats::NatsTransport;
use mpc_wallet_core::transport::{ProtocolMessage, Transport};

fn gg20_factory() -> Box<dyn MpcProtocol> {
    Box::new(Gg20Protocol::new())
}

fn frost_ed25519_factory() -> Box<dyn MpcProtocol> {
    Box::new(FrostEd25519Protocol::new())
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
// MPC keygen + sign via NATS (multi-round protocol)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires NATS: ./scripts/local-infra.sh up"]
async fn test_nats_keygen_gg20_2of3() {
    let url = nats_url();
    let shares = nats_keygen(gg20_factory, 2, 3, &url).await;

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
// NATS sign + FROST keygen — requires shared PartyKeys across phases
// ═══════════════════════════════════════════════════════════════════════
// TODO (Phase 1 continued): nats_sign() creates fresh PartyKeys with different
// Ed25519 envelope keys than the keygen phase — SignedEnvelope verification fails.
// Fix: persist PartyKeys from keygen phase and reuse in sign phase.
// FROST keygen needs investigation — may require different message ordering.
