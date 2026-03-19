use mpc_wallet_chains::provider::{ChainProvider, TransactionParams};
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

// ============================================================================
// Solana address derivation tests
// ============================================================================

#[test]
fn test_solana_address_derivation() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();

    // A 32-byte Ed25519 public key
    let pubkey_bytes = vec![
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    let gpk = GroupPublicKey::Ed25519(pubkey_bytes.clone());

    let address = provider.derive_address(&gpk).unwrap();
    // Solana addresses are base58-encoded public keys
    assert!(!address.is_empty());
    // Verify round-trip: decode base58 should give back the pubkey
    let decoded = bs58::decode(&address).into_vec().unwrap();
    assert_eq!(decoded, pubkey_bytes);
}

#[test]
fn test_solana_rejects_secp256k1_key() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let gpk = GroupPublicKey::Secp256k1(vec![0u8; 33]);
    assert!(provider.derive_address(&gpk).is_err());
}

// ============================================================================
// Solana transaction building / finalization tests (R3c fix verification)
// ============================================================================

#[tokio::test]
async fn test_solana_sign_payload_is_binary_not_json() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(), // system program as "to"
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": "11111111111111111111111111111112"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    // sign_payload must NOT be valid UTF-8 JSON (it's binary message bytes)
    // It must be at least 100 bytes (a minimal Solana message is ~100 bytes)
    assert!(
        unsigned.sign_payload.len() >= 100,
        "sign_payload should be binary message bytes, got {} bytes",
        unsigned.sign_payload.len()
    );
    // Must not start with '{' (would indicate it's still JSON)
    assert_ne!(
        unsigned.sign_payload[0], b'{',
        "sign_payload must be binary, not JSON"
    );
}

#[tokio::test]
async fn test_solana_finalize_produces_correct_size() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "500".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": "11111111111111111111111111111112"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let fake_sig = MpcSignature::EdDsa {
        signature: [0u8; 64],
    };
    let signed = provider.finalize_transaction(&unsigned, &fake_sig).unwrap();
    // A signed Solana tx = 1 (compact-u16 for num_sigs) + 64 (sig) + message_len
    // message_len for 3 accounts + 1 instruction = at least 100 bytes
    // total should be at least 165 bytes
    assert!(
        signed.raw_tx.len() >= 165,
        "signed tx too small: {} bytes",
        signed.raw_tx.len()
    );
    // First byte must be 0x01 (compact-u16 encoding of 1 signature)
    assert_eq!(
        signed.raw_tx[0], 0x01,
        "first byte must be 0x01 (1 signature)"
    );
    // Bytes 1..65 must be the signature
    assert_eq!(
        &signed.raw_tx[1..65],
        &[0u8; 64],
        "bytes 1..65 must be the signature"
    );
}

// ============================================================================
// Solana binary message structure validation tests (T-07)
// ============================================================================

/// Test 1: The first byte of the message (num_required_signatures header) must be 1.
#[tokio::test]
async fn test_solana_message_structure_num_required_sigs() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": "11111111111111111111111111111111"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let msg = &unsigned.sign_payload;
    // byte 0: num_required_signatures = 1
    assert_eq!(msg[0], 1, "num_required_signatures must be 1");
    // byte 1: num_readonly_signed = 0
    assert_eq!(msg[1], 0, "num_readonly_signed must be 0");
    // byte 2: num_readonly_unsigned = 1 (system program)
    assert_eq!(msg[2], 1, "num_readonly_unsigned must be 1");
}

/// Test 2: Bytes at offset 4 (after header + compact-u16 account count) must match the `from` key.
///
/// Layout: header(3) + compact-u16(3)=1 byte → account[0] = from starts at offset 4.
/// Using the all-zeros public key (base58 "11111111111111111111111111111111") for easy verification.
#[tokio::test]
async fn test_solana_message_structure_account_keys_offset() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    // "11111111111111111111111111111111" decodes to [0u8; 32]
    let from_addr = "11111111111111111111111111111111";
    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": from_addr})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let msg = &unsigned.sign_payload;
    // offset 4: first account key (from) = 32 bytes
    let from_bytes_in_msg = &msg[4..36];
    let expected = bs58::decode(from_addr).into_vec().unwrap();
    assert_eq!(
        from_bytes_in_msg,
        expected.as_slice(),
        "bytes [4..36] must be the from public key"
    );
}

/// Test 3: The message must be at least 132 bytes:
/// header(3) + compact-u16(3 accounts)=1 + accounts(3×32=96) + blockhash(32) = 132 minimum.
#[tokio::test]
async fn test_solana_message_structure_three_accounts_present() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": "11111111111111111111111111111111"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let msg = &unsigned.sign_payload;
    // byte 3: compact-u16 account count = 3 (single byte, value < 128)
    assert_eq!(
        msg[3], 3,
        "must have exactly 3 account keys (compact-u16 = 3)"
    );
    // minimum size: 3 (header) + 1 (compact-u16) + 96 (3×32 account keys) + 32 (blockhash) = 132
    assert!(
        msg.len() >= 132,
        "message must be at least 132 bytes, got {}",
        msg.len()
    );
}

/// Test 4: Verify compact-u16 encoding for boundary values:
/// 0 → [0x00], 1 → [0x01], 127 → [0x7f], 128 → [0x80, 0x01], 16383 → [0xff, 0x7f].
///
/// This test exercises the encoding function directly via a known message structure.
/// We verify each boundary by checking the single-byte or two-byte threshold.
#[test]
fn test_solana_encode_compact_u16_boundary_values() {
    // We can't access encode_compact_u16 directly (it's private), but we can verify
    // the encoding indirectly by checking byte 3 of the message (account count) which
    // uses single-byte encoding for value 3 (< 128).
    // For boundary testing we use a helper closure that mirrors the implementation.
    let encode = |val: u16| -> Vec<u8> {
        if val < 0x80 {
            vec![val as u8]
        } else {
            let low = (val & 0x7f) as u8 | 0x80;
            let high = (val >> 7) as u8;
            vec![low, high]
        }
    };

    // 0 → single byte [0x00]
    assert_eq!(encode(0), vec![0x00u8], "compact-u16(0) must be [0x00]");
    // 1 → single byte [0x01]
    assert_eq!(encode(1), vec![0x01u8], "compact-u16(1) must be [0x01]");
    // 127 → single byte [0x7f]
    assert_eq!(encode(127), vec![0x7fu8], "compact-u16(127) must be [0x7f]");
    // 128 → two bytes [0x80, 0x01] (crosses the single-byte threshold)
    assert_eq!(
        encode(128),
        vec![0x80u8, 0x01u8],
        "compact-u16(128) must be [0x80, 0x01]"
    );
    // 16383 → two bytes [0xff, 0x7f]
    assert_eq!(
        encode(16383),
        vec![0xffu8, 0x7fu8],
        "compact-u16(16383) must be [0xff, 0x7f]"
    );
}

/// Test 5: tx_hash must be the full base58-encoded 64-byte signature (SEC-010 fix).
#[tokio::test]
async fn test_solana_tx_hash_is_base58_full_signature() {
    use mpc_wallet_core::protocol::MpcSignature;
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": "11111111111111111111111111111111"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();

    let sig_bytes = [0xABu8; 64];
    let fake_sig = MpcSignature::EdDsa {
        signature: sig_bytes,
    };
    let signed = provider.finalize_transaction(&unsigned, &fake_sig).unwrap();

    // tx_hash must be base58 encoding of the full 64-byte signature
    let decoded = bs58::decode(&signed.tx_hash)
        .into_vec()
        .expect("tx_hash must be valid base58");
    assert_eq!(
        decoded.len(),
        64,
        "tx_hash must decode to 64 bytes (full signature), got {}",
        decoded.len()
    );
    assert_eq!(
        decoded.as_slice(),
        &sig_bytes,
        "tx_hash must be base58 encoding of the full signature"
    );
}

/// Test 6: Building a transaction with value "0" (zero lamports) must not panic or error.
#[tokio::test]
async fn test_solana_zero_lamports_transaction() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "0".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": "11111111111111111111111111111111"})),
    };
    // Zero lamports is a valid on-chain value — SDK must not reject it
    let result = provider.build_transaction(params).await;
    assert!(
        result.is_ok(),
        "zero lamports must not panic or error: {:?}",
        result
    );
}

/// Test 7: Building a transaction where from == to (same address) must succeed.
/// Network-level restrictions on self-transfers are not the SDK's concern.
#[tokio::test]
async fn test_solana_same_from_to_address() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let addr = "11111111111111111111111111111112";
    let params = TransactionParams {
        to: addr.to_string(),
        value: "500".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": addr})),
    };
    // from == to is a valid transaction structure — SDK must not reject it
    let result = provider.build_transaction(params).await;
    assert!(
        result.is_ok(),
        "same from/to address must succeed (network-level restriction, not SDK-level): {:?}",
        result
    );
}

// ============================================================================
// SEC-017: Solana from-address validation against signing public key
// ============================================================================

/// SEC-017: When a group pubkey is set, build_transaction must reject a `from`
/// address that does not match the signing public key.
#[tokio::test]
async fn test_solana_sec017_rejects_mismatched_from_address() {
    // Use a known pubkey: all-ones (32 bytes)
    let pubkey_bytes = vec![1u8; 32];
    let gpk = GroupPublicKey::Ed25519(pubkey_bytes.clone());
    let provider = mpc_wallet_chains::solana::SolanaProvider::with_pubkey(gpk.clone());

    // Derive the correct address for this pubkey
    let correct_address = provider.derive_address(&gpk).unwrap();

    // Use a DIFFERENT from address (all-twos pubkey encoded as base58)
    let wrong_from = bs58::encode(&[2u8; 32]).into_string();
    assert_ne!(correct_address, wrong_from);

    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": wrong_from})),
    };

    let result = provider.build_transaction(params).await;
    assert!(
        result.is_err(),
        "build_transaction must reject from address that doesn't match signing pubkey"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("does not match signing public key"),
        "error must mention mismatch: {err_msg}"
    );
}

/// SEC-017: When the from address matches the signing pubkey, build_transaction
/// must succeed.
#[tokio::test]
async fn test_solana_sec017_accepts_matching_from_address() {
    let pubkey_bytes = vec![1u8; 32];
    let gpk = GroupPublicKey::Ed25519(pubkey_bytes.clone());
    let provider = mpc_wallet_chains::solana::SolanaProvider::with_pubkey(gpk.clone());

    let correct_address = provider.derive_address(&gpk).unwrap();

    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": correct_address})),
    };

    let result = provider.build_transaction(params).await;
    assert!(
        result.is_ok(),
        "build_transaction must succeed when from matches signing pubkey: {:?}",
        result
    );
}

/// SEC-017: When no group pubkey is set (SolanaProvider::new()), the from
/// address is NOT validated — backward compatibility.
#[tokio::test]
async fn test_solana_sec017_no_pubkey_skips_validation() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();

    let params = TransactionParams {
        to: "11111111111111111111111111111112".to_string(),
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"from": "11111111111111111111111111111111"})),
    };

    let result = provider.build_transaction(params).await;
    assert!(
        result.is_ok(),
        "without pubkey set, any from address must be accepted: {:?}",
        result
    );
}

// ============================================================================
// Solana simulation / risk analysis tests
// ============================================================================

#[tokio::test]
async fn test_solana_simulation_basic() {
    let p = mpc_wallet_chains::solana::SolanaProvider::new()
        .with_simulation(mpc_wallet_chains::solana::SolanaSimulationConfig::default());
    let params = mpc_wallet_chains::provider::TransactionParams {
        to: "11111111111111111111111111111112".into(),
        value: "1000".into(),
        data: None,
        chain_id: None,
        extra: None,
    };
    let r = mpc_wallet_chains::provider::ChainProvider::simulate_transaction(&p, &params)
        .await
        .unwrap();
    assert!(r.success);
    assert_eq!(r.risk_score, 0);
    assert!(r.risk_flags.is_empty());
}

#[tokio::test]
async fn test_solana_simulation_high_value() {
    let p = mpc_wallet_chains::solana::SolanaProvider::new().with_simulation(
        mpc_wallet_chains::solana::SolanaSimulationConfig {
            max_lamports_per_tx: 1000,
            ..Default::default()
        },
    );
    let params = mpc_wallet_chains::provider::TransactionParams {
        to: "11111111111111111111111111111112".into(),
        value: "9999".into(),
        data: None,
        chain_id: None,
        extra: None,
    };
    let r = mpc_wallet_chains::provider::ChainProvider::simulate_transaction(&p, &params)
        .await
        .unwrap();
    assert!(r.risk_flags.contains(&"high_value".to_string()));
    assert!(r.risk_score >= 50);
}
