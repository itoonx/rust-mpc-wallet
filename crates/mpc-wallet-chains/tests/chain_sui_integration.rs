use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

// ============================================================================
// Sui test helpers
// ============================================================================

/// Build a minimal valid `TransactionParams` for Sui.
///
/// Sui's `build_sui_transaction` reads:
///   - `params.extra["sender"]`  → sender address (must be `0x` + 64 hex chars)
///   - `params.to`               → recipient address (must be `0x` + 64 hex chars)
///   - `params.value`            → amount (parseable as u64)
///
/// Default addresses used by the two-argument overload below are:
///   sender    = `0x000...0001`
///   recipient = `0x000...0002`
fn sui_params(to: &str, sender: &str, value: u64) -> TransactionParams {
    TransactionParams {
        to: to.to_string(),
        value: value.to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({ "sender": sender })),
    }
}

/// Convenience wrapper that supplies canonical 32-byte zero-padded Sui addresses.
fn sui_params_default(value: u64) -> TransactionParams {
    sui_params(
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        value,
    )
}

// ============================================================================
// Sui address derivation tests
// ============================================================================

#[test]
fn test_sui_address_derivation() {
    let provider = mpc_wallet_chains::sui::SuiProvider::new();

    let pubkey_bytes = vec![
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    let gpk = GroupPublicKey::Ed25519(pubkey_bytes);

    let address = provider.derive_address(&gpk).unwrap();
    // Sui addresses are 0x-prefixed hex, 32 bytes = 64 hex chars + 0x prefix
    assert!(
        address.starts_with("0x"),
        "expected 0x prefix, got: {address}"
    );
    assert_eq!(address.len(), 66); // 0x + 64 hex chars
}

// ============================================================================
// Sui transaction building / finalization tests (R3d fix verification)
// ============================================================================

/// Test 1: sign_payload produced by build_transaction is a 32-byte Blake2b-256 hash,
/// not all zeros.
#[tokio::test]
async fn test_sui_sign_payload_is_blake2b_hashed() {
    let pubkey = GroupPublicKey::Ed25519(vec![1u8; 32]);
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(pubkey);

    let params = sui_params_default(1000);
    let unsigned = provider
        .build_transaction(params)
        .await
        .expect("build_transaction should succeed");

    // Blake2b-256 output is exactly 32 bytes
    assert_eq!(
        unsigned.sign_payload.len(),
        32,
        "sign_payload must be 32 bytes (Blake2b-256 output), got {}",
        unsigned.sign_payload.len()
    );

    // Must not be all zeros — a real hash of non-empty data
    assert!(
        unsigned.sign_payload.iter().any(|&b| b != 0),
        "sign_payload must not be all zeros"
    );
}

/// Test 2: finalized transaction encodes the Sui wire-format signature correctly.
///
/// Sui serialized-signature format: [0x00] || sig(64 bytes) || pubkey(32 bytes) = 97 bytes.
/// After the BCS migration (T-S2-04), `raw_tx` IS the 97-byte raw signature directly —
/// no JSON wrapper.
#[tokio::test]
async fn test_sui_finalize_has_correct_signature_format() {
    let pubkey_bytes = vec![2u8; 32];
    let pubkey = GroupPublicKey::Ed25519(pubkey_bytes.clone());
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(pubkey);

    let params = sui_params(
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        1000,
    );
    let unsigned = provider
        .build_transaction(params)
        .await
        .expect("build_transaction should succeed");

    let sig_bytes = [3u8; 64];
    let mpc_sig = MpcSignature::EdDsa { signature: sig_bytes };

    let signed = provider
        .finalize_transaction(&unsigned, &mpc_sig)
        .expect("finalize_transaction should succeed");

    // raw_tx is the 97-byte Sui serialized signature directly (BCS migration)
    // 97 bytes total: flag(1) + ed25519_sig(64) + ed25519_pubkey(32)
    assert_eq!(
        signed.raw_tx.len(),
        97,
        "Sui serialized signature must be 97 bytes, got {}",
        signed.raw_tx.len()
    );

    // Byte 0: Ed25519 scheme flag = 0x00
    assert_eq!(signed.raw_tx[0], 0x00, "first byte must be Ed25519 flag 0x00");

    // Bytes 1..65: the 64-byte EdDSA signature
    assert_eq!(
        &signed.raw_tx[1..65],
        &[3u8; 64],
        "bytes 1..65 must be the EdDSA signature"
    );

    // Bytes 65..97: the 32-byte Ed25519 public key
    assert_eq!(
        &signed.raw_tx[65..97],
        pubkey_bytes.as_slice(),
        "bytes 65..97 must be the Ed25519 public key"
    );
}

/// Test 3: build_transaction rejects a Secp256k1 key — Sui requires Ed25519.
#[tokio::test]
async fn test_sui_rejects_wrong_key_type_in_build() {
    let pubkey = GroupPublicKey::Secp256k1(vec![4u8; 33]);
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(pubkey);

    let params = sui_params_default(1000);
    let result = provider.build_transaction(params).await;

    assert!(
        result.is_err(),
        "build_transaction should fail for a Secp256k1 key on Sui"
    );
}

/// Test 4: finalize_transaction rejects a non-EdDSA signature type.
#[tokio::test]
async fn test_sui_rejects_wrong_signature_type_in_finalize() {
    let pubkey = GroupPublicKey::Ed25519(vec![5u8; 32]);
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(pubkey);

    // Build a valid unsigned transaction first
    let params = sui_params_default(1000);
    let unsigned = provider
        .build_transaction(params)
        .await
        .expect("build_transaction should succeed with Ed25519 key");

    // Attempt to finalize with an ECDSA signature (wrong type for Sui)
    let wrong_sig = MpcSignature::Ecdsa {
        r: vec![0u8; 32],
        s: vec![0u8; 32],
        recovery_id: 0,
    };

    let result = provider.finalize_transaction(&unsigned, &wrong_sig);

    assert!(
        result.is_err(),
        "finalize_transaction should fail when given an ECDSA signature for Sui"
    );
}

// ============================================================================
// SuiProvider::new() / Default + broadcast_stub tests (R3d improvements)
// ============================================================================

/// Test 5: SuiProvider::new() / Default does not panic and derive_address works.
#[test]
fn test_sui_provider_default_works() {
    // SuiProvider::new() / default() should not panic
    let provider = mpc_wallet_chains::sui::SuiProvider::new();
    // derive_address should still work (doesn't need pubkey stored)
    let pubkey = GroupPublicKey::Ed25519([1u8; 32].to_vec());
    let addr = provider.derive_address(&pubkey).unwrap();
    assert!(addr.starts_with("0x"), "Sui address must start with 0x");
    assert_eq!(addr.len(), 66, "Sui address must be 66 chars (0x + 64 hex)");
}

/// Test 6: broadcast_stub must return Err (not yet implemented).
#[tokio::test]
async fn test_sui_broadcast_stub_returns_not_implemented() {
    use mpc_wallet_chains::provider::SignedTransaction;
    let provider = mpc_wallet_chains::sui::SuiProvider::new();
    let fake_signed = SignedTransaction {
        chain: Chain::Sui,
        raw_tx: vec![0u8; 97],
        tx_hash: "0xdeadbeef".to_string(),
    };
    let result = provider.broadcast_stub(&fake_signed).await;
    assert!(result.is_err(), "broadcast_stub must return Err until implemented");
}

// ============================================================================
// Sui sender address validation tests (T-06)
// ============================================================================

#[test]
fn test_sui_validate_address_valid() {
    let valid = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let result = mpc_wallet_chains::sui::tx::validate_sui_address(valid);
    assert!(result.is_ok(), "valid Sui address must pass validation: {:?}", result);
    assert_eq!(result.unwrap()[31], 0x01, "last byte must be 0x01");
}

#[test]
fn test_sui_validate_address_missing_prefix() {
    let bad = "0000000000000000000000000000000000000000000000000000000000000001";
    let result = mpc_wallet_chains::sui::tx::validate_sui_address(bad);
    assert!(result.is_err(), "address without 0x prefix must fail");
}

#[test]
fn test_sui_validate_address_wrong_length() {
    let bad = "0x00000000000000000000000000000000000000000000000000000000000001";
    let result = mpc_wallet_chains::sui::tx::validate_sui_address(bad);
    assert!(result.is_err(), "address with wrong length must fail");
}

#[tokio::test]
async fn test_sui_build_with_sender_validates_address() {
    use mpc_wallet_core::protocol::GroupPublicKey;
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(
        GroupPublicKey::Ed25519(vec![1u8; 32])
    );
    let params = TransactionParams {
        to: "0x0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        value: "1000".to_string(),
        data: None, chain_id: None, extra: None,
    };
    let valid_sender = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let result = provider.build_transaction_with_sender(params.clone(), valid_sender).await;
    assert!(result.is_ok(), "valid sender must succeed: {:?}", result);
    let bad_sender = "not-a-valid-address";
    let result = provider.build_transaction_with_sender(params, bad_sender).await;
    assert!(result.is_err(), "invalid sender must return error");
}

// ============================================================================
// Sui address validation — invalid hex characters (SEC-023 fix, LESSON-012)
// ============================================================================

/// SEC-023: validate_sui_address must reject `0x` + 64 chars that are not valid hex.
#[test]
fn test_sui_validate_address_invalid_hex_chars() {
    // 0x + 64 chars but not valid hex (contains 'g')
    let bad = "0xgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
    let result = mpc_wallet_chains::sui::tx::validate_sui_address(bad);
    assert!(result.is_err(), "address with invalid hex chars must fail: {:?}", result);
}

// ============================================================================
// Sui BCS serialization tests (T-S2-04)
// ============================================================================

/// BCS tx → Blake2b-256 sign_payload must be exactly 32 bytes and non-zero.
#[tokio::test]
async fn test_sui_bcs_sign_payload_is_32_bytes() {
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(
        GroupPublicKey::Ed25519(vec![1u8; 32])
    );
    let params = TransactionParams {
        to: "0x0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        value: "1000000".to_string(),
        data: None, chain_id: None,
        extra: Some(serde_json::json!({"sender": "0x0000000000000000000000000000000000000000000000000000000000000001"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    assert_eq!(unsigned.sign_payload.len(), 32, "sign_payload must be 32 bytes (Blake2b-256)");
    assert_ne!(unsigned.sign_payload, vec![0u8; 32], "sign_payload must not be all zeros");
}

/// tx_data must be bcs_bytes || pubkey(32): last 32 bytes must equal the provider pubkey.
///
/// BCS encoding of SuiTransferPayload(sender[32], recipient[32], amount:u64, ref[32])
/// is at least 32+32+8+32 = 104 bytes, so tx_data must be > 32 bytes total.
#[tokio::test]
async fn test_sui_bcs_tx_data_contains_bcs_plus_pubkey() {
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(
        GroupPublicKey::Ed25519(vec![0xAAu8; 32])
    );
    let params = TransactionParams {
        to: "0x0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        value: "500".to_string(),
        data: None, chain_id: None,
        extra: Some(serde_json::json!({"sender": "0x0000000000000000000000000000000000000000000000000000000000000001"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    // tx_data must be at least 32 bytes longer than the BCS payload alone
    assert!(unsigned.tx_data.len() > 32, "tx_data must contain BCS bytes + pubkey");
    // Last 32 bytes must be the pubkey [0xAA; 32]
    let (_, pubkey_suffix) = unsigned.tx_data.split_at(unsigned.tx_data.len() - 32);
    assert_eq!(pubkey_suffix, &[0xAAu8; 32], "last 32 bytes of tx_data must be the pubkey");
}

/// finalize_sui_transaction must produce a 97-byte raw signature with correct layout.
/// raw_tx = [0x00 | sig(64) | pubkey(32)] — no JSON wrapper (BCS migration).
#[tokio::test]
async fn test_sui_bcs_finalize_97_byte_signature() {
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(
        GroupPublicKey::Ed25519(vec![0xBBu8; 32])
    );
    let params = TransactionParams {
        to: "0x0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        value: "1000".to_string(),
        data: None, chain_id: None,
        extra: Some(serde_json::json!({"sender": "0x0000000000000000000000000000000000000000000000000000000000000001"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let sig = MpcSignature::EdDsa { signature: [0xCCu8; 64] };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.raw_tx.len(), 97, "raw_tx must be 97 bytes");
    assert_eq!(signed.raw_tx[0], 0x00, "byte 0 must be Ed25519 flag 0x00");
    assert_eq!(&signed.raw_tx[1..65], &[0xCCu8; 64], "bytes 1..65 must be the signature");
    assert_eq!(&signed.raw_tx[65..97], &[0xBBu8; 32], "bytes 65..97 must be the pubkey");
}
