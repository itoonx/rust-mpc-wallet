use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

// ============================================================================
// Address derivation tests
// ============================================================================

#[test]
fn test_evm_address_derivation() {
    let provider = mpc_wallet_chains::evm::EvmProvider::ethereum();

    // Known uncompressed secp256k1 public key (65 bytes, 0x04 prefix)
    // This is a test key: secret = 1
    let pubkey_hex = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let gpk = GroupPublicKey::Secp256k1Uncompressed(pubkey_bytes);

    let address = provider.derive_address(&gpk).unwrap();
    // Known Ethereum address for secret key = 1
    assert_eq!(
        address.to_lowercase(),
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
}

#[test]
fn test_evm_address_from_compressed() {
    let provider = mpc_wallet_chains::evm::EvmProvider::ethereum();

    // Compressed form of the same key
    let pubkey_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let gpk = GroupPublicKey::Secp256k1(pubkey_bytes);

    let address = provider.derive_address(&gpk).unwrap();
    assert_eq!(
        address.to_lowercase(),
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
}

#[test]
fn test_bitcoin_taproot_address_derivation() {
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::mainnet();

    // A compressed secp256k1 key
    let pubkey_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let gpk = GroupPublicKey::Secp256k1(pubkey_bytes);

    let address = provider.derive_address(&gpk).unwrap();
    // Should be a bc1p... address (bech32m)
    assert!(
        address.starts_with("bc1p"),
        "expected bc1p address, got: {address}"
    );
}

#[test]
fn test_bitcoin_testnet_address() {
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::testnet();

    let pubkey_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let gpk = GroupPublicKey::Secp256k1(pubkey_bytes);

    let address = provider.derive_address(&gpk).unwrap();
    // Testnet taproot addresses start with tb1p
    assert!(
        address.starts_with("tb1p"),
        "expected tb1p address, got: {address}"
    );
}

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

#[test]
fn test_evm_rejects_ed25519_key() {
    let provider = mpc_wallet_chains::evm::EvmProvider::ethereum();
    let gpk = GroupPublicKey::Ed25519(vec![0u8; 32]);
    assert!(provider.derive_address(&gpk).is_err());
}

#[test]
fn test_solana_rejects_secp256k1_key() {
    let provider = mpc_wallet_chains::solana::SolanaProvider::new();
    let gpk = GroupPublicKey::Secp256k1(vec![0u8; 33]);
    assert!(provider.derive_address(&gpk).is_err());
}

// ============================================================================
// Sui transaction building / finalization tests (R3d fix verification)
// ============================================================================

/// Build a minimal valid `TransactionParams` for Sui.
///
/// Sui's `build_sui_transaction` reads:
///   - `params.extra["sender"]`  → sender address
///   - `params.to`               → recipient address
///   - `params.value`            → amount (parseable as u64)
fn sui_params(to: &str, sender: &str, value: u64) -> TransactionParams {
    TransactionParams {
        to: to.to_string(),
        value: value.to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({ "sender": sender })),
    }
}

/// Test 1: sign_payload produced by build_transaction is a 32-byte Blake2b-256 hash,
/// not all zeros.
#[tokio::test]
async fn test_sui_sign_payload_is_blake2b_hashed() {
    let pubkey = GroupPublicKey::Ed25519(vec![1u8; 32]);
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(pubkey);

    let params = sui_params("0xdef", "0xabc", 1000);
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
/// The `raw_tx` field contains JSON; the 97-byte blob is hex-encoded under the
/// "signature" key.
#[tokio::test]
async fn test_sui_finalize_has_correct_signature_format() {
    let pubkey_bytes = vec![2u8; 32];
    let pubkey = GroupPublicKey::Ed25519(pubkey_bytes.clone());
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(pubkey);

    let params = sui_params("0xdef", "0xabc", 1000);
    let unsigned = provider
        .build_transaction(params)
        .await
        .expect("build_transaction should succeed");

    let sig_bytes = [3u8; 64];
    let mpc_sig = MpcSignature::EdDsa { signature: sig_bytes };

    let signed = provider
        .finalize_transaction(&unsigned, &mpc_sig)
        .expect("finalize_transaction should succeed");

    // raw_tx is JSON: {"tx_bytes": "<hex>", "signature": "<hex>"}
    let raw_json: serde_json::Value =
        serde_json::from_slice(&signed.raw_tx).expect("raw_tx must be valid JSON");

    let sig_hex = raw_json["signature"]
        .as_str()
        .expect("signature field must be a string");

    let sui_sig = hex::decode(sig_hex).expect("signature must be valid hex");

    // 97 bytes total: flag(1) + ed25519_sig(64) + ed25519_pubkey(32)
    assert_eq!(
        sui_sig.len(),
        97,
        "Sui serialized signature must be 97 bytes, got {}",
        sui_sig.len()
    );

    // Byte 0: Ed25519 scheme flag = 0x00
    assert_eq!(sui_sig[0], 0x00, "first byte must be Ed25519 flag 0x00");

    // Bytes 1..65: the 64-byte EdDSA signature
    assert_eq!(
        &sui_sig[1..65],
        &[3u8; 64],
        "bytes 1..65 must be the EdDSA signature"
    );

    // Bytes 65..97: the 32-byte Ed25519 public key
    assert_eq!(
        &sui_sig[65..97],
        pubkey_bytes.as_slice(),
        "bytes 65..97 must be the Ed25519 public key"
    );
}

/// Test 3: build_transaction rejects a Secp256k1 key — Sui requires Ed25519.
#[tokio::test]
async fn test_sui_rejects_wrong_key_type_in_build() {
    let pubkey = GroupPublicKey::Secp256k1(vec![4u8; 33]);
    let provider = mpc_wallet_chains::sui::SuiProvider::with_pubkey(pubkey);

    let params = sui_params("0xdef", "0xabc", 1000);
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
    let params = sui_params("0xdef", "0xabc", 1000);
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
// EVM multi-network tests (R3a)
// ============================================================================

/// Build minimal `TransactionParams` suitable for an EVM chain.
fn evm_params() -> TransactionParams {
    TransactionParams {
        to: "0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf".to_string(),
        value: "1000000000000000000".to_string(), // 1 ETH in wei
        data: None,
        chain_id: None,
        extra: None,
    }
}

/// Verify that `EvmProvider::new(Chain::Polygon)` encodes `chain_id = 137`
/// in the signed transaction payload.
#[tokio::test]
async fn test_evm_polygon_chain_id() {
    use alloy::consensus::TxEip1559;

    let provider = mpc_wallet_chains::evm::EvmProvider::new(Chain::Polygon)
        .expect("Polygon is a valid EVM chain");

    let unsigned = provider
        .build_transaction(evm_params())
        .await
        .expect("build_transaction should succeed for Polygon");

    // Deserialize the stored tx_data and check chain_id
    let tx: TxEip1559 = serde_json::from_slice(&unsigned.tx_data)
        .expect("tx_data must deserialize to TxEip1559");

    assert_eq!(
        tx.chain_id, 137,
        "Polygon chain_id must be 137, got {}",
        tx.chain_id
    );
}

/// Verify that `EvmProvider::new(Chain::Bsc)` encodes `chain_id = 56`
/// in the signed transaction payload.
#[tokio::test]
async fn test_evm_bsc_chain_id() {
    use alloy::consensus::TxEip1559;

    let provider = mpc_wallet_chains::evm::EvmProvider::new(Chain::Bsc)
        .expect("BSC is a valid EVM chain");

    let unsigned = provider
        .build_transaction(evm_params())
        .await
        .expect("build_transaction should succeed for BSC");

    let tx: TxEip1559 = serde_json::from_slice(&unsigned.tx_data)
        .expect("tx_data must deserialize to TxEip1559");

    assert_eq!(
        tx.chain_id, 56,
        "BSC chain_id must be 56, got {}",
        tx.chain_id
    );
}

/// Verify that `EvmProvider::chain()` returns the exact `Chain` variant
/// passed to `EvmProvider::new`.
#[tokio::test]
async fn test_evm_provider_returns_correct_chain() {
    let polygon = mpc_wallet_chains::evm::EvmProvider::new(Chain::Polygon)
        .expect("Polygon is a valid EVM chain");
    assert_eq!(
        polygon.chain(),
        Chain::Polygon,
        "provider.chain() must return Chain::Polygon"
    );

    let bsc = mpc_wallet_chains::evm::EvmProvider::new(Chain::Bsc)
        .expect("BSC is a valid EVM chain");
    assert_eq!(
        bsc.chain(),
        Chain::Bsc,
        "provider.chain() must return Chain::Bsc"
    );
}
