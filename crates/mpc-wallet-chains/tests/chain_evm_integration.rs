use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_core::protocol::GroupPublicKey;

// ============================================================================
// EVM address derivation tests
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
fn test_evm_rejects_ed25519_key() {
    let provider = mpc_wallet_chains::evm::EvmProvider::ethereum();
    let gpk = GroupPublicKey::Ed25519(vec![0u8; 32]);
    assert!(provider.derive_address(&gpk).is_err());
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
