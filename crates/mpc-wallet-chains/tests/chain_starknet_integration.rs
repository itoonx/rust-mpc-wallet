use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

fn secp256k1_pubkey() -> GroupPublicKey {
    GroupPublicKey::Secp256k1(vec![2; 33])
}

fn transfer_params() -> TransactionParams {
    TransactionParams {
        to: format!("0x{}", "ab".repeat(32)),
        value: "1000000000000000000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({
            "sender_address": format!("0x{}", "01".repeat(32)),
            "nonce": 0,
            "max_fee": 100000,
            "chain_id": "SN_MAIN"
        })),
    }
}

#[test]
fn test_starknet_address_derivation() {
    let provider = mpc_wallet_chains::starknet::StarknetProvider::new();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(addr.starts_with("0x"));
    assert_eq!(addr.len(), 66); // 0x + 64 hex
}

#[test]
fn test_starknet_address_accepts_any_key_type() {
    let provider = mpc_wallet_chains::starknet::StarknetProvider::new();
    // Starknet accepts all key types for address derivation
    assert!(provider
        .derive_address(&GroupPublicKey::Ed25519(vec![1; 32]))
        .is_ok());
    assert!(provider
        .derive_address(&GroupPublicKey::Secp256k1(vec![2; 33]))
        .is_ok());
}

#[tokio::test]
async fn test_starknet_sign_payload_32_bytes() {
    let provider = mpc_wallet_chains::starknet::StarknetProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    assert_eq!(unsigned.sign_payload.len(), 32);
    assert_eq!(unsigned.chain, Chain::Starknet);
}

#[tokio::test]
async fn test_starknet_finalize_ecdsa() {
    let provider = mpc_wallet_chains::starknet::StarknetProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::Ecdsa {
        r: vec![0xAA; 32],
        s: vec![0xBB; 32],
        recovery_id: 0,
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Starknet);
}

#[tokio::test]
async fn test_starknet_rejects_eddsa() {
    let provider = mpc_wallet_chains::starknet::StarknetProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::EdDsa { signature: [0; 64] };
    assert!(provider.finalize_transaction(&unsigned, &sig).is_err());
}

#[tokio::test]
async fn test_starknet_broadcast_invalid_url() {
    let provider = mpc_wallet_chains::starknet::StarknetProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::Ecdsa {
        r: vec![0; 32],
        s: vec![0; 32],
        recovery_id: 0,
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert!(provider
        .broadcast(&signed, "http://invalid.localhost:1")
        .await
        .is_err());
}

#[test]
fn test_registry_creates_starknet() {
    let registry = ChainRegistry::default_mainnet();
    let provider = registry.provider(Chain::Starknet).unwrap();
    assert_eq!(provider.chain(), Chain::Starknet);
}
