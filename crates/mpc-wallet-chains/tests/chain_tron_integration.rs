use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

fn secp256k1_pubkey() -> GroupPublicKey {
    GroupPublicKey::Secp256k1Uncompressed(vec![4; 65])
}

fn transfer_params() -> TransactionParams {
    TransactionParams {
        to: "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW".to_string(),
        value: "1000000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"owner_address": "41" })),
    }
}

#[test]
fn test_tron_address_derivation() {
    let provider = mpc_wallet_chains::tron::TronProvider::new();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(addr.starts_with('T'), "TRON address must start with T");
    assert_eq!(provider.chain(), Chain::Tron);
}

#[test]
fn test_tron_rejects_ed25519() {
    let provider = mpc_wallet_chains::tron::TronProvider::new();
    let pubkey = GroupPublicKey::Ed25519(vec![1; 32]);
    assert!(provider.derive_address(&pubkey).is_err());
}

#[tokio::test]
async fn test_tron_sign_payload_32_bytes() {
    let provider = mpc_wallet_chains::tron::TronProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    assert_eq!(unsigned.sign_payload.len(), 32);
    assert_eq!(unsigned.chain, Chain::Tron);
}

#[tokio::test]
async fn test_tron_finalize_ecdsa() {
    let provider = mpc_wallet_chains::tron::TronProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::Ecdsa {
        r: vec![0xAA; 32],
        s: vec![0xBB; 32],
        recovery_id: 0,
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Tron);
}

#[tokio::test]
async fn test_tron_rejects_eddsa() {
    let provider = mpc_wallet_chains::tron::TronProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::EdDsa { signature: [0; 64] };
    assert!(provider.finalize_transaction(&unsigned, &sig).is_err());
}

#[tokio::test]
async fn test_tron_broadcast_invalid_url() {
    let provider = mpc_wallet_chains::tron::TronProvider::new();
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
fn test_registry_creates_tron() {
    let registry = ChainRegistry::default_mainnet();
    let provider = registry.provider(Chain::Tron).unwrap();
    assert_eq!(provider.chain(), Chain::Tron);
}
