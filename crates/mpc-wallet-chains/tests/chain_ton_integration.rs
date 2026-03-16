use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

fn ed25519_pubkey() -> GroupPublicKey {
    GroupPublicKey::Ed25519(vec![1; 32])
}

fn transfer_params() -> TransactionParams {
    TransactionParams {
        to: format!("0:{}", "ab".repeat(32)),
        value: "1000000000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"bounce": true})),
    }
}

#[test]
fn test_ton_address_derivation() {
    let provider = mpc_wallet_chains::ton::TonProvider::new();
    let addr = provider.derive_address(&ed25519_pubkey()).unwrap();
    assert!(addr.starts_with("0:"), "TON address must start with 0:");
    assert_eq!(addr.len(), 66); // "0:" + 64 hex
}

#[test]
fn test_ton_rejects_secp256k1() {
    let provider = mpc_wallet_chains::ton::TonProvider::new();
    let pubkey = GroupPublicKey::Secp256k1(vec![2; 33]);
    assert!(provider.derive_address(&pubkey).is_err());
}

#[tokio::test]
async fn test_ton_sign_payload_32_bytes() {
    let provider = mpc_wallet_chains::ton::TonProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    assert_eq!(unsigned.sign_payload.len(), 32);
    assert_eq!(unsigned.chain, Chain::Ton);
}

#[tokio::test]
async fn test_ton_finalize_ed25519() {
    let provider = mpc_wallet_chains::ton::TonProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::EdDsa {
        signature: [0xDD; 64],
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Ton);
    // First 64 bytes should be the signature
    assert!(signed.raw_tx.len() >= 64);
}

#[tokio::test]
async fn test_ton_broadcast_invalid_url() {
    let provider = mpc_wallet_chains::ton::TonProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::EdDsa { signature: [0; 64] };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert!(provider
        .broadcast(&signed, "http://invalid.localhost:1")
        .await
        .is_err());
}

#[test]
fn test_ton_cell_boc_serialization() {
    let cell = mpc_wallet_chains::ton::cell::build_transfer_cell(0, &[0xAB; 32], 1_000_000, true);
    let boc = cell.to_boc();
    // BOC magic bytes
    assert_eq!(&boc[..4], &[0xB5, 0xEE, 0x9C, 0x72]);
    assert!(!cell.hash().is_empty());
}

#[test]
fn test_registry_creates_ton() {
    let registry = ChainRegistry::default_mainnet();
    let provider = registry.provider(Chain::Ton).unwrap();
    assert_eq!(provider.chain(), Chain::Ton);
}
