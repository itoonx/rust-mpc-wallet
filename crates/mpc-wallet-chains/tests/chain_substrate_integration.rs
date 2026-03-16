use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

fn ed25519_pubkey() -> GroupPublicKey {
    GroupPublicKey::Ed25519(vec![1; 32])
}

fn transfer_params() -> TransactionParams {
    TransactionParams {
        to: format!("0x{}", "ab".repeat(32)),
        value: "1000000000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"nonce": 0, "spec_version": 1})),
    }
}

#[test]
fn test_polkadot_address() {
    let provider = mpc_wallet_chains::substrate::SubstrateProvider::polkadot();
    let addr = provider.derive_address(&ed25519_pubkey()).unwrap();
    assert!(!addr.is_empty());
    assert_eq!(provider.chain(), Chain::Polkadot);
}

#[test]
fn test_kusama_address() {
    let provider = mpc_wallet_chains::substrate::SubstrateProvider::kusama();
    let addr = provider.derive_address(&ed25519_pubkey()).unwrap();
    assert!(!addr.is_empty());
    assert_eq!(provider.chain(), Chain::Kusama);
}

#[test]
fn test_substrate_rejects_secp256k1() {
    let provider = mpc_wallet_chains::substrate::SubstrateProvider::polkadot();
    let pubkey = GroupPublicKey::Secp256k1(vec![2; 33]);
    assert!(provider.derive_address(&pubkey).is_err());
}

#[tokio::test]
async fn test_substrate_sign_payload_32_bytes() {
    let provider = mpc_wallet_chains::substrate::SubstrateProvider::polkadot();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    assert_eq!(unsigned.sign_payload.len(), 32);
    assert_eq!(unsigned.chain, Chain::Polkadot);
}

#[tokio::test]
async fn test_substrate_finalize_ed25519() {
    let provider = mpc_wallet_chains::substrate::SubstrateProvider::polkadot();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::EdDsa {
        signature: [0xCC; 64],
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Polkadot);
    // First byte should be Ed25519 type (0x00)
    assert_eq!(signed.raw_tx[0], 0x00);
}

#[tokio::test]
async fn test_substrate_rejects_ecdsa_signature() {
    let provider = mpc_wallet_chains::substrate::SubstrateProvider::kusama();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::Ecdsa {
        r: vec![0; 32],
        s: vec![0; 32],
        recovery_id: 0,
    };
    assert!(provider.finalize_transaction(&unsigned, &sig).is_err());
}

#[test]
fn test_registry_creates_all_substrate_chains() {
    let registry = ChainRegistry::default_mainnet();
    for chain in [
        Chain::Polkadot,
        Chain::Kusama,
        Chain::Astar,
        Chain::Acala,
        Chain::Phala,
        Chain::Interlay,
    ] {
        let provider = registry.provider(chain).unwrap();
        assert_eq!(provider.chain(), chain);
    }
}

#[test]
fn test_substrate_different_addresses_per_chain() {
    let pubkey = ed25519_pubkey();
    let dot = mpc_wallet_chains::substrate::SubstrateProvider::polkadot()
        .derive_address(&pubkey)
        .unwrap();
    let ksm = mpc_wallet_chains::substrate::SubstrateProvider::kusama()
        .derive_address(&pubkey)
        .unwrap();
    assert_ne!(
        dot, ksm,
        "Polkadot and Kusama must have different SS58 addresses"
    );
}
