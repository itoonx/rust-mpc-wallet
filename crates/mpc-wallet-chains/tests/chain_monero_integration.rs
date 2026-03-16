use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

fn ed25519_pubkey() -> GroupPublicKey {
    GroupPublicKey::Ed25519(vec![1; 32])
}

fn transfer_params() -> TransactionParams {
    TransactionParams {
        to: "4".to_string() + &"a".repeat(94), // simplified Monero address
        value: "1000000000000".to_string(),
        data: None,
        chain_id: None,
        extra: None,
    }
}

#[test]
fn test_monero_address_derivation() {
    let provider = mpc_wallet_chains::monero::MoneroProvider::new();
    let addr = provider.derive_address(&ed25519_pubkey()).unwrap();
    assert!(!addr.is_empty());
    assert_eq!(provider.chain(), Chain::Monero);
}

#[test]
fn test_monero_rejects_secp256k1() {
    let provider = mpc_wallet_chains::monero::MoneroProvider::new();
    let pubkey = GroupPublicKey::Secp256k1(vec![2; 33]);
    assert!(provider.derive_address(&pubkey).is_err());
}

#[tokio::test]
async fn test_monero_sign_payload_32_bytes() {
    let provider = mpc_wallet_chains::monero::MoneroProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    assert_eq!(unsigned.sign_payload.len(), 32);
    assert_eq!(unsigned.chain, Chain::Monero);
}

#[tokio::test]
async fn test_monero_finalize_ed25519() {
    let provider = mpc_wallet_chains::monero::MoneroProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::EdDsa {
        signature: [0xEE; 64],
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Monero);
}

#[tokio::test]
async fn test_monero_rejects_ecdsa() {
    let provider = mpc_wallet_chains::monero::MoneroProvider::new();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::Ecdsa {
        r: vec![0; 32],
        s: vec![0; 32],
        recovery_id: 0,
    };
    assert!(provider.finalize_transaction(&unsigned, &sig).is_err());
}

#[test]
fn test_registry_creates_monero() {
    let registry = ChainRegistry::default_mainnet();
    let provider = registry.provider(Chain::Monero).unwrap();
    assert_eq!(provider.chain(), Chain::Monero);
}
