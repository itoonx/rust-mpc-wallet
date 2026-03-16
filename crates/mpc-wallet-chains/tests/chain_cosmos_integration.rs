use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

fn secp256k1_pubkey() -> GroupPublicKey {
    GroupPublicKey::Secp256k1(vec![2; 33])
}

fn transfer_params() -> TransactionParams {
    TransactionParams {
        to: "cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu".to_string(),
        value: "1000000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({
            "from_address": "cosmos1abc...",
            "account_number": 0,
            "sequence": 0,
        })),
    }
}

#[test]
fn test_cosmos_hub_address() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::cosmos_hub();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(
        addr.starts_with("cosmos1"),
        "Cosmos address must start with cosmos1"
    );
}

#[test]
fn test_osmosis_address() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::osmosis();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(addr.starts_with("osmo1"));
}

#[test]
fn test_celestia_address() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::celestia();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(addr.starts_with("celestia1"));
}

#[test]
fn test_injective_address() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::injective();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(addr.starts_with("inj1"));
}

#[test]
fn test_sei_address() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::sei();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(addr.starts_with("sei1"));
}

#[tokio::test]
async fn test_cosmos_sign_payload_32_bytes() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::cosmos_hub();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    assert_eq!(unsigned.sign_payload.len(), 32);
    assert_eq!(unsigned.chain, Chain::CosmosHub);
}

#[tokio::test]
async fn test_cosmos_finalize_ecdsa() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::cosmos_hub();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::Ecdsa {
        r: vec![0xAA; 32],
        s: vec![0xBB; 32],
        recovery_id: 0,
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::CosmosHub);
}

#[test]
fn test_registry_creates_all_cosmos_chains() {
    let registry = ChainRegistry::default_mainnet();
    for chain in [
        Chain::CosmosHub,
        Chain::Osmosis,
        Chain::Celestia,
        Chain::Injective,
        Chain::Sei,
    ] {
        let provider = registry.provider(chain).unwrap();
        assert_eq!(provider.chain(), chain);
    }
}

#[test]
fn test_cosmos_different_addresses_per_chain() {
    let pubkey = secp256k1_pubkey();
    let cosmos = mpc_wallet_chains::cosmos::CosmosProvider::cosmos_hub()
        .derive_address(&pubkey)
        .unwrap();
    let osmo = mpc_wallet_chains::cosmos::CosmosProvider::osmosis()
        .derive_address(&pubkey)
        .unwrap();
    assert_ne!(cosmos, osmo);
}
