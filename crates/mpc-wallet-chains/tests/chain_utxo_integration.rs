use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

fn secp256k1_pubkey() -> GroupPublicKey {
    GroupPublicKey::Secp256k1(vec![2; 33])
}

fn transfer_params() -> TransactionParams {
    TransactionParams {
        to: "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXBGd1".to_string(),
        value: "100000".to_string(),
        data: None,
        chain_id: None,
        extra: None,
    }
}

#[test]
fn test_litecoin_address_derivation() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::litecoin();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(!addr.is_empty());
    assert_eq!(provider.chain(), Chain::Litecoin);
}

#[test]
fn test_dogecoin_address_derivation() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::dogecoin();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(!addr.is_empty());
    assert_eq!(provider.chain(), Chain::Dogecoin);
}

#[test]
fn test_zcash_address_derivation() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::zcash();
    let addr = provider.derive_address(&secp256k1_pubkey()).unwrap();
    assert!(!addr.is_empty());
    assert_eq!(provider.chain(), Chain::Zcash);
}

#[test]
fn test_utxo_rejects_ed25519_key() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::litecoin();
    let pubkey = GroupPublicKey::Ed25519(vec![1; 32]);
    assert!(provider.derive_address(&pubkey).is_err());
}

#[tokio::test]
async fn test_utxo_build_sign_payload_32_bytes() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::litecoin();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    assert_eq!(unsigned.sign_payload.len(), 32);
    assert_eq!(unsigned.chain, Chain::Litecoin);
}

#[tokio::test]
async fn test_utxo_finalize_ecdsa() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::dogecoin();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::Ecdsa {
        r: vec![0xAA; 32],
        s: vec![0xBB; 32],
        recovery_id: 0,
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Dogecoin);
    assert!(!signed.raw_tx.is_empty());
}

#[tokio::test]
async fn test_utxo_rejects_eddsa_signature() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::zcash();
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::EdDsa { signature: [0; 64] };
    assert!(provider.finalize_transaction(&unsigned, &sig).is_err());
}

#[test]
fn test_registry_creates_utxo_chains() {
    let registry = ChainRegistry::default_mainnet();
    for chain in [Chain::Litecoin, Chain::Dogecoin, Chain::Zcash] {
        let provider = registry.provider(chain).unwrap();
        assert_eq!(provider.chain(), chain);
    }
}

#[test]
fn test_utxo_different_addresses_per_chain() {
    let pubkey = secp256k1_pubkey();
    let ltc = mpc_wallet_chains::utxo::UtxoProvider::litecoin()
        .derive_address(&pubkey)
        .unwrap();
    let doge = mpc_wallet_chains::utxo::UtxoProvider::dogecoin()
        .derive_address(&pubkey)
        .unwrap();
    let zec = mpc_wallet_chains::utxo::UtxoProvider::zcash()
        .derive_address(&pubkey)
        .unwrap();
    assert_ne!(ltc, doge);
    assert_ne!(ltc, zec);
    assert_ne!(doge, zec);
}
