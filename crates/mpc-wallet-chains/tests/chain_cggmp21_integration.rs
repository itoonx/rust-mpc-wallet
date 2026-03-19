//! CGGMP21 chain integration tests.
//!
//! CGGMP21 (CryptoScheme::Cggmp21Secp256k1) produces MpcSignature::Ecdsa,
//! identical to GG20. These tests verify that all secp256k1-based chain
//! providers accept CGGMP21-produced signatures without modification.

use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::MpcSignature;
use mpc_wallet_core::types::CryptoScheme;

// ============================================================================
// Helper: create a mock CGGMP21-produced ECDSA signature
// ============================================================================

/// Simulate a CGGMP21-produced ECDSA signature.
/// CGGMP21 outputs MpcSignature::Ecdsa with (r, s, recovery_id) — same as GG20.
fn cggmp21_ecdsa_signature() -> MpcSignature {
    // A valid low-s signature (s < secp256k1 n/2)
    MpcSignature::Ecdsa {
        r: vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ],
        s: vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ],
        recovery_id: 0,
    }
}

// ============================================================================
// EVM chain tests — CGGMP21 Ecdsa signatures
// ============================================================================

#[tokio::test]
async fn test_evm_with_cggmp21_signature() {
    let provider = mpc_wallet_chains::evm::EvmProvider::ethereum();
    let params = TransactionParams {
        to: "0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf".to_string(),
        value: "1000000000000000000".to_string(),
        data: None,
        chain_id: None,
        extra: None,
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let sig = cggmp21_ecdsa_signature();
    let signed = provider.finalize_transaction(&unsigned, &sig);
    assert!(
        signed.is_ok(),
        "EVM must accept CGGMP21-produced Ecdsa signature: {:?}",
        signed.err()
    );
    let signed = signed.unwrap();
    assert_eq!(signed.chain, Chain::Ethereum);
    assert!(!signed.raw_tx.is_empty());
    assert!(signed.tx_hash.starts_with("0x"));
}

#[tokio::test]
async fn test_evm_polygon_with_cggmp21_signature() {
    let provider =
        mpc_wallet_chains::evm::EvmProvider::new(Chain::Polygon).expect("Polygon is valid EVM");
    let params = TransactionParams {
        to: "0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf".to_string(),
        value: "1000000".to_string(),
        data: None,
        chain_id: None,
        extra: None,
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let sig = cggmp21_ecdsa_signature();
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Polygon);
    assert!(!signed.raw_tx.is_empty());
}

// ============================================================================
// UTXO chain tests — CGGMP21 Ecdsa signatures (legacy P2PKH)
// ============================================================================

#[tokio::test]
async fn test_litecoin_with_cggmp21_signature() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::litecoin();
    let params = TransactionParams {
        to: "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXBGd1".to_string(),
        value: "100000".to_string(),
        data: None,
        chain_id: None,
        extra: None,
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let sig = cggmp21_ecdsa_signature();
    let signed = provider.finalize_transaction(&unsigned, &sig);
    assert!(
        signed.is_ok(),
        "Litecoin (UTXO) must accept CGGMP21-produced Ecdsa signature"
    );
    assert_eq!(signed.unwrap().chain, Chain::Litecoin);
}

#[tokio::test]
async fn test_dogecoin_with_cggmp21_signature() {
    let provider = mpc_wallet_chains::utxo::UtxoProvider::dogecoin();
    let params = TransactionParams {
        to: "D5foobar123".to_string(),
        value: "50000".to_string(),
        data: None,
        chain_id: None,
        extra: None,
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let sig = cggmp21_ecdsa_signature();
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Dogecoin);
    assert!(!signed.raw_tx.is_empty());
}

// ============================================================================
// TRON — CGGMP21 Ecdsa signature
// ============================================================================

#[tokio::test]
async fn test_tron_with_cggmp21_signature() {
    let provider = mpc_wallet_chains::tron::TronProvider::new();
    let params = TransactionParams {
        to: "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW".to_string(),
        value: "1000000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({"owner_address": "41"})),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let sig = cggmp21_ecdsa_signature();
    let signed = provider.finalize_transaction(&unsigned, &sig);
    assert!(
        signed.is_ok(),
        "TRON must accept CGGMP21-produced Ecdsa signature"
    );
    assert_eq!(signed.unwrap().chain, Chain::Tron);
}

// ============================================================================
// Cosmos — CGGMP21 Ecdsa signature
// ============================================================================

#[tokio::test]
async fn test_cosmos_hub_with_cggmp21_signature() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::cosmos_hub();
    let params = TransactionParams {
        to: "cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu".to_string(),
        value: "1000000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({
            "from_address": "cosmos1abc...",
            "account_number": 0,
            "sequence": 0,
        })),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let sig = cggmp21_ecdsa_signature();
    let signed = provider.finalize_transaction(&unsigned, &sig);
    assert!(
        signed.is_ok(),
        "Cosmos Hub must accept CGGMP21-produced Ecdsa signature"
    );
    assert_eq!(signed.unwrap().chain, Chain::CosmosHub);
}

#[tokio::test]
async fn test_osmosis_with_cggmp21_signature() {
    let provider = mpc_wallet_chains::cosmos::CosmosProvider::osmosis();
    let params = TransactionParams {
        to: "osmo1abc".to_string(),
        value: "500000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({
            "from_address": "osmo1xyz...",
            "account_number": 1,
            "sequence": 0,
        })),
    };
    let unsigned = provider.build_transaction(params).await.unwrap();
    let sig = cggmp21_ecdsa_signature();
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Osmosis);
}

// ============================================================================
// Registry: compatible_schemes verification
// ============================================================================

#[test]
fn test_compatible_schemes_evm_includes_cggmp21() {
    let schemes = ChainRegistry::compatible_schemes(Chain::Ethereum);
    assert!(
        schemes.contains(&CryptoScheme::Cggmp21Secp256k1),
        "Ethereum compatible_schemes must include Cggmp21Secp256k1"
    );
    assert!(
        schemes.contains(&CryptoScheme::Gg20Ecdsa),
        "Ethereum compatible_schemes must include Gg20Ecdsa"
    );
}

#[test]
fn test_compatible_schemes_tron_includes_cggmp21() {
    let schemes = ChainRegistry::compatible_schemes(Chain::Tron);
    assert!(schemes.contains(&CryptoScheme::Cggmp21Secp256k1));
    assert!(schemes.contains(&CryptoScheme::Gg20Ecdsa));
}

#[test]
fn test_compatible_schemes_cosmos_includes_cggmp21() {
    for chain in [
        Chain::CosmosHub,
        Chain::Osmosis,
        Chain::Celestia,
        Chain::Injective,
        Chain::Sei,
    ] {
        let schemes = ChainRegistry::compatible_schemes(chain);
        assert!(
            schemes.contains(&CryptoScheme::Cggmp21Secp256k1),
            "{:?} must include CGGMP21",
            chain
        );
    }
}

#[test]
fn test_compatible_schemes_utxo_includes_cggmp21() {
    for chain in [Chain::Litecoin, Chain::Dogecoin, Chain::Zcash] {
        let schemes = ChainRegistry::compatible_schemes(chain);
        assert!(
            schemes.contains(&CryptoScheme::Cggmp21Secp256k1),
            "{:?} must include CGGMP21",
            chain
        );
    }
}

#[test]
fn test_compatible_schemes_bitcoin_includes_cggmp21_and_frost() {
    let schemes = ChainRegistry::compatible_schemes(Chain::BitcoinMainnet);
    assert!(schemes.contains(&CryptoScheme::Cggmp21Secp256k1));
    assert!(schemes.contains(&CryptoScheme::Gg20Ecdsa));
    assert!(schemes.contains(&CryptoScheme::FrostSecp256k1Tr));
}

#[test]
fn test_compatible_schemes_ed25519_chains_exclude_cggmp21() {
    for chain in [Chain::Solana, Chain::Sui] {
        let schemes = ChainRegistry::compatible_schemes(chain);
        assert!(
            !schemes.contains(&CryptoScheme::Cggmp21Secp256k1),
            "{:?} must NOT include CGGMP21 (Ed25519 only)",
            chain
        );
        assert!(schemes.contains(&CryptoScheme::FrostEd25519));
    }
}

#[test]
fn test_all_secp256k1_chains_accept_cggmp21() {
    // Comprehensive: every chain that lists Gg20Ecdsa must also list Cggmp21Secp256k1
    for chain in ChainRegistry::supported_chains() {
        let schemes = ChainRegistry::compatible_schemes(chain);
        if schemes.contains(&CryptoScheme::Gg20Ecdsa) {
            assert!(
                schemes.contains(&CryptoScheme::Cggmp21Secp256k1),
                "{:?} supports GG20 but not CGGMP21 — both produce Ecdsa signatures",
                chain
            );
        }
    }
}
