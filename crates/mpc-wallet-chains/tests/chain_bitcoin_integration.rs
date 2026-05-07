use mpc_wallet_chains::provider::{ChainProvider, TransactionParams};
use mpc_wallet_core::protocol::GroupPublicKey;

// ============================================================================
// Bitcoin address derivation tests
// ============================================================================

// Sprint 40: BitcoinProvider::derive_address now defaults to P2WPKH (`bc1q…` /
// `tb1q…`). Taproot derivation still exists via `bitcoin::address::derive_taproot_address`
// but is parked behind ECDSA until FROST-Secp256k1-TR implements BIP-341 key tweaking.

#[test]
fn test_bitcoin_default_address_is_p2wpkh_mainnet() {
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::mainnet();
    let pubkey_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let gpk = GroupPublicKey::Secp256k1(pubkey_bytes);
    let address = provider.derive_address(&gpk).unwrap();
    assert!(
        address.starts_with("bc1q"),
        "expected bc1q P2WPKH address, got: {address}"
    );
}

#[test]
fn test_bitcoin_default_address_is_p2wpkh_testnet() {
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::testnet();
    let pubkey_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let gpk = GroupPublicKey::Secp256k1(pubkey_bytes);
    let address = provider.derive_address(&gpk).unwrap();
    assert!(
        address.starts_with("tb1q"),
        "expected tb1q P2WPKH address, got: {address}"
    );
}

#[test]
fn test_bitcoin_default_address_is_p2wpkh_signet() {
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::signet();
    let pubkey = GroupPublicKey::Secp256k1([2u8; 33].to_vec());
    let addr = provider.derive_address(&pubkey).unwrap();
    assert!(
        addr.starts_with("tb1q"),
        "signet default P2WPKH must start with tb1q, got: {addr}"
    );
}

#[test]
fn test_bitcoin_taproot_helper_still_works() {
    // The Taproot helper is still callable directly even though it's not the default.
    let pubkey = GroupPublicKey::Secp256k1([2u8; 33].to_vec());
    let mainnet = mpc_wallet_chains::bitcoin::address::derive_taproot_address(
        &pubkey,
        bitcoin::Network::Bitcoin,
    )
    .unwrap();
    let testnet = mpc_wallet_chains::bitcoin::address::derive_taproot_address(
        &pubkey,
        bitcoin::Network::Testnet,
    )
    .unwrap();
    assert!(mainnet.starts_with("bc1p"), "expected bc1p, got: {mainnet}");
    assert!(testnet.starts_with("tb1p"), "expected tb1p, got: {testnet}");
}

#[test]
fn test_bitcoin_mainnet_testnet_addresses_differ() {
    // Same pubkey should yield different addresses on mainnet vs testnet
    let pubkey = GroupPublicKey::Secp256k1([2u8; 33].to_vec());
    let mainnet_addr = mpc_wallet_chains::bitcoin::BitcoinProvider::mainnet()
        .derive_address(&pubkey)
        .unwrap();
    let testnet_addr = mpc_wallet_chains::bitcoin::BitcoinProvider::testnet()
        .derive_address(&pubkey)
        .unwrap();
    assert_ne!(mainnet_addr, testnet_addr);
}

// ============================================================================
// Bitcoin transaction simulation tests (R3b — T-S10-03)
// ============================================================================

#[tokio::test]
async fn test_bitcoin_simulation_basic() {
    use mpc_wallet_chains::bitcoin::{BitcoinProvider, BitcoinSimulationConfig};

    let provider = BitcoinProvider::testnet().with_simulation(BitcoinSimulationConfig::default());
    let params = TransactionParams {
        to: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
        value: "100000".into(), // 0.001 BTC — well above dust
        data: None,
        chain_id: None,
        extra: None,
    };
    let result = provider.simulate_transaction(&params).await.unwrap();
    assert!(result.success);
    assert_eq!(result.risk_score, 0);
    assert!(result.risk_flags.is_empty());
}

#[tokio::test]
async fn test_bitcoin_simulation_dust_detected() {
    use mpc_wallet_chains::bitcoin::{BitcoinProvider, BitcoinSimulationConfig};

    let provider = BitcoinProvider::testnet().with_simulation(BitcoinSimulationConfig::default());
    let params = TransactionParams {
        to: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
        value: "100".into(), // below 546 dust threshold
        data: None,
        chain_id: None,
        extra: None,
    };
    let result = provider.simulate_transaction(&params).await.unwrap();
    assert!(result.risk_flags.contains(&"dust_output".to_string()));
    assert!(result.risk_score >= 40);
}

#[tokio::test]
async fn test_bitcoin_simulation_high_fee() {
    use mpc_wallet_chains::bitcoin::{BitcoinProvider, BitcoinSimulationConfig};

    let provider = BitcoinProvider::testnet().with_simulation(BitcoinSimulationConfig::default());
    let params = TransactionParams {
        to: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".into(),
        value: "100000".into(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({
            "fee_rate_sat_vb": 1000,
            "fee_sat": 2_000_000
        })),
    };
    let result = provider.simulate_transaction(&params).await.unwrap();
    assert!(result.risk_flags.contains(&"high_fee_rate".to_string()));
    assert!(result.risk_flags.contains(&"excessive_fee".to_string()));
    assert!(result.risk_score >= 110);
}

#[tokio::test]
async fn test_bitcoin_simulation_not_configured() {
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::testnet();
    let params = TransactionParams {
        to: "tb1q".into(),
        value: "0".into(),
        data: None,
        chain_id: None,
        extra: None,
    };
    assert!(provider.simulate_transaction(&params).await.is_err());
}
