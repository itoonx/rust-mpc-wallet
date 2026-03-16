use mpc_wallet_chains::provider::{ChainProvider, TransactionParams};
use mpc_wallet_core::protocol::GroupPublicKey;

// ============================================================================
// Bitcoin address derivation tests
// ============================================================================

#[test]
fn test_bitcoin_taproot_address_derivation() {
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::mainnet();

    // A compressed secp256k1 key
    let pubkey_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let gpk = GroupPublicKey::Secp256k1(pubkey_bytes);

    let address = provider.derive_address(&gpk).unwrap();
    // Should be a bc1p... address (bech32m)
    assert!(
        address.starts_with("bc1p"),
        "expected bc1p address, got: {address}"
    );
}

#[test]
fn test_bitcoin_testnet_address() {
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::testnet();

    let pubkey_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    let gpk = GroupPublicKey::Secp256k1(pubkey_bytes);

    let address = provider.derive_address(&gpk).unwrap();
    // Testnet taproot addresses start with tb1p
    assert!(
        address.starts_with("tb1p"),
        "expected tb1p address, got: {address}"
    );
}

// ============================================================================
// Bitcoin testnet / signet address tests (R3b)
// ============================================================================

#[test]
fn test_bitcoin_testnet_p2tr_address_prefix() {
    // BitcoinProvider::testnet() address must start with "tb1p"
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::testnet();
    let pubkey = GroupPublicKey::Secp256k1([2u8; 33].to_vec());
    let addr = provider.derive_address(&pubkey).unwrap();
    assert!(
        addr.starts_with("tb1p"),
        "testnet P2TR must start with tb1p, got: {addr}"
    );
}

#[test]
fn test_bitcoin_signet_p2tr_address_prefix() {
    // BitcoinProvider::signet() address must also start with "tb1p"
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::signet();
    let pubkey = GroupPublicKey::Secp256k1([2u8; 33].to_vec());
    let addr = provider.derive_address(&pubkey).unwrap();
    assert!(
        addr.starts_with("tb1p"),
        "signet P2TR must start with tb1p, got: {addr}"
    );
}

#[test]
fn test_bitcoin_mainnet_p2tr_address_prefix() {
    // Existing mainnet address test — make sure still starts with "bc1p"
    let provider = mpc_wallet_chains::bitcoin::BitcoinProvider::mainnet();
    let pubkey = GroupPublicKey::Secp256k1([2u8; 33].to_vec());
    let addr = provider.derive_address(&pubkey).unwrap();
    assert!(
        addr.starts_with("bc1p"),
        "mainnet P2TR must start with bc1p, got: {addr}"
    );
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
