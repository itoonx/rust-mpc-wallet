use mpc_wallet_chains::provider::ChainProvider;
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
