use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

fn ed25519_pubkey() -> GroupPublicKey {
    GroupPublicKey::Ed25519([1u8; 32].to_vec())
}

fn transfer_params() -> TransactionParams {
    TransactionParams {
        to: format!("0x{}", "ab".repeat(32)),
        value: "1000".to_string(),
        data: None,
        chain_id: None,
        extra: Some(serde_json::json!({
            "sender": format!("0x{}", "01".repeat(32)),
            "sequence_number": 0,
            "max_gas_amount": 2000,
            "gas_unit_price": 100,
            "expiration_timestamp_secs": 9999999999u64,
            "chain_id": 1
        })),
    }
}

// ============================================================================
// Address derivation tests
// ============================================================================

#[test]
fn test_aptos_address_derivation() {
    let provider = mpc_wallet_chains::aptos::AptosProvider::new();
    let pubkey = ed25519_pubkey();
    let addr = provider.derive_address(&pubkey).unwrap();
    assert!(addr.starts_with("0x"), "Aptos address must start with 0x");
    assert_eq!(
        addr.len(),
        66,
        "Aptos address must be 66 chars (0x + 64 hex)"
    );
}

#[test]
fn test_aptos_rejects_secp256k1_key() {
    let provider = mpc_wallet_chains::aptos::AptosProvider::new();
    let pubkey = GroupPublicKey::Secp256k1(vec![2; 33]);
    assert!(provider.derive_address(&pubkey).is_err());
}

#[test]
fn test_aptos_address_uses_sha3_not_blake2() {
    // Verify Aptos address differs from Sui for same pubkey (different hash algorithm)
    let pubkey = ed25519_pubkey();
    let aptos_addr = mpc_wallet_chains::aptos::address::derive_aptos_address(&pubkey).unwrap();
    let sui_addr = mpc_wallet_chains::sui::address::derive_sui_address(&pubkey).unwrap();
    assert_ne!(
        aptos_addr, sui_addr,
        "Aptos and Sui must produce different addresses for same key"
    );
}

// ============================================================================
// Address validation tests
// ============================================================================

#[test]
fn test_aptos_validate_address_valid() {
    let addr = format!("0x{}", "ab".repeat(32));
    assert!(mpc_wallet_chains::aptos::validate_aptos_address(&addr).is_ok());
}

#[test]
fn test_aptos_validate_address_missing_prefix() {
    let addr = "ab".repeat(32);
    assert!(mpc_wallet_chains::aptos::validate_aptos_address(&addr).is_err());
}

#[test]
fn test_aptos_validate_address_wrong_length() {
    assert!(mpc_wallet_chains::aptos::validate_aptos_address("0xabcd").is_err());
}

// ============================================================================
// Transaction building tests
// ============================================================================

#[tokio::test]
async fn test_aptos_sign_payload_is_prefix_plus_bcs() {
    // Sprint 42 fix: sign_payload is the raw Ed25519 message
    // (prefix(32) ‖ BCS(RawTransaction)), NOT a 32-byte SHA3-256 digest.
    // Pre-hashing here would double-hash through Ed25519's internal SHA-512
    // and Aptos validators reject with INVALID_SIGNATURE.
    let provider = mpc_wallet_chains::aptos::AptosProvider::with_pubkey(ed25519_pubkey());
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    assert!(
        unsigned.sign_payload.len() > 32,
        "sign_payload must contain prefix ‖ bcs_bytes, got {}",
        unsigned.sign_payload.len()
    );
    assert_eq!(unsigned.chain, Chain::Aptos);
}

#[tokio::test]
async fn test_aptos_rejects_wrong_key_type_in_build() {
    let provider =
        mpc_wallet_chains::aptos::AptosProvider::with_pubkey(GroupPublicKey::Secp256k1(vec![
            2;
            33
        ]));
    assert!(provider.build_transaction(transfer_params()).await.is_err());
}

// ============================================================================
// Finalization tests
// ============================================================================

#[tokio::test]
async fn test_aptos_finalize_correct_format() {
    let provider = mpc_wallet_chains::aptos::AptosProvider::with_pubkey(ed25519_pubkey());
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::EdDsa {
        signature: [0xBB; 64],
    };
    let signed = provider.finalize_transaction(&unsigned, &sig).unwrap();
    assert_eq!(signed.chain, Chain::Aptos);
    // raw_tx = bcs_bytes ‖ Authenticator(99 bytes) where the auth is
    //   0x00 (variant) ‖ 0x20 (vec len) ‖ pubkey(32) ‖ 0x40 (vec len) ‖ sig(64).
    // Verified against @aptos-labs/ts-sdk in tests/chain_aptos_integration.rs.
    let bcs_len = unsigned.tx_data.len() - 32;
    assert_eq!(signed.raw_tx.len(), bcs_len + 99);
    assert_eq!(signed.raw_tx[bcs_len], 0x00, "Ed25519 variant tag");
    assert_eq!(
        signed.raw_tx[bcs_len + 1],
        0x20,
        "vec<u8> len = 32 (pubkey)"
    );
    assert_eq!(signed.raw_tx[bcs_len + 34], 0x40, "vec<u8> len = 64 (sig)");
    assert_eq!(
        &signed.raw_tx[bcs_len + 35..bcs_len + 99],
        &[0xBB; 64],
        "signature bytes"
    );
}

#[tokio::test]
async fn test_aptos_rejects_wrong_signature_type() {
    let provider = mpc_wallet_chains::aptos::AptosProvider::with_pubkey(ed25519_pubkey());
    let unsigned = provider.build_transaction(transfer_params()).await.unwrap();
    let sig = MpcSignature::Ecdsa {
        r: vec![0; 32],
        s: vec![0; 32],
        recovery_id: 0,
    };
    assert!(provider.finalize_transaction(&unsigned, &sig).is_err());
}

// ============================================================================
// Provider + broadcast tests
// ============================================================================

#[test]
fn test_aptos_provider_default_works() {
    let provider = mpc_wallet_chains::aptos::AptosProvider::new();
    let pubkey = ed25519_pubkey();
    let addr = provider.derive_address(&pubkey).unwrap();
    assert!(addr.starts_with("0x"));
}

#[tokio::test]
async fn test_aptos_broadcast_invalid_url_returns_error() {
    use mpc_wallet_chains::provider::SignedTransaction;
    let provider = mpc_wallet_chains::aptos::AptosProvider::new();
    let fake_signed = SignedTransaction {
        chain: Chain::Aptos,
        raw_tx: vec![0u8; 128],
        tx_hash: "0xdeadbeef".to_string(),
    };
    let result = provider
        .broadcast(&fake_signed, "http://invalid.localhost:1")
        .await;
    assert!(result.is_err());
}

// ============================================================================
// Simulation tests
// ============================================================================

#[tokio::test]
async fn test_aptos_simulation_high_value() {
    let provider = mpc_wallet_chains::aptos::AptosProvider::new()
        .with_simulation(mpc_wallet_chains::aptos::AptosSimulationConfig::default());
    let mut params = transfer_params();
    params.value = "999999999999999".to_string();
    let result = provider.simulate_transaction(&params).await.unwrap();
    assert!(result.risk_flags.contains(&"high_value".to_string()));
    assert!(result.risk_score >= 50);
}

#[tokio::test]
async fn test_aptos_simulation_excessive_gas() {
    let provider = mpc_wallet_chains::aptos::AptosProvider::new()
        .with_simulation(mpc_wallet_chains::aptos::AptosSimulationConfig::default());
    let mut params = transfer_params();
    params.extra = Some(serde_json::json!({
        "sender": format!("0x{}", "01".repeat(32)),
        "max_gas_amount": 999999
    }));
    let result = provider.simulate_transaction(&params).await.unwrap();
    assert!(result.risk_flags.contains(&"excessive_gas".to_string()));
}

// ============================================================================
// Registry tests
// ============================================================================

#[test]
fn test_registry_creates_aptos_provider() {
    use mpc_wallet_chains::registry::ChainRegistry;
    let registry = ChainRegistry::default_mainnet();
    let provider = registry.provider(Chain::Aptos).unwrap();
    assert_eq!(provider.chain(), Chain::Aptos);
}
