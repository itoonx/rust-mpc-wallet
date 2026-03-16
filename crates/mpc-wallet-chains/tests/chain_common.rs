// Shared test imports and helpers for chain integration tests
//
// This file is a placeholder for helpers shared across multiple chain test files.
// Currently each chain test file is self-contained. Add shared helpers here as needed.
//
// Per-chain test files:
//   chain_evm_integration.rs     — EVM (Ethereum, Polygon, BSC) tests
//   chain_bitcoin_integration.rs — Bitcoin (mainnet, testnet, signet) tests
//   chain_solana_integration.rs  — Solana tests
//   chain_sui_integration.rs     — Sui tests

// ============================================================================
// SimulationResult tests
// ============================================================================

#[test]
fn test_simulation_result_construction_and_serde() {
    use mpc_wallet_chains::provider::SimulationResult;

    let result = SimulationResult {
        success: true,
        gas_used: 21000,
        return_data: vec![0xde, 0xad],
        risk_flags: vec!["proxy_detected".into(), "large_approval".into()],
        risk_score: 42,
    };
    assert!(result.success);
    assert_eq!(result.gas_used, 21000);
    assert_eq!(result.return_data, vec![0xde, 0xad]);
    assert_eq!(result.risk_flags.len(), 2);
    assert_eq!(result.risk_score, 42);

    // Verify JSON serialization roundtrip
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: SimulationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.success, true);
    assert_eq!(deserialized.gas_used, 21000);
    assert_eq!(deserialized.return_data, vec![0xde, 0xad]);
    assert_eq!(deserialized.risk_flags, vec!["proxy_detected", "large_approval"]);
    assert_eq!(deserialized.risk_score, 42);
}

/// Verify that the default `simulate_transaction` returns an error for all chain providers.
#[tokio::test]
async fn test_simulate_transaction_default_returns_not_implemented() {
    use mpc_wallet_chains::provider::{ChainProvider, TransactionParams};

    let providers: Vec<Box<dyn ChainProvider>> = vec![
        Box::new(mpc_wallet_chains::evm::EvmProvider::ethereum()),
        Box::new(mpc_wallet_chains::bitcoin::BitcoinProvider::mainnet()),
        Box::new(mpc_wallet_chains::solana::SolanaProvider::new()),
        Box::new(mpc_wallet_chains::sui::SuiProvider::new()),
    ];

    let dummy_params = TransactionParams {
        to: "0x0000000000000000000000000000000000000000".into(),
        value: "0".into(),
        data: None,
        chain_id: Some(1),
        extra: None,
    };

    for provider in &providers {
        let result = provider.simulate_transaction(&dummy_params).await;
        assert!(result.is_err(), "default simulate_transaction must return Err for {:?}", provider.chain());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("simulation not implemented"),
            "error should mention simulation: {err_msg}"
        );
    }
}
