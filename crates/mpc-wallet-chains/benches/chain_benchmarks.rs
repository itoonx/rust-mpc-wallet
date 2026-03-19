//! Chain Provider Benchmarks
//!
//! Measures latency for chain-specific operations:
//! - Address derivation (per chain category)
//! - Transaction building
//! - Transaction simulation (risk scoring)
//!
//! Run: `cargo bench -p mpc-wallet-chains`

use criterion::{criterion_group, criterion_main, Criterion};

use mpc_wallet_chains::provider::{Chain, TransactionParams};
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::{KeyShare, MpcProtocol};
use mpc_wallet_core::transport::local::LocalTransportNetwork;
use mpc_wallet_core::types::{PartyId, ThresholdConfig};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Pre-generate key shares for benchmarking.
fn gen_ecdsa_shares() -> Vec<KeyShare> {
    let runtime = rt();
    runtime.block_on(async {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);
        let mut handles = Vec::new();
        for i in 1..=3 {
            let transport = net.get_transport(PartyId(i));
            let protocol = Box::new(mpc_wallet_core::protocol::gg20::Gg20Protocol::new())
                as Box<dyn MpcProtocol>;
            handles.push(tokio::spawn(async move {
                protocol.keygen(config, PartyId(i), &*transport).await
            }));
        }
        let mut shares = Vec::new();
        for h in handles {
            shares.push(h.await.unwrap().unwrap());
        }
        shares
    })
}

fn gen_ed25519_shares() -> Vec<KeyShare> {
    let runtime = rt();
    runtime.block_on(async {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let net = LocalTransportNetwork::new(3);
        let mut handles = Vec::new();
        for i in 1..=3 {
            let transport = net.get_transport(PartyId(i));
            let protocol =
                Box::new(mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol::new())
                    as Box<dyn MpcProtocol>;
            handles.push(tokio::spawn(async move {
                protocol.keygen(config, PartyId(i), &*transport).await
            }));
        }
        let mut shares = Vec::new();
        for h in handles {
            shares.push(h.await.unwrap().unwrap());
        }
        shares
    })
}

// ─── Address Derivation Benchmarks ──────────────────────────────────────────

fn bench_address_derivation(c: &mut Criterion) {
    let ecdsa_shares = gen_ecdsa_shares();
    let ed25519_shares = gen_ed25519_shares();
    let ecdsa_gpk = &ecdsa_shares[0].group_public_key;
    let ed25519_gpk = &ed25519_shares[0].group_public_key;

    let registry = ChainRegistry::default_testnet();
    let mut group = c.benchmark_group("address_derivation");

    // EVM (Keccak256 → checksum address)
    group.bench_function("evm_ethereum", |b| {
        let provider = registry.provider(Chain::Ethereum).unwrap();
        b.iter(|| provider.derive_address(ecdsa_gpk).unwrap());
    });

    // Bitcoin Taproot (bech32m)
    let secp_shares = {
        let runtime = rt();
        runtime.block_on(async {
            let config = ThresholdConfig::new(2, 3).unwrap();
            let net = LocalTransportNetwork::new(3);
            let mut handles = Vec::new();
            for i in 1..=3 {
                let transport = net.get_transport(PartyId(i));
                let protocol = Box::new(
                    mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol::new(),
                ) as Box<dyn MpcProtocol>;
                handles.push(tokio::spawn(async move {
                    protocol.keygen(config, PartyId(i), &*transport).await
                }));
            }
            let mut shares = Vec::new();
            for h in handles {
                shares.push(h.await.unwrap().unwrap());
            }
            shares
        })
    };
    let secp_gpk = &secp_shares[0].group_public_key;

    group.bench_function("bitcoin_taproot", |b| {
        let provider = registry.provider(Chain::BitcoinTestnet).unwrap();
        b.iter(|| provider.derive_address(secp_gpk).unwrap());
    });

    // Solana (Base58)
    group.bench_function("solana_base58", |b| {
        let provider = registry.provider(Chain::Solana).unwrap();
        b.iter(|| provider.derive_address(ed25519_gpk).unwrap());
    });

    // Sui (SHA256 → 0x hex)
    group.bench_function("sui_sha256", |b| {
        let provider = registry.provider(Chain::Sui).unwrap();
        b.iter(|| provider.derive_address(ed25519_gpk).unwrap());
    });

    // Cosmos (bech32)
    group.bench_function("cosmos_bech32", |b| {
        let provider = registry.provider(Chain::CosmosHub).unwrap();
        b.iter(|| provider.derive_address(ecdsa_gpk).unwrap());
    });

    // Substrate (SS58)
    group.bench_function("substrate_ss58", |b| {
        let provider = registry.provider(Chain::Polkadot).unwrap();
        b.iter(|| provider.derive_address(ed25519_gpk).unwrap());
    });

    group.finish();
}

// ─── Transaction Building Benchmarks ────────────────────────────────────────

fn bench_tx_building(c: &mut Criterion) {
    let runtime = rt();
    let _ecdsa_shares = gen_ecdsa_shares();
    let _ed25519_shares = gen_ed25519_shares();
    let registry = ChainRegistry::default_testnet();

    let mut group = c.benchmark_group("tx_building");

    // EVM EIP-1559 TX
    let evm_params = TransactionParams {
        to: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28".into(),
        value: "1000000000000000000".into(), // 1 ETH in wei
        data: None,
        chain_id: Some(1),
        extra: None,
    };

    group.bench_function("evm_build_tx", |b| {
        let provider = registry.provider(Chain::Ethereum).unwrap();
        b.to_async(&runtime)
            .iter(|| provider.build_transaction(evm_params.clone()));
    });

    // Solana Transfer TX
    let sol_params = TransactionParams {
        to: "11111111111111111111111111111112".into(),
        value: "1000000000".into(), // 1 SOL in lamports
        data: None,
        chain_id: None,
        extra: None,
    };

    group.bench_function("solana_build_tx", |b| {
        let provider = registry.provider(Chain::Solana).unwrap();
        b.to_async(&runtime)
            .iter(|| provider.build_transaction(sol_params.clone()));
    });

    group.finish();
}

// ─── Simulation Benchmarks ──────────────────────────────────────────────────

fn bench_simulation(c: &mut Criterion) {
    let runtime = rt();
    let registry = ChainRegistry::default_testnet();
    let mut group = c.benchmark_group("simulation");

    // EVM simulation (risk scoring)
    let evm_params = TransactionParams {
        to: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28".into(),
        value: "1000000000000000000".into(),
        data: Some(vec![0xa9, 0x05, 0x9c, 0xbb]), // transfer() selector
        chain_id: Some(1),
        extra: None,
    };

    group.bench_function("evm_simulate", |b| {
        let provider = registry.provider(Chain::Ethereum).unwrap();
        b.to_async(&runtime)
            .iter(|| provider.simulate_transaction(&evm_params));
    });

    // Solana simulation
    let sol_params = TransactionParams {
        to: "11111111111111111111111111111112".into(),
        value: "5000000000000".into(), // high value
        data: None,
        chain_id: None,
        extra: None,
    };

    group.bench_function("solana_simulate", |b| {
        let provider = registry.provider(Chain::Solana).unwrap();
        b.to_async(&runtime)
            .iter(|| provider.simulate_transaction(&sol_params));
    });

    // Bitcoin simulation
    let btc_params = TransactionParams {
        to: "tb1pexample".into(),
        value: "100000".into(), // 100k sats
        data: None,
        chain_id: None,
        extra: None,
    };

    group.bench_function("bitcoin_simulate", |b| {
        let provider = registry.provider(Chain::BitcoinTestnet).unwrap();
        b.to_async(&runtime)
            .iter(|| provider.simulate_transaction(&btc_params));
    });

    group.finish();
}

// ─── Register All Benchmarks ────────────────────────────────────────────────

criterion_group!(
    chain_benches,
    bench_address_derivation,
    bench_tx_building,
    bench_simulation,
);

criterion_main!(chain_benches);
