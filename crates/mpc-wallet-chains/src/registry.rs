//! Chain Registry — unified factory for chain providers.
//!
//! Centralizes provider instantiation so CLI commands and services
//! don't need to know about per-chain constructor patterns.

use serde::{Deserialize, Serialize};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::types::CryptoScheme;

use crate::aptos::AptosProvider;
use crate::bitcoin::BitcoinProvider;
use crate::cosmos::CosmosProvider;
use crate::evm::EvmProvider;
use crate::monero::MoneroProvider;
use crate::provider::{Chain, ChainProvider, SignedTransaction};
use crate::rpc::RpcRegistry;
use crate::solana::SolanaProvider;
use crate::starknet::StarknetProvider;
use crate::substrate::SubstrateProvider;
use crate::sui::SuiProvider;
use crate::ton::TonProvider;
use crate::tron::TronProvider;
use crate::utxo::UtxoProvider;

/// Network environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkEnv {
    Mainnet,
    Testnet,
    Devnet,
    Custom(String),
}

/// Chain registry — single entry point for creating chain providers.
///
/// # Usage
/// ```rust,no_run
/// use mpc_wallet_chains::registry::ChainRegistry;
/// use mpc_wallet_chains::provider::Chain;
///
/// let registry = ChainRegistry::default_mainnet();
/// let provider = registry.provider(Chain::Ethereum).unwrap();
/// ```
pub struct ChainRegistry {
    env: NetworkEnv,
    rpc: Option<RpcRegistry>,
}

impl ChainRegistry {
    /// Create a registry for mainnet chains.
    pub fn default_mainnet() -> Self {
        Self {
            env: NetworkEnv::Mainnet,
            rpc: None,
        }
    }

    /// Create a registry for testnet chains.
    pub fn default_testnet() -> Self {
        Self {
            env: NetworkEnv::Testnet,
            rpc: None,
        }
    }

    /// Attach an RPC registry for endpoint resolution.
    pub fn with_rpc(mut self, rpc: RpcRegistry) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Get a reference to the attached RPC registry, if any.
    pub fn rpc(&self) -> Option<&RpcRegistry> {
        self.rpc.as_ref()
    }

    /// Get the network environment.
    pub fn network(&self) -> &NetworkEnv {
        &self.env
    }

    /// Create a provider for the given chain.
    ///
    /// This is the single entry point — no more per-chain match blocks.
    pub fn provider(&self, chain: Chain) -> Result<Box<dyn ChainProvider>, CoreError> {
        let provider: Box<dyn ChainProvider> = match chain {
            Chain::Ethereum
            | Chain::Polygon
            | Chain::Bsc
            | Chain::Arbitrum
            | Chain::Optimism
            | Chain::Base
            | Chain::Avalanche
            | Chain::Linea
            | Chain::ZkSync
            | Chain::Scroll
            | Chain::Mantle
            | Chain::Blast
            | Chain::Zora
            | Chain::Fantom
            | Chain::Gnosis
            | Chain::Cronos
            | Chain::Celo
            | Chain::Moonbeam
            | Chain::Ronin
            | Chain::OpBnb
            | Chain::Immutable
            | Chain::MantaPacific
            | Chain::Hyperliquid
            | Chain::Berachain
            | Chain::MegaEth
            | Chain::Monad => Box::new(EvmProvider::new(chain)?),
            Chain::BitcoinMainnet => {
                let p = match self.env {
                    NetworkEnv::Testnet | NetworkEnv::Devnet => BitcoinProvider::testnet(),
                    _ => BitcoinProvider::mainnet(),
                };
                Box::new(p)
            }
            Chain::BitcoinTestnet => Box::new(BitcoinProvider::testnet()),
            Chain::Aptos => Box::new(AptosProvider::new()),
            Chain::Movement => Box::new(AptosProvider::movement()),
            Chain::Litecoin => Box::new(UtxoProvider::litecoin()),
            Chain::Dogecoin => Box::new(UtxoProvider::dogecoin()),
            Chain::Zcash => Box::new(UtxoProvider::zcash()),
            Chain::Polkadot => Box::new(SubstrateProvider::polkadot()),
            Chain::Kusama => Box::new(SubstrateProvider::kusama()),
            Chain::Astar => Box::new(SubstrateProvider::astar()),
            Chain::Acala => Box::new(SubstrateProvider::acala()),
            Chain::Phala => Box::new(SubstrateProvider::phala()),
            Chain::Interlay => Box::new(SubstrateProvider::interlay()),
            Chain::Monero => Box::new(MoneroProvider::new()),
            Chain::Ton => Box::new(TonProvider::new()),
            Chain::Tron => Box::new(TronProvider::new()),
            Chain::CosmosHub => Box::new(CosmosProvider::cosmos_hub()),
            Chain::Osmosis => Box::new(CosmosProvider::osmosis()),
            Chain::Celestia => Box::new(CosmosProvider::celestia()),
            Chain::Injective => Box::new(CosmosProvider::injective()),
            Chain::Sei => Box::new(CosmosProvider::sei()),
            Chain::Starknet => Box::new(StarknetProvider::new()),
            Chain::Solana => Box::new(SolanaProvider::new()),
            Chain::Sui => Box::new(SuiProvider::new()),
        };
        Ok(provider)
    }

    /// List all supported chains.
    pub fn supported_chains() -> Vec<Chain> {
        vec![
            // EVM L1s
            Chain::Ethereum,
            Chain::Polygon,
            Chain::Bsc,
            // EVM L2s — P0
            Chain::Arbitrum,
            Chain::Optimism,
            Chain::Base,
            // EVM L2s — P1
            Chain::Avalanche,
            Chain::Linea,
            Chain::ZkSync,
            Chain::Scroll,
            // EVM L2s — P2
            Chain::Mantle,
            Chain::Blast,
            Chain::Zora,
            Chain::Fantom,
            Chain::Gnosis,
            // EVM L2s — P3
            Chain::Cronos,
            Chain::Celo,
            Chain::Moonbeam,
            Chain::Ronin,
            Chain::OpBnb,
            Chain::Immutable,
            Chain::MantaPacific,
            // EVM — Phase 5 (Emerging)
            Chain::Hyperliquid,
            Chain::Berachain,
            Chain::MegaEth,
            Chain::Monad,
            // Move chains
            Chain::Aptos,
            Chain::Movement,
            // UTXO chains
            Chain::BitcoinMainnet,
            Chain::BitcoinTestnet,
            Chain::Litecoin,
            Chain::Dogecoin,
            Chain::Zcash,
            // CryptoNote
            Chain::Monero,
            // Alt L1s
            Chain::Ton,
            Chain::Tron,
            // Substrate / Polkadot
            Chain::Polkadot,
            Chain::Kusama,
            Chain::Astar,
            Chain::Acala,
            Chain::Phala,
            Chain::Interlay,
            // Cosmos / IBC
            Chain::CosmosHub,
            Chain::Osmosis,
            Chain::Celestia,
            Chain::Injective,
            Chain::Sei,
            // Specialized
            Chain::Starknet,
            // Other
            Chain::Solana,
            Chain::Sui,
        ]
    }

    /// Return the list of `CryptoScheme` variants that produce signatures
    /// compatible with the given chain's `finalize_transaction`.
    ///
    /// Both `Gg20Ecdsa` and `Cggmp21Secp256k1` produce `MpcSignature::Ecdsa`,
    /// so every secp256k1-based chain accepts either protocol.
    pub fn compatible_schemes(chain: Chain) -> Vec<CryptoScheme> {
        match chain {
            // EVM chains — secp256k1 ECDSA
            Chain::Ethereum
            | Chain::Polygon
            | Chain::Bsc
            | Chain::Arbitrum
            | Chain::Optimism
            | Chain::Base
            | Chain::Avalanche
            | Chain::Linea
            | Chain::ZkSync
            | Chain::Scroll
            | Chain::Mantle
            | Chain::Blast
            | Chain::Zora
            | Chain::Fantom
            | Chain::Gnosis
            | Chain::Cronos
            | Chain::Celo
            | Chain::Moonbeam
            | Chain::Ronin
            | Chain::OpBnb
            | Chain::Immutable
            | Chain::MantaPacific
            | Chain::Hyperliquid
            | Chain::Berachain
            | Chain::MegaEth
            | Chain::Monad => vec![CryptoScheme::Gg20Ecdsa, CryptoScheme::Cggmp21Secp256k1],

            // UTXO chains — legacy P2PKH uses ECDSA
            Chain::Litecoin | Chain::Dogecoin | Chain::Zcash => {
                vec![CryptoScheme::Gg20Ecdsa, CryptoScheme::Cggmp21Secp256k1]
            }

            // Bitcoin — Taproot uses Schnorr, but legacy would use ECDSA
            Chain::BitcoinMainnet | Chain::BitcoinTestnet => {
                vec![
                    CryptoScheme::FrostSecp256k1Tr,
                    CryptoScheme::Gg20Ecdsa,
                    CryptoScheme::Cggmp21Secp256k1,
                ]
            }

            // TRON — secp256k1 ECDSA
            Chain::Tron => vec![CryptoScheme::Gg20Ecdsa, CryptoScheme::Cggmp21Secp256k1],

            // Cosmos chains — secp256k1 ECDSA (or EdDSA for some, but primarily ECDSA)
            Chain::CosmosHub | Chain::Osmosis | Chain::Celestia | Chain::Injective | Chain::Sei => {
                vec![CryptoScheme::Gg20Ecdsa, CryptoScheme::Cggmp21Secp256k1]
            }

            // Ed25519 chains
            Chain::Solana | Chain::Sui | Chain::Aptos | Chain::Movement => {
                vec![CryptoScheme::FrostEd25519]
            }

            // Substrate chains — Sr25519
            Chain::Polkadot
            | Chain::Kusama
            | Chain::Astar
            | Chain::Acala
            | Chain::Phala
            | Chain::Interlay => vec![CryptoScheme::Sr25519Threshold],

            // StarkNet — STARK curve
            Chain::Starknet => vec![CryptoScheme::StarkThreshold],

            // TON — Ed25519
            Chain::Ton => vec![CryptoScheme::FrostEd25519],

            // Monero — Ed25519-like
            Chain::Monero => vec![CryptoScheme::FrostEd25519],
        }
    }

    /// Broadcast a signed transaction, resolving the RPC endpoint automatically.
    ///
    /// Uses `rest_endpoint()` for Bitcoin chains, `endpoint()` for JSON-RPC chains.
    /// Requires an `RpcRegistry` to be attached via `with_rpc()`.
    pub async fn broadcast(&self, signed: &SignedTransaction) -> Result<String, CoreError> {
        let rpc = self
            .rpc
            .as_ref()
            .ok_or_else(|| CoreError::Other("no RPC registry attached".into()))?;

        let url = match signed.chain {
            Chain::BitcoinMainnet | Chain::BitcoinTestnet => rpc.rest_endpoint(signed.chain)?,
            _ => rpc.endpoint(signed.chain)?,
        };

        let provider = self.provider(signed.chain)?;
        provider.broadcast(signed, &url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_registry_creates_all_chains() {
        let registry = ChainRegistry::default_mainnet();
        for chain in ChainRegistry::supported_chains() {
            let provider = registry.provider(chain);
            assert!(
                provider.is_ok(),
                "failed to create provider for {:?}",
                chain
            );
            assert_eq!(provider.unwrap().chain(), chain);
        }
    }

    #[test]
    fn test_registry_testnet() {
        let registry = ChainRegistry::default_testnet();
        let btc = registry.provider(Chain::BitcoinTestnet).unwrap();
        assert_eq!(btc.chain(), Chain::BitcoinTestnet);
    }

    #[test]
    fn test_registry_derive_address_evm() {
        use mpc_wallet_core::protocol::GroupPublicKey;
        let registry = ChainRegistry::default_mainnet();
        let provider = registry.provider(Chain::Ethereum).unwrap();
        // Use a known secp256k1 pubkey (65 bytes, 0x04 prefix)
        let pubkey = GroupPublicKey::Secp256k1Uncompressed(vec![4; 65]);
        // Just verify it doesn't panic — actual address correctness tested elsewhere
        let _ = provider.derive_address(&pubkey);
    }

    #[test]
    fn test_supported_chains_count() {
        assert_eq!(ChainRegistry::supported_chains().len(), 50);
    }

    #[test]
    fn test_registry_network_env() {
        let r = ChainRegistry::default_mainnet();
        assert_eq!(*r.network(), NetworkEnv::Mainnet);
        let r = ChainRegistry::default_testnet();
        assert_eq!(*r.network(), NetworkEnv::Testnet);
    }

    #[test]
    fn test_compatible_schemes_all_evm_include_cggmp21() {
        use mpc_wallet_core::types::CryptoScheme;
        let evm_chains = vec![
            Chain::Ethereum,
            Chain::Polygon,
            Chain::Bsc,
            Chain::Arbitrum,
            Chain::Base,
        ];
        for chain in evm_chains {
            let schemes = ChainRegistry::compatible_schemes(chain);
            assert!(
                schemes.contains(&CryptoScheme::Cggmp21Secp256k1),
                "{:?} must include CGGMP21",
                chain
            );
            assert!(
                schemes.contains(&CryptoScheme::Gg20Ecdsa),
                "{:?} must include GG20",
                chain
            );
        }
    }

    #[test]
    fn test_compatible_schemes_ed25519_no_ecdsa() {
        use mpc_wallet_core::types::CryptoScheme;
        let schemes = ChainRegistry::compatible_schemes(Chain::Solana);
        assert!(schemes.contains(&CryptoScheme::FrostEd25519));
        assert!(!schemes.contains(&CryptoScheme::Gg20Ecdsa));
        assert!(!schemes.contains(&CryptoScheme::Cggmp21Secp256k1));
    }

    #[test]
    fn test_registry_bitcoin_mainnet_in_testnet_env() {
        // When the registry is testnet, BitcoinMainnet chain should use testnet network
        let registry = ChainRegistry::default_testnet();
        let provider = registry.provider(Chain::BitcoinMainnet).unwrap();
        // BitcoinProvider in testnet env returns BitcoinTestnet chain
        assert_eq!(provider.chain(), Chain::BitcoinTestnet);
    }
}
