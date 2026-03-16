//! Chain Registry — unified factory for chain providers.
//!
//! Centralizes provider instantiation so CLI commands and services
//! don't need to know about per-chain constructor patterns.

use serde::{Deserialize, Serialize};

use mpc_wallet_core::error::CoreError;

use crate::bitcoin::BitcoinProvider;
use crate::evm::EvmProvider;
use crate::provider::{Chain, ChainProvider};
use crate::solana::SolanaProvider;
use crate::sui::SuiProvider;

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
}

impl ChainRegistry {
    /// Create a registry for mainnet chains.
    pub fn default_mainnet() -> Self {
        Self {
            env: NetworkEnv::Mainnet,
        }
    }

    /// Create a registry for testnet chains.
    pub fn default_testnet() -> Self {
        Self {
            env: NetworkEnv::Testnet,
        }
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
            Chain::Ethereum | Chain::Polygon | Chain::Bsc => {
                Box::new(EvmProvider::new(chain)?)
            }
            Chain::BitcoinMainnet => {
                let p = match self.env {
                    NetworkEnv::Testnet | NetworkEnv::Devnet => BitcoinProvider::testnet(),
                    _ => BitcoinProvider::mainnet(),
                };
                Box::new(p)
            }
            Chain::BitcoinTestnet => Box::new(BitcoinProvider::testnet()),
            Chain::Solana => Box::new(SolanaProvider::new()),
            Chain::Sui => Box::new(SuiProvider::new()),
        };
        Ok(provider)
    }

    /// List all supported chains.
    pub fn supported_chains() -> Vec<Chain> {
        vec![
            Chain::Ethereum,
            Chain::Polygon,
            Chain::Bsc,
            Chain::BitcoinMainnet,
            Chain::BitcoinTestnet,
            Chain::Solana,
            Chain::Sui,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ChainProvider;

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
        assert_eq!(ChainRegistry::supported_chains().len(), 7);
    }

    #[test]
    fn test_registry_network_env() {
        let r = ChainRegistry::default_mainnet();
        assert_eq!(*r.network(), NetworkEnv::Mainnet);
        let r = ChainRegistry::default_testnet();
        assert_eq!(*r.network(), NetworkEnv::Testnet);
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
