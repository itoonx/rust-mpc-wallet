//! Per-chain compile-time metadata — single source of truth.
//!
//! Adding a new chain to the LIVE set = one entry in `CHAIN_METADATA`.
//! No more grep-and-edit across CLI helpers, RPC URL resolvers, balance
//! checks, explorer URL constructors, faucet hint strings, and unit
//! name `eprintln!()`s.
//!
//! Static const so the metadata is type-safe, compile-time, and
//! IDE-jumpable. Wraps:
//!   - native symbol / unit / decimals
//!   - default address format
//!   - compatible MPC schemes
//!   - accepted token standards
//!   - per-network info (RPC URL, explorer base, faucet URL, chain id)
//!   - Dwellir slug for RPC provider lookup
//!
//! Scope: 6 LIVE chains in this iteration (EVM L1+L2s, Bitcoin, Solana,
//! Sui, Aptos, TRON). Substrate/Cosmos/Ton/Monero/Starknet to follow.

use mpc_wallet_core::types::CryptoScheme;

use crate::address_type::AddressType;
use crate::provider::Chain;
use crate::registry::NetworkEnv;

/// Top-level token standards recognized cross-chain. Mirrors the
/// discriminants of `TokenIdentifier` but flattens away the per-standard
/// payload so `ChainMetadata` can declare *which* token kinds a chain
/// accepts without carrying any token instance data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStandard {
    Native,
    Erc20,
    Erc721,
    Erc1155,
    SplToken,
    SplToken2022,
    SuiCoin,
    AptosLegacyCoin,
    AptosFungibleAsset,
    Trc20,
}

/// Per-network endpoint info. One per (chain, env) the provider supports.
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub env: NetworkEnv,
    /// Numeric chain id (EVM only — `None` for non-EVM).
    pub chain_id: Option<u64>,
    /// Public default RPC URL for this (chain, env). Overridable by env var
    /// or CLI flag at the caller level.
    pub default_rpc: &'static str,
    /// Explorer base URL (no trailing slash). E.g. `https://etherscan.io`.
    pub explorer_base_url: &'static str,
    /// Path between base URL and tx hash. E.g. `/tx/`.
    pub explorer_tx_path: &'static str,
    /// Optional faucet URL for testnets. `None` for mainnet.
    pub faucet_url: Option<&'static str>,
    /// Subdomain slug for the Dwellir RPC provider for THIS network.
    /// Slugs typically vary per env (e.g. `ethereum-mainnet` vs
    /// `ethereum-sepolia`). `None` if Dwellir does not host this
    /// (chain, env).
    pub dwellir_slug: Option<&'static str>,
}

impl NetworkInfo {
    /// Build the full explorer URL for a tx hash on this network.
    pub fn explorer_tx_url(&self, tx_hash: &str) -> String {
        format!(
            "{}{}{}",
            self.explorer_base_url, self.explorer_tx_path, tx_hash
        )
    }
}

/// Compile-time per-chain metadata. Each `ChainMetadata` entry is the
/// single source of truth for a chain — adding a new chain = adding one
/// entry to `CHAIN_METADATA`, then writing the provider impl.
#[derive(Debug, Clone)]
pub struct ChainMetadata {
    pub chain: Chain,
    /// Human-readable name. E.g. `"Ethereum"`, `"Bitcoin Testnet"`.
    pub display_name: &'static str,
    /// Native asset ticker. E.g. `"ETH"`, `"SOL"`, `"BTC"`.
    pub native_symbol: &'static str,
    /// Smallest unit name for `eprintln!` and CLI display.
    /// E.g. `"wei"`, `"lamports"`, `"MIST"`, `"octas"`, `"sun"`, `"sat"`.
    pub native_unit: &'static str,
    /// Decimals to convert smallest unit → display unit. 18 for ETH, 9 for
    /// SOL/SUI, 8 for BTC/APT (legacy was 6 — confirm per-chain), 6 for TRX.
    pub native_decimals: u8,
    /// Default address derivation format for this chain.
    pub default_addr_type: AddressType,
    /// MPC schemes whose signatures can be finalized into this chain's
    /// signed-tx format.
    pub compatible_schemes: &'static [CryptoScheme],
    /// Token standards this chain accepts (always includes `Native`).
    pub token_standards: &'static [TokenStandard],
    /// Per-network endpoint records.
    pub networks: &'static [NetworkInfo],
}

impl ChainMetadata {
    /// Lookup the network record for a given environment. `None` if this
    /// chain does not have an entry for that env.
    pub fn network(&self, env: &NetworkEnv) -> Option<&NetworkInfo> {
        self.networks.iter().find(|n| &n.env == env)
    }

    /// Convenience: does this chain accept a given token standard?
    pub fn supports(&self, standard: TokenStandard) -> bool {
        self.token_standards.contains(&standard)
    }
}

// ── Per-network records ────────────────────────────────────────────────
// Stored as named consts so per-chain ChainMetadata entries stay readable.

const ETHEREUM_NETWORKS: &[NetworkInfo] = &[
    NetworkInfo {
        env: NetworkEnv::Mainnet,
        chain_id: Some(1),
        default_rpc: "https://eth.llamarpc.com",
        explorer_base_url: "https://etherscan.io",
        explorer_tx_path: "/tx/",
        faucet_url: None,
        dwellir_slug: Some("ethereum-mainnet"),
    },
    NetworkInfo {
        env: NetworkEnv::Testnet,
        chain_id: Some(11_155_111),
        default_rpc: "https://ethereum-sepolia-rpc.publicnode.com",
        explorer_base_url: "https://sepolia.etherscan.io",
        explorer_tx_path: "/tx/",
        faucet_url: Some("https://sepoliafaucet.com"),
        dwellir_slug: Some("ethereum-sepolia"),
    },
];

const BITCOIN_TESTNET_NETWORKS: &[NetworkInfo] = &[NetworkInfo {
    env: NetworkEnv::Testnet,
    chain_id: None,
    default_rpc: "https://blockstream.info/testnet/api",
    explorer_base_url: "https://mempool.space/testnet",
    explorer_tx_path: "/tx/",
    faucet_url: Some("https://coinfaucet.eu/en/btc-testnet/"),
    dwellir_slug: None, // Dwellir does not host Bitcoin REST
}];

const SOLANA_NETWORKS: &[NetworkInfo] = &[
    NetworkInfo {
        env: NetworkEnv::Mainnet,
        chain_id: None,
        default_rpc: "https://api.mainnet-beta.solana.com",
        explorer_base_url: "https://explorer.solana.com",
        explorer_tx_path: "/tx/",
        faucet_url: None,
        dwellir_slug: Some("solana-mainnet"),
    },
    NetworkInfo {
        env: NetworkEnv::Devnet,
        chain_id: None,
        default_rpc: "https://api.devnet.solana.com",
        explorer_base_url: "https://explorer.solana.com",
        explorer_tx_path: "/tx/",
        faucet_url: Some("https://faucet.solana.com"),
        dwellir_slug: Some("solana-devnet"),
    },
    NetworkInfo {
        env: NetworkEnv::Testnet,
        chain_id: None,
        default_rpc: "https://api.testnet.solana.com",
        explorer_base_url: "https://explorer.solana.com",
        explorer_tx_path: "/tx/",
        faucet_url: Some("https://faucet.solana.com"),
        dwellir_slug: Some("solana-testnet"),
    },
];

const SUI_NETWORKS: &[NetworkInfo] = &[
    NetworkInfo {
        env: NetworkEnv::Mainnet,
        chain_id: None,
        default_rpc: "https://fullnode.mainnet.sui.io:443",
        explorer_base_url: "https://suiscan.xyz/mainnet",
        explorer_tx_path: "/tx/",
        faucet_url: None,
        dwellir_slug: Some("sui-mainnet"),
    },
    NetworkInfo {
        env: NetworkEnv::Testnet,
        chain_id: None,
        default_rpc: "https://fullnode.testnet.sui.io:443",
        explorer_base_url: "https://suiscan.xyz/testnet",
        explorer_tx_path: "/tx/",
        faucet_url: Some("https://faucet.sui.io/"),
        dwellir_slug: Some("sui-testnet"),
    },
    NetworkInfo {
        env: NetworkEnv::Devnet,
        chain_id: None,
        default_rpc: "https://fullnode.devnet.sui.io:443",
        explorer_base_url: "https://suiscan.xyz/devnet",
        explorer_tx_path: "/tx/",
        faucet_url: Some("https://faucet.sui.io/"),
        dwellir_slug: None, // Dwellir does not list Sui devnet
    },
];

const APTOS_NETWORKS: &[NetworkInfo] = &[
    NetworkInfo {
        env: NetworkEnv::Mainnet,
        chain_id: Some(1),
        default_rpc: "https://api.mainnet.aptoslabs.com",
        explorer_base_url: "https://aptoscan.com",
        explorer_tx_path: "/transaction/",
        faucet_url: None,
        dwellir_slug: Some("aptos-mainnet"),
    },
    NetworkInfo {
        env: NetworkEnv::Testnet,
        chain_id: Some(2),
        default_rpc: "https://api.testnet.aptoslabs.com",
        explorer_base_url: "https://aptoscan.com",
        explorer_tx_path: "/transaction/",
        faucet_url: Some("https://aptos.dev/network/faucet"),
        dwellir_slug: Some("aptos-testnet"),
    },
    NetworkInfo {
        env: NetworkEnv::Devnet,
        chain_id: Some(165),
        default_rpc: "https://api.devnet.aptoslabs.com",
        explorer_base_url: "https://aptoscan.com",
        explorer_tx_path: "/transaction/",
        faucet_url: Some("https://aptos.dev/network/faucet"),
        dwellir_slug: None,
    },
];

const TRON_NETWORKS: &[NetworkInfo] = &[
    NetworkInfo {
        env: NetworkEnv::Mainnet,
        chain_id: None,
        default_rpc: "https://api.trongrid.io",
        explorer_base_url: "https://tronscan.org",
        explorer_tx_path: "/#/transaction/",
        faucet_url: None,
        dwellir_slug: Some("tron-mainnet"),
    },
    NetworkInfo {
        env: NetworkEnv::Testnet,
        chain_id: None,
        default_rpc: "https://api.shasta.trongrid.io",
        explorer_base_url: "https://shasta.tronscan.org",
        explorer_tx_path: "/#/transaction/",
        faucet_url: Some("https://shasta.tronex.io"),
        dwellir_slug: None, // Dwellir lists tron-mainnet only
    },
];

// ── Scheme + token-standard slices ─────────────────────────────────────

const SECP256K1_ECDSA_SCHEMES: &[CryptoScheme] =
    &[CryptoScheme::Gg20Ecdsa, CryptoScheme::Cggmp21Secp256k1];

const BITCOIN_SCHEMES: &[CryptoScheme] = &[
    CryptoScheme::Gg20Ecdsa,
    CryptoScheme::Cggmp21Secp256k1,
    CryptoScheme::FrostSecp256k1Tr,
];

const ED25519_SCHEMES: &[CryptoScheme] = &[CryptoScheme::FrostEd25519];

const EVM_TOKENS: &[TokenStandard] = &[TokenStandard::Native, TokenStandard::Erc20];
const BTC_TOKENS: &[TokenStandard] = &[TokenStandard::Native];
const SOLANA_TOKENS: &[TokenStandard] = &[
    TokenStandard::Native,
    TokenStandard::SplToken,
    TokenStandard::SplToken2022,
];
const SUI_TOKENS: &[TokenStandard] = &[TokenStandard::Native, TokenStandard::SuiCoin];
const APTOS_TOKENS: &[TokenStandard] = &[
    TokenStandard::Native,
    TokenStandard::AptosLegacyCoin,
    TokenStandard::AptosFungibleAsset,
];
const TRON_TOKENS: &[TokenStandard] = &[TokenStandard::Native, TokenStandard::Trc20];

/// The metadata table. Scope (Step 3): the 6 LIVE-broadcast chains. Other
/// `Chain` variants stay unwired against this table and their providers
/// keep using the trait's default `metadata()` panic until they migrate.
pub const CHAIN_METADATA: &[ChainMetadata] = &[
    ChainMetadata {
        chain: Chain::Ethereum,
        display_name: "Ethereum",
        native_symbol: "ETH",
        native_unit: "wei",
        native_decimals: 18,
        default_addr_type: AddressType::EvmHex,
        compatible_schemes: SECP256K1_ECDSA_SCHEMES,
        token_standards: EVM_TOKENS,
        networks: ETHEREUM_NETWORKS,
    },
    ChainMetadata {
        chain: Chain::BitcoinTestnet,
        display_name: "Bitcoin Testnet",
        native_symbol: "tBTC",
        native_unit: "sats",
        native_decimals: 8,
        default_addr_type: AddressType::Bech32P2wpkh,
        compatible_schemes: BITCOIN_SCHEMES,
        token_standards: BTC_TOKENS,
        networks: BITCOIN_TESTNET_NETWORKS,
    },
    ChainMetadata {
        chain: Chain::Solana,
        display_name: "Solana",
        native_symbol: "SOL",
        native_unit: "lamports",
        native_decimals: 9,
        default_addr_type: AddressType::SolanaEd25519,
        compatible_schemes: ED25519_SCHEMES,
        token_standards: SOLANA_TOKENS,
        networks: SOLANA_NETWORKS,
    },
    ChainMetadata {
        chain: Chain::Sui,
        display_name: "Sui",
        native_symbol: "SUI",
        native_unit: "MIST",
        native_decimals: 9,
        default_addr_type: AddressType::SuiBlake2b,
        compatible_schemes: ED25519_SCHEMES,
        token_standards: SUI_TOKENS,
        networks: SUI_NETWORKS,
    },
    ChainMetadata {
        chain: Chain::Aptos,
        display_name: "Aptos",
        native_symbol: "APT",
        native_unit: "octas",
        native_decimals: 8,
        default_addr_type: AddressType::AptosSha3,
        compatible_schemes: ED25519_SCHEMES,
        token_standards: APTOS_TOKENS,
        networks: APTOS_NETWORKS,
    },
    ChainMetadata {
        chain: Chain::Tron,
        display_name: "TRON",
        native_symbol: "TRX",
        native_unit: "sun",
        native_decimals: 6,
        default_addr_type: AddressType::TronBase58Check,
        compatible_schemes: SECP256K1_ECDSA_SCHEMES,
        token_standards: TRON_TOKENS,
        networks: TRON_NETWORKS,
    },
];

/// Lookup metadata for a chain. Returns `None` until the chain's entry
/// lands in `CHAIN_METADATA` (Step 3).
pub fn metadata_for(chain: Chain) -> Option<&'static ChainMetadata> {
    CHAIN_METADATA.iter().find(|m| m.chain == chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explorer_tx_url_concatenates_correctly() {
        let n = NetworkInfo {
            env: NetworkEnv::Mainnet,
            chain_id: Some(1),
            default_rpc: "https://eth.llamarpc.com",
            explorer_base_url: "https://etherscan.io",
            explorer_tx_path: "/tx/",
            faucet_url: None,
            dwellir_slug: None,
        };
        assert_eq!(n.explorer_tx_url("0xabc"), "https://etherscan.io/tx/0xabc");
    }

    #[test]
    fn metadata_for_returns_some_for_live_chains() {
        for c in [
            Chain::Ethereum,
            Chain::BitcoinTestnet,
            Chain::Solana,
            Chain::Sui,
            Chain::Aptos,
            Chain::Tron,
        ] {
            assert!(metadata_for(c).is_some(), "metadata missing for {c:?}");
        }
    }

    #[test]
    fn metadata_for_returns_none_for_unwired_chains() {
        // Substrate/Cosmos/Ton/Monero/Starknet not yet wired (Step 3 scope).
        for c in [
            Chain::Polkadot,
            Chain::CosmosHub,
            Chain::Ton,
            Chain::Monero,
            Chain::Starknet,
        ] {
            assert!(metadata_for(c).is_none(), "unexpected metadata for {c:?}");
        }
    }

    #[test]
    fn every_entry_chain_field_matches_slot_key() {
        // The const table is keyed by `chain` field; ensure no copy-paste drift.
        for m in CHAIN_METADATA {
            assert_eq!(
                metadata_for(m.chain).map(|x| x.chain),
                Some(m.chain),
                "{:?} not findable",
                m.chain
            );
        }
    }

    #[test]
    fn every_entry_has_at_least_one_network_and_one_scheme() {
        for m in CHAIN_METADATA {
            assert!(!m.networks.is_empty(), "{:?} has no networks", m.chain);
            assert!(
                !m.compatible_schemes.is_empty(),
                "{:?} has no schemes",
                m.chain
            );
            assert!(
                m.token_standards.contains(&TokenStandard::Native),
                "{:?} must accept Native",
                m.chain
            );
        }
    }

    #[test]
    fn every_explorer_base_url_is_https() {
        for m in CHAIN_METADATA {
            for n in m.networks {
                assert!(
                    n.explorer_base_url.starts_with("https://"),
                    "{:?} {:?} explorer not https: {}",
                    m.chain,
                    n.env,
                    n.explorer_base_url
                );
                assert!(
                    n.default_rpc.starts_with("https://"),
                    "{:?} {:?} rpc not https: {}",
                    m.chain,
                    n.env,
                    n.default_rpc
                );
            }
        }
    }

    #[test]
    fn no_duplicate_chain_entries() {
        let mut seen = std::collections::HashSet::new();
        for m in CHAIN_METADATA {
            assert!(seen.insert(m.chain), "duplicate entry for {:?}", m.chain);
        }
    }

    #[test]
    fn token_standard_native_is_distinct() {
        assert_ne!(TokenStandard::Native, TokenStandard::Erc20);
    }

    #[test]
    fn ethereum_sepolia_chain_id_correct() {
        let eth = metadata_for(Chain::Ethereum).unwrap();
        let sepolia = eth.network(&NetworkEnv::Testnet).unwrap();
        assert_eq!(sepolia.chain_id, Some(11_155_111));
        let mainnet = eth.network(&NetworkEnv::Mainnet).unwrap();
        assert_eq!(mainnet.chain_id, Some(1));
    }

    #[test]
    fn supports_native_token_for_all_live_chains() {
        for m in CHAIN_METADATA {
            assert!(m.supports(TokenStandard::Native));
        }
    }
}
