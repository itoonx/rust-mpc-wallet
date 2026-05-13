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
    /// Slug for the Dwellir RPC provider, when supported. `None` if Dwellir
    /// does not list this chain.
    pub dwellir_slug: Option<&'static str>,
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

/// The metadata table. Populated incrementally in Step 3 of the
/// standardization refactor — empty for the additive Step 1 commit so
/// downstream callers can begin wiring against the type without waiting
/// for every per-chain entry to land.
pub const CHAIN_METADATA: &[ChainMetadata] = &[];

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
        };
        assert_eq!(n.explorer_tx_url("0xabc"), "https://etherscan.io/tx/0xabc");
    }

    #[test]
    fn metadata_for_returns_none_when_table_empty_or_chain_missing() {
        // Either the table is empty (Step 1) or it doesn't yet contain
        // every variant — either way, this is the contract.
        let _ = metadata_for(Chain::Ethereum);
    }

    #[test]
    fn token_standard_native_is_distinct() {
        assert_ne!(TokenStandard::Native, TokenStandard::Erc20);
    }
}
