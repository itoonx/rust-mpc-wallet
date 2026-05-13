//! Dwellir RPC provider preset.
//!
//! Dwellir uses a single API key for all supported chains.
//! HTTPS: `https://api-{slug}.n.dwellir.com/{api_key}`
//! WSS:   `wss://api-{slug}.n.dwellir.com/{api_key}`
//!
//! Slug convention (verified against Dwellir's live endpoints, May 2026):
//! - EVM: `{chain}-{network}` — e.g. `ethereum-mainnet`, `ethereum-sepolia`,
//!   `polygon-amoy`, `arbitrum-sepolia`.
//! - Substrate / cosmos / specialized: bare chain name (no `-mainnet` suffix) —
//!   e.g. `polkadot`, `kusama`.
//! - Aptos / Movement / Solana / Sui: `{chain}-mainnet` for mainnet, `-testnet`
//!   / `-devnet` for non-mainnet.
//!
//! Per-account chain availability varies — a missing endpoint surfaces as a
//! DNS resolution failure when the URL is requested.

use crate::provider::Chain;
use crate::registry::NetworkEnv;
use crate::rpc::RpcProvider;

/// Dwellir RPC provider — single API key, multiple chains.
pub struct DwellirProvider {
    api_key: String,
}

impl DwellirProvider {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
        }
    }

    /// Map Chain to Dwellir's subdomain slug.
    ///
    /// Source-of-truth precedence (Step 8):
    /// 1. `CHAIN_METADATA` — per-NetworkInfo `dwellir_slug`. Wired for the
    ///    6 LIVE chains; one place to edit when slugs change.
    /// 2. Fallback hardcoded match below — covers chains not yet in
    ///    `CHAIN_METADATA` (EVM L2s beyond Ethereum, Substrate, Cosmos,
    ///    Ton, Movement, Starknet). These migrate as their `ChainMetadata`
    ///    entries land.
    fn chain_slug(chain: Chain, network: &NetworkEnv) -> Option<&'static str> {
        if let Some(m) = crate::metadata::metadata_for(chain) {
            if let Some(n) = m.network(network) {
                if n.dwellir_slug.is_some() {
                    return n.dwellir_slug;
                }
            }
        }
        // Step 7 cleanup: arms for chains in CHAIN_METADATA (Ethereum,
        // Solana, Sui, Aptos, Tron) are dead — the metadata path above
        // serves them. Only chains without a metadata entry remain here.
        match (chain, network) {
            // EVM L1s + L2s not yet in CHAIN_METADATA
            (Chain::Polygon, NetworkEnv::Testnet) => Some("polygon-amoy"),
            (Chain::Polygon, _) => Some("polygon-mainnet"),
            (Chain::Bsc, NetworkEnv::Testnet) => Some("bsc-testnet"),
            (Chain::Bsc, _) => Some("bsc-mainnet"),
            (Chain::Arbitrum, NetworkEnv::Testnet) => Some("arbitrum-sepolia"),
            (Chain::Arbitrum, _) => Some("arbitrum-mainnet"),
            (Chain::Optimism, NetworkEnv::Testnet) => Some("optimism-sepolia"),
            (Chain::Optimism, _) => Some("optimism-mainnet"),
            (Chain::Base, NetworkEnv::Testnet) => Some("base-sepolia"),
            (Chain::Base, _) => Some("base-mainnet"),
            (Chain::Avalanche, NetworkEnv::Testnet) => Some("avalanche-fuji"),
            (Chain::Avalanche, _) => Some("avalanche-mainnet"),
            (Chain::Linea, NetworkEnv::Testnet) => Some("linea-sepolia"),
            (Chain::Linea, _) => Some("linea-mainnet"),
            (Chain::ZkSync, _) => Some("zksync-mainnet"),
            (Chain::Scroll, _) => Some("scroll-mainnet"),
            (Chain::Mantle, _) => Some("mantle-mainnet"),
            (Chain::Blast, _) => Some("blast-mainnet"),
            (Chain::Zora, _) => Some("zora-mainnet"),
            (Chain::Fantom, _) => Some("fantom-mainnet"),
            (Chain::Gnosis, _) => Some("gnosis-mainnet"),
            (Chain::Cronos, _) => Some("cronos-mainnet"),
            (Chain::Celo, _) => Some("celo-mainnet"),
            (Chain::Moonbeam, _) => Some("moonbeam"),
            (Chain::Ronin, _) => Some("ronin-mainnet"),
            (Chain::OpBnb, _) => Some("opbnb-mainnet"),
            (Chain::Immutable, _) => Some("immutable-mainnet"),
            (Chain::MantaPacific, _) => Some("manta-pacific-mainnet"),
            (Chain::Hyperliquid, _) => Some("hyperliquid-mainnet"),
            (Chain::Berachain, _) => Some("berachain-mainnet"),
            (Chain::MegaEth, _) => Some("megaeth-mainnet"),
            (Chain::Monad, _) => Some("monad-mainnet"),
            // Movement (Aptos sister chain) — not in CHAIN_METADATA yet
            (Chain::Movement, NetworkEnv::Testnet) => Some("movement-testnet"),
            (Chain::Movement, _) => Some("movement-mainnet"),
            // Substrate / Polkadot — bare chain name (no -mainnet suffix)
            (Chain::Polkadot, _) => Some("polkadot"),
            (Chain::Kusama, _) => Some("kusama"),
            (Chain::Astar, _) => Some("astar"),
            (Chain::Acala, _) => Some("acala"),
            (Chain::Phala, _) => Some("phala"),
            (Chain::Interlay, _) => Some("interlay"),
            // Cosmos / IBC
            (Chain::CosmosHub, _) => Some("cosmoshub"),
            (Chain::Osmosis, _) => Some("osmosis"),
            (Chain::Celestia, _) => Some("celestia-mainnet"),
            (Chain::Injective, _) => Some("injective"),
            (Chain::Sei, _) => Some("sei-mainnet"),
            // Specialized / Alt L1s
            (Chain::Starknet, _) => Some("starknet-mainnet"),
            (Chain::Ton, NetworkEnv::Testnet) => Some("ton-testnet"),
            (Chain::Ton, _) => Some("ton-mainnet"),
            // Bitcoin mainnet only (testnet metadata covers tBTC)
            (Chain::BitcoinMainnet, _) => Some("bitcoin-mainnet"),
            _ => None,
        }
    }
}

impl RpcProvider for DwellirProvider {
    fn name(&self) -> &str {
        "dwellir"
    }

    fn supported_chains(&self) -> Vec<Chain> {
        vec![
            Chain::Ethereum,
            Chain::Polygon,
            Chain::Bsc,
            Chain::Arbitrum,
            Chain::Optimism,
            Chain::Base,
            Chain::Avalanche,
            Chain::Linea,
            Chain::ZkSync,
            Chain::Scroll,
            Chain::Mantle,
            Chain::Blast,
            Chain::Zora,
            Chain::Fantom,
            Chain::Gnosis,
            Chain::Cronos,
            Chain::Celo,
            Chain::Moonbeam,
            Chain::Ronin,
            Chain::OpBnb,
            Chain::Immutable,
            Chain::MantaPacific,
            Chain::Hyperliquid,
            Chain::Berachain,
            Chain::MegaEth,
            Chain::Monad,
            Chain::Aptos,
            Chain::Movement,
            Chain::Polkadot,
            Chain::Kusama,
            Chain::Astar,
            Chain::Acala,
            Chain::Phala,
            Chain::Interlay,
            Chain::Starknet,
            Chain::CosmosHub,
            Chain::Osmosis,
            Chain::Celestia,
            Chain::Injective,
            Chain::Sei,
            Chain::Ton,
            Chain::Tron,
            Chain::BitcoinMainnet,
            Chain::Solana,
            Chain::Sui,
        ]
    }

    fn https_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("https://api-{slug}.n.dwellir.com/{}", self.api_key))
    }

    fn wss_endpoint(&self, chain: Chain, network: &NetworkEnv) -> Option<String> {
        let slug = Self::chain_slug(chain, network)?;
        Some(format!("wss://api-{slug}.n.dwellir.com/{}", self.api_key))
    }

    fn api_key_header(&self) -> Option<(&str, &str)> {
        None // Dwellir uses path-based auth
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::metadata_for;

    /// Parity: for every (chain, env) where the metadata declares a
    /// `dwellir_slug`, the dwellir provider's slug must match — no drift
    /// allowed once metadata claims authority.
    #[test]
    fn parity_metadata_dwellir_slug_matches_provider() {
        let envs = [NetworkEnv::Mainnet, NetworkEnv::Testnet, NetworkEnv::Devnet];
        for m in crate::metadata::CHAIN_METADATA {
            for env in &envs {
                let Some(n) = m.network(env) else { continue };
                let Some(meta_slug) = n.dwellir_slug else {
                    continue;
                };
                let provider_slug = DwellirProvider::chain_slug(m.chain, env)
                    .expect("provider missing slug while metadata declares one");
                assert_eq!(
                    provider_slug, meta_slug,
                    "{:?} {:?}: metadata={meta_slug} provider={provider_slug}",
                    m.chain, env
                );
            }
        }
    }

    /// Once metadata is wired (Step 8), live-chain slugs MUST come from
    /// metadata, not from the fallback match. We confirm by reading the
    /// metadata directly — if it returns `Some`, that's the source.
    #[test]
    fn live_chain_dwellir_slugs_come_from_metadata() {
        for c in [Chain::Ethereum, Chain::Solana, Chain::Sui, Chain::Aptos] {
            let m = metadata_for(c).expect("live chain has metadata");
            let any_slug = m.networks.iter().any(|n| n.dwellir_slug.is_some());
            assert!(any_slug, "{:?} should have at least one dwellir_slug", c);
        }
    }
}
