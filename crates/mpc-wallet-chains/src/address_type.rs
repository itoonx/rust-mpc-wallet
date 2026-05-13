//! Typed address-format enum for chain providers.
//!
//! Retires stringly-typed `"p2wpkh"` / `"taproot"` magic strings that
//! previously lived in `TransactionParams.extra["addr_type"]`. Adding a
//! new address format = one variant here, caught at compile time.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressType {
    /// EVM `0x` + 20-byte Keccak256(pubkey)[12..] hex.
    EvmHex,
    /// Bitcoin native SegWit P2WPKH (bech32, `bc1`/`tb1`).
    Bech32P2wpkh,
    /// Bitcoin Taproot P2TR (bech32m).
    BitcoinTaproot,
    /// Solana Base58 Ed25519 pubkey (32 bytes).
    SolanaEd25519,
    /// Sui `0x` + 32-byte Blake2b(flag ‖ pubkey).
    SuiBlake2b,
    /// Aptos `0x` + 32-byte SHA3-256(pubkey ‖ scheme_id).
    AptosSha3,
    /// TRON Base58Check (`0x41` prefix + Keccak256(pubkey)[12..]).
    TronBase58Check,
}

impl AddressType {
    /// Stable lowercase identifier — used for CLI flags and legacy JSON extras.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvmHex => "evm_hex",
            Self::Bech32P2wpkh => "p2wpkh",
            Self::BitcoinTaproot => "taproot",
            Self::SolanaEd25519 => "solana_ed25519",
            Self::SuiBlake2b => "sui_blake2b",
            Self::AptosSha3 => "aptos_sha3",
            Self::TronBase58Check => "tron_base58check",
        }
    }
}

impl std::fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_have_distinct_strings() {
        let all = [
            AddressType::EvmHex,
            AddressType::Bech32P2wpkh,
            AddressType::BitcoinTaproot,
            AddressType::SolanaEd25519,
            AddressType::SuiBlake2b,
            AddressType::AptosSha3,
            AddressType::TronBase58Check,
        ];
        let mut seen = std::collections::HashSet::new();
        for v in all {
            assert!(seen.insert(v.as_str()), "duplicate as_str() for {v:?}");
        }
    }

    #[test]
    fn json_round_trip() {
        for v in [
            AddressType::EvmHex,
            AddressType::Bech32P2wpkh,
            AddressType::SuiBlake2b,
        ] {
            let j = serde_json::to_string(&v).unwrap();
            let back: AddressType = serde_json::from_str(&j).unwrap();
            assert_eq!(v, back);
        }
    }
}
