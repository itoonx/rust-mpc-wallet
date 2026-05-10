//! Cross-chain fungible-token transfer schema.
//!
//! Lives at the chain-crate level (not CLI-only) so SDK integrators can
//! construct token transfers programmatically without hand-writing JSON.
//!
//! Wire convention: serialize a `TokenIdentifier` as JSON into
//! `TransactionParams.extra["token"]`. Chain providers parse their own variant
//! in `build_transaction`; cross-chain dispatch stays at the CLI layer.
//! Absence of the field means `Native` (the chain's gas token) — backwards
//! compatible with all pre-Sprint-45 callers.
//!
//! See `docs/TOKEN_TRANSFER_DESIGN.md` for the per-chain token-standard
//! survey, sprint roadmap, and rationale behind the schema shape.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TokenIdentifier {
    /// Move the chain's native gas token (ETH / SOL / SUI / APT / TRX / BTC).
    /// Default when `extra["token"]` is absent.
    Native,

    /// EVM ERC-20 fungible (Sprint 45). ERC-721 / ERC-1155 deferred.
    Evm {
        contract: String,
        standard: EvmTokenStandard,
        #[serde(default)]
        token_id: Option<String>,
    },

    /// Solana SPL Token / Token-2022 (Sprint 49).
    Spl {
        mint: String,
        program: SplProgram,
        decimals: u8,
    },

    /// Sui `Coin<T>` for any type tag (Sprint 46).
    Sui { type_tag: String },

    /// Aptos has two parallel standards — Coin (legacy) and Fungible Asset (new).
    /// Both must be supported (Sprints 46 + 47). Field is named `flavor` (not
    /// `kind`) to avoid clashing with the outer enum's discriminator tag.
    Aptos { flavor: AptosTokenKind },

    /// TRON TRC-20 via TVM smart contract (Sprint 48).
    Tron { contract: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvmTokenStandard {
    Erc20,
    Erc721,
    Erc1155,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SplProgram {
    SplToken,
    Token2022,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AptosTokenKind {
    Coin { type_tag: String },
    FungibleAsset { metadata: String },
}

impl TokenIdentifier {
    /// Read the token spec from `params.extra["token"]`. Returns `Native` when
    /// the field is absent — keeps native-only callers unchanged.
    pub fn from_extra(extra: Option<&serde_json::Value>) -> Result<Self, String> {
        let Some(extra) = extra else {
            return Ok(Self::Native);
        };
        let Some(token) = extra.get("token") else {
            return Ok(Self::Native);
        };
        serde_json::from_value(token.clone()).map_err(|e| format!("invalid token spec: {e}"))
    }

    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_native_when_field_absent() {
        let extra = serde_json::json!({"foo": "bar"});
        let tok = TokenIdentifier::from_extra(Some(&extra)).unwrap();
        assert!(tok.is_native());
    }

    #[test]
    fn parses_native_when_extra_absent() {
        let tok = TokenIdentifier::from_extra(None).unwrap();
        assert!(tok.is_native());
    }

    #[test]
    fn parses_evm_erc20() {
        let extra = serde_json::json!({
            "token": {
                "kind": "evm",
                "contract": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
                "standard": "erc20",
            }
        });
        let tok = TokenIdentifier::from_extra(Some(&extra)).unwrap();
        match tok {
            TokenIdentifier::Evm {
                contract,
                standard,
                token_id,
            } => {
                assert_eq!(contract, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
                assert_eq!(standard, EvmTokenStandard::Erc20);
                assert_eq!(token_id, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parses_aptos_fa() {
        let extra = serde_json::json!({
            "token": {
                "kind": "aptos",
                "flavor": { "type": "fungible_asset", "metadata": "0xabc123" }
            }
        });
        let tok = TokenIdentifier::from_extra(Some(&extra)).unwrap();
        match tok {
            TokenIdentifier::Aptos {
                flavor: AptosTokenKind::FungibleAsset { metadata },
            } => {
                assert_eq!(metadata, "0xabc123");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn parses_aptos_coin() {
        let extra = serde_json::json!({
            "token": {
                "kind": "aptos",
                "flavor": { "type": "coin", "type_tag": "0x1::aptos_coin::AptosCoin" }
            }
        });
        let tok = TokenIdentifier::from_extra(Some(&extra)).unwrap();
        match tok {
            TokenIdentifier::Aptos {
                flavor: AptosTokenKind::Coin { type_tag },
            } => {
                assert_eq!(type_tag, "0x1::aptos_coin::AptosCoin");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
