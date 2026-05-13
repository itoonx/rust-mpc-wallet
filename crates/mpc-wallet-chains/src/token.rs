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

    /// Parse the user-facing `--token <shorthand>` form into a typed
    /// `TokenIdentifier`. Lives at the chain-crate level so CLI/SDK
    /// callers share one parser. The supported shorthands are:
    ///
    ///   - `native` → `Native`
    ///   - `erc20:<contract>` → EVM ERC-20
    ///   - `spl:<mint>:<decimals>` / `spl-2022:<mint>:<decimals>` → Solana SPL
    ///   - `sui-coin:<type-tag>` → Sui `Coin<T>`
    ///   - `aptos-coin:<type-tag>` → Aptos legacy `Coin<T>`
    ///   - `aptos-fa:<metadata-addr>` → Aptos Fungible Asset
    ///   - `trc20:<contract>` → TRON TRC-20
    pub fn parse_shorthand(s: &str) -> Result<Self, String> {
        if s == "native" {
            return Ok(Self::Native);
        }
        let (prefix, rest) = s.split_once(':').ok_or_else(|| {
            format!("token shorthand must be 'native' or '<kind>:<args>', got '{s}'")
        })?;
        match prefix {
            "erc20" => Ok(Self::Evm {
                contract: rest.to_string(),
                standard: EvmTokenStandard::Erc20,
                token_id: None,
            }),
            "erc721" | "erc1155" => Err(format!(
                "token {prefix}: NFT support deferred; see docs/TOKEN_TRANSFER_DESIGN.md §7"
            )),
            "spl" | "spl-2022" => {
                let parts: Vec<&str> = rest.split(':').collect();
                if parts.len() != 2 {
                    return Err(format!("token spl shorthand: '{prefix}:<mint>:<decimals>'"));
                }
                let decimals: u8 = parts[1]
                    .parse()
                    .map_err(|e| format!("spl decimals must be u8: {e}"))?;
                let program = if prefix == "spl-2022" {
                    SplProgram::Token2022
                } else {
                    SplProgram::SplToken
                };
                Ok(Self::Spl {
                    mint: parts[0].to_string(),
                    program,
                    decimals,
                })
            }
            "sui-coin" => Ok(Self::Sui {
                type_tag: rest.to_string(),
            }),
            "aptos-coin" => Ok(Self::Aptos {
                flavor: AptosTokenKind::Coin {
                    type_tag: rest.to_string(),
                },
            }),
            "aptos-fa" => Ok(Self::Aptos {
                flavor: AptosTokenKind::FungibleAsset {
                    metadata: rest.to_string(),
                },
            }),
            "trc20" => Ok(Self::Tron {
                contract: rest.to_string(),
            }),
            other => Err(format!("token: unknown shorthand prefix '{other}'")),
        }
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
    fn parse_shorthand_native() {
        assert_eq!(
            TokenIdentifier::parse_shorthand("native").unwrap(),
            TokenIdentifier::Native
        );
    }

    #[test]
    fn parse_shorthand_erc20() {
        let t = TokenIdentifier::parse_shorthand("erc20:0xabc").unwrap();
        match t {
            TokenIdentifier::Evm {
                contract,
                standard,
                token_id,
            } => {
                assert_eq!(contract, "0xabc");
                assert_eq!(standard, EvmTokenStandard::Erc20);
                assert_eq!(token_id, None);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_shorthand_spl_token_and_2022() {
        let t = TokenIdentifier::parse_shorthand("spl:M1nt:6").unwrap();
        match t {
            TokenIdentifier::Spl {
                mint,
                program,
                decimals,
            } => {
                assert_eq!(mint, "M1nt");
                assert_eq!(program, SplProgram::SplToken);
                assert_eq!(decimals, 6);
            }
            _ => panic!("wrong"),
        }
        let t = TokenIdentifier::parse_shorthand("spl-2022:M:9").unwrap();
        match t {
            TokenIdentifier::Spl { program, .. } => {
                assert_eq!(program, SplProgram::Token2022);
            }
            _ => panic!("wrong"),
        }
    }

    #[test]
    fn parse_shorthand_sui_aptos_tron() {
        assert!(matches!(
            TokenIdentifier::parse_shorthand("sui-coin:0xa::usdc::USDC").unwrap(),
            TokenIdentifier::Sui { .. }
        ));
        assert!(matches!(
            TokenIdentifier::parse_shorthand("aptos-coin:0x1::aptos_coin::AptosCoin").unwrap(),
            TokenIdentifier::Aptos {
                flavor: AptosTokenKind::Coin { .. }
            }
        ));
        assert!(matches!(
            TokenIdentifier::parse_shorthand("aptos-fa:0xa").unwrap(),
            TokenIdentifier::Aptos {
                flavor: AptosTokenKind::FungibleAsset { .. }
            }
        ));
        assert!(matches!(
            TokenIdentifier::parse_shorthand("trc20:TG3XX").unwrap(),
            TokenIdentifier::Tron { .. }
        ));
    }

    #[test]
    fn parse_shorthand_rejects_unknown_prefix() {
        assert!(TokenIdentifier::parse_shorthand("foo:bar").is_err());
        assert!(TokenIdentifier::parse_shorthand("erc721:0xabc").is_err());
        assert!(TokenIdentifier::parse_shorthand("notaprefix").is_err());
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
