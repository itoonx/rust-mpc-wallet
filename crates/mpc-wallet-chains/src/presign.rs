//! Typed presign extras — replaces opaque `serde_json::Value` blobs
//! that previously carried chain-specific RPC-fetched parameters.
//!
//! `PresignExtras` is what `ChainProvider::fetch_presign_extras()` returns
//! after performing the chain's RPC dance (nonce/gas/blockhash/UTXOs/etc).
//! The CLI takes this back, hands it to the provider's `build_transaction`
//! call, and never has to know what fields each chain needs.
//!
//! Adding a new chain = one new variant here + the provider impl. The CLI
//! never branches on `Chain::...` for presign field shapes again.

use serde::{Deserialize, Serialize};

use mpc_wallet_core::protocol::GroupPublicKey;

use crate::address_type::AddressType;
use crate::token::TokenIdentifier;

/// Inputs to `ChainProvider::fetch_presign_extras`. Borrowed view of all
/// information the per-chain RPC dance might need.
///
/// `recipient` and `value_str` are forwarded raw from the user-supplied
/// `--to` and `--value` CLI args. EVM needs them for `eth_estimateGas`
/// against the real destination; other chains may ignore them.
pub struct PresignContext<'a> {
    pub rpc_url: &'a str,
    pub sender: &'a str,
    pub group_pubkey: &'a GroupPublicKey,
    pub token: Option<&'a TokenIdentifier>,
    pub recipient: &'a str,
    pub value_str: &'a str,
}

/// UTXO record carried in Bitcoin presign extras.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

/// Sui Object reference triple (`object_id`, `version`, `digest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiObjectRef {
    pub object_id: String,
    pub version: u64,
    pub digest: String,
}

/// Typed per-chain presign payload. One variant per LIVE chain (Step 1
/// scope: EVM, Bitcoin, Solana, Sui, Aptos, TRON). Future chains add a
/// variant here and an impl on their provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "chain_kind", rename_all = "snake_case")]
pub enum PresignExtras {
    Evm {
        nonce: u64,
        gas_limit: u64,
        /// Decimal string (wei). String rather than u128 because
        /// serde_json does not support u128 and EVM RPCs already speak
        /// strings for big numbers.
        max_fee_per_gas: String,
        max_priority_fee_per_gas: String,
        chain_id: u64,
    },
    Btc {
        utxos: Vec<Utxo>,
        fee_rate_sat_per_vb: u64,
        addr_type: AddressType,
        pubkey_hex: String,
        change_address: String,
    },
    Sol {
        recent_blockhash: String,
        sender: String,
    },
    Sui {
        gas_payment: SuiObjectRef,
        gas_price: u64,
        gas_budget: u64,
        sender: String,
        pubkey_hex: String,
        /// Source `Coin<T>` object when sending a non-SUI token; `None` for
        /// native SUI sends.
        coin_payment: Option<SuiObjectRef>,
    },
    Aptos {
        sequence_number: u64,
        max_gas_amount: u64,
        gas_unit_price: u64,
        expiration_timestamp_secs: u64,
        chain_id: u8,
        sender: String,
        pubkey_hex: String,
    },
    Tron {
        owner_address: String,
        ref_block_bytes: String,
        ref_block_hash: String,
        timestamp: i64,
        expiration: i64,
        /// `Some` for TRC-20 (TVM calls require it), `None` for native TRX
        /// (validator rejects native txs that carry `fee_limit` — see L-017).
        fee_limit: Option<u64>,
    },
}

impl PresignExtras {
    /// Convert the typed presign payload to the legacy JSON shape that
    /// today's per-chain `build_transaction` consumers expect.
    ///
    /// This is a transition shim — Step 4 of the standardization refactor
    /// flips CLI presign through this enum without touching the downstream
    /// build path. A future step migrates `build_transaction` to read the
    /// typed enum directly and this method goes away.
    pub fn to_legacy_extras_json(&self) -> serde_json::Value {
        match self {
            Self::Evm {
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                chain_id,
            } => {
                // Legacy emitted these as u64 numbers (not strings). Best-effort
                // parse — values realistically fit in u64 today; on overflow we
                // emit the string form so consumers can still recover.
                let max_fee_json = match max_fee_per_gas.parse::<u64>() {
                    Ok(v) => serde_json::json!(v),
                    Err(_) => serde_json::json!(max_fee_per_gas),
                };
                let prio_json = match max_priority_fee_per_gas.parse::<u64>() {
                    Ok(v) => serde_json::json!(v),
                    Err(_) => serde_json::json!(max_priority_fee_per_gas),
                };
                serde_json::json!({
                    "chain_id": chain_id,
                    "nonce": nonce,
                    "gas_limit": gas_limit,
                    "max_fee_per_gas": max_fee_json,
                    "max_priority_fee_per_gas": prio_json,
                })
            }
            Self::Btc {
                utxos,
                fee_rate_sat_per_vb,
                addr_type,
                pubkey_hex,
                change_address,
            } => {
                let utxos_json: Vec<serde_json::Value> = utxos
                    .iter()
                    .map(|u| {
                        serde_json::json!({
                            "txid": u.txid,
                            "vout": u.vout,
                            "value": u.value_sats,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "addr_type": addr_type.as_str(),
                    "pubkey_hex": pubkey_hex,
                    "utxos": utxos_json,
                    "change_address": change_address,
                    "fee_rate_sat_per_vb": fee_rate_sat_per_vb,
                })
            }
            Self::Sol {
                recent_blockhash,
                sender,
            } => serde_json::json!({
                "from": sender,
                "recent_blockhash": recent_blockhash,
            }),
            Self::Sui {
                gas_payment,
                gas_price,
                gas_budget,
                sender,
                pubkey_hex,
                coin_payment,
            } => {
                let mut o = serde_json::json!({
                    "sender": sender,
                    "pubkey_hex": pubkey_hex,
                    "gas_payment_object_id": gas_payment.object_id,
                    "gas_payment_version": gas_payment.version,
                    "gas_payment_digest": gas_payment.digest,
                    "gas_price": gas_price,
                    "gas_budget": gas_budget,
                });
                if let Some(c) = coin_payment {
                    if let serde_json::Value::Object(ref mut m) = o {
                        m.insert(
                            "coin_payment_object_id".into(),
                            serde_json::json!(c.object_id),
                        );
                        m.insert("coin_payment_version".into(), serde_json::json!(c.version));
                        m.insert("coin_payment_digest".into(), serde_json::json!(c.digest));
                    }
                }
                o
            }
            Self::Aptos {
                sequence_number,
                max_gas_amount,
                gas_unit_price,
                expiration_timestamp_secs,
                chain_id,
                sender,
                pubkey_hex,
            } => serde_json::json!({
                "sender": sender,
                "pubkey_hex": pubkey_hex,
                "sequence_number": sequence_number,
                "max_gas_amount": max_gas_amount,
                "gas_unit_price": gas_unit_price,
                "expiration_timestamp_secs": expiration_timestamp_secs,
                "chain_id": chain_id,
            }),
            Self::Tron {
                owner_address,
                ref_block_bytes,
                ref_block_hash,
                timestamp,
                expiration,
                fee_limit,
            } => {
                let mut o = serde_json::json!({
                    "owner_address": owner_address,
                    "ref_block_bytes": ref_block_bytes,
                    "ref_block_hash": ref_block_hash,
                    "timestamp": timestamp,
                    "expiration": expiration,
                });
                if let Some(f) = fee_limit {
                    if let serde_json::Value::Object(ref mut m) = o {
                        m.insert("fee_limit".into(), serde_json::json!(f));
                    }
                }
                o
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_round_trip_serde() {
        let e = PresignExtras::Evm {
            nonce: 42,
            gas_limit: 21_000,
            max_fee_per_gas: "30000000000".into(),
            max_priority_fee_per_gas: "1500000000".into(),
            chain_id: 11155111,
        };
        let j = serde_json::to_string(&e).unwrap();
        let back: PresignExtras = serde_json::from_str(&j).unwrap();
        match back {
            PresignExtras::Evm {
                nonce, chain_id, ..
            } => {
                assert_eq!(nonce, 42);
                assert_eq!(chain_id, 11155111);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tron_fee_limit_optionality() {
        // Native TRX path must allow None.
        let native = PresignExtras::Tron {
            owner_address: "414e...".into(),
            ref_block_bytes: "abcd".into(),
            ref_block_hash: "1234567890abcdef".into(),
            timestamp: 1,
            expiration: 2,
            fee_limit: None,
        };
        let j = serde_json::to_string(&native).unwrap();
        assert!(j.contains("\"fee_limit\":null"));
        // TRC-20 path carries it.
        let trc20 = PresignExtras::Tron {
            owner_address: "414e...".into(),
            ref_block_bytes: "abcd".into(),
            ref_block_hash: "1234567890abcdef".into(),
            timestamp: 1,
            expiration: 2,
            fee_limit: Some(100_000_000),
        };
        let j = serde_json::to_string(&trc20).unwrap();
        assert!(j.contains("100000000"));
    }

    #[test]
    fn sui_coin_payment_optional() {
        let native_sui = PresignExtras::Sui {
            gas_payment: SuiObjectRef {
                object_id: "0x1".into(),
                version: 1,
                digest: "AAA".into(),
            },
            gas_price: 1000,
            gas_budget: 10_000_000,
            sender: "0x9".into(),
            pubkey_hex: "00".into(),
            coin_payment: None,
        };
        let j = serde_json::to_string(&native_sui).unwrap();
        assert!(j.contains("\"coin_payment\":null"));
    }
}
