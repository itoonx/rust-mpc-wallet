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

use crate::address_type::AddressType;

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
