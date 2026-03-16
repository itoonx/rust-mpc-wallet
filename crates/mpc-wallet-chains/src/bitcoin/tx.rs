use bitcoin::hashes::Hash;
use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Build an unsigned Taproot transaction.
///
/// # SEC-009 fix (T-S5-03)
///
/// The `prev_out.script_pubkey` used for the Taproot sighash computation must be
/// the actual P2TR output script of the UTXO being spent (`OP_1 <x-only-pubkey>`),
/// not an empty script. An incorrect script produces an invalid sighash and the
/// resulting transaction will be rejected by Bitcoin nodes.
///
/// Callers must supply `prev_xonly_pubkey_hex` (32-byte x-only pubkey, hex-encoded)
/// or `prev_script_pubkey_hex` (full P2TR script, hex-encoded) in `params.extra`.
/// If neither is supplied, the function returns `Err(CoreError::InvalidInput(...))`.
pub async fn build_taproot_transaction(
    chain: Chain,
    _network: bitcoin::Network,
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    let prev_txid: Txid = params
        .extra
        .as_ref()
        .and_then(|e| e.get("prev_txid"))
        .and_then(|v| v.as_str())
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000")
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid prev_txid: {e}")))?;

    let prev_vout = params
        .extra
        .as_ref()
        .and_then(|e| e.get("prev_vout"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let input_amount = params
        .extra
        .as_ref()
        .and_then(|e| e.get("input_amount"))
        .and_then(|v| v.as_u64())
        .unwrap_or(100_000);

    let value: u64 = params
        .value
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid value: {e}")))?;

    let dest_script = params
        .extra
        .as_ref()
        .and_then(|e| e.get("dest_script_hex"))
        .and_then(|v| v.as_str())
        .map(|h| {
            let bytes = hex::decode(h).unwrap_or_default();
            ScriptBuf::from_bytes(bytes)
        })
        .unwrap_or_else(ScriptBuf::new);

    // ── SEC-009 fix: require the actual P2TR script_pubkey of the UTXO ────────
    //
    // For a Taproot key-path spend, the sighash commits to `script_pubkey` of the
    // input's previous output. Using an empty script produces an incorrect sighash —
    // the resulting signature will always be rejected by Bitcoin full nodes.
    //
    // Prefer `prev_xonly_pubkey_hex` (32 bytes) which we use to reconstruct the
    // canonical P2TR script. Alternatively accept `prev_script_pubkey_hex` (full script).
    let prev_script_pubkey = if let Some(script_hex) = params
        .extra
        .as_ref()
        .and_then(|e| e.get("prev_script_pubkey_hex"))
        .and_then(|v| v.as_str())
    {
        let bytes = hex::decode(script_hex).map_err(|e| {
            CoreError::InvalidInput(format!("invalid prev_script_pubkey_hex: {e}"))
        })?;
        ScriptBuf::from_bytes(bytes)
    } else if let Some(xonly_hex) = params
        .extra
        .as_ref()
        .and_then(|e| e.get("prev_xonly_pubkey_hex"))
        .and_then(|v| v.as_str())
    {
        // Reconstruct P2TR script: OP_1 (0x51) + PUSH32 (0x20) + <32-byte x-only pubkey>
        let pk_bytes = hex::decode(xonly_hex).map_err(|e| {
            CoreError::InvalidInput(format!("invalid prev_xonly_pubkey_hex: {e}"))
        })?;
        if pk_bytes.len() != 32 {
            return Err(CoreError::InvalidInput(
                "prev_xonly_pubkey_hex must be exactly 32 bytes (64 hex chars)".into(),
            ));
        }
        let mut script_bytes = vec![0x51u8, 0x20];
        script_bytes.extend_from_slice(&pk_bytes);
        ScriptBuf::from_bytes(script_bytes)
    } else {
        // SEC-009: refuse to proceed — empty script_pubkey is always wrong for Taproot.
        return Err(CoreError::InvalidInput(
            "SEC-009: prev_xonly_pubkey_hex or prev_script_pubkey_hex is required \
             for Taproot key-path sighash. An empty script_pubkey produces an \
             invalid sighash that will be rejected by Bitcoin nodes."
                .into(),
        ));
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(prev_txid, prev_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: dest_script,
        }],
    };

    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::TapSighashType;

    let prev_out = TxOut {
        value: Amount::from_sat(input_amount),
        // SEC-009 fix applied: use the actual P2TR script_pubkey
        script_pubkey: prev_script_pubkey,
    };

    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&[prev_out]),
            TapSighashType::Default,
        )
        .map_err(|e| CoreError::Crypto(format!("sighash error: {e}")))?;

    let tx_data = serde_json::to_vec(&SerializableTx::from_tx(&tx))
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(UnsignedTransaction {
        chain,
        sign_payload: sighash.as_byte_array().to_vec(),
        tx_data,
    })
}

/// Finalize a Taproot transaction with a Schnorr signature.
pub fn finalize_taproot_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let MpcSignature::Schnorr { signature } = sig else {
        return Err(CoreError::InvalidInput(
            "Bitcoin Taproot requires Schnorr signature".into(),
        ));
    };

    let stx: SerializableTx = serde_json::from_slice(&unsigned.tx_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    // SEC-016 fix: use proper error propagation instead of unwrap
    let mut tx = stx.to_tx().map_err(|e| CoreError::Serialization(e))?;

    let mut witness = bitcoin::Witness::new();
    witness.push(signature.as_slice());
    tx.input[0].witness = witness;

    use bitcoin::consensus::Encodable;
    let mut raw_tx = Vec::new();
    tx.consensus_encode(&mut raw_tx)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    let tx_hash = tx.compute_txid().to_string();

    Ok(SignedTransaction {
        chain: unsigned.chain,
        raw_tx,
        tx_hash,
    })
}

/// Helper for serializing bitcoin Transaction via serde.
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableTx {
    hex: String,
}

impl SerializableTx {
    fn from_tx(tx: &bitcoin::Transaction) -> Self {
        use bitcoin::consensus::Encodable;
        let mut buf = Vec::new();
        tx.consensus_encode(&mut buf).unwrap();
        Self { hex: hex::encode(buf) }
    }

    /// Deserialize with proper error propagation (SEC-016 fix: no panicking unwrap).
    fn to_tx(&self) -> Result<bitcoin::Transaction, String> {
        use bitcoin::consensus::Decodable;
        let bytes = hex::decode(&self.hex).map_err(|e| format!("hex decode: {e}"))?;
        bitcoin::Transaction::consensus_decode(&mut &bytes[..])
            .map_err(|e| format!("consensus decode: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::TransactionParams;

    /// Valid 32-byte x-only pubkey (the generator point G, for test use only)
    const TEST_XONLY_HEX: &str =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn params_with_xonly() -> TransactionParams {
        TransactionParams {
            to: "bc1p_dest".into(),
            value: "50000".into(),
            data: None,
            chain_id: None,
            extra: Some(serde_json::json!({
                "prev_txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "prev_vout": 0,
                "input_amount": 100000,
                "prev_xonly_pubkey_hex": TEST_XONLY_HEX
            })),
        }
    }

    #[tokio::test]
    async fn test_sec009_xonly_pubkey_produces_valid_sighash() {
        let result = build_taproot_transaction(
            Chain::BitcoinMainnet,
            bitcoin::Network::Bitcoin,
            params_with_xonly(),
        )
        .await;
        assert!(result.is_ok(), "SEC-009 fix: build with xonly pubkey should succeed");
        // Taproot sighash is exactly 32 bytes
        assert_eq!(result.unwrap().sign_payload.len(), 32);
    }

    #[tokio::test]
    async fn test_sec009_missing_script_pubkey_returns_error() {
        let params = TransactionParams {
            to: "bc1p_dest".into(),
            value: "50000".into(),
            data: None,
            chain_id: None,
            extra: Some(serde_json::json!({
                "prev_txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "prev_vout": 0,
                "input_amount": 100000,
                // Neither prev_xonly_pubkey_hex nor prev_script_pubkey_hex supplied
            })),
        };
        let result = build_taproot_transaction(
            Chain::BitcoinMainnet,
            bitcoin::Network::Bitcoin,
            params,
        )
        .await;
        assert!(result.is_err(), "must reject missing script_pubkey");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("SEC-009") || msg.contains("script_pubkey"),
            "error must mention SEC-009 or script_pubkey, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_sec009_full_script_pubkey_hex_accepted() {
        let script_hex = format!("5120{}", TEST_XONLY_HEX);
        let params = TransactionParams {
            to: "bc1p_dest".into(),
            value: "50000".into(),
            data: None,
            chain_id: None,
            extra: Some(serde_json::json!({
                "prev_txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "prev_vout": 0,
                "input_amount": 100000,
                "prev_script_pubkey_hex": script_hex
            })),
        };
        let result = build_taproot_transaction(
            Chain::BitcoinMainnet,
            bitcoin::Network::Bitcoin,
            params,
        )
        .await;
        assert!(result.is_ok(), "full script_pubkey_hex should be accepted");
    }

    #[tokio::test]
    async fn test_invalid_xonly_pubkey_length_rejected() {
        let params = TransactionParams {
            to: "bc1p_dest".into(),
            value: "50000".into(),
            data: None,
            chain_id: None,
            extra: Some(serde_json::json!({
                "prev_txid": "0000000000000000000000000000000000000000000000000000000000000001",
                "prev_vout": 0,
                "input_amount": 100000,
                "prev_xonly_pubkey_hex": "deadbeef"  // only 4 bytes
            })),
        };
        let result = build_taproot_transaction(
            Chain::BitcoinMainnet,
            bitcoin::Network::Bitcoin,
            params,
        )
        .await;
        assert!(result.is_err(), "short xonly pubkey must be rejected");
    }

    #[test]
    fn test_serializable_tx_roundtrip_no_panic() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let s = SerializableTx::from_tx(&tx);
        let decoded = s.to_tx().expect("roundtrip must not fail");
        assert_eq!(decoded.output[0].value, Amount::from_sat(50_000));
    }
}
