use bitcoin::hashes::Hash;
use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Build an unsigned Taproot transaction.
pub async fn build_taproot_transaction(
    chain: Chain,
    _network: bitcoin::Network,
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    // Parse the previous outpoint from extra params
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

    // Parse destination address
    let dest_script = params
        .extra
        .as_ref()
        .and_then(|e| e.get("dest_script_hex"))
        .and_then(|v| v.as_str())
        .map(|h| {
            let bytes = hex::decode(h).unwrap_or_default();
            ScriptBuf::from_bytes(bytes)
        })
        .unwrap_or_else(|| ScriptBuf::new());

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(prev_txid, prev_vout),
            script_sig: ScriptBuf::new(), // Taproot uses witness
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: dest_script,
        }],
    };

    // Compute the sighash for key-path spend
    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::TapSighashType;

    let prev_out = TxOut {
        value: Amount::from_sat(input_amount),
        script_pubkey: ScriptBuf::new(), // Will be set by caller
    };

    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prev_out]), TapSighashType::Default)
        .map_err(|e| CoreError::Crypto(format!("sighash error: {e}")))?;

    let tx_data =
        serde_json::to_vec(&SerializableTx::from_tx(&tx))
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

    let mut tx = stx.to_tx();

    // For key-path spend, witness is just the signature (64 bytes for default sighash type)
    let mut witness = bitcoin::Witness::new();
    witness.push(signature.as_slice());
    tx.input[0].witness = witness;

    // Serialize the signed transaction
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
        Self {
            hex: hex::encode(buf),
        }
    }

    fn to_tx(&self) -> bitcoin::Transaction {
        use bitcoin::consensus::Decodable;
        let bytes = hex::decode(&self.hex).unwrap();
        bitcoin::Transaction::consensus_decode(&mut &bytes[..]).unwrap()
    }
}
