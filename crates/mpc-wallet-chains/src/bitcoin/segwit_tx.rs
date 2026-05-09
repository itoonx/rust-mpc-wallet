//! P2WPKH (native SegWit, BIP-143) transaction builder for ECDSA MPC signing.
//!
//! Used for Bitcoin chains when the configured scheme is `Gg20Ecdsa` (or
//! `Cggmp21Secp256k1`). Sign payload is the BIP-143 sighash for input 0;
//! finalize attaches a witness `[ DER(sig) ‖ SIGHASH_ALL, compressed_pubkey ]`.
//!
//! A single-input, two-output transaction is produced (recipient + change back
//! to the sender). Caller supplies the UTXO list, recipient address, value,
//! fee_rate, and the sender's compressed pubkey via `params.extra`.

use bitcoin::absolute::LockTime;
use bitcoin::ecdsa::Signature as BitcoinEcdsaSignature;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::ecdsa::Signature as Secp256k1EcdsaSignature;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SegwitTxData {
    /// Hex-encoded unsigned transaction.
    tx_hex: String,
    /// Hex-encoded compressed pubkey of the sender (33 bytes).
    pubkey_hex: String,
}

/// Build a P2WPKH-spending transaction.
///
/// Required `params.extra` keys:
/// - `pubkey_hex`: 66-char compressed sender pubkey (33 bytes).
/// - `utxos`: array of `{ txid: hex, vout: u32, value: u64_sats }`.
/// - `fee_sats`: total fee to subtract from change (u64). If absent, uses
///   `fee_rate_sat_per_vb` × 110 vbytes (typical 1-in-2-out segwit tx).
/// - `change_address`: bech32 address of the sender (for the change output).
///
/// Optional:
/// - `fee_rate_sat_per_vb`: u64.
pub async fn build_p2wpkh_transaction(
    chain: Chain,
    network: Network,
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let extra = params
        .extra
        .as_ref()
        .ok_or_else(|| CoreError::InvalidInput("Bitcoin send requires extra params".into()))?;

    // ── Sender pubkey (compressed, 33 bytes) ───────────────────────────────
    let pubkey_hex = extra
        .get("pubkey_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::InvalidInput("missing 'pubkey_hex' in extra".into()))?;
    let pubkey_bytes = hex::decode(pubkey_hex)
        .map_err(|e| CoreError::InvalidInput(format!("invalid pubkey_hex: {e}")))?;
    let compressed_pk = CompressedPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| CoreError::InvalidInput(format!("invalid compressed pubkey: {e}")))?;

    // ── UTXOs (we pick the largest single UTXO ≥ value+fee) ────────────────
    let utxos = extra
        .get("utxos")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CoreError::InvalidInput("missing 'utxos' array in extra".into()))?;
    if utxos.is_empty() {
        return Err(CoreError::InvalidInput(
            "utxos array is empty — fund the address first".into(),
        ));
    }

    let value_sats: u64 = params
        .value
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid value (sats): {e}")))?;

    let fee_sats: u64 = if let Some(f) = extra.get("fee_sats").and_then(|v| v.as_u64()) {
        f
    } else {
        let rate = extra
            .get("fee_rate_sat_per_vb")
            .and_then(|v| v.as_u64())
            .unwrap_or(2);
        rate.saturating_mul(110) // typical 1-in-2-out segwit vbytes
    };

    // Pick the largest UTXO that covers value+fee.
    let mut sorted: Vec<&serde_json::Value> = utxos.iter().collect();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.get("value").and_then(|v| v.as_u64()).unwrap_or(0)));
    let chosen = sorted
        .iter()
        .find(|u| {
            u.get("value")
                .and_then(|v| v.as_u64())
                .is_some_and(|val| val >= value_sats + fee_sats)
        })
        .ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "no single UTXO covers value+fee ({} sats); multi-input not yet supported",
                value_sats + fee_sats
            ))
        })?;

    let in_txid_str = chosen
        .get("txid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::InvalidInput("UTXO missing txid".into()))?;
    let in_vout = chosen
        .get("vout")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| CoreError::InvalidInput("UTXO missing vout".into()))?
        as u32;
    let in_value = chosen
        .get("value")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| CoreError::InvalidInput("UTXO missing value".into()))?;

    let in_txid: Txid = in_txid_str
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid UTXO txid: {e}")))?;

    // ── Recipient script ───────────────────────────────────────────────────
    let recipient_addr: Address<_> = params
        .to
        .parse::<Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| CoreError::InvalidInput(format!("invalid recipient address: {e}")))?
        .require_network(network)
        .map_err(|e| CoreError::InvalidInput(format!("recipient network mismatch: {e}")))?;
    let recipient_script = recipient_addr.script_pubkey();

    // ── Change output back to sender ───────────────────────────────────────
    let change_addr_str = extra
        .get("change_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::InvalidInput("missing 'change_address' in extra".into()))?;
    let change_addr: Address<_> = change_addr_str
        .parse::<Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| CoreError::InvalidInput(format!("invalid change address: {e}")))?
        .require_network(network)
        .map_err(|e| CoreError::InvalidInput(format!("change address network mismatch: {e}")))?;
    let change_script = change_addr.script_pubkey();

    let change_sats = in_value
        .checked_sub(value_sats)
        .and_then(|x| x.checked_sub(fee_sats))
        .ok_or_else(|| CoreError::InvalidInput("UTXO value < value + fee".into()))?;

    // ── Assemble unsigned transaction ──────────────────────────────────────
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(value_sats),
        script_pubkey: recipient_script,
    }];
    // Drop dust change (< 546 sats; it'd be unspendable anyway).
    if change_sats >= 546 {
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: change_script,
        });
    }

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(in_txid, in_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    // ── BIP-143 sighash for input 0 ────────────────────────────────────────
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &ScriptBuf::new_p2wpkh(&compressed_pk.wpubkey_hash()),
            Amount::from_sat(in_value),
            EcdsaSighashType::All,
        )
        .map_err(|e| CoreError::Crypto(format!("p2wpkh sighash: {e}")))?;

    // tx_data: serialize via consensus encoding for round-trip in finalize.
    use bitcoin::consensus::Encodable;
    let mut tx_buf = Vec::new();
    tx.consensus_encode(&mut tx_buf)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;
    let payload = SegwitTxData {
        tx_hex: hex::encode(&tx_buf),
        pubkey_hex: pubkey_hex.to_string(),
    };
    let tx_data =
        serde_json::to_vec(&payload).map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(UnsignedTransaction {
        chain,
        sign_payload: sighash.as_byte_array().to_vec(),
        tx_data,
    })
}

/// Finalize a P2WPKH transaction with an ECDSA MPC signature.
pub fn finalize_p2wpkh_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let MpcSignature::Ecdsa { r, s, .. } = sig else {
        return Err(CoreError::InvalidInput(
            "P2WPKH requires ECDSA signature".into(),
        ));
    };
    if r.len() != 32 || s.len() != 32 {
        return Err(CoreError::Crypto(format!(
            "ECDSA r/s must be 32 bytes (got r={}, s={})",
            r.len(),
            s.len()
        )));
    }

    // Build secp256k1 Signature from raw r||s bytes.
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(r);
    compact[32..].copy_from_slice(s);
    let mut secp_sig = Secp256k1EcdsaSignature::from_compact(&compact)
        .map_err(|e| CoreError::Crypto(format!("invalid ECDSA r||s: {e}")))?;
    // Bitcoin enforces low-s strictly (BIP-146); normalise just in case.
    secp_sig.normalize_s();

    let btc_sig = BitcoinEcdsaSignature {
        signature: secp_sig,
        sighash_type: EcdsaSighashType::All,
    };

    let payload: SegwitTxData = serde_json::from_slice(&unsigned.tx_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    use bitcoin::consensus::Decodable;
    let raw = hex::decode(&payload.tx_hex)
        .map_err(|e| CoreError::Serialization(format!("tx hex: {e}")))?;
    let mut tx = Transaction::consensus_decode(&mut &raw[..])
        .map_err(|e| CoreError::Serialization(format!("decode tx: {e}")))?;

    let pubkey_bytes = hex::decode(&payload.pubkey_hex)
        .map_err(|e| CoreError::Serialization(format!("pubkey hex: {e}")))?;
    let pubkey = PublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| CoreError::Crypto(format!("pubkey decode: {e}")))?;

    // Witness layout for P2WPKH: [ DER_sig ‖ sighash_byte, compressed_pubkey ]
    let mut witness = Witness::new();
    witness.push(btc_sig.serialize());
    witness.push(pubkey.to_bytes());
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
