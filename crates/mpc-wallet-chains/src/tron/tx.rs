//! TRON transaction builder.
//!
//! Wire format is Protobuf — see [`super::proto`]. The signing payload is
//! `tx_id = SHA-256(Transaction.raw)`. Signed wire format is `raw_data ‖ r ‖ s ‖ v`.
//! Broadcasting is JSON-shaped (`{ raw_data_hex, signature: [hex] }`) and the
//! gateway / RPC client splits the body and sig back apart — see
//! [`super::rpc_client`].

use sha2::{Digest, Sha256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};
use crate::tron::address::validate_tron_address;
use crate::tron::proto;

/// Length of a finalized TRON ECDSA signature: r(32) ‖ s(32) ‖ v(1).
pub const TRON_SIG_LEN: usize = 65;

fn missing_extra(field: &str) -> CoreError {
    CoreError::InvalidInput(format!("TRON extra missing required field `{field}`"))
}

fn parse_hex_field(
    extra: &serde_json::Value,
    key: &str,
    expect_len: usize,
) -> Result<Vec<u8>, CoreError> {
    let s = extra
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing_extra(key))?
        .trim_start_matches("0x");
    let bytes = hex::decode(s)
        .map_err(|e| CoreError::InvalidInput(format!("TRON extra `{key}` invalid hex: {e}")))?;
    if bytes.len() != expect_len {
        return Err(CoreError::InvalidInput(format!(
            "TRON extra `{key}` must be {expect_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn parse_i64_field(extra: &serde_json::Value, key: &str) -> Result<i64, CoreError> {
    extra
        .get(key)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| missing_extra(key))
}

/// Recover the T-address that signed a TRON transaction.
///
/// `prehash` is the 32-byte `SHA-256(raw_data)` payload MPC signed.
/// `parity ∈ {0, 1}` is the raw recovery id (the wire-format `v` byte is
/// `27 + parity` per Ethereum convention — `tronweb` writes `0x1B`/`0x1C`).
pub fn recover_tron_sender_from_parity(
    prehash: &[u8],
    r: &[u8],
    s: &[u8],
    parity: u8,
) -> Result<String, CoreError> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use mpc_wallet_core::protocol::GroupPublicKey;

    if r.len() != 32 || s.len() != 32 {
        return Err(CoreError::InvalidInput(format!(
            "TRON sig must be r=32 s=32, got r={} s={}",
            r.len(),
            s.len()
        )));
    }
    if prehash.len() != 32 {
        return Err(CoreError::InvalidInput(format!(
            "TRON prehash must be 32 bytes, got {}",
            prehash.len()
        )));
    }
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(r);
    rs[32..].copy_from_slice(s);
    let signature =
        Signature::from_slice(&rs).map_err(|e| CoreError::Crypto(format!("invalid sig: {e}")))?;
    let recovery_id = RecoveryId::try_from(parity)
        .map_err(|e| CoreError::Crypto(format!("invalid parity {parity}: {e}")))?;
    let verifying = VerifyingKey::recover_from_prehash(prehash, &signature, recovery_id)
        .map_err(|e| CoreError::Crypto(format!("recover_from_prehash: {e}")))?;
    let group_pubkey = GroupPublicKey::Secp256k1Uncompressed(
        verifying.to_encoded_point(false).as_bytes().to_vec(),
    );
    crate::tron::address::derive_tron_address(&group_pubkey)
}

/// Recover the T-address from a signed TRON tx. Reads `recovery_id` from the
/// MpcSignature directly (raw 0/1 — what GG20/CGGMP21 produce internally
/// before wire-format encoding).
pub fn recover_tron_sender(prehash: &[u8], sig: &MpcSignature) -> Result<String, CoreError> {
    let (r, s, parity) = match sig {
        MpcSignature::Ecdsa { r, s, recovery_id } => (r, s, *recovery_id),
        _ => {
            return Err(CoreError::InvalidInput(
                "TRON requires ECDSA signature".into(),
            ))
        }
    };
    recover_tron_sender_from_parity(prehash, r, s, parity)
}

/// Decode a base58check T-address to its 21-byte raw form (`0x41 ‖ hash160`).
pub fn decode_tron_address(addr: &str) -> Result<Vec<u8>, CoreError> {
    validate_tron_address(addr)?;
    let decoded = bs58::decode(addr)
        .into_vec()
        .map_err(|e| CoreError::InvalidInput(format!("TRON base58 decode: {e}")))?;
    Ok(decoded[..21].to_vec())
}

/// Build an unsigned TRON `TransferContract` transaction.
///
/// Required `params.extra` keys:
/// - `owner_address` (hex, 21 bytes — 0x41 prefix + hash160)
/// - `ref_block_bytes` (hex, 2 bytes)
/// - `ref_block_hash` (hex, 8 bytes)
/// - `expiration` (i64, ms since epoch)
/// - `timestamp` (i64, ms since epoch)
///
/// Optional:
/// - `fee_limit` (i64, sun) — only encoded for `TriggerSmartContract` flows.
///   Native TransferContract MUST omit this; tronweb does the same. Including
///   it produces a non-canonical body that fails the validator's
///   `raw_data_hex` ↔ `raw_data` JSON cross-check.
///
/// `params.value` is the transfer amount in **sun** (1 TRX = 1_000_000 sun).
/// `params.to` is a base58 T-address.
pub async fn build_tron_transaction(
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    let amount: i64 = params.value.parse().map_err(|_| {
        CoreError::InvalidInput(format!("invalid TRX amount (sun): {}", params.value))
    })?;
    if amount <= 0 {
        return Err(CoreError::InvalidInput(
            "TRON transfer amount must be > 0 sun".into(),
        ));
    }

    let extra = params
        .extra
        .as_ref()
        .ok_or_else(|| CoreError::InvalidInput("TRON requires `extra` block".into()))?;

    let owner = parse_hex_field(extra, "owner_address", 21)?;
    let ref_block_bytes_v = parse_hex_field(extra, "ref_block_bytes", 2)?;
    let ref_block_hash_v = parse_hex_field(extra, "ref_block_hash", 8)?;
    let expiration = parse_i64_field(extra, "expiration")?;
    let timestamp = parse_i64_field(extra, "timestamp")?;
    let fee_limit = extra.get("fee_limit").and_then(|v| v.as_i64());

    let to = decode_tron_address(&params.to)?;

    let mut ref_block_bytes = [0u8; 2];
    ref_block_bytes.copy_from_slice(&ref_block_bytes_v);
    let mut ref_block_hash = [0u8; 8];
    ref_block_hash.copy_from_slice(&ref_block_hash_v);

    let raw_data = proto::build_transfer_raw_data(
        &owner,
        &to,
        amount,
        &ref_block_bytes,
        &ref_block_hash,
        expiration,
        timestamp,
        fee_limit,
    );

    // tx_id = SHA-256(raw_data) — the 32-byte prehash MPC signs.
    // Per L-011, when GG20/CGGMP21 see a 32-byte sign_payload they treat it as
    // an already-prehashed message and skip an internal SHA-256.
    let sign_payload = Sha256::digest(&raw_data).to_vec();

    Ok(UnsignedTransaction {
        chain: Chain::Tron,
        sign_payload,
        tx_data: raw_data,
    })
}

/// Finalize a TRON transaction with an ECDSA signature.
///
/// Wire format on the trailing 65 bytes: `r(32) ‖ s(32) ‖ v(1)`.
/// `v = 27 + recovery_id` (Ethereum-style — `0x1B` or `0x1C`). `tronweb`
/// writes the byte this way; TronGrid validators accept it directly.
pub fn finalize_tron_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let (r, s, recovery_id) = match sig {
        MpcSignature::Ecdsa { r, s, recovery_id } => (r.clone(), s.clone(), *recovery_id),
        _ => {
            return Err(CoreError::InvalidInput(
                "TRON requires ECDSA signature".into(),
            ));
        }
    };
    if r.len() != 32 || s.len() != 32 {
        return Err(CoreError::InvalidInput(format!(
            "TRON sig must be r=32 s=32, got r={} s={}",
            r.len(),
            s.len()
        )));
    }
    if recovery_id > 1 {
        return Err(CoreError::Crypto(format!(
            "TRON recovery_id must be 0 or 1, got {recovery_id}"
        )));
    }

    let mut raw_tx = unsigned.tx_data.clone();
    raw_tx.extend_from_slice(&r);
    raw_tx.extend_from_slice(&s);
    raw_tx.push(27 + recovery_id);

    // tx_hash = tx_id = SHA-256(raw_data) — TRON's canonical transaction id.
    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: Chain::Tron,
        raw_tx,
        tx_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_appends_r_s_v_with_eth_offset() {
        let unsigned = UnsignedTransaction {
            chain: Chain::Tron,
            sign_payload: vec![0xAA; 32],
            tx_data: vec![0xBB; 100],
        };
        let sig = MpcSignature::Ecdsa {
            r: vec![0x11; 32],
            s: vec![0x22; 32],
            recovery_id: 1,
        };
        let signed = finalize_tron_transaction(&unsigned, &sig).unwrap();
        assert_eq!(signed.raw_tx.len(), 100 + TRON_SIG_LEN);
        assert_eq!(&signed.raw_tx[100..132], &[0x11; 32]);
        assert_eq!(&signed.raw_tx[132..164], &[0x22; 32]);
        // 27 + parity(1) = 0x1C — Ethereum-style v byte.
        assert_eq!(signed.raw_tx[164], 0x1C);
    }
}
