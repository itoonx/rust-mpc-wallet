use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::MpcSignature;

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// The secp256k1 curve order n (big-endian, 32 bytes).
/// S values must satisfy `s <= n/2` for EIP-2 / low-S canonicalization.
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Half of the secp256k1 curve order (n/2), used for low-S check.
const SECP256K1_N_HALF: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// Compare two 32-byte big-endian values. Returns `std::cmp::Ordering`.
fn cmp_bytes32(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        match x.cmp(y) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Subtract b from a (big-endian 32-byte), assuming a >= b.
fn sub_bytes32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (a[i] as u16).wrapping_sub(b[i] as u16).wrapping_sub(borrow);
        result[i] = diff as u8;
        borrow = if diff > 0xFF { 1 } else { 0 };
    }
    result
}

/// Normalise an ECDSA S value to the lower half of the curve order (low-S).
///
/// # SEC-012 fix
///
/// EIP-2 (included in Homestead) requires that ECDSA S values satisfy
/// `s <= secp256k1_n / 2`. High-S signatures (`s > n/2`) are rejected by
/// many Ethereum nodes, wallets, and infrastructure providers (e.g. MetaMask,
/// Infura). MPC protocols may produce high-S values; this function normalises
/// them by computing `s' = n - s` and flipping the recovery ID.
///
/// Returns `(normalised_s, new_recovery_id)`.
fn normalise_low_s(s_bytes: &[u8; 32], recovery_id: u8) -> ([u8; 32], u8) {
    if cmp_bytes32(s_bytes, &SECP256K1_N_HALF) == std::cmp::Ordering::Greater {
        // s > n/2 — normalise: s' = n - s, flip parity bit
        let s_norm = sub_bytes32(&SECP256K1_N, s_bytes);
        let new_recovery = recovery_id ^ 1;
        (s_norm, new_recovery)
    } else {
        (*s_bytes, recovery_id)
    }
}

/// Build an unsigned EVM transaction (EIP-1559).
pub async fn build_evm_transaction(
    chain: Chain,
    chain_id: u64,
    params: TransactionParams,
) -> Result<UnsignedTransaction, CoreError> {
    use alloy::consensus::TxEip1559;
    use alloy::primitives::{Address, Bytes, TxKind, U256};

    let to_addr: Address = params
        .to
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid to address: {e}")))?;

    // Parse value: hex if "0x" prefix, else decimal. Avoid the previous bug
    // where bare digits like "1000000000000000" were silently parsed as hex.
    let value = if let Some(hex) = params.value.strip_prefix("0x") {
        U256::from_str_radix(hex, 16)
            .map_err(|e| CoreError::InvalidInput(format!("invalid hex value: {e}")))?
    } else {
        U256::from_str_radix(&params.value, 10)
            .map_err(|e| CoreError::InvalidInput(format!("invalid decimal value: {e}")))?
    };

    let tx = TxEip1559 {
        chain_id,
        nonce: params
            .extra
            .as_ref()
            .and_then(|e| e.get("nonce"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        gas_limit: params
            .extra
            .as_ref()
            .and_then(|e| e.get("gas_limit"))
            .and_then(|v| v.as_u64())
            .unwrap_or(21000),
        max_fee_per_gas: params
            .extra
            .as_ref()
            .and_then(|e| e.get("max_fee_per_gas"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u128)
            .unwrap_or(30_000_000_000),
        max_priority_fee_per_gas: params
            .extra
            .as_ref()
            .and_then(|e| e.get("max_priority_fee_per_gas"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u128)
            .unwrap_or(1_000_000_000),
        to: TxKind::Call(to_addr),
        value,
        input: Bytes::from(params.data.unwrap_or_default()),
        access_list: Default::default(),
    };

    use alloy::consensus::SignableTransaction;
    let sign_hash = tx.clone().signature_hash().to_vec();
    let tx_data = serde_json::to_vec(&tx).map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(UnsignedTransaction {
        chain,
        sign_payload: sign_hash,
        tx_data,
    })
}

/// Finalize an EVM transaction by attaching the ECDSA signature.
///
/// # SEC-012: low-S enforcement
///
/// This function automatically normalises high-S signatures to low-S by computing
/// `s' = n - s` (where n is the secp256k1 curve order) and flipping the recovery
/// ID. The resulting signature is canonical per EIP-2 and will be accepted by all
/// Ethereum nodes and infrastructure providers.
pub fn finalize_evm_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy::eips::Encodable2718;
    use alloy::primitives::{Signature, B256};

    let MpcSignature::Ecdsa { r, s, recovery_id } = sig else {
        return Err(CoreError::InvalidInput(
            "EVM requires ECDSA signature".into(),
        ));
    };

    // Validate s length
    if s.len() != 32 {
        return Err(CoreError::EvmLowS(format!(
            "s-value must be 32 bytes, got {}",
            s.len()
        )));
    }

    let tx: TxEip1559 = serde_json::from_slice(&unsigned.tx_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    let r_b256 = B256::from_slice(r);

    // SEC-012: normalise S to low-S (EIP-2 canonicalization)
    let s_arr: [u8; 32] = s
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::EvmLowS("s-value must be exactly 32 bytes".into()))?;
    let (s_norm, rid_norm) = normalise_low_s(&s_arr, *recovery_id);
    let s_b256 = B256::from_slice(&s_norm);

    let parity = rid_norm & 1 == 1;
    let alloy_sig = Signature::from_scalars_and_parity(r_b256, s_b256, parity);

    let signed = tx.into_signed(alloy_sig);
    let envelope = TxEnvelope::Eip1559(signed);

    let raw_tx = envelope.encoded_2718();
    let tx_hash = format!("0x{}", hex::encode(envelope.tx_hash()));

    Ok(SignedTransaction {
        chain: unsigned.chain,
        raw_tx,
        tx_hash,
    })
}

/// Recover the EIP-55 sender address from a 2718-encoded EIP-1559 envelope.
/// Used as a pre-broadcast sanity check so a wrong recovery_id never escapes.
pub fn recover_eip1559_sender(raw_tx: &[u8]) -> Result<String, CoreError> {
    use alloy::consensus::transaction::SignerRecoverable;
    use alloy::consensus::TxEnvelope;
    use alloy::eips::Decodable2718;
    let envelope = TxEnvelope::decode_2718(&mut &raw_tx[..])
        .map_err(|e| CoreError::Other(format!("decode 2718: {e}")))?;
    let signer = envelope
        .recover_signer()
        .map_err(|e| CoreError::Crypto(format!("recover_signer: {e}")))?;
    Ok(signer.to_checksum(None))
}

/// Decode a 2718-encoded EIP-1559 envelope and return a summary of its fields
/// (chain_id, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, value).
/// Used as a diagnostic to verify what's actually being broadcast.
pub fn decode_eip1559_summary(raw_tx: &[u8]) -> Result<String, CoreError> {
    use alloy::consensus::Transaction;
    use alloy::consensus::TxEnvelope;
    use alloy::eips::Decodable2718;
    let envelope = TxEnvelope::decode_2718(&mut &raw_tx[..])
        .map_err(|e| CoreError::Other(format!("decode 2718: {e}")))?;
    let tx = match envelope {
        TxEnvelope::Eip1559(s) => s,
        other => {
            return Err(CoreError::Other(format!(
                "expected EIP-1559 envelope, got {other:?}"
            )))
        }
    };
    let inner = tx.tx();
    Ok(format!(
        "chain_id={} nonce={} gas_limit={} max_fee_per_gas={} max_priority_fee_per_gas={} value={}",
        inner.chain_id().unwrap_or(0),
        inner.nonce(),
        inner.gas_limit(),
        inner.max_fee_per_gas(),
        inner.max_priority_fee_per_gas().unwrap_or(0),
        inner.value(),
    ))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// secp256k1 n/2 + 1 — a value just above the midpoint (high-S)
    const HIGH_S: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B,
        0x20, 0xA1,
    ];

    /// A low-S value (just 1)
    const LOW_S: [u8; 32] = {
        let mut v = [0u8; 32];
        v[31] = 1;
        v
    };

    #[test]
    fn test_low_s_unchanged() {
        let (s_out, rid_out) = normalise_low_s(&LOW_S, 0);
        assert_eq!(s_out, LOW_S, "low-S must not change");
        assert_eq!(rid_out, 0, "recovery_id must not change for low-S");
    }

    #[test]
    fn test_high_s_normalised() {
        let (s_out, rid_out) = normalise_low_s(&HIGH_S, 0);
        assert_ne!(s_out, HIGH_S, "high-S must be normalised");
        assert_eq!(rid_out, 1, "recovery_id must flip for high-S");
        // normalised s must be <= n/2
        assert!(
            cmp_bytes32(&s_out, &SECP256K1_N_HALF) != std::cmp::Ordering::Greater,
            "normalised s must be <= n/2"
        );
    }

    #[test]
    fn test_recovery_id_flip_is_symmetric() {
        // Normalising twice should yield the original (idempotent round-trip)
        let (s1, rid1) = normalise_low_s(&HIGH_S, 0);
        // s1 is now low-S, so normalising again should be a no-op
        let (s2, rid2) = normalise_low_s(&s1, rid1);
        assert_eq!(s1, s2);
        assert_eq!(rid1, rid2);
    }

    #[test]
    fn test_n_half_is_boundary_low_s() {
        // n/2 itself is a valid low-S value (not strictly greater)
        let (s_out, rid_out) = normalise_low_s(&SECP256K1_N_HALF, 0);
        assert_eq!(
            s_out, SECP256K1_N_HALF,
            "n/2 is low-S — must not be normalised"
        );
        assert_eq!(rid_out, 0);
    }

    #[test]
    fn test_sub_bytes32_basic() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[31] = 5;
        b[31] = 3;
        let result = sub_bytes32(&a, &b);
        assert_eq!(result[31], 2);
    }
}
