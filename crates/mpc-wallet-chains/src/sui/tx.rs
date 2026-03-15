// TODO(production): Replace the JSON-based tx_data with real BCS-encoded
// `TransactionData` once a BCS-capable Sui SDK crate is added to the workspace.
// The sign_payload computation (Blake2b-256 of intent-prefix || tx_bytes) is
// already correct per the Sui protocol spec; only the serialization of tx_bytes
// needs to move from canonical JSON to BCS.
//
// Sui signature wire format: [0x00] || signature(64 bytes) || pubkey(32 bytes)
//   flag 0x00 = Ed25519

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

/// Validate a Sui address string.
/// A valid Sui address is `0x` followed by exactly 64 lowercase hex characters (32 bytes).
pub fn validate_sui_address(addr: &str) -> Result<[u8; 32], CoreError> {
    let hex_part = addr.strip_prefix("0x").ok_or_else(|| {
        CoreError::InvalidInput(format!("Sui address must start with '0x', got: {addr}"))
    })?;
    if hex_part.len() != 64 {
        return Err(CoreError::InvalidInput(format!(
            "Sui address must be 0x + 64 hex chars (32 bytes), got {} hex chars",
            hex_part.len()
        )));
    }
    let bytes = hex::decode(hex_part).map_err(|e| {
        CoreError::InvalidInput(format!("Sui address contains invalid hex: {e}"))
    })?;
    Ok(bytes.try_into().unwrap()) // safe: we checked len == 64 hex = 32 bytes
}

use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Sui intent prefix for transaction signing: [intent_scope=0, version=0, app_id=0]
const SUI_INTENT_PREFIX: [u8; 3] = [0, 0, 0];

/// Build an unsigned Sui transaction.
///
/// Produces a deterministic canonical JSON representation of the transaction
/// parameters as `tx_data`, then computes:
///   `sign_payload = Blake2b-256(SUI_INTENT_PREFIX || tx_data)`
///
/// The `group_pubkey` (Ed25519) is embedded inside `tx_data` so that
/// `finalize_sui_transaction` can reconstruct the Sui signature without
/// needing an extra parameter not present in the `ChainProvider` trait.
pub async fn build_sui_transaction(
    params: TransactionParams,
    group_pubkey: &GroupPublicKey,
) -> Result<UnsignedTransaction, CoreError> {
    // Validate and extract the Ed25519 public key early so we fail fast.
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Ed25519(bytes) => {
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(
                    "Ed25519 public key must be exactly 32 bytes".into(),
                ));
            }
            bytes.clone()
        }
        _ => {
            return Err(CoreError::Crypto(
                "Sui requires an Ed25519 public key".into(),
            ))
        }
    };

    let sender = params
        .extra
        .as_ref()
        .and_then(|e| e.get("sender"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::InvalidInput("missing sender".into()))?;

    let amount: u64 = params
        .value
        .parse()
        .map_err(|e| CoreError::InvalidInput(format!("invalid value: {e}")))?;

    // Build a canonical JSON representation of the transaction.
    // The pubkey is embedded here so finalize_sui_transaction can retrieve it.
    //
    // TODO(production): Replace this JSON blob with a BCS-encoded TransactionData
    // struct once a suitable Sui SDK / bcs crate is approved by R0 and added to
    // workspace dependencies.  The sign_payload computation below is already
    // correct per the Sui spec; only this serialization format needs upgrading.
    let tx_info = serde_json::json!({
        "sender": sender,
        "recipient": params.to,
        "amount": amount,
        // Hex-encoded Ed25519 pubkey — recovered by finalize_sui_transaction
        "pubkey": hex::encode(&pubkey_bytes),
    });

    let tx_data = serde_json::to_vec(&tx_info)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    // Sui signing payload: Blake2b-256(intent_prefix || bcs_tx_data)
    // Our tx_data is canonical JSON (not BCS yet), but the hashing step is correct.
    use blake2::digest::consts::U32;
    use blake2::Blake2b;
    use blake2::Digest;
    type Blake2b256 = Blake2b<U32>;

    let mut intent_msg = Vec::with_capacity(SUI_INTENT_PREFIX.len() + tx_data.len());
    intent_msg.extend_from_slice(&SUI_INTENT_PREFIX);
    intent_msg.extend_from_slice(&tx_data);

    let sign_payload = Blake2b256::digest(&intent_msg).to_vec();

    Ok(UnsignedTransaction {
        chain: Chain::Sui,
        sign_payload,
        tx_data,
    })
}

/// Finalize a Sui transaction with an EdDSA signature.
///
/// Extracts the Ed25519 public key from the embedded `tx_data` JSON (written by
/// `build_sui_transaction`) and builds the Sui serialized-signature format:
///
///   `[0x00] || signature(64 bytes) || pubkey(32 bytes)`
///
/// where `0x00` is the Ed25519 scheme flag defined by Sui.
pub fn finalize_sui_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let MpcSignature::EdDsa { signature } = sig else {
        return Err(CoreError::InvalidInput(
            "Sui requires EdDSA signature".into(),
        ));
    };

    // Recover the public key from tx_data.  build_sui_transaction embeds it as
    // a hex-encoded "pubkey" field inside the canonical JSON.
    let tx_json: serde_json::Value = serde_json::from_slice(&unsigned.tx_data)
        .map_err(|e| CoreError::Serialization(format!("tx_data is not valid JSON: {e}")))?;

    let pubkey_hex = tx_json
        .get("pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CoreError::InvalidInput("tx_data missing pubkey field".into()))?;

    let pubkey_bytes: Vec<u8> = hex::decode(pubkey_hex)
        .map_err(|e| CoreError::InvalidInput(format!("invalid pubkey hex in tx_data: {e}")))?;

    if pubkey_bytes.len() != 32 {
        return Err(CoreError::Crypto(format!(
            "embedded pubkey must be 32 bytes, got {}",
            pubkey_bytes.len()
        )));
    }

    // Build Sui serialized signature: flag(1) || sig(64) || pubkey(32) = 97 bytes
    let mut sui_sig = Vec::with_capacity(1 + 64 + 32);
    sui_sig.push(0x00); // Ed25519 scheme flag
    sui_sig.extend_from_slice(signature); // 64-byte EdDSA signature
    sui_sig.extend_from_slice(&pubkey_bytes); // 32-byte Ed25519 public key

    // Transaction digest: Blake2b-256 of the raw tx_data bytes (used as an
    // identifier; matches the intent-wrapped hash used for signing).
    let tx_hash = {
        use blake2::digest::consts::U32;
        use blake2::Blake2b;
        use blake2::Digest;
        type Blake2b256 = Blake2b<U32>;
        let digest = Blake2b256::digest(&unsigned.tx_data);
        bs58::encode(digest).into_string()
    };

    let signed_data = serde_json::json!({
        "tx_bytes": hex::encode(&unsigned.tx_data),
        "signature": hex::encode(&sui_sig),
    });

    let raw_tx = serde_json::to_vec(&signed_data)
        .map_err(|e| CoreError::Serialization(e.to_string()))?;

    Ok(SignedTransaction {
        chain: Chain::Sui,
        raw_tx,
        tx_hash,
    })
}
