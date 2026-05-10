// Aptos transaction serialization using BCS encoding.
//
// Builds a real `RawTransaction` (see `aptos::types`) wrapping the canonical
// `0x1::aptos_account::transfer(recipient, amount)` entry function. BCS bytes
// are byte-for-byte compatible with @aptos-labs/ts-sdk output — verified by
// the `bcs_matches_aptos_sdk_reference` test in `aptos::types`.
//
// Sign payload: `SHA3-256("APTOS::RawTransaction") ‖ bcs_bytes`. This is the
// raw message Ed25519 sees — Ed25519 itself internally SHA-512s it. We do NOT
// pre-hash with SHA3-256 (that would double-hash and Aptos would return
// `INVALID_SIGNATURE`).
// Wire format:  `bcs_bytes ‖ [0x00 ‖ 0x20 ‖ pubkey(32) ‖ 0x40 ‖ sig(64)]`
//   (0x00 = Ed25519 variant tag, 0x20/0x40 = Vec<u8> length prefixes).

use sha3::{Digest, Sha3_256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::aptos::address::validate_aptos_address;
use crate::aptos::types::RawTransaction;
use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Pre-broadcast invariant: verify the Ed25519 MPC signature against the
/// wallet's group public key over `unsigned.sign_payload`. Mirrors
/// `solana::tx::verify_solana_signature` and `sui::tx::verify_sui_signature`.
pub fn verify_aptos_signature(
    group_pubkey: &GroupPublicKey,
    sig: &MpcSignature,
    sign_payload: &[u8],
) -> Result<(), CoreError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pubkey_bytes: [u8; 32] = match group_pubkey {
        GroupPublicKey::Ed25519(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            a
        }
        _ => {
            return Err(CoreError::InvalidInput(
                "Aptos requires 32-byte Ed25519 group key".into(),
            ))
        }
    };
    let MpcSignature::EdDsa { signature } = sig else {
        return Err(CoreError::InvalidInput(
            "Aptos requires EdDsa signature".into(),
        ));
    };
    let sig_arr: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Crypto("Aptos sig must be 64 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| CoreError::Crypto(format!("invalid Aptos pubkey: {e}")))?;
    let ed_sig = Signature::from_bytes(&sig_arr);
    vk.verify(sign_payload, &ed_sig)
        .map_err(|e| CoreError::Crypto(format!("Aptos Ed25519 verify failed: {e}")))?;
    Ok(())
}

/// Compute the Aptos signing prefix: SHA3-256(b"APTOS::RawTransaction").
fn aptos_signing_prefix() -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"APTOS::RawTransaction");
    hasher.finalize().to_vec()
}

/// Build an unsigned Aptos transaction using BCS encoding.
///
/// Reads `sender`, `sequence_number`, `max_gas_amount`, `gas_unit_price`,
/// `expiration_timestamp_secs`, and `chain_id` from `params.extra`.
///
/// Sign payload = SHA3-256(prefix_hash || bcs_bytes) where
/// prefix_hash = SHA3-256(b"APTOS::RawTransaction").
///
/// Stores `bcs_bytes || pubkey(32)` in `tx_data`.
pub async fn build_aptos_transaction(
    params: TransactionParams,
    group_pubkey: &GroupPublicKey,
) -> Result<UnsignedTransaction, CoreError> {
    build_move_transaction(Chain::Aptos, params, group_pubkey).await
}

/// Build an unsigned Move VM transaction (Aptos or Movement).
pub async fn build_move_transaction(
    chain: Chain,
    params: TransactionParams,
    group_pubkey: &GroupPublicKey,
) -> Result<UnsignedTransaction, CoreError> {
    // 1. Extract and validate sender
    let sender_hex = params
        .extra
        .as_ref()
        .and_then(|e| e["sender"].as_str())
        .ok_or_else(|| CoreError::InvalidInput("Aptos: missing sender in extra".into()))?;
    let sender_bytes = validate_aptos_address(sender_hex)?;

    // 2. Validate and decode recipient
    let recipient_bytes = validate_aptos_address(&params.to)?;

    // 3. Parse amount
    let amount: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    // 4. Parse extra params with defaults
    let extra = params.extra.as_ref();
    let sequence_number = extra
        .and_then(|e| e["sequence_number"].as_u64())
        .unwrap_or(0);
    let max_gas_amount = extra
        .and_then(|e| e["max_gas_amount"].as_u64())
        .unwrap_or(2000);
    let gas_unit_price = extra
        .and_then(|e| e["gas_unit_price"].as_u64())
        .unwrap_or(100);
    let expiration_timestamp_secs = extra
        .and_then(|e| e["expiration_timestamp_secs"].as_u64())
        .unwrap_or(u64::MAX);
    let chain_id = extra.and_then(|e| e["chain_id"].as_u64()).unwrap_or(1) as u8;

    // 5. Token-aware RawTransaction build:
    //    Native APT → 0x1::aptos_account::transfer(recipient, amount).
    //    Coin<T>    → 0x1::coin::transfer<T>(recipient, amount).
    //    Fungible Asset comes in Sprint 47.
    let token = crate::token::TokenIdentifier::from_extra(params.extra.as_ref())
        .map_err(CoreError::InvalidInput)?;
    let raw_tx = match token {
        crate::token::TokenIdentifier::Native => RawTransaction::new_transfer(
            sender_bytes,
            sequence_number,
            recipient_bytes,
            amount,
            max_gas_amount,
            gas_unit_price,
            expiration_timestamp_secs,
            chain_id,
        ),
        crate::token::TokenIdentifier::Aptos {
            flavor: crate::token::AptosTokenKind::Coin { type_tag },
        } => {
            let coin_type = crate::aptos::types::StructTag::parse(&type_tag)
                .map_err(CoreError::InvalidInput)?;
            RawTransaction::new_coin_transfer(
                sender_bytes,
                sequence_number,
                coin_type,
                recipient_bytes,
                amount,
                max_gas_amount,
                gas_unit_price,
                expiration_timestamp_secs,
                chain_id,
            )
        }
        crate::token::TokenIdentifier::Aptos {
            flavor: crate::token::AptosTokenKind::FungibleAsset { metadata },
        } => {
            // Parse the FA metadata Object<Metadata> address (32-byte hex).
            let metadata_bytes = validate_aptos_address(&metadata)?;
            RawTransaction::new_fungible_asset_transfer(
                sender_bytes,
                sequence_number,
                metadata_bytes,
                recipient_bytes,
                amount,
                max_gas_amount,
                gas_unit_price,
                expiration_timestamp_secs,
                chain_id,
            )
        }
        other => {
            return Err(CoreError::InvalidInput(format!(
                "Aptos build_transaction got non-Aptos token spec: {other:?}"
            )));
        }
    };

    // 6. BCS encode
    let bcs_bytes =
        bcs::to_bytes(&raw_tx).map_err(|e| CoreError::Protocol(format!("BCS failed: {e}")))?;

    // 7. Compute sign_payload: prefix ‖ bcs_bytes  (NOT the hash of that).
    //    Ed25519 itself hashes the message with SHA-512 internally; pre-hashing
    //    here with SHA3-256 would produce a signature over the wrong digest
    //    (Aptos rejects with INVALID_SIGNATURE).
    let prefix = aptos_signing_prefix();
    let mut sign_payload = Vec::with_capacity(prefix.len() + bcs_bytes.len());
    sign_payload.extend_from_slice(&prefix);
    sign_payload.extend_from_slice(&bcs_bytes);

    // 8. Validate Ed25519 key
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Ed25519(ref b) => {
            if b.len() != 32 {
                return Err(CoreError::InvalidInput(
                    "Ed25519 pubkey must be 32 bytes".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            arr
        }
        _ => return Err(CoreError::InvalidInput("Aptos requires Ed25519 key".into())),
    };

    // 9. Store: tx_data = bcs_bytes || pubkey(32)
    let mut tx_data = bcs_bytes;
    tx_data.extend_from_slice(&pubkey_bytes);

    Ok(UnsignedTransaction {
        chain,
        sign_payload,
        tx_data,
    })
}

/// Finalize an Aptos/Movement transaction with an EdDSA signature.
///
/// Expects `unsigned.tx_data` in the format: `bcs_bytes || pubkey(32)`.
///
/// Builds the signed transaction bytes:
///   `bcs_bytes || [0x00, sig(64), 0x20, pubkey(32)]`
///
/// where `0x00` is the Ed25519 scheme tag and `0x20` is the pubkey length (32).
pub fn finalize_aptos_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let sig_bytes = match sig {
        MpcSignature::EdDsa { signature } => *signature,
        _ => {
            return Err(CoreError::InvalidInput(
                "Aptos requires EdDsa signature".into(),
            ))
        }
    };

    if unsigned.tx_data.len() < 32 {
        return Err(CoreError::Protocol("tx_data too short".into()));
    }
    let (bcs_bytes, pubkey_bytes) = unsigned.tx_data.split_at(unsigned.tx_data.len() - 32);
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(pubkey_bytes);

    // Build SignedTransaction wire format: bcs(RawTransaction) ‖ bcs(TransactionAuthenticator).
    // Aptos `TransactionAuthenticator::Ed25519 { public_key, signature }` BCS:
    //   variant_tag(0x00) ‖ Vec<u8>(public_key, 32) ‖ Vec<u8>(signature, 64)
    //   = 0x00 ‖ 0x20 ‖ pubkey(32) ‖ 0x40 ‖ sig(64) = 99 bytes
    // Verified against @aptos-labs/ts-sdk AccountAuthenticatorEd25519 reference.
    let mut raw_tx = Vec::with_capacity(bcs_bytes.len() + 99);
    raw_tx.extend_from_slice(bcs_bytes);
    raw_tx.push(0x00); // Authenticator variant: Ed25519
    raw_tx.push(0x20); // Vec<u8> length prefix = 32 (pubkey)
    raw_tx.extend_from_slice(&pubkey_arr);
    raw_tx.push(0x40); // Vec<u8> length prefix = 64 (signature)
    raw_tx.extend_from_slice(&sig_bytes);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: unsigned.chain,
        raw_tx,
        tx_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> GroupPublicKey {
        GroupPublicKey::Ed25519([1u8; 32].to_vec())
    }

    fn test_params() -> TransactionParams {
        TransactionParams {
            to: format!("0x{}", "ab".repeat(32)),
            value: "1000".to_string(),
            data: None,
            chain_id: None,
            extra: Some(serde_json::json!({
                "sender": format!("0x{}", "01".repeat(32)),
                "sequence_number": 0,
                "max_gas_amount": 2000,
                "gas_unit_price": 100,
                "expiration_timestamp_secs": 9999999999u64,
                "chain_id": 1
            })),
        }
    }

    #[tokio::test]
    async fn test_build_aptos_sign_payload_starts_with_prefix() {
        // sign_payload = SHA3-256("APTOS::RawTransaction") ‖ bcs_bytes
        // (raw message for Ed25519, NOT a 32-byte digest).
        let unsigned = build_aptos_transaction(test_params(), &test_pubkey())
            .await
            .unwrap();
        let prefix = aptos_signing_prefix();
        assert!(
            unsigned.sign_payload.len() > 32,
            "sign_payload must contain prefix ‖ bcs_bytes, got {}",
            unsigned.sign_payload.len()
        );
        assert_eq!(
            &unsigned.sign_payload[..32],
            prefix.as_slice(),
            "sign_payload must start with the SHA3-256(\"APTOS::RawTransaction\") prefix"
        );
    }

    #[tokio::test]
    async fn test_build_aptos_tx_data_contains_pubkey() {
        let pubkey = test_pubkey();
        let unsigned = build_aptos_transaction(test_params(), &pubkey)
            .await
            .unwrap();
        let last_32 = &unsigned.tx_data[unsigned.tx_data.len() - 32..];
        assert_eq!(last_32, &[1u8; 32]);
    }

    #[tokio::test]
    async fn test_build_aptos_rejects_secp256k1() {
        let pubkey = GroupPublicKey::Secp256k1(vec![2; 33]);
        let result = build_aptos_transaction(test_params(), &pubkey).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_finalize_aptos_rejects_ecdsa() {
        let unsigned = UnsignedTransaction {
            chain: Chain::Aptos,
            sign_payload: vec![0u8; 32],
            tx_data: vec![0u8; 64],
        };
        let sig = MpcSignature::Ecdsa {
            r: vec![0u8; 32],
            s: vec![0u8; 32],
            recovery_id: 0,
        };
        assert!(finalize_aptos_transaction(&unsigned, &sig).is_err());
    }

    #[tokio::test]
    async fn test_finalize_aptos_format() {
        let unsigned = build_aptos_transaction(test_params(), &test_pubkey())
            .await
            .unwrap();
        let sig = MpcSignature::EdDsa {
            signature: [0xAA; 64],
        };
        let signed = finalize_aptos_transaction(&unsigned, &sig).unwrap();
        // raw_tx = bcs_bytes ‖ [0x00 ‖ 0x20 ‖ pubkey(32) ‖ 0x40 ‖ sig(64)] = bcs_bytes + 99
        let bcs_len = unsigned.tx_data.len() - 32;
        assert_eq!(signed.raw_tx.len(), bcs_len + 99);
        // Authenticator layout
        assert_eq!(signed.raw_tx[bcs_len], 0x00, "Ed25519 variant tag");
        assert_eq!(
            signed.raw_tx[bcs_len + 1],
            0x20,
            "Vec<u8> length=32 for pubkey"
        );
        assert_eq!(
            &signed.raw_tx[bcs_len + 2..bcs_len + 34],
            &[1u8; 32],
            "pubkey bytes"
        );
        assert_eq!(
            signed.raw_tx[bcs_len + 34],
            0x40,
            "Vec<u8> length=64 for sig"
        );
        assert_eq!(
            &signed.raw_tx[bcs_len + 35..bcs_len + 99],
            &[0xAA; 64],
            "sig bytes"
        );
    }
}
