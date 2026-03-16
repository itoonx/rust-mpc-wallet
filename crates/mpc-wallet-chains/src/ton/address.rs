//! TON address derivation.
//!
//! TON address is derived from the StateInit hash of the wallet contract.
//! Raw address = `workchain_id:sha256(state_init_cell)`
//! where state_init contains the wallet code cell and data cell (with pubkey).

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha2::{Digest, Sha256};

use super::cell::Cell;

/// Derive a TON raw address from an Ed25519 public key.
///
/// Constructs a simplified wallet StateInit:
///   state_init = Cell(code_hash || data_cell_hash)
///   data_cell = Cell(seqno=0 || pubkey)
///   address = 0:sha256(state_init_cell.hash())
pub fn derive_ton_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Ed25519(bytes) => {
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(
                    "invalid Ed25519 public key length".into(),
                ));
            }
            bytes.clone()
        }
        _ => {
            return Err(CoreError::Crypto("TON requires Ed25519 public key".into()));
        }
    };

    // Build data cell: seqno(4 bytes, 0) || subwallet_id(4 bytes) || pubkey(32 bytes)
    let mut data_cell_data = Vec::new();
    data_cell_data.extend_from_slice(&0u32.to_be_bytes()); // seqno = 0
    data_cell_data.extend_from_slice(&698983191u32.to_be_bytes()); // default subwallet_id
    data_cell_data.extend_from_slice(&pubkey_bytes);
    let data_cell = Cell::new(data_cell_data);

    // Build code cell (wallet v4 code hash placeholder — real code cell is the compiled contract)
    let code_cell = Cell::new(vec![0xFF; 32]); // placeholder code hash

    // Build StateInit cell: code_cell + data_cell as refs
    let state_init = Cell::with_refs(vec![0x00; 1], vec![code_cell, data_cell]);

    // Address = SHA-256 of StateInit cell hash
    let state_hash = Sha256::digest(state_init.hash());

    // Raw address: workchain:hash
    Ok(format!("0:{}", hex::encode(state_hash)))
}

/// Validate a TON raw address format: `workchain_id:64_hex_chars`.
pub fn validate_ton_address(addr: &str) -> Result<(), CoreError> {
    let parts: Vec<&str> = addr.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(CoreError::InvalidInput(format!(
            "TON address must be 'workchain:hash', got: {addr}"
        )));
    }
    let _workchain: i8 = parts[0]
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid TON workchain_id: {}", parts[0])))?;
    let hash_hex = parts[1];
    if hash_hex.len() != 64 {
        return Err(CoreError::InvalidInput(format!(
            "TON address hash must be 64 hex chars, got {}",
            hash_hex.len()
        )));
    }
    hex::decode(hash_hex)
        .map_err(|e| CoreError::InvalidInput(format!("TON address invalid hex: {e}")))?;
    Ok(())
}
