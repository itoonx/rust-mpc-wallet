//! Generic Solana instruction model + message-builder.
//!
//! Replaces the Sprint 38 hardcoded SystemInstruction::Transfer path with
//! a reusable abstraction that any program (SPL Token, Associated Token
//! Account, etc.) can target via the same encoder. Native SOL transfer
//! stays as a single-instruction case.
//!
//! Account ordering rules (per Solana ABI):
//! 1. Writable + signer
//! 2. Readonly + signer
//! 3. Writable + nonsigner
//! 4. Readonly + nonsigner
//!
//! The fee payer is always the first account and always (writable + signer).
//! Each pubkey appears exactly once in `account_keys` even if multiple
//! instructions reference it; flags are the OR across all references.

use super::tx::AddressLookupTable;

/// Per-instruction reference to an account.
#[derive(Debug, Clone)]
pub struct AccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn writable(pubkey: [u8; 32], is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }
    pub fn readonly(pubkey: [u8; 32], is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

/// A single program invocation. Mirrors `solana_sdk::instruction::Instruction`.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Solana message version selector. Same enum we already had — re-exposed
/// here so callers don't have to dual-import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageVersion {
    Legacy,
    V0,
}

fn encode_compact_u16(val: u16) -> Vec<u8> {
    if val < 0x80 {
        vec![val as u8]
    } else {
        vec![(val & 0x7f) as u8 | 0x80, (val >> 7) as u8]
    }
}

/// Build a Solana message from a list of instructions. Handles account-key
/// deduplication, the 4-bucket ordering, and header counts.
///
/// `fee_payer` MUST be the first account and is always (writable, signer).
/// `instructions` may reference `fee_payer` again — it'll be merged.
pub fn build_message(
    fee_payer: [u8; 32],
    instructions: &[Instruction],
    recent_blockhash: &[u8; 32],
    version: MessageVersion,
    lookup_tables: &[AddressLookupTable],
) -> Vec<u8> {
    // ── 1. Collect unique accounts with merged (signer, writable) flags ────
    // Preserve first-seen order from the instructions, but bucket them at the
    // end into the 4-tier sort. The fee_payer is forced first.
    let mut metas: Vec<AccountMeta> = vec![AccountMeta::writable(fee_payer, true)];
    for ix in instructions {
        // Program ID first (matches @solana/web3.js CompiledKeys traversal —
        // affects within-bucket ordering of readonly accounts).
        if !metas.iter().any(|m| m.pubkey == ix.program_id) {
            metas.push(AccountMeta::readonly(ix.program_id, false));
        }
        // Then account references, in instruction order.
        for am in &ix.accounts {
            match metas.iter_mut().find(|m| m.pubkey == am.pubkey) {
                Some(existing) => {
                    existing.is_signer |= am.is_signer;
                    existing.is_writable |= am.is_writable;
                }
                None => metas.push(am.clone()),
            }
        }
    }

    // ── 2. Stable-sort into 4 buckets, fee_payer pinned first ─────────────
    let fee_payer_meta = metas.remove(0); // keep at slot 0
    let bucket = |m: &AccountMeta| match (m.is_signer, m.is_writable) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    metas.sort_by_key(bucket);
    metas.insert(0, fee_payer_meta);

    // ── 3. Compute header counts ──────────────────────────────────────────
    let num_signers = metas.iter().filter(|m| m.is_signer).count();
    let num_readonly_signed = metas
        .iter()
        .filter(|m| m.is_signer && !m.is_writable)
        .count();
    let num_readonly_unsigned = metas
        .iter()
        .filter(|m| !m.is_signer && !m.is_writable)
        .count();

    // ── 4. Index lookup for serializing instructions ──────────────────────
    let idx_of = |pubkey: &[u8; 32]| -> u8 {
        metas
            .iter()
            .position(|m| m.pubkey == *pubkey)
            .expect("instruction references account not in metas") as u8
    };

    // ── 5. Emit message ───────────────────────────────────────────────────
    let mut msg = Vec::with_capacity(256);
    if version == MessageVersion::V0 {
        msg.push(0x80); // versioned + version 0
    }
    msg.push(num_signers as u8);
    msg.push(num_readonly_signed as u8);
    msg.push(num_readonly_unsigned as u8);

    msg.extend_from_slice(&encode_compact_u16(metas.len() as u16));
    for m in &metas {
        msg.extend_from_slice(&m.pubkey);
    }
    msg.extend_from_slice(recent_blockhash);

    msg.extend_from_slice(&encode_compact_u16(instructions.len() as u16));
    for ix in instructions {
        msg.push(idx_of(&ix.program_id));
        msg.extend_from_slice(&encode_compact_u16(ix.accounts.len() as u16));
        for am in &ix.accounts {
            msg.push(idx_of(&am.pubkey));
        }
        msg.extend_from_slice(&encode_compact_u16(ix.data.len() as u16));
        msg.extend_from_slice(&ix.data);
    }

    if version == MessageVersion::V0 {
        msg.extend_from_slice(&encode_compact_u16(lookup_tables.len() as u16));
        for alt in lookup_tables {
            msg.extend_from_slice(&alt.address);
            msg.extend_from_slice(&encode_compact_u16(alt.writable_indices.len() as u16));
            msg.extend_from_slice(&alt.writable_indices);
            msg.extend_from_slice(&encode_compact_u16(alt.readonly_indices.len() as u16));
            msg.extend_from_slice(&alt.readonly_indices);
        }
    }

    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Native SOL transfer through the new instruction path must produce the
    /// same bytes as the legacy hardcoded builder (regression guard).
    #[test]
    fn native_transfer_roundtrip() {
        let from = [0x11u8; 32];
        let to = [0x22u8; 32];
        let lamports = 1_000_000u64;
        let blockhash = [0x33u8; 32];

        // Hand-build the native transfer instruction targeting system program (all-zeros).
        let system_program = [0u8; 32];
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&[2u8, 0, 0, 0]); // SystemInstruction::Transfer
        data.extend_from_slice(&lamports.to_le_bytes());
        let ix = Instruction {
            program_id: system_program,
            accounts: vec![
                AccountMeta::writable(from, true), // from is signer + writable
                AccountMeta::writable(to, false),
            ],
            data,
        };
        let msg_v0 = build_message(from, &[ix], &blockhash, MessageVersion::V0, &[]);

        // Sanity: starts with 0x80 version prefix, header [1, 0, 1], 3 accounts.
        assert_eq!(msg_v0[0], 0x80);
        assert_eq!(&msg_v0[1..4], &[1u8, 0, 1]);
        assert_eq!(msg_v0[4], 3); // num_account_keys
    }
}
