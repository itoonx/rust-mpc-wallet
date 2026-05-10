//! SPL Token instruction encoders + Associated Token Account helpers.
//!
//! Two instructions are needed for a fungible-token transfer:
//!
//! 1. **`CreateAssociatedTokenAccountIdempotent`** (ATA program, discriminator 1)
//!    — ensures the recipient's ATA exists. No-op if the account is already
//!    initialized; otherwise creates it (sender pays ~0.002 SOL rent).
//!
//! 2. **`TransferChecked`** (SPL Token / Token-2022, discriminator 12) —
//!    moves `amount` from sender's ATA to recipient's ATA. The "checked"
//!    variant verifies the supplied `decimals` match the mint, catching
//!    a class of off-by-decimal bugs that the legacy `Transfer` discriminator
//!    silently passed.

use super::ata::ASSOCIATED_TOKEN_PROGRAM_ID;
use super::instruction::{AccountMeta, Instruction};

/// `CreateAssociatedTokenAccountIdempotent` — `[1u8]` (single-byte data).
/// Solana System Program ID (all-zeros).
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// Build an idempotent CreateATA instruction. Always safe to include —
/// it's a no-op if the recipient ATA already exists. Funder pays the rent.
///
/// Account order (per `spl-associated-token-account` source):
/// 0. funder (writable, signer)
/// 1. ata (writable, NOT signer — derived address)
/// 2. owner (readonly, NOT signer)
/// 3. mint (readonly)
/// 4. system_program (readonly)
/// 5. token_program (readonly — SPL or Token-2022)
pub fn create_ata_idempotent(
    funder: [u8; 32],
    ata: [u8; 32],
    owner: [u8; 32],
    mint: [u8; 32],
    token_program: [u8; 32],
) -> Instruction {
    Instruction {
        program_id: ASSOCIATED_TOKEN_PROGRAM_ID,
        accounts: vec![
            AccountMeta::writable(funder, true),
            AccountMeta::writable(ata, false),
            AccountMeta::readonly(owner, false),
            AccountMeta::readonly(mint, false),
            AccountMeta::readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::readonly(token_program, false),
        ],
        data: vec![1u8], // discriminator: 1 = CreateIdempotent
    }
}

/// Build a `TransferChecked` instruction.
///
/// Data layout: `[12u8] ‖ amount_le_u64 ‖ decimals_u8` = 10 bytes.
///
/// Account order:
/// 0. source (writable — sender's ATA)
/// 1. mint (readonly — checked against decimals)
/// 2. destination (writable — recipient's ATA)
/// 3. authority (signer — sender wallet)
pub fn transfer_checked(
    source_ata: [u8; 32],
    mint: [u8; 32],
    dest_ata: [u8; 32],
    authority: [u8; 32],
    amount: u64,
    decimals: u8,
    token_program: [u8; 32],
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12u8); // discriminator: TransferChecked
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::writable(source_ata, false),
            AccountMeta::readonly(mint, false),
            AccountMeta::writable(dest_ata, false),
            AccountMeta::readonly(authority, true),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solana::ata::TOKEN_PROGRAM_ID;

    #[test]
    fn transfer_checked_data_layout() {
        let ix = transfer_checked(
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            1_500_000,
            6,
            TOKEN_PROGRAM_ID,
        );
        assert_eq!(ix.data.len(), 10);
        assert_eq!(ix.data[0], 12);
        assert_eq!(&ix.data[1..9], &1_500_000u64.to_le_bytes());
        assert_eq!(ix.data[9], 6); // decimals
        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.accounts[0].pubkey, [0x11; 32]);
        assert!(ix.accounts[0].is_writable && !ix.accounts[0].is_signer); // source
        assert!(!ix.accounts[1].is_writable && !ix.accounts[1].is_signer); // mint
        assert!(ix.accounts[2].is_writable && !ix.accounts[2].is_signer); // dest
        assert!(!ix.accounts[3].is_writable && ix.accounts[3].is_signer); // authority
    }

    #[test]
    fn create_ata_idempotent_data_is_single_byte() {
        let ix = create_ata_idempotent(
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            TOKEN_PROGRAM_ID,
        );
        assert_eq!(ix.data, vec![1u8]);
        assert_eq!(ix.accounts.len(), 6);
        assert_eq!(ix.accounts[0].pubkey, [0x11; 32]); // funder
        assert!(ix.accounts[0].is_writable && ix.accounts[0].is_signer);
    }
}
