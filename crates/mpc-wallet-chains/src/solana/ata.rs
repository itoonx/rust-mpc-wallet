//! Solana Program Derived Address (PDA) helpers for Associated Token Accounts.
//!
//! The ATA is the canonical token account for a given (owner, mint, program)
//! triple, derived deterministically as a PDA off the Associated Token
//! Account program. SPL Token transfers move tokens between ATAs, NOT between
//! wallet addresses — every fungible-token send needs the source and
//! destination ATA addresses computed up front.
//!
//! PDA algorithm (per Solana docs):
//! 1. For bump in 255..=0:
//!    point = sha256(seeds[0] ‖ ... ‖ seeds[N-1] ‖ [bump] ‖ program_id ‖ b"ProgramDerivedAddress")
//! 2. If `point` is OFF the ed25519 curve, return (point, bump). Done.
//!    Otherwise decrement bump and retry.
//!
//! "Off the curve" means: the 32-byte value, treated as a compressed Edwards
//! point, fails to decompress to a valid point. We use ed25519-dalek's
//! VerifyingKey::from_bytes — `Err` means off-curve.

use sha2::{Digest, Sha256};

/// SPL Token program ID (legacy). Base58: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`.
pub const TOKEN_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];

/// SPL Token-2022 program ID. Base58: `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.
pub const TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];

/// Associated Token Account program ID.
/// Base58: `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: [u8; 32] = [
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
];

const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";

/// Returns true if `bytes` decodes as a valid point on the ed25519 curve.
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    use ed25519_dalek::VerifyingKey;
    VerifyingKey::from_bytes(bytes).is_ok()
}

/// `find_program_address(seeds, program_id)` — Solana's canonical PDA finder.
/// Returns (address, bump). Searches bumps 255..=0 for an off-curve hash.
fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> ([u8; 32], u8) {
    for bump in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        for s in seeds {
            hasher.update(s);
        }
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(PDA_MARKER);
        let h: [u8; 32] = hasher.finalize().into();
        if !is_on_curve(&h) {
            return (h, bump);
        }
    }
    // Vanishingly unlikely — every bump landed on the curve.
    panic!("find_program_address exhausted bump space (Solana ABI invariant violated)");
}

/// Derive the Associated Token Account address for `(owner, mint, token_program)`.
///
/// Seeds (per `spl-associated-token-account` source):
///   `[owner, token_program, mint]`
///
/// Use `TOKEN_PROGRAM_ID` for legacy SPL, `TOKEN_2022_PROGRAM_ID` for Token-2022.
pub fn derive_ata(owner: &[u8; 32], mint: &[u8; 32], token_program: &[u8; 32]) -> [u8; 32] {
    let (addr, _bump) =
        find_program_address(&[owner, token_program, mint], &ASSOCIATED_TOKEN_PROGRAM_ID);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector from `@solana/spl-token`'s `getAssociatedTokenAddressSync`:
    ///
    /// ```js
    /// import { getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID } from '@solana/spl-token';
    /// import { PublicKey } from '@solana/web3.js';
    /// const owner = new PublicKey('5m19MH9tCAhxjWeQJNAXxAzY5Je6BWnKT8HeAmGCKbzW');
    /// const mint  = new PublicKey('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'); // devnet USDC
    /// console.log(getAssociatedTokenAddressSync(mint, owner, false, TOKEN_PROGRAM_ID).toBase58());
    /// // → BdgdrSe...
    /// ```
    /// We verify against the algorithm by deriving locally — the byte-equal
    /// check happens via `scripts/solana-spl-ref-vector.mjs` capturing the
    /// expected base58 ATA in the broader integration test.
    #[test]
    fn token_program_id_matches_base58() {
        let want = bs58::decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .into_vec()
            .unwrap();
        assert_eq!(&TOKEN_PROGRAM_ID, want.as_slice());
    }

    #[test]
    fn token_2022_program_id_matches_base58() {
        let want = bs58::decode("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
            .into_vec()
            .unwrap();
        assert_eq!(&TOKEN_2022_PROGRAM_ID, want.as_slice());
    }

    #[test]
    fn ata_program_id_matches_base58() {
        let want = bs58::decode("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
            .into_vec()
            .unwrap();
        assert_eq!(&ASSOCIATED_TOKEN_PROGRAM_ID, want.as_slice());
    }

    #[test]
    fn derive_ata_deterministic() {
        let owner = bs58::decode("5m19MH9tCAhxjWeQJNAXxAzY5Je6BWnKT8HeAmGCKbzW")
            .into_vec()
            .unwrap();
        let mint = bs58::decode("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
            .into_vec()
            .unwrap();
        let owner_arr: [u8; 32] = owner.try_into().unwrap();
        let mint_arr: [u8; 32] = mint.try_into().unwrap();

        let ata1 = derive_ata(&owner_arr, &mint_arr, &TOKEN_PROGRAM_ID);
        let ata2 = derive_ata(&owner_arr, &mint_arr, &TOKEN_PROGRAM_ID);
        assert_eq!(ata1, ata2, "derivation must be deterministic");

        // ATA must be off-curve (PDA invariant).
        use ed25519_dalek::VerifyingKey;
        assert!(
            VerifyingKey::from_bytes(&ata1).is_err(),
            "ATA must be off-curve"
        );
    }

    #[test]
    fn derive_ata_different_mints() {
        let owner = [0x11u8; 32];
        let mint1 = [0x22u8; 32];
        let mint2 = [0x33u8; 32];
        let a = derive_ata(&owner, &mint1, &TOKEN_PROGRAM_ID);
        let b = derive_ata(&owner, &mint2, &TOKEN_PROGRAM_ID);
        assert_ne!(a, b, "different mints must yield different ATAs");
    }
}
