// Capture canonical Solana message bytes for a SPL Token transfer with
// CreateATAIdempotent prefix instruction. Pinned in
// `crates/mpc-wallet-chains/tests/chain_solana_integration.rs::
// spl_message_matches_spl_token_sdk_reference` for byte-equal parity.
//
// Run: `node scripts/solana-spl-ref-vector.mjs`.

import {
  Connection,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  createAssociatedTokenAccountIdempotentInstruction,
  createTransferCheckedInstruction,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { bytesToHex } from "@noble/hashes/utils";

// Deterministic inputs — synthetic addresses keep the capture reproducible.
const FEE_PAYER = new PublicKey("5m19MH9tCAhxjWeQJNAXxAzY5Je6BWnKT8HeAmGCKbzW");
const RECIPIENT = new PublicKey("BNeRq5pyyqnbPQVpWfNmbTKGyaWoUf6mNvGCo15D5VjA");
const MINT = new PublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"); // devnet USDC
const AMOUNT = 100_000n;
const DECIMALS = 6;

// Fixed blockhash so the capture is deterministic.
const BLOCKHASH = "11111111111111111111111111111111"; // 32 zero bytes — base58 of all-zero

const sourceAta = getAssociatedTokenAddressSync(MINT, FEE_PAYER, false, TOKEN_PROGRAM_ID);
const destAta = getAssociatedTokenAddressSync(MINT, RECIPIENT, false, TOKEN_PROGRAM_ID);

const ixs = [
  createAssociatedTokenAccountIdempotentInstruction(
    FEE_PAYER,
    destAta,
    RECIPIENT,
    MINT,
    TOKEN_PROGRAM_ID,
  ),
  createTransferCheckedInstruction(
    sourceAta,
    MINT,
    destAta,
    FEE_PAYER,
    AMOUNT,
    DECIMALS,
    [],
    TOKEN_PROGRAM_ID,
  ),
];

// Build legacy message (no v0 prefix) — matches our CLI default.
const message = new TransactionMessage({
  payerKey: FEE_PAYER,
  recentBlockhash: BLOCKHASH,
  instructions: ixs,
}).compileToLegacyMessage();

const messageBytes = message.serialize();

console.error("ACCOUNT KEYS (in order, from message):");
for (let i = 0; i < message.accountKeys.length; i++) {
  console.error(`  [${i}] ${message.accountKeys[i].toBase58()}`);
}
console.error("HEADER:", JSON.stringify(message.header));

console.log(
  JSON.stringify(
    {
      fee_payer: FEE_PAYER.toBase58(),
      recipient: RECIPIENT.toBase58(),
      mint: MINT.toBase58(),
      source_ata: sourceAta.toBase58(),
      dest_ata: destAta.toBase58(),
      amount: AMOUNT.toString(),
      decimals: DECIMALS,
      message_hex: "0x" + bytesToHex(messageBytes),
      message_len: messageBytes.length,
    },
    null,
    2,
  ),
);
