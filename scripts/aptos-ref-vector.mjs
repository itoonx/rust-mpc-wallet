// Capture reference BCS vector + sign hash for the canonical
// 0x1::aptos_account::transfer entry function.
// Run with: node scripts/aptos-ref-vector.mjs
//
// Inputs are deterministic so the resulting bytes can be hardcoded
// as test constants in chain_aptos_integration.rs to assert byte-for-byte
// parity against our hand-rolled aptos::types::RawTransaction.

import {
  AccountAddress,
  ChainId,
  EntryFunction,
  Identifier,
  ModuleId,
  RawTransaction,
  Serializer,
  TransactionPayloadEntryFunction,
  U64,
} from "@aptos-labs/ts-sdk";
import { sha3_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";

// ── Deterministic inputs ────────────────────────────────────────────────────
const SENDER = AccountAddress.from(
  "0x1111111111111111111111111111111111111111111111111111111111111111",
);
const RECIPIENT = AccountAddress.from(
  "0x2222222222222222222222222222222222222222222222222222222222222222",
);
const AMOUNT = 100_000n;                         // 0.001 APT in octas
const SEQUENCE = 7n;
const MAX_GAS = 2000n;
const GAS_UNIT_PRICE = 100n;
const EXPIRATION = 99_999_999_999n;              // far future, fixed
const CHAIN_ID = 2;                              // testnet

// ── Build the RawTransaction without RPC ────────────────────────────────────
// We avoid generateRawTransaction (which calls RPC for chain id + account
// sequence). Instead, we construct each field directly.
const moduleId = new ModuleId(
  AccountAddress.from("0x1"),
  new Identifier("aptos_account"),
);
// Aptos's EntryFunction expects typed argument instances (AccountAddress,
// U64, etc.) — they implement `serializeForEntryFunction` which wraps the
// BCS bytes with the `Vec<u8>` length prefix when the wire format is
// `Vec<Vec<u8>>`.
const entryFunction = new EntryFunction(
  moduleId,
  new Identifier("transfer"),
  [],                                            // no type args
  [RECIPIENT, new U64(AMOUNT)],
);

const payload = new TransactionPayloadEntryFunction(entryFunction);

const rawTx = new RawTransaction(
  SENDER,
  SEQUENCE,
  payload,
  MAX_GAS,
  GAS_UNIT_PRICE,
  EXPIRATION,
  new ChainId(CHAIN_ID),
);

const rawSer = new Serializer();
rawTx.serialize(rawSer);
const rawBcs = rawSer.toUint8Array();

// ── Compute sign hash ──────────────────────────────────────────────────────
// Aptos prepends SHA3-256("APTOS::RawTransaction") to the BCS bytes, then
// the prehash that's actually signed is SHA3-256(prefix ‖ bcs).
const prefix = sha3_256(new TextEncoder().encode("APTOS::RawTransaction"));
const signingMessage = new Uint8Array(prefix.length + rawBcs.length);
signingMessage.set(prefix, 0);
signingMessage.set(rawBcs, prefix.length);
const signHash = sha3_256(signingMessage);

// ── Output ─────────────────────────────────────────────────────────────────
const out = {
  inputs: {
    sender: SENDER.toString(),
    recipient: RECIPIENT.toString(),
    amount: AMOUNT.toString(),
    sequence_number: SEQUENCE.toString(),
    max_gas_amount: MAX_GAS.toString(),
    gas_unit_price: GAS_UNIT_PRICE.toString(),
    expiration_timestamp_secs: EXPIRATION.toString(),
    chain_id: CHAIN_ID,
  },
  prefix_hex: "0x" + bytesToHex(prefix),
  bcs_hex: "0x" + bytesToHex(rawBcs),
  bcs_len: rawBcs.length,
  sign_hash_hex: "0x" + bytesToHex(signHash),
};

console.log(JSON.stringify(out, null, 2));
