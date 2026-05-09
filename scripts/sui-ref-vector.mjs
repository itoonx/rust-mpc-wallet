// Capture reference BCS vector + sign hash for the canonical TransferSui PTB.
// Run with: node scripts/sui-ref-vector.mjs
//
// Inputs are deterministic so we can hardcode the resulting bytes as test
// constants in chain_sui_integration.rs and assert byte-for-byte parity
// against our hand-rolled TransactionData::V1.

import { Transaction } from "@mysten/sui/transactions";
import { bcs } from "@mysten/sui/bcs";
import { blake2b } from "@noble/hashes/blake2b";
import { bytesToHex } from "@noble/hashes/utils";

// ── Deterministic inputs ────────────────────────────────────────────────────
const SENDER     = "0x" + "11".repeat(32);                  // 0x1111…
const RECIPIENT  = "0x" + "22".repeat(32);                  // 0x2222…
const AMOUNT     = 100_000_000n;                            // 0.1 SUI in MIST
const GAS_OBJECT = "0x" + "33".repeat(32);                  // 0x3333…
const GAS_VERSION = 42n;                                    // arbitrary, fixed
const GAS_DIGEST = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 base58 zero bytes
const GAS_PRICE  = 1000n;
const GAS_BUDGET = 10_000_000n;

// ── Build canonical transferSui PTB ────────────────────────────────────────
// Pattern: SplitCoins(GasCoin, [amount]) → TransferObjects([split], recipient)
const tx = new Transaction();
tx.setSender(SENDER);
tx.setGasOwner(SENDER);
tx.setGasPrice(GAS_PRICE);
tx.setGasBudget(GAS_BUDGET);
tx.setGasPayment([
  { objectId: GAS_OBJECT, version: GAS_VERSION.toString(), digest: GAS_DIGEST },
]);

const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(AMOUNT)]);
tx.transferObjects([coin], tx.pure.address(RECIPIENT));

// ── Build & dump BCS bytes for the TransactionData enum ────────────────────
// `tx.build({ onlyTransactionKind: false })` returns the full TransactionData
// BCS bytes ready to be signed.
const bytes = await tx.build({
  onlyTransactionKind: false,
  // Explicitly avoid talking to RPC by passing a no-op client surface:
  client: {
    // SDK calls these internally for object resolution; supplying gas data
    // up-front lets us bypass them.
    getReferenceGasPrice: async () => GAS_PRICE,
  },
});

// ── Compute sign hash: Blake2b-256(intent ‖ bcs) ───────────────────────────
// IntentMessage scope=0 (TransactionData), version=0, app_id=0 (Sui)
const intent = new Uint8Array([0x00, 0x00, 0x00]);
const intentMsg = new Uint8Array(intent.length + bytes.length);
intentMsg.set(intent, 0);
intentMsg.set(bytes, intent.length);
const signHash = blake2b(intentMsg, { dkLen: 32 });

// ── Output ─────────────────────────────────────────────────────────────────
const out = {
  inputs: {
    sender: SENDER,
    recipient: RECIPIENT,
    amount: AMOUNT.toString(),
    gas_object_id: GAS_OBJECT,
    gas_version: GAS_VERSION.toString(),
    gas_digest_b58: GAS_DIGEST,
    gas_price: GAS_PRICE.toString(),
    gas_budget: GAS_BUDGET.toString(),
  },
  bcs_hex: "0x" + bytesToHex(bytes),
  bcs_len: bytes.length,
  sign_hash_hex: "0x" + bytesToHex(signHash),
};

console.log(JSON.stringify(out, null, 2));
