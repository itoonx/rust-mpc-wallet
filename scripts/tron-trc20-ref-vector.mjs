// Capture canonical Transaction.raw bytes for a TRON TRC-20 token transfer
// (TriggerSmartContract, ContractType=31). Pinned in
// `crates/mpc-wallet-chains/src/tron/proto.rs::tests` for byte-equal parity
// against tronweb. Mirrors the Sprint 43 native-TRX capture pattern.
//
// Run: `node scripts/tron-trc20-ref-vector.mjs`.

import { TronWeb } from "tronweb";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

// Deterministic inputs — synthetic addresses keep the capture reproducible.
// owner = caller (sender), contract = TRC-20 contract, recipient = beneficiary.
const OWNER_HEX = "411111111111111111111111111111111111111111";
const CONTRACT_HEX = "419999999999999999999999999999999999999999"; // T...
const RECIPIENT_HEX = "412222222222222222222222222222222222222222";
const AMOUNT = 1_000_000n; // smallest unit (e.g. 1 USDT at 6 decimals)
const REF_BLOCK_BYTES = "0001";
const REF_BLOCK_HASH = "0102030405060708";
const TIMESTAMP = 1_700_000_000_000;
const EXPIRATION = TIMESTAMP + 60_000;
const FEE_LIMIT = 100_000_000; // 100 TRX cap — required for TVM calls

const tronWeb = new TronWeb({ fullHost: "https://api.shasta.trongrid.io" });

// Build TRC-20 transfer calldata: same ABI as ERC-20.
//   selector = 0xa9059cbb (keccak256("transfer(address,uint256)")[0..4])
//   data = selector ‖ pad32(recipient_evm) ‖ pad32(amount)
// TRON addresses are 21 bytes (0x41 ‖ hash160) but the calldata uses the
// 20-byte EVM hash160 — drop the 0x41 prefix.
const recipient20 = RECIPIENT_HEX.slice(2); // strip "41"
const calldata =
  "a9059cbb" +
  recipient20.padStart(64, "0") +
  AMOUNT.toString(16).padStart(64, "0");

const txJson = {
  raw_data: {
    contract: [
      {
        type: "TriggerSmartContract",
        parameter: {
          value: {
            owner_address: OWNER_HEX,
            contract_address: CONTRACT_HEX,
            data: calldata,
          },
          type_url: "type.googleapis.com/protocol.TriggerSmartContract",
        },
      },
    ],
    ref_block_bytes: REF_BLOCK_BYTES,
    ref_block_hash: REF_BLOCK_HASH,
    expiration: EXPIRATION,
    fee_limit: FEE_LIMIT,
    timestamp: TIMESTAMP,
  },
  visible: false,
};

let rawHex;
try {
  const pb = tronWeb.utils.transaction.txJsonToPb(txJson);
  rawHex = tronWeb.utils.transaction.txPbToRawDataHex(pb).toLowerCase();
} catch (e) {
  try {
    const mod = await import("tronweb/lib/esm/utils/transaction.js");
    const pb = mod.txJsonToPb(txJson);
    rawHex = mod.txPbToRawDataHex(pb).toLowerCase();
  } catch (e2) {
    console.error(
      "Could not access tronweb proto utilities.\nv5: " +
        e.message +
        "\nv6: " +
        e2.message,
    );
    process.exit(1);
  }
}

const rawBytes = hexToBytes(rawHex);
const txId = sha256(rawBytes);

console.log(
  JSON.stringify(
    {
      inputs: {
        owner: OWNER_HEX,
        contract: CONTRACT_HEX,
        recipient: RECIPIENT_HEX,
        amount: AMOUNT.toString(),
        fee_limit: FEE_LIMIT,
      },
      calldata: "0x" + calldata,
      raw_hex: "0x" + rawHex,
      raw_len: rawBytes.length,
      tx_id_hex: "0x" + bytesToHex(txId),
    },
    null,
    2,
  ),
);
