// Capture reference Transaction.raw protobuf bytes + tx_id for a canonical
// TRON TransferContract. Run with: node scripts/tron-ref-vector.mjs
//
// Inputs are deterministic so the resulting bytes can be hardcoded as test
// constants in `tron::proto::tests::proto_matches_tronweb_reference` to assert
// byte-for-byte parity against our hand-rolled protobuf encoder.

import { TronWeb } from "tronweb";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

// ── Deterministic inputs ────────────────────────────────────────────────────
const OWNER_HEX = "411111111111111111111111111111111111111111";
const TO_HEX = "412222222222222222222222222222222222222222";
const AMOUNT_SUN = 1_000_000;
const REF_BLOCK_BYTES_HEX = "0001";
const REF_BLOCK_HASH_HEX = "0102030405060708";
const TIMESTAMP = 1_700_000_000_000;
const EXPIRATION = TIMESTAMP + 60_000;
// fee_limit (field 18) is omitted: TRON only uses it for TriggerSmartContract,
// not native TransferContract. tronweb's transactionBuilder.sendTrx does the
// same — including it produces a non-canonical raw_data_hex that fails
// validator cross-check against the parsed raw_data JSON object.

const tronWeb = new TronWeb({ fullHost: "https://api.shasta.trongrid.io" });

const txJson = {
  raw_data: {
    contract: [
      {
        type: "TransferContract",
        parameter: {
          value: {
            owner_address: OWNER_HEX,
            to_address: TO_HEX,
            amount: AMOUNT_SUN,
          },
          type_url: "type.googleapis.com/protocol.TransferContract",
        },
      },
    ],
    ref_block_bytes: REF_BLOCK_BYTES_HEX,
    ref_block_hash: REF_BLOCK_HASH_HEX,
    expiration: EXPIRATION,
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
      "Could not access tronweb proto utilities.\nv5 path: " +
        e.message +
        "\nv6 path: " +
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
        owner_address_hex: OWNER_HEX,
        to_address_hex: TO_HEX,
        amount_sun: AMOUNT_SUN,
        ref_block_bytes: REF_BLOCK_BYTES_HEX,
        ref_block_hash: REF_BLOCK_HASH_HEX,
        timestamp: TIMESTAMP,
        expiration: EXPIRATION,
      },
      raw_hex: "0x" + rawHex,
      raw_len: rawBytes.length,
      tx_id_hex: "0x" + bytesToHex(txId),
    },
    null,
    2,
  ),
);
