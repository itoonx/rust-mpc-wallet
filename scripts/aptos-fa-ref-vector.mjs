// Capture canonical BCS bytes for `0x1::primary_fungible_store::transfer<T>`.
// Pinned in `crates/mpc-wallet-chains/src/aptos/types.rs::tests::
// bcs_matches_aptos_sdk_fa_reference` for byte-equal parity against
// @aptos-labs/ts-sdk.
//
// Run: `node scripts/aptos-fa-ref-vector.mjs`.

import {
  AccountAddress,
  ChainId,
  EntryFunction,
  Identifier,
  ModuleId,
  RawTransaction,
  Serializer,
  TransactionPayloadEntryFunction,
  TypeTagStruct,
  StructTag,
  U64,
} from "@aptos-labs/ts-sdk";
import { bytesToHex } from "@noble/hashes/utils";

const SENDER = AccountAddress.from(
  "0x1111111111111111111111111111111111111111111111111111111111111111",
);
const RECIPIENT = AccountAddress.from(
  "0x2222222222222222222222222222222222222222222222222222222222222222",
);
// FA metadata Object — a 32-byte address pointing to the on-chain
// `Object<Metadata>` for the token (e.g. testnet USDC's metadata object).
// The address is encoded as a regular AccountAddress in BCS — Object<T> is
// a phantom-typed wrapper around an address.
const METADATA = AccountAddress.from(
  "0x3333333333333333333333333333333333333333333333333333333333333333",
);
const AMOUNT = 100_000n;
const SEQUENCE = 7n;
const MAX_GAS = 2000n;
const GAS_UNIT_PRICE = 100n;
const EXPIRATION = 99_999_999_999n;
const CHAIN_ID = 2;

// Type arg = 0x1::fungible_asset::Metadata (the canonical metadata type).
// The `T` of `transfer<T: key>` is parameterized over the metadata's type;
// in practice every FA uses 0x1::fungible_asset::Metadata as T.
const META_TYPE = new TypeTagStruct(
  new StructTag(
    AccountAddress.from("0x1"),
    new Identifier("fungible_asset"),
    new Identifier("Metadata"),
    [],
  ),
);

const moduleId = new ModuleId(
  AccountAddress.from("0x1"),
  new Identifier("primary_fungible_store"),
);
const entryFunction = new EntryFunction(
  moduleId,
  new Identifier("transfer"),
  [META_TYPE],
  [METADATA, RECIPIENT, new U64(AMOUNT)],
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

const ser = new Serializer();
rawTx.serialize(ser);
const bytes = ser.toUint8Array();

console.log(
  JSON.stringify(
    {
      metadata: METADATA.toString(),
      bcs_hex: "0x" + bytesToHex(bytes),
      bcs_len: bytes.length,
    },
    null,
    2,
  ),
);
