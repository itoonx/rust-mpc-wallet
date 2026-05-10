// Capture canonical BCS bytes for `0x1::coin::transfer<T>(recipient, amount)`.
// Pinned in `crates/mpc-wallet-chains/src/aptos/types.rs::tests` for byte-equal
// parity against @aptos-labs/ts-sdk.
//
// Run: `node scripts/aptos-coin-ref-vector.mjs`.

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

// Deterministic inputs — mirror the existing `aptos-ref-vector.mjs` pattern.
const SENDER = AccountAddress.from(
  "0x1111111111111111111111111111111111111111111111111111111111111111",
);
const RECIPIENT = AccountAddress.from(
  "0x2222222222222222222222222222222222222222222222222222222222222222",
);
const AMOUNT = 100_000n;
const SEQUENCE = 7n;
const MAX_GAS = 2000n;
const GAS_UNIT_PRICE = 100n;
const EXPIRATION = 99_999_999_999n;
const CHAIN_ID = 2;

// Coin type — `0x1::aptos_coin::AptosCoin` (also used for native APT via
// 0x1::coin::transfer). For real USDC on Aptos, swap in the actual
// `0xbae...::usdc::USDC` struct tag.
const COIN_TYPE_ADDR = AccountAddress.from("0x1");
const COIN_TYPE = new TypeTagStruct(
  new StructTag(COIN_TYPE_ADDR, new Identifier("aptos_coin"), new Identifier("AptosCoin"), []),
);

const moduleId = new ModuleId(AccountAddress.from("0x1"), new Identifier("coin"));
const entryFunction = new EntryFunction(
  moduleId,
  new Identifier("transfer"),
  [COIN_TYPE],
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

const ser = new Serializer();
rawTx.serialize(ser);
const bytes = ser.toUint8Array();

console.log(
  JSON.stringify(
    {
      coin_type: "0x1::aptos_coin::AptosCoin",
      bcs_hex: "0x" + bytesToHex(bytes),
      bcs_len: bytes.length,
    },
    null,
    2,
  ),
);
