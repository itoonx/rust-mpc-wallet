// Capture canonical BCS bytes for a Sui `Coin<T>` (non-SUI) PTB transfer.
// Pinned in `crates/mpc-wallet-chains/src/sui/types.rs::tests` for byte-equal
// parity against @mysten/sui's Transaction builder.
//
// Run: `node scripts/sui-coin-ref-vector.mjs`.

import { Transaction } from "@mysten/sui/transactions";
import { toHex } from "@mysten/sui/utils";

const SENDER = "0x1111111111111111111111111111111111111111111111111111111111111111";
const RECIPIENT = "0x2222222222222222222222222222222222222222222222222222222222222222";
const AMOUNT = 100_000n;

const COIN_OBJECT = "0x5555555555555555555555555555555555555555555555555555555555555555";
const COIN_VERSION = "7";
// 32-byte digest — same value reused for both Coin and Gas to keep capture deterministic.
const DIGEST_B58 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const GAS_OBJECT = "0x3333333333333333333333333333333333333333333333333333333333333333";
const GAS_VERSION = "42";

const tx = new Transaction();
const coin = tx.objectRef({
  objectId: COIN_OBJECT,
  version: COIN_VERSION,
  digest: DIGEST_B58,
});
const [split] = tx.splitCoins(coin, [tx.pure.u64(AMOUNT)]);
tx.transferObjects([split], tx.pure.address(RECIPIENT));

tx.setSender(SENDER);
tx.setGasOwner(SENDER);
tx.setGasPrice(1000n);
tx.setGasBudget(10_000_000n);
tx.setGasPayment([
  { objectId: GAS_OBJECT, version: GAS_VERSION, digest: DIGEST_B58 },
]);

const bytes = await tx.build({ onlyTransactionKind: false });

console.log(
  JSON.stringify(
    {
      bcs_hex: toHex(bytes),
      bcs_len: bytes.length,
    },
    null,
    2,
  ),
);
