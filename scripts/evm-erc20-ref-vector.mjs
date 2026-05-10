// Capture canonical ABI-encoded calldata for `transfer(address,uint256)`.
// Pinned in `crates/mpc-wallet-chains/src/evm/erc20.rs::tests` for byte-equal
// parity against viem.
//
// Run: `node scripts/evm-erc20-ref-vector.mjs`.

import { encodeFunctionData, parseAbi } from "viem";

const abi = parseAbi(["function transfer(address to, uint256 amount)"]);

// Deterministic inputs.
const CASES = [
  { to: "0xAf3C5fEB2da46D532b0e6A9d78000508681047E7", amount: 1_500_000n }, // 1.5 USDC at 6 decimals
  { to: "0x0000000000000000000000000000000000000000", amount: 0n },
  { to: "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF", amount: (1n << 256n) - 1n }, // max uint256
];

for (const { to, amount } of CASES) {
  const data = encodeFunctionData({
    abi,
    functionName: "transfer",
    args: [to, amount],
  });
  console.log(JSON.stringify({ to, amount: amount.toString(), calldata: data }));
}
