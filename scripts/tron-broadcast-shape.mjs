// Print the EXACT JSON body that tronweb POSTs to /wallet/broadcasttransaction
// so we can mirror its shape from Rust. This is the source of truth.
import { TronWeb } from "tronweb";

const tronWeb = new TronWeb({
  fullHost: "https://api.shasta.trongrid.io",
  privateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
});

// Intercept the broadcast HTTP call so we just print the body without sending.
const origPost = tronWeb.fullNode.request.bind(tronWeb.fullNode);
tronWeb.fullNode.request = async (url, payload, method) => {
  if (url.includes("broadcasttransaction") || url.includes("broadcasthex")) {
    console.log("URL:", url);
    console.log("BODY:", JSON.stringify(payload, null, 2));
    process.exit(0);
  }
  return origPost(url, payload, method);
};

// Build a deterministic-ish transfer (RPC fills in fresh ref_block_*; we just
// need the JSON shape, not byte equality).
const myAddr = tronWeb.address.fromPrivateKey(
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
console.log("FROM:", myAddr);
const tx = await tronWeb.transactionBuilder.sendTrx(
  "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW",
  1_000_000,
  myAddr,
);
const signed = await tronWeb.trx.sign(tx);
console.log("SIGNED TX OBJECT:", JSON.stringify(signed, null, 2));
await tronWeb.trx.sendRawTransaction(signed);
