# L-017: TRON broadcast body needs the structured `raw_data` JSON object — and TronGrid hides validation errors behind swagger reflection

- **Date:** 2026-05-10
- **Category:** Wire format / API protocol
- **Severity:** High (silent — local sig recovery passes, broadcast rejected with no diagnosable error)
- **Found by:** Sprint 43 — first TRON Shasta testnet broadcast attempt

## What happened

After the TRON proto encoder shipped (byte-equal to `tronweb`'s reference vector) and local sig recovery passed against the wallet's T-address, the live broadcast came back with:

```
TRON broadcast rejected: code=UNKNOWN msg='' error='' raw=...
```

No code, no message, no error. The "raw" body in our error log read: `{ "Error": "string" }` — literal schema-reflection JSON, not a real response.

## Root cause

Three concrete bugs, all hidden by one diagnostic trap:

### Bug 1: TonGrid returns swagger schema reflection on malformed bodies

When `/wallet/broadcasttransaction` receives a body that fails its top-level shape validation (missing required fields, wrong types), TronGrid's gateway responds with `{ "Error": "string" }` — the literal JSON-schema description of the success-or-error union. It looks like an error response but it's actually a 200 OK with the OpenAPI spec inlined. There is **no** `code` or `message` field, so error-parsing code that reads `resp["code"]` defaults to `"UNKNOWN"` and gives up.

Verified by `curl`-probing the endpoint with deliberately malformed bodies — same `{Error: string}` shape comes back regardless of the specific reason.

### Bug 2: Native TransferContract MUST omit `fee_limit`

`fee_limit` (Transaction.raw field 18) is documented as transaction-wide gas cap, but TRON validators only accept it for `TriggerSmartContract` calls. For native `TransferContract` it must be **absent** from `raw_data_hex`. Our auto-fetch was setting `fee_limit = 100_000_000` (100 TRX cap), which produced a body that the validator's structural check rejected — and TonGrid responded with the swagger reflection.

Captured `tronweb.transactionBuilder.sendTrx` output to confirm: it omits `fee_limit` for transfers.

### Bug 3: Broadcast body needs both `raw_data_hex` AND structured `raw_data`

Our first broadcast body was `{ txID, raw_data_hex, signature }`. The TronGrid endpoint requires the full shape:

```json
{
  "visible": false,
  "txID": "...",
  "raw_data": { ...structured object... },
  "raw_data_hex": "...",
  "signature": ["..."]
}
```

The validator parses `raw_data` independently, then **cross-checks** it against `raw_data_hex` byte-for-byte. Without `raw_data`, the cross-check fails before any signature/state validation runs — and you get swagger reflection.

### Bug 4 (latent): Signature v byte is `27 + parity`, not raw 0/1

Documentation across the TRON ecosystem is contradictory. tronweb's actual output (captured via the diagnostic script) ends every signature with `0x1B` or `0x1C`. We were writing raw `0` or `1`. Validators may accept either form (some reduce internally), but to match tronweb byte-for-byte and avoid path-dependent rejections, we now write `27 + recovery_id` in the wire format. Local sig-recovery still uses raw 0/1 (k256's `RecoveryId::try_from` expects 0/1) — the offset is wire-format only.

## Fix

- `tron/proto.rs`: `fee_limit_sun: Option<i64>` (None = omit). Added `decode_transfer_raw_to_json` — a tiny protobuf walker that re-derives the JSON shape from our own raw_data bytes, so the broadcast path doesn't need the structured fields threaded through.
- `tron/tx.rs::finalize_tron_transaction`: write `v = 27 + recovery_id`. Split sig recovery into `recover_tron_sender_from_parity` (takes raw 0/1) so wire-format vs internal-format stays explicit.
- `tron/rpc_client.rs::broadcast`: emit full `{visible, txID, raw_data, raw_data_hex, signature}` body. Comment documents the swagger-reflection trap so the next debugger doesn't lose an hour.
- `cli/src/commands/send.rs`: drop `fee_limit` from auto-fetched extras for Tron arm.
- `scripts/tron-broadcast-shape.mjs` (new): hooks into tronweb's HTTP layer to print the EXACT JSON body it POSTs. Use this anytime the broadcast shape needs ground truth — it's the source of truth for the wire format, more reliable than docs.

## Takeaway

**When an external API returns an error you can't parse, dump the raw response body verbatim before doing anything else.** TonGrid's `{Error: string}` reflection is indistinguishable from a real error if you're just reading `resp["code"]`. We added a verbose error path that includes the full response JSON; without it we'd have spent another round-trip guessing at sig formats.

**For any chain we hand-roll wire formats for, capture the upstream SDK's actual HTTP request body**, not just its tx-construction output. Sprint 41 (Sui) and Sprint 42 (Aptos) both validated unsigned BCS bytes via reference vectors but didn't validate the broadcast envelope. Sui and Aptos broadcast endpoints happen to be simpler shapes that tolerated our bodies; TRON's stricter validation surfaced the gap. Going forward, every chain integration should include a `broadcast-shape.mjs` companion script that prints the SDK's actual POST body — it takes 10 minutes to write and saves hours when the wire format is contested.

**Never trust documentation about cryptographic byte conventions.** TRON docs and forum posts disagree about the v byte (raw 0/1 vs 27+parity). Run the SDK, capture the bytes, mirror them.

## Verification

- `cargo test --workspace --tests` → 941 pass (938 baseline + 3 new TRON proto/finalize tests).
- Live Shasta broadcast: `632a52ef4129f52e03d950cd7552202a964c126d6a251ccb6b0a6467f04b9ce2`
  (https://shasta.tronscan.org/#/transaction/632a52ef4129f52e03d950cd7552202a964c126d6a251ccb6b0a6467f04b9ce2).
- Wallet recorded in `tests/e2e/funded-wallets.local.json`.
