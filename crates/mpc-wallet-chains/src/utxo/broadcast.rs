//! Shared UTXO broadcast — REST POST /tx for Bitcoin-family chains.

use mpc_wallet_core::error::CoreError;

use crate::provider::SignedTransaction;

/// Broadcast a raw UTXO transaction via REST API (Blockstream/Mempool pattern).
///
/// POST `{rpc_url}/tx` with raw hex in body. Returns txid as plain text.
/// Used by Bitcoin, Litecoin, Dogecoin, Zcash.
pub async fn broadcast_utxo_rest(
    signed: &SignedTransaction,
    rpc_url: &str,
) -> Result<String, CoreError> {
    let raw_hex = hex::encode(&signed.raw_tx);
    let url = format!("{rpc_url}/tx");
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(raw_hex)
        .send()
        .await
        .map_err(|e| CoreError::Other(format!("broadcast request failed: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| CoreError::Other(format!("broadcast response read failed: {e}")))?;
    if !status.is_success() {
        return Err(CoreError::Other(format!(
            "broadcast failed ({status}): {body}"
        )));
    }
    Ok(body.trim().to_string())
}
