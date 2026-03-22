#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz key share deserialization.
/// Goal: ensure no panics on corrupted/malformed share data.
fuzz_target!(|data: &[u8]| {
    // GG20 share data
    let _ = serde_json::from_slice::<serde_json::Value>(data);

    // Also test as raw KeyShare JSON
    let _ = serde_json::from_slice::<mpc_wallet_core::protocol::KeyShare>(data);
});
