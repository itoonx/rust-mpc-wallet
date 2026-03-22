#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz ProtocolMessage JSON deserialization.
/// Goal: ensure no panics on arbitrary input bytes.
fuzz_target!(|data: &[u8]| {
    // Must not panic on any input
    let _ = serde_json::from_slice::<mpc_wallet_core::transport::ProtocolMessage>(data);
});
