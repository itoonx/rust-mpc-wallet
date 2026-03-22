#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz Paillier ciphertext deserialization and operations.
/// Goal: ensure no panics on malformed ciphertext bytes.
fuzz_target!(|data: &[u8]| {
    // Try to deserialize as PaillierCiphertext
    let _ = serde_json::from_slice::<mpc_wallet_core::paillier::PaillierCiphertext>(data);

    // Try to deserialize as PaillierPublicKey
    let _ = serde_json::from_slice::<mpc_wallet_core::paillier::PaillierPublicKey>(data);
});
