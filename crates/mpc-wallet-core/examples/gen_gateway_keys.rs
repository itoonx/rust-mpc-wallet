//! Generate Ed25519 gateway signing keypair (cross-platform, no openssl needed).
//!
//! Usage:
//!   cargo run -p mpc-wallet-core --example gen_gateway_keys -- <output_dir>
//!
//! Outputs:
//!   <output_dir>/gateway_signing_seed.hex   — 32-byte private seed (hex)
//!   <output_dir>/gateway_signing_pubkey.hex  — 32-byte public key (hex)
//!
//! If the files already exist, prints their contents and exits (idempotent).

use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::{fs, path::PathBuf, process};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: gen_gateway_keys <output_dir>");
        process::exit(1);
    }

    let dir = PathBuf::from(&args[1]);
    fs::create_dir_all(&dir).expect("cannot create output directory");

    let seed_path = dir.join("gateway_signing_seed.hex");
    let pub_path = dir.join("gateway_signing_pubkey.hex");

    if seed_path.exists() && pub_path.exists() {
        // Reuse existing keys
        let seed_hex = fs::read_to_string(&seed_path).unwrap().trim().to_string();
        let pub_hex = fs::read_to_string(&pub_path).unwrap().trim().to_string();
        println!("SEED={seed_hex}");
        println!("PUBKEY={pub_hex}");
        return;
    }

    // Generate fresh keypair using OS randomness
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let seed_hex = hex::encode(signing_key.to_bytes());
    let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());

    fs::write(&seed_path, &seed_hex).expect("cannot write seed file");
    fs::write(&pub_path, &pub_hex).expect("cannot write pubkey file");

    println!("SEED={seed_hex}");
    println!("PUBKEY={pub_hex}");
}
