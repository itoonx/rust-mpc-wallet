//! Generate Ed25519 gateway signing keypair + test admin client key + node verifying keys.
//!
//! Usage:
//!   cargo run -p mpc-wallet-core --example gen_gateway_keys -- <output_dir>
//!
//! Outputs:
//!   <output_dir>/gateway_signing_seed.hex    — gateway 32-byte private seed (hex)
//!   <output_dir>/gateway_signing_pubkey.hex  — gateway 32-byte public key (hex)
//!   <output_dir>/test_admin_seed.hex         — test admin client seed (hex)
//!   <output_dir>/test_admin_pubkey.hex       — test admin client pubkey (hex)
//!   <output_dir>/test-client-keys.json       — client key registry for gateway
//!   <output_dir>/node-verifying-keys.json    — MPC node verifying keys (from deterministic seeds)
//!
//! If the files already exist, prints their contents and exits (idempotent).

use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::{
    fs,
    path::{Path, PathBuf},
    process,
};

fn generate_keypair(dir: &Path, seed_name: &str, pub_name: &str) -> (String, String) {
    let seed_path = dir.join(seed_name);
    let pub_path = dir.join(pub_name);

    if seed_path.exists() && pub_path.exists() {
        let seed_hex = fs::read_to_string(&seed_path).unwrap().trim().to_string();
        let pub_hex = fs::read_to_string(&pub_path).unwrap().trim().to_string();
        return (seed_hex, pub_hex);
    }

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let seed_hex = hex::encode(signing_key.to_bytes());
    let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());

    fs::write(&seed_path, &seed_hex).expect("cannot write seed file");
    fs::write(&pub_path, &pub_hex).expect("cannot write pubkey file");

    (seed_hex, pub_hex)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: gen_gateway_keys <output_dir>");
        process::exit(1);
    }

    let dir = PathBuf::from(&args[1]);
    fs::create_dir_all(&dir).expect("cannot create output directory");

    // 1. Gateway signing keypair
    let (gw_seed, gw_pub) = generate_keypair(
        &dir,
        "gateway_signing_seed.hex",
        "gateway_signing_pubkey.hex",
    );
    println!("SEED={gw_seed}");
    println!("PUBKEY={gw_pub}");

    // 2. Test admin client keypair (for regression tests)
    let (admin_seed, admin_pub) =
        generate_keypair(&dir, "test_admin_seed.hex", "test_admin_pubkey.hex");
    let admin_key_id = &admin_pub[..16]; // first 8 bytes = 16 hex chars
    println!("ADMIN_SEED={admin_seed}");
    println!("ADMIN_PUBKEY={admin_pub}");
    println!("ADMIN_KEY_ID={admin_key_id}");

    // 3. Write test-client-keys.json (admin entry)
    let registry_path = dir.join("test-client-keys.json");
    let registry_json = format!(
        r#"[
  {{"pubkey":"{admin_pub}","key_id":"{admin_key_id}","role":"admin","label":"test-admin","mfa":true}}
]"#
    );
    fs::write(&registry_path, &registry_json).expect("cannot write client keys file");

    // 4. Generate node verifying keys from deterministic signing keys
    //    Matches local-infra.sh: NODE_SIGNING_KEY = printf "%02x" $i repeated 32 times
    //    Node 1: 0101...01 (32 bytes), Node 2: 0202...02, Node 3: 0303...03
    let node_keys_path = dir.join("node-verifying-keys.json");
    let mut entries = Vec::new();
    for i in 1u8..=3 {
        let seed = [i; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let vk_hex = hex::encode(signing_key.verifying_key().to_bytes());
        entries.push(format!(
            r#"  {{"party_id":{i},"verifying_key_hex":"{vk_hex}"}}"#
        ));
    }
    let node_keys_json = format!("[\n{}\n]", entries.join(",\n"));
    fs::write(&node_keys_path, &node_keys_json).expect("cannot write node verifying keys file");
}
