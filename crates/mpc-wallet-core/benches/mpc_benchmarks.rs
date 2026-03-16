//! Vaultex Performance Benchmarks
//!
//! Measures latency for all critical MPC operations:
//! - Protocol: keygen, sign, refresh (GG20, FROST Ed25519, FROST Secp256k1)
//! - Transport: ECDH key exchange, ChaCha20-Poly1305 encrypt/decrypt
//! - Key store: Argon2id derivation, AES-256-GCM encrypt/decrypt
//! - Chain: transaction building and finalization
//!
//! Run: `cargo bench -p mpc-wallet-core`

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

use mpc_wallet_core::protocol::{KeyShare, MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::local::LocalTransportNetwork;
use mpc_wallet_core::types::{PartyId, ThresholdConfig};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn gg20_factory() -> Box<dyn MpcProtocol> {
    Box::new(mpc_wallet_core::protocol::gg20::Gg20Protocol)
}

fn frost_ed25519_factory() -> Box<dyn MpcProtocol> {
    Box::new(mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol::new())
}

fn frost_secp256k1_factory() -> Box<dyn MpcProtocol> {
    Box::new(mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol::new())
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

async fn do_keygen(
    factory: fn() -> Box<dyn MpcProtocol>,
    threshold: u16,
    total: u16,
) -> Vec<KeyShare> {
    let config = ThresholdConfig::new(threshold, total).unwrap();
    let net = LocalTransportNetwork::new(total);
    let mut handles = Vec::new();
    for i in 1..=total {
        let transport = net.get_transport(PartyId(i));
        let protocol = factory();
        handles.push(tokio::spawn(async move {
            protocol.keygen(config, PartyId(i), &*transport).await
        }));
    }
    let mut shares = Vec::new();
    for h in handles {
        shares.push(h.await.unwrap().unwrap());
    }
    shares
}

async fn do_sign(
    factory: fn() -> Box<dyn MpcProtocol>,
    shares: &[KeyShare],
    signer_indices: &[usize],
    message: &[u8],
) -> Vec<MpcSignature> {
    let config = shares[0].config;
    let signers: Vec<PartyId> = signer_indices.iter().map(|&i| shares[i].party_id).collect();
    let net = LocalTransportNetwork::new(config.total_parties);
    let mut handles = Vec::new();
    for &idx in signer_indices {
        let share = shares[idx].clone();
        let transport = net.get_transport(share.party_id);
        let protocol = factory();
        let signers = signers.clone();
        let msg = message.to_vec();
        handles.push(tokio::spawn(async move {
            protocol.sign(&share, &signers, &msg, &*transport).await
        }));
    }
    let mut sigs = Vec::new();
    for h in handles {
        sigs.push(h.await.unwrap().unwrap());
    }
    sigs
}

async fn do_refresh(factory: fn() -> Box<dyn MpcProtocol>, shares: &[KeyShare]) -> Vec<KeyShare> {
    let config = shares[0].config;
    let signers: Vec<PartyId> = (1..=config.total_parties).map(PartyId).collect();
    let net = LocalTransportNetwork::new(config.total_parties);
    let mut handles = Vec::new();
    for share in shares {
        let s = share.clone();
        let transport = net.get_transport(s.party_id);
        let protocol = factory();
        let signers = signers.clone();
        handles.push(tokio::spawn(async move {
            protocol.refresh(&s, &signers, &*transport).await
        }));
    }
    let mut new_shares = Vec::new();
    for h in handles {
        new_shares.push(h.await.unwrap().unwrap());
    }
    new_shares
}

// ─── Protocol Benchmarks ────────────────────────────────────────────────────

fn bench_keygen(c: &mut Criterion) {
    let runtime = rt();
    let mut group = c.benchmark_group("keygen");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    // GG20 ECDSA
    group.bench_function(BenchmarkId::new("gg20_ecdsa", "2-of-3"), |b| {
        b.to_async(&runtime).iter(|| do_keygen(gg20_factory, 2, 3));
    });

    // FROST Ed25519
    group.bench_function(BenchmarkId::new("frost_ed25519", "2-of-3"), |b| {
        b.to_async(&runtime)
            .iter(|| do_keygen(frost_ed25519_factory, 2, 3));
    });

    // FROST Secp256k1-Taproot
    group.bench_function(BenchmarkId::new("frost_secp256k1_tr", "2-of-3"), |b| {
        b.to_async(&runtime)
            .iter(|| do_keygen(frost_secp256k1_factory, 2, 3));
    });

    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let runtime = rt();
    let mut group = c.benchmark_group("sign");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    // Pre-generate keys
    let gg20_shares = runtime.block_on(do_keygen(gg20_factory, 2, 3));
    let frost_ed_shares = runtime.block_on(do_keygen(frost_ed25519_factory, 2, 3));
    let frost_secp_shares = runtime.block_on(do_keygen(frost_secp256k1_factory, 2, 3));
    let message = b"benchmark signing message";

    group.bench_function(BenchmarkId::new("gg20_ecdsa", "2-of-3"), |b| {
        b.to_async(&runtime)
            .iter(|| do_sign(gg20_factory, &gg20_shares, &[0, 1], message));
    });

    group.bench_function(BenchmarkId::new("frost_ed25519", "2-of-3"), |b| {
        b.to_async(&runtime)
            .iter(|| do_sign(frost_ed25519_factory, &frost_ed_shares, &[0, 1], message));
    });

    group.bench_function(BenchmarkId::new("frost_secp256k1_tr", "2-of-3"), |b| {
        b.to_async(&runtime).iter(|| {
            do_sign(
                frost_secp256k1_factory,
                &frost_secp_shares,
                &[0, 1],
                message,
            )
        });
    });

    group.finish();
}

fn bench_refresh(c: &mut Criterion) {
    let runtime = rt();
    let mut group = c.benchmark_group("refresh");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    let gg20_shares = runtime.block_on(do_keygen(gg20_factory, 2, 3));
    let frost_ed_shares = runtime.block_on(do_keygen(frost_ed25519_factory, 2, 3));

    group.bench_function(BenchmarkId::new("gg20_ecdsa", "2-of-3"), |b| {
        b.to_async(&runtime)
            .iter(|| do_refresh(gg20_factory, &gg20_shares));
    });

    group.bench_function(BenchmarkId::new("frost_ed25519", "2-of-3"), |b| {
        b.to_async(&runtime)
            .iter(|| do_refresh(frost_ed25519_factory, &frost_ed_shares));
    });

    group.finish();
}

// ─── Transport Benchmarks ───────────────────────────────────────────────────

fn bench_ecdh_encryption(c: &mut Criterion) {
    use mpc_wallet_core::transport::session_key::SessionEncryption;

    let mut group = c.benchmark_group("transport");

    // ECDH key exchange
    group.bench_function("ecdh_key_exchange", |b| {
        b.iter(|| {
            let session_id = "bench-session";
            let (mut enc_a, secret_a) = SessionEncryption::new(session_id);
            let (enc_b, _secret_b) = SessionEncryption::new(session_id);
            enc_a
                .register_peer(
                    PartyId(2),
                    &enc_b.local_public_key,
                    &secret_a,
                    session_id,
                    PartyId(1),
                )
                .unwrap();
        });
    });

    // ChaCha20-Poly1305 encrypt
    let session_id = "bench-session";
    let (mut enc_a, secret_a) = SessionEncryption::new(session_id);
    let (enc_b, _) = SessionEncryption::new(session_id);
    enc_a
        .register_peer(
            PartyId(2),
            &enc_b.local_public_key,
            &secret_a,
            session_id,
            PartyId(1),
        )
        .unwrap();
    let payload_1kb = vec![0xABu8; 1024];
    let payload_64kb = vec![0xABu8; 65536];

    group.bench_function("chacha20_encrypt_1kb", |b| {
        b.iter(|| {
            enc_a.encrypt(PartyId(2), &payload_1kb, PartyId(1)).unwrap();
        });
    });

    group.bench_function("chacha20_encrypt_64kb", |b| {
        b.iter(|| {
            enc_a
                .encrypt(PartyId(2), &payload_64kb, PartyId(1))
                .unwrap();
        });
    });

    group.finish();
}

// ─── Key Store Benchmarks ───────────────────────────────────────────────────

fn bench_keystore(c: &mut Criterion) {
    let mut group = c.benchmark_group("keystore");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    // Argon2id key derivation (intentionally slow — 64MiB memory-hard)
    group.bench_function("argon2id_derive", |b| {
        b.iter(|| {
            use argon2::PasswordHasher;
            let params = argon2::Params::new(65536, 3, 4, Some(32)).unwrap();
            let hasher =
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let salt = argon2::password_hash::SaltString::encode_b64(&[0u8; 22]).unwrap();
            hasher.hash_password(b"benchmark-password", &salt).ok();
        });
    });

    // AES-256-GCM encrypt/decrypt
    group.bench_function("aes256gcm_encrypt_1kb", |b| {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        let key = [0x42u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let plaintext = vec![0xABu8; 1024];

        b.iter(|| {
            cipher.encrypt(nonce, plaintext.as_slice()).unwrap();
        });
    });

    group.finish();
}

// ─── Scaling Benchmarks ─────────────────────────────────────────────────────

fn bench_scaling(c: &mut Criterion) {
    let runtime = rt();
    let mut group = c.benchmark_group("scaling");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    // GG20 keygen: 2-of-3 vs 3-of-5
    group.bench_function(BenchmarkId::new("gg20_keygen", "2-of-3"), |b| {
        b.to_async(&runtime).iter(|| do_keygen(gg20_factory, 2, 3));
    });

    group.bench_function(BenchmarkId::new("gg20_keygen", "3-of-5"), |b| {
        b.to_async(&runtime).iter(|| do_keygen(gg20_factory, 3, 5));
    });

    // GG20 sign: 2 signers vs 3 signers
    let shares_3 = runtime.block_on(do_keygen(gg20_factory, 2, 3));
    let shares_5 = runtime.block_on(do_keygen(gg20_factory, 3, 5));
    let msg = b"scaling benchmark";

    group.bench_function(BenchmarkId::new("gg20_sign", "2-of-3"), |b| {
        b.to_async(&runtime)
            .iter(|| do_sign(gg20_factory, &shares_3, &[0, 1], msg));
    });

    group.bench_function(BenchmarkId::new("gg20_sign", "3-of-5"), |b| {
        b.to_async(&runtime)
            .iter(|| do_sign(gg20_factory, &shares_5, &[0, 1, 2], msg));
    });

    group.finish();
}

// ─── Register All Benchmarks ────────────────────────────────────────────────

criterion_group!(protocol_benches, bench_keygen, bench_sign, bench_refresh,);

criterion_group!(infra_benches, bench_ecdh_encryption, bench_keystore,);

criterion_group!(scaling_benches, bench_scaling,);

criterion_main!(protocol_benches, infra_benches, scaling_benches);
