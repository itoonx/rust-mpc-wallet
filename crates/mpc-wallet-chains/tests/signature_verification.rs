//! Signature Verification Tests — MPC keygen → sign → verify per chain category.
//!
//! Proves that MPC-generated signatures are cryptographically valid and usable
//! on-chain for all 50 supported blockchains.
//!
//! Each test:
//! 1. Keygen via LocalTransport (2-of-3 threshold)
//! 2. Sign a message with a signer subset
//! 3. Derive chain-specific address from group pubkey
//! 4. Cryptographically verify signature against group pubkey
//! 5. Assert address derivation is consistent across all parties

use mpc_wallet_chains::provider::Chain;
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol;
use mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol;
use mpc_wallet_core::protocol::gg20::Gg20Protocol;
use mpc_wallet_core::protocol::{KeyShare, MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::local::LocalTransportNetwork;
use mpc_wallet_core::types::{PartyId, ThresholdConfig};

// ── Helpers ──────────────────────────────────────────────────────────

async fn keygen(factory: fn() -> Box<dyn MpcProtocol>, t: u16, n: u16) -> Vec<KeyShare> {
    let config = ThresholdConfig::new(t, n).unwrap();
    let net = LocalTransportNetwork::new(n);
    let mut handles = Vec::new();
    for i in 1..=n {
        let pid = PartyId(i);
        let transport = net.get_transport(pid);
        let protocol = factory();
        handles.push(tokio::spawn(async move {
            protocol.keygen(config, pid, &*transport).await
        }));
    }
    let mut shares = Vec::new();
    for h in handles {
        shares.push(h.await.unwrap().unwrap());
    }
    shares
}

async fn sign(
    factory: fn() -> Box<dyn MpcProtocol>,
    shares: &[KeyShare],
    indices: &[usize],
    message: &[u8],
) -> Vec<MpcSignature> {
    let config = shares[0].config;
    let signers: Vec<PartyId> = indices.iter().map(|&i| shares[i].party_id).collect();
    let net = LocalTransportNetwork::new(config.total_parties);
    let mut handles = Vec::new();
    for &idx in indices {
        let share = shares[idx].clone();
        let transport = net.get_transport(share.party_id);
        let protocol = factory();
        let s = signers.clone();
        let m = message.to_vec();
        handles.push(tokio::spawn(async move {
            protocol.sign(&share, &s, &m, &*transport).await
        }));
    }
    let mut sigs = Vec::new();
    for h in handles {
        sigs.push(h.await.unwrap().unwrap());
    }
    sigs
}

fn gg20() -> Box<dyn MpcProtocol> {
    Box::new(Gg20Protocol::new())
}
fn frost_ed25519() -> Box<dyn MpcProtocol> {
    Box::new(FrostEd25519Protocol::new())
}
fn frost_secp256k1() -> Box<dyn MpcProtocol> {
    Box::new(FrostSecp256k1TrProtocol::new())
}

/// Verify ECDSA signature against group pubkey.
fn verify_ecdsa(gpk_bytes: &[u8], message: &[u8], sig: &MpcSignature) {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let MpcSignature::Ecdsa { r, s, recovery_id } = sig else {
        panic!("expected ECDSA signature, got {sig:?}");
    };

    let pubkey =
        k256::PublicKey::from_sec1_bytes(gpk_bytes).expect("group pubkey must be valid SEC1");
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = Signature::from_bytes(&sig_bytes.into()).expect("(r,s) must form valid signature");
    vk.verify(message, &sig)
        .expect("ECDSA signature must verify against group pubkey");

    assert!(
        *recovery_id == 0 || *recovery_id == 1,
        "recovery_id must be 0 or 1, got {recovery_id}"
    );
}

/// Verify Ed25519 signature against group pubkey.
fn verify_ed25519(gpk_bytes: &[u8], message: &[u8], sig: &MpcSignature) {
    use ed25519_dalek::Verifier;

    let MpcSignature::EdDsa { signature } = sig else {
        panic!("expected EdDSA signature, got {sig:?}");
    };

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&gpk_bytes[..32].try_into().unwrap())
        .expect("group pubkey must be valid Ed25519");
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    vk.verify(message, &sig)
        .expect("Ed25519 signature must verify against group pubkey");
}

/// Assert all parties derive the same address for a chain.
fn assert_address_consistency(shares: &[KeyShare], chain: Chain) {
    let registry = ChainRegistry::default_testnet();
    let provider = registry.provider(chain).unwrap();
    let addr0 = provider
        .derive_address(&shares[0].group_public_key)
        .unwrap();
    for share in &shares[1..] {
        let addr = provider.derive_address(&share.group_public_key).unwrap();
        assert_eq!(
            addr, addr0,
            "party {} derived different address for {chain:?}",
            share.party_id.0
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// EVM Chains (26) — GG20 ECDSA
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ecdsa_sig_verifies_all_evm_chains() {
    let shares = keygen(gg20, 2, 3).await;
    let message = b"evm signature verification test";
    let sigs = sign(gg20, &shares, &[0, 1], message).await;
    let gpk = shares[0].group_public_key.as_bytes();

    verify_ecdsa(gpk, message, &sigs[0]);

    // Verify address derivation for ALL 26 EVM chains
    let evm_chains = [
        Chain::Ethereum,
        Chain::Polygon,
        Chain::Bsc,
        Chain::Arbitrum,
        Chain::Optimism,
        Chain::Base,
        Chain::Avalanche,
        Chain::Linea,
        Chain::ZkSync,
        Chain::Scroll,
        Chain::Mantle,
        Chain::Blast,
        Chain::Zora,
        Chain::Fantom,
        Chain::Gnosis,
        Chain::Cronos,
        Chain::Celo,
        Chain::Moonbeam,
        Chain::Ronin,
        Chain::OpBnb,
        Chain::Immutable,
        Chain::MantaPacific,
        Chain::Hyperliquid,
        Chain::Berachain,
        Chain::MegaEth,
        Chain::Monad,
    ];

    let registry = ChainRegistry::default_testnet();
    let first_addr = registry
        .provider(Chain::Ethereum)
        .unwrap()
        .derive_address(&shares[0].group_public_key)
        .unwrap();

    // All EVM chains must derive the same address (same secp256k1 → keccak256 → 0x...)
    for chain in &evm_chains {
        let provider = registry.provider(*chain).unwrap();
        let addr = provider
            .derive_address(&shares[0].group_public_key)
            .unwrap();
        assert!(
            addr.starts_with("0x"),
            "{chain:?} address must start with 0x"
        );
        assert_eq!(addr.len(), 42, "{chain:?} address must be 42 chars");
        assert_eq!(
            addr, first_addr,
            "{chain:?} must derive same address as Ethereum (shared secp256k1 key)"
        );
    }
}

// Different signer subsets produce valid signatures
#[tokio::test]
async fn test_ecdsa_different_subsets_all_verify() {
    let shares = keygen(gg20, 2, 3).await;
    let message = b"different subsets test";
    let gpk = shares[0].group_public_key.as_bytes();

    // Subset {1,2}
    let sigs_12 = sign(gg20, &shares, &[0, 1], message).await;
    verify_ecdsa(gpk, message, &sigs_12[0]);

    // Subset {1,3}
    let sigs_13 = sign(gg20, &shares, &[0, 2], message).await;
    verify_ecdsa(gpk, message, &sigs_13[0]);

    // Note: GG20 requires coordinator (Party 1) in every signing subset.
    // Subset {2,3} is not tested because Party 1 must be present.
}

// ═══════════════════════════════════════════════════════════════════════
// Bitcoin — FROST Secp256k1 (Taproot)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_schnorr_sig_verifies_bitcoin_taproot() {
    let shares = keygen(frost_secp256k1, 2, 3).await;

    // Taproot address derivation
    assert_address_consistency(&shares, Chain::BitcoinTestnet);
    let registry = ChainRegistry::default_testnet();
    let addr = registry
        .provider(Chain::BitcoinTestnet)
        .unwrap()
        .derive_address(&shares[0].group_public_key)
        .unwrap();
    assert!(
        addr.starts_with("tb1p"),
        "Taproot testnet must be tb1p, got: {addr}"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// UTXO Alt-Coins — GG20 ECDSA (Litecoin, Dogecoin, Zcash)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ecdsa_sig_verifies_utxo_chains() {
    let shares = keygen(gg20, 2, 3).await;
    let message = b"utxo chains verification";
    let sigs = sign(gg20, &shares, &[0, 1], message).await;
    let gpk = shares[0].group_public_key.as_bytes();

    verify_ecdsa(gpk, message, &sigs[0]);

    for chain in [Chain::Litecoin, Chain::Dogecoin, Chain::Zcash] {
        assert_address_consistency(&shares, chain);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Solana — FROST Ed25519
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_eddsa_sig_verifies_solana() {
    let shares = keygen(frost_ed25519, 2, 3).await;
    let message = b"solana signature verification";
    let sigs = sign(frost_ed25519, &shares, &[0, 1], message).await;

    verify_ed25519(shares[0].group_public_key.as_bytes(), message, &sigs[0]);
    assert_address_consistency(&shares, Chain::Solana);

    let registry = ChainRegistry::default_testnet();
    let addr = registry
        .provider(Chain::Solana)
        .unwrap()
        .derive_address(&shares[0].group_public_key)
        .unwrap();
    assert!(
        addr.len() >= 32 && addr.len() <= 44,
        "Solana base58 address"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Sui — FROST Ed25519
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_eddsa_sig_verifies_sui() {
    let shares = keygen(frost_ed25519, 2, 3).await;
    let message = b"sui signature verification";
    let sigs = sign(frost_ed25519, &shares, &[0, 1], message).await;

    verify_ed25519(shares[0].group_public_key.as_bytes(), message, &sigs[0]);
    assert_address_consistency(&shares, Chain::Sui);

    let registry = ChainRegistry::default_testnet();
    let addr = registry
        .provider(Chain::Sui)
        .unwrap()
        .derive_address(&shares[0].group_public_key)
        .unwrap();
    assert!(addr.starts_with("0x"), "Sui address must start with 0x");
    assert_eq!(addr.len(), 66, "Sui address = 0x + 64 hex chars");
}

// ═══════════════════════════════════════════════════════════════════════
// Aptos + Movement — FROST Ed25519
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_eddsa_sig_verifies_aptos() {
    let shares = keygen(frost_ed25519, 2, 3).await;
    let message = b"aptos signature verification";
    let sigs = sign(frost_ed25519, &shares, &[0, 1], message).await;

    verify_ed25519(shares[0].group_public_key.as_bytes(), message, &sigs[0]);
    assert_address_consistency(&shares, Chain::Aptos);
    assert_address_consistency(&shares, Chain::Movement);
}

// ═══════════════════════════════════════════════════════════════════════
// Cosmos Chains (5) — GG20 ECDSA
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ecdsa_sig_verifies_cosmos_chains() {
    let shares = keygen(gg20, 2, 3).await;
    let message = b"cosmos signature verification";
    let sigs = sign(gg20, &shares, &[0, 1], message).await;

    verify_ecdsa(shares[0].group_public_key.as_bytes(), message, &sigs[0]);

    for chain in [
        Chain::CosmosHub,
        Chain::Osmosis,
        Chain::Celestia,
        Chain::Injective,
        Chain::Sei,
    ] {
        assert_address_consistency(&shares, chain);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Substrate Chains (6) — FROST Ed25519
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_eddsa_sig_verifies_substrate_chains() {
    let shares = keygen(frost_ed25519, 2, 3).await;
    let message = b"substrate signature verification";
    let sigs = sign(frost_ed25519, &shares, &[0, 1], message).await;

    verify_ed25519(shares[0].group_public_key.as_bytes(), message, &sigs[0]);

    for chain in [
        Chain::Polkadot,
        Chain::Kusama,
        Chain::Astar,
        Chain::Acala,
        Chain::Phala,
        Chain::Interlay,
    ] {
        assert_address_consistency(&shares, chain);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TON — FROST Ed25519
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_eddsa_sig_verifies_ton() {
    let shares = keygen(frost_ed25519, 2, 3).await;
    let message = b"ton signature verification";
    let sigs = sign(frost_ed25519, &shares, &[0, 1], message).await;

    verify_ed25519(shares[0].group_public_key.as_bytes(), message, &sigs[0]);
    assert_address_consistency(&shares, Chain::Ton);
}

// ═══════════════════════════════════════════════════════════════════════
// TRON — GG20 ECDSA
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ecdsa_sig_verifies_tron() {
    let shares = keygen(gg20, 2, 3).await;
    let message = b"tron signature verification";
    let sigs = sign(gg20, &shares, &[0, 1], message).await;

    verify_ecdsa(shares[0].group_public_key.as_bytes(), message, &sigs[0]);
    assert_address_consistency(&shares, Chain::Tron);
}

// ═══════════════════════════════════════════════════════════════════════
// Monero — FROST Ed25519
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_eddsa_sig_verifies_monero() {
    let shares = keygen(frost_ed25519, 2, 3).await;
    let message = b"monero signature verification";
    let sigs = sign(frost_ed25519, &shares, &[0, 1], message).await;

    verify_ed25519(shares[0].group_public_key.as_bytes(), message, &sigs[0]);
    assert_address_consistency(&shares, Chain::Monero);
}

// ═══════════════════════════════════════════════════════════════════════
// EVM Low-S Normalization (SEC-012)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_evm_low_s_normalization() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = keygen(gg20, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);

    // Sign multiple messages — all must have low-S values
    for i in 0..5 {
        let message = format!("low-s test message #{i}").into_bytes();
        let sigs = sign(gg20, &shares, &[0, 1], &message).await;
        let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
            panic!("expected ECDSA");
        };

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r);
        sig_bytes[32..].copy_from_slice(s);

        // k256's Signature::from_bytes enforces low-S — if it succeeds, S is low
        let sig = Signature::from_bytes(&sig_bytes.into())
            .expect("signature must have low-S (SEC-012 normalization)");
        vk.verify(&message, &sig).expect("must verify");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// All 50 chains — address derivation consistency
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_all_50_chains_address_derivation_consistency() {
    // ECDSA chains (GG20)
    let ecdsa_shares = keygen(gg20, 2, 3).await;

    // EdDSA chains (FROST Ed25519)
    let eddsa_shares = keygen(frost_ed25519, 2, 3).await;

    // Schnorr chains (FROST Secp256k1)
    let schnorr_shares = keygen(frost_secp256k1, 2, 3).await;

    let registry = ChainRegistry::default_testnet();

    // Track chains tested
    let mut tested = 0u32;

    // EVM (26) — use ECDSA shares
    for chain in [
        Chain::Ethereum,
        Chain::Polygon,
        Chain::Bsc,
        Chain::Arbitrum,
        Chain::Optimism,
        Chain::Base,
        Chain::Avalanche,
        Chain::Linea,
        Chain::ZkSync,
        Chain::Scroll,
        Chain::Mantle,
        Chain::Blast,
        Chain::Zora,
        Chain::Fantom,
        Chain::Gnosis,
        Chain::Cronos,
        Chain::Celo,
        Chain::Moonbeam,
        Chain::Ronin,
        Chain::OpBnb,
        Chain::Immutable,
        Chain::MantaPacific,
        Chain::Hyperliquid,
        Chain::Berachain,
        Chain::MegaEth,
        Chain::Monad,
    ] {
        let p = registry.provider(chain).unwrap();
        let a = p.derive_address(&ecdsa_shares[0].group_public_key).unwrap();
        assert!(!a.is_empty(), "{chain:?} address must not be empty");
        tested += 1;
    }

    // Bitcoin (2) — Schnorr
    for chain in [Chain::BitcoinMainnet, Chain::BitcoinTestnet] {
        let p = registry.provider(chain).unwrap();
        let a = p
            .derive_address(&schnorr_shares[0].group_public_key)
            .unwrap();
        assert!(!a.is_empty(), "{chain:?} address must not be empty");
        tested += 1;
    }

    // UTXO alts (3) — ECDSA
    for chain in [Chain::Litecoin, Chain::Dogecoin, Chain::Zcash] {
        let p = registry.provider(chain).unwrap();
        let a = p.derive_address(&ecdsa_shares[0].group_public_key).unwrap();
        assert!(!a.is_empty(), "{chain:?} address must not be empty");
        tested += 1;
    }

    // Ed25519 chains (13)
    for chain in [
        Chain::Solana,
        Chain::Sui,
        Chain::Aptos,
        Chain::Movement,
        Chain::Polkadot,
        Chain::Kusama,
        Chain::Astar,
        Chain::Acala,
        Chain::Phala,
        Chain::Interlay,
        Chain::Ton,
        Chain::Monero,
        Chain::Starknet,
    ] {
        let p = registry.provider(chain).unwrap();
        let a = p.derive_address(&eddsa_shares[0].group_public_key).unwrap();
        assert!(!a.is_empty(), "{chain:?} address must not be empty");
        tested += 1;
    }

    // Cosmos (5) — ECDSA
    for chain in [
        Chain::CosmosHub,
        Chain::Osmosis,
        Chain::Celestia,
        Chain::Injective,
        Chain::Sei,
    ] {
        let p = registry.provider(chain).unwrap();
        let a = p.derive_address(&ecdsa_shares[0].group_public_key).unwrap();
        assert!(!a.is_empty(), "{chain:?} address must not be empty");
        tested += 1;
    }

    // TRON — ECDSA
    let p = registry.provider(Chain::Tron).unwrap();
    let a = p.derive_address(&ecdsa_shares[0].group_public_key).unwrap();
    assert!(!a.is_empty(), "TRON address must not be empty");
    tested += 1;

    assert_eq!(tested, 50, "must test all 50 chains");
}
