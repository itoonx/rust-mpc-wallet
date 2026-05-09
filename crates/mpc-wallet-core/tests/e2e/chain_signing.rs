//! E2E tests: Chain address derivation from MPC keygen output.
//!
//! Uses LocalTransport for keygen (fast, reliable) then verifies chain-specific
//! address derivation works correctly with the group public key.
//!
//! Requires: `./scripts/local-infra.sh up` (for consistency, runs with test suite)

use mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol;
use mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol;
use mpc_wallet_core::protocol::gg20::Gg20Protocol;
use mpc_wallet_core::protocol::{MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::local::LocalTransportNetwork;
use mpc_wallet_core::types::{PartyId, ThresholdConfig};

use mpc_wallet_chains::provider::Chain;
use mpc_wallet_chains::registry::ChainRegistry;

/// Keygen via LocalTransport (reliable, in-process).
async fn local_keygen(
    protocol_factory: fn() -> Box<dyn MpcProtocol>,
    threshold: u16,
    total: u16,
) -> Vec<mpc_wallet_core::protocol::KeyShare> {
    let config = ThresholdConfig::new(threshold, total).unwrap();
    let net = LocalTransportNetwork::new(total);

    let mut handles = Vec::new();
    for i in 1..=total {
        let party_id = PartyId(i);
        let transport = net.get_transport(party_id);
        let protocol = protocol_factory();
        handles.push(tokio::spawn(async move {
            protocol.keygen(config, party_id, &*transport).await
        }));
    }

    let mut shares = Vec::new();
    for h in handles {
        shares.push(h.await.unwrap().unwrap());
    }
    shares
}

/// Sign via LocalTransport.
async fn local_sign(
    protocol_factory: fn() -> Box<dyn MpcProtocol>,
    shares: &[mpc_wallet_core::protocol::KeyShare],
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
        let protocol = protocol_factory();
        let signers_clone = signers.clone();
        let msg = message.to_vec();
        handles.push(tokio::spawn(async move {
            protocol
                .sign(&share, &signers_clone, &msg, &*transport)
                .await
        }));
    }

    let mut sigs = Vec::new();
    for h in handles {
        sigs.push(h.await.unwrap().unwrap());
    }
    sigs
}

fn gg20_factory() -> Box<dyn MpcProtocol> {
    Box::new(Gg20Protocol::new())
}

fn frost_ed25519_factory() -> Box<dyn MpcProtocol> {
    Box::new(FrostEd25519Protocol::new())
}

fn frost_secp256k1_factory() -> Box<dyn MpcProtocol> {
    Box::new(FrostSecp256k1TrProtocol::new())
}

// ═══════════════════════════════════════════════════════════════════════
// EVM: GG20 ECDSA → Ethereum address → sign → verify
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "E2E: keygen + EVM address derivation + ECDSA sign + verify"]
async fn test_gg20_evm_full_loop() {
    use k256::ecdsa::{Signature, VerifyingKey};
    use sha2::Digest;

    let shares = local_keygen(gg20_factory, 2, 3).await;

    // Derive Ethereum address
    let registry = ChainRegistry::default_testnet();
    let provider = registry.provider(Chain::Ethereum).unwrap();
    let address = provider
        .derive_address(&shares[0].group_public_key)
        .unwrap();

    assert!(address.starts_with("0x"), "ETH address must start with 0x");
    assert_eq!(address.len(), 42, "ETH address must be 42 chars");

    // Sign a 32-byte EVM-style prehash. Per Sprint 38 lesson L-011, GG20 now
    // treats 32-byte input as a prehash (does NOT re-hash with SHA-256), so
    // verification must use the prehash directly — not Sha256(tx_hash).
    let tx_hash = sha2::Sha256::digest(b"evm e2e test transaction").to_vec();
    assert_eq!(tx_hash.len(), 32, "EVM prehash must be 32 bytes");
    let sigs = local_sign(gg20_factory, &shares, &[0, 1], &tx_hash).await;
    let MpcSignature::Ecdsa { r, s, recovery_id } = &sigs[0] else {
        panic!("expected ECDSA signature");
    };

    // Verify cryptographically against the prehash itself (matches the
    // post-L-011 prehash-as-input convention used by every chain provider).
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let pubkey = k256::PublicKey::from_sec1_bytes(shares[0].group_public_key.as_bytes()).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify_prehash(&tx_hash, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("EVM ECDSA signature must verify against group pubkey (prehash)");

    assert!(
        *recovery_id == 0 || *recovery_id == 1,
        "recovery_id must be 0 or 1"
    );

    // Verify address derivation is consistent
    for share in &shares[1..] {
        let addr = provider.derive_address(&share.group_public_key).unwrap();
        assert_eq!(addr, address, "all parties must derive same ETH address");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Solana: FROST Ed25519 → Solana address → sign → verify
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "E2E: keygen + Solana address derivation + EdDSA sign + verify"]
async fn test_frost_ed25519_solana_full_loop() {
    let shares = local_keygen(frost_ed25519_factory, 2, 3).await;

    // Derive Solana address
    let registry = ChainRegistry::default_testnet();
    let provider = registry.provider(Chain::Solana).unwrap();
    let address = provider
        .derive_address(&shares[0].group_public_key)
        .unwrap();

    assert!(
        address.len() >= 32 && address.len() <= 44,
        "Solana address length: 32-44 chars, got {}",
        address.len()
    );

    // Sign
    let message = b"solana e2e test";
    let sigs = local_sign(frost_ed25519_factory, &shares, &[0, 1], message).await;
    let MpcSignature::EdDsa { signature } = &sigs[0] else {
        panic!("expected EdDSA signature");
    };

    assert_eq!(signature.len(), 64);

    // Verify
    let vk = ed25519_dalek::VerifyingKey::from_bytes(
        &shares[0].group_public_key.as_bytes()[..32]
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(signature.as_slice().try_into().unwrap());
    use ed25519_dalek::Verifier;
    vk.verify(message, &sig)
        .expect("Solana Ed25519 signature must verify");
}

// ═══════════════════════════════════════════════════════════════════════
// Bitcoin: FROST Secp256k1 → P2WPKH (default) + Taproot helper
// ═══════════════════════════════════════════════════════════════════════
// Sprint 40 (L-014): BitcoinProvider::derive_address now returns P2WPKH
// (`tb1q…`) since FROST-Secp256k1-TR doesn't yet implement the BIP-341
// key tweak. Taproot derivation moved to the standalone helper.

#[tokio::test]
#[ignore = "E2E: keygen + Bitcoin P2WPKH (default) and Taproot helper"]
async fn test_frost_secp256k1_bitcoin_full_loop() {
    let shares = local_keygen(frost_secp256k1_factory, 2, 3).await;

    // Default address derivation = P2WPKH (`tb1q…`)
    let registry = ChainRegistry::default_testnet();
    let provider = registry.provider(Chain::BitcoinTestnet).unwrap();
    let address = provider
        .derive_address(&shares[0].group_public_key)
        .unwrap();
    assert!(
        address.starts_with("tb1q"),
        "Bitcoin testnet default is P2WPKH (tb1q), got: {address}"
    );

    // (Taproot helper coverage lives in chain_bitcoin_integration.rs to avoid
    //  pulling the `bitcoin` crate into mpc-wallet-core dev-deps just for the
    //  Network enum.)

    // All parties derive the same default address
    for share in &shares[1..] {
        let addr = provider.derive_address(&share.group_public_key).unwrap();
        assert_eq!(addr, address, "all parties must derive same BTC address");
    }
}
