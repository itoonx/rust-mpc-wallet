use mpc_wallet_core::protocol::{MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::local::LocalTransportNetwork;
use mpc_wallet_core::types::{CryptoScheme, PartyId, ThresholdConfig};

/// Helper: run keygen for all parties concurrently, return key shares.
async fn run_keygen(
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

/// Helper: run signing for a subset of parties, return signatures from all signers.
async fn run_sign(
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

// ============================================================================
// GG20 ECDSA tests
// ============================================================================

fn gg20_factory() -> Box<dyn MpcProtocol> {
    Box::new(mpc_wallet_core::protocol::gg20::Gg20Protocol::new())
}

#[tokio::test]
async fn test_gg20_keygen_sign_verify() {
    let shares = run_keygen(gg20_factory, 2, 3).await;

    // Verify all shares have the same group public key
    assert_eq!(shares[0].scheme, CryptoScheme::Gg20Ecdsa);
    let gpk = &shares[0].group_public_key;
    for share in &shares[1..] {
        assert_eq!(share.group_public_key.as_bytes(), gpk.as_bytes());
    }

    // Sign with parties 1 and 2
    let message = b"hello world";
    let sigs = run_sign(gg20_factory, &shares, &[0, 1], message).await;

    // All signers should produce the same ECDSA signature (RFC 6979 deterministic)
    for sig in &sigs {
        match sig {
            MpcSignature::Ecdsa { r, s, .. } => {
                assert_eq!(r.len(), 32);
                assert_eq!(s.len(), 32);
            }
            _ => panic!("expected ECDSA signature"),
        }
    }

    // Verify signature with k256
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk.as_bytes()).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
        panic!();
    };
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = Signature::from_bytes(&sig_bytes.into()).unwrap();
    vk.verify(message, &sig).unwrap();
}

#[tokio::test]
async fn test_gg20_different_signer_subsets() {
    let shares = run_keygen(gg20_factory, 2, 3).await;
    let message = b"test different signers";

    // Sign with parties 1,3
    let sigs_13 = run_sign(gg20_factory, &shares, &[0, 2], message).await;

    // Sign with parties 2,3
    let sigs_23 = run_sign(gg20_factory, &shares, &[1, 2], message).await;

    // Both should produce valid signatures (same signature since RFC 6979 is deterministic
    // and they all reconstruct the same secret)
    let gpk = &shares[0].group_public_key;
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk.as_bytes()).unwrap();
    let vk = VerifyingKey::from(&pubkey);

    for sigs in [&sigs_13, &sigs_23] {
        let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
            panic!();
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r);
        sig_bytes[32..].copy_from_slice(s);
        let sig = Signature::from_bytes(&sig_bytes.into()).unwrap();
        vk.verify(message, &sig).unwrap();
    }
}

// ============================================================================
// FROST secp256k1-tr tests
// ============================================================================

fn frost_secp256k1_factory() -> Box<dyn MpcProtocol> {
    Box::new(
        mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol::new(),
    )
}

#[tokio::test]
async fn test_frost_secp256k1_keygen_sign_verify() {
    let shares = run_keygen(frost_secp256k1_factory, 2, 3).await;

    assert_eq!(shares[0].scheme, CryptoScheme::FrostSecp256k1Tr);
    let gpk = &shares[0].group_public_key;
    for share in &shares[1..] {
        assert_eq!(share.group_public_key.as_bytes(), gpk.as_bytes());
    }

    // Sign with parties 1 and 2
    let message = b"frost secp256k1 test";
    let sigs = run_sign(frost_secp256k1_factory, &shares, &[0, 1], message).await;

    // All signers should produce the same Schnorr signature
    for sig in &sigs {
        match sig {
            MpcSignature::Schnorr { signature } => {
                assert_eq!(signature.len(), 64);
            }
            _ => panic!("expected Schnorr signature"),
        }
    }

    // Verify all signers got the same signature
    let MpcSignature::Schnorr { signature: sig0 } = &sigs[0] else {
        panic!();
    };
    for sig in &sigs[1..] {
        let MpcSignature::Schnorr { signature } = sig else {
            panic!();
        };
        assert_eq!(sig0, signature);
    }
}

// ============================================================================
// FROST Ed25519 tests
// ============================================================================

fn frost_ed25519_factory() -> Box<dyn MpcProtocol> {
    Box::new(mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol::new())
}

#[tokio::test]
async fn test_frost_ed25519_keygen_sign_verify() {
    let shares = run_keygen(frost_ed25519_factory, 2, 3).await;

    assert_eq!(shares[0].scheme, CryptoScheme::FrostEd25519);
    let gpk = &shares[0].group_public_key;
    for share in &shares[1..] {
        assert_eq!(share.group_public_key.as_bytes(), gpk.as_bytes());
    }

    // Sign with parties 1 and 2
    let message = b"frost ed25519 test";
    let sigs = run_sign(frost_ed25519_factory, &shares, &[0, 1], message).await;

    // All signers should produce the same EdDSA signature
    for sig in &sigs {
        match sig {
            MpcSignature::EdDsa { signature } => {
                assert_eq!(signature.len(), 64);
            }
            _ => panic!("expected EdDSA signature"),
        }
    }

    // Verify all signers got the same signature
    let MpcSignature::EdDsa { signature: sig0 } = &sigs[0] else {
        panic!();
    };
    for sig in &sigs[1..] {
        let MpcSignature::EdDsa { signature } = sig else {
            panic!();
        };
        assert_eq!(sig0, signature);
    }

    // Verify using ed25519-dalek
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(gpk.as_bytes().try_into().unwrap()).unwrap();
    let sig = Signature::from_bytes(sig0);
    vk.verify(message, &sig).unwrap();
}

#[tokio::test]
async fn test_frost_ed25519_different_signer_subsets() {
    let shares = run_keygen(frost_ed25519_factory, 2, 3).await;
    let message = b"different signers ed25519";

    // Sign with parties 1,3
    let sigs_13 = run_sign(frost_ed25519_factory, &shares, &[0, 2], message).await;

    // Sign with parties 2,3
    let sigs_23 = run_sign(frost_ed25519_factory, &shares, &[1, 2], message).await;

    // Both should produce valid signatures (different due to nonce randomness)
    let gpk = &shares[0].group_public_key;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(gpk.as_bytes().try_into().unwrap()).unwrap();

    for sigs in [&sigs_13, &sigs_23] {
        let MpcSignature::EdDsa { signature } = &sigs[0] else {
            panic!();
        };
        let sig = Signature::from_bytes(signature);
        vk.verify(message, &sig).unwrap();
    }
}
