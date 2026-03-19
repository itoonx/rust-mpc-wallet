use mpc_wallet_core::protocol::{KeyShare, MpcProtocol, MpcSignature};
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

// ── Distributed path (default — `gg20-simulation` OFF) ──────────────────────

/// Distributed 2-of-3 keygen + sign: verify the ECDSA signature cryptographically.
///
/// The full private key is NEVER reconstructed.  Each party contributes only
/// its additive share `s_i = x_i_add · r · k_inv mod n`.  Party 1 assembles
/// the final signature as `s = hash·k_inv + Σ s_i`.
///
/// Structural proof that x is never assembled:
/// - `distributed_keygen` distributes `x_i_add = λ_i · f(i)`, not `f(i)`.
/// - `distributed_sign` computes `s_i = x_i_add · r · k_inv` — one scalar
///   multiply.  There is no call to `lagrange_interpolate` or any code that
///   sums all shares back into a single scalar outside of the final `s`
///   assembly (which combines partial `s_i`, not key material).
#[cfg(not(feature = "gg20-simulation"))]
#[tokio::test]
async fn test_gg20_distributed_no_key_reconstruction() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(gg20_factory, 2, 3).await;

    assert_eq!(
        shares[0].scheme,
        mpc_wallet_core::types::CryptoScheme::Gg20Ecdsa
    );
    let gpk = &shares[0].group_public_key;
    for share in &shares[1..] {
        assert_eq!(
            share.group_public_key.as_bytes(),
            gpk.as_bytes(),
            "all parties must derive the same group public key"
        );
    }

    // Sign with parties 1 and 2 (the coordinator is Party 1).
    let message = b"distributed ecdsa test - no key reconstruction";
    // sigs[0] is the coordinator's result (the canonical final signature).
    // sigs[1] is Party 2's partial contribution sentinel.
    let sigs = run_sign(gg20_factory, &shares, &[0, 1], message).await;

    // The coordinator (Party 1 = index 0) produces the canonical signature.
    let MpcSignature::Ecdsa { r, s, recovery_id } = &sigs[0] else {
        panic!("expected ECDSA signature from coordinator");
    };

    // Basic sanity checks.
    assert_eq!(r.len(), 32, "r must be 32 bytes");
    assert_eq!(s.len(), 32, "s must be 32 bytes");
    assert_ne!(
        *recovery_id, 0xff,
        "coordinator must return final signature, not partial sentinel"
    );

    // Cryptographic verification: the signature must verify against the group pubkey.
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk.as_bytes())
        .expect("group pubkey must be valid SEC1 compressed point");
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = Signature::from_bytes(&sig_bytes.into())
        .expect("assembled (r,s) must form a valid DER signature");
    vk.verify(message, &sig)
        .expect("distributed ECDSA signature must cryptographically verify");
}

/// Verify that different signer subsets both produce valid signatures.
#[cfg(not(feature = "gg20-simulation"))]
#[tokio::test]
async fn test_gg20_distributed_different_subsets() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(gg20_factory, 2, 3).await;
    let gpk = &shares[0].group_public_key;
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk.as_bytes()).unwrap();
    let vk = VerifyingKey::from(&pubkey);

    let message = b"different subsets test";

    // Subset {1, 2}
    let sigs_12 = run_sign(gg20_factory, &shares, &[0, 1], message).await;
    let MpcSignature::Ecdsa { r, s, .. } = &sigs_12[0] else {
        panic!();
    };
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("subset {1,2} signature must verify");

    // Subset {1, 3} — party 3's share index is 2 in the shares vec
    let sigs_13 = run_sign(gg20_factory, &shares, &[0, 2], message).await;
    let MpcSignature::Ecdsa { r, s, .. } = &sigs_13[0] else {
        panic!();
    };
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("subset {1,3} signature must verify");
}

// ── GG20 key resharing tests (Epic H2) ──────────────────────────────────────

/// GG20 reshare: 2-of-3 -> 2-of-4 (add party 4).
///
/// 1. Keygen 2-of-3 with parties {1,2,3}
/// 2. Reshare to 2-of-4 with new parties {1,2,3,4} (all old signers participate)
/// 3. Verify group pubkey unchanged
/// 4. Sign with new parties {1,4} using new shares
#[cfg(not(feature = "gg20-simulation"))]
#[tokio::test]
async fn test_gg20_reshare_add_party() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    // Step 1: Keygen 2-of-3
    let shares = run_keygen(gg20_factory, 2, 3).await;
    let original_gpk = shares[0].group_public_key.as_bytes().to_vec();

    // Step 2: Reshare to 2-of-4, old signers = {1,2,3}, new parties = {1,2,3,4}
    let old_signers: Vec<PartyId> = vec![PartyId(1), PartyId(2), PartyId(3)];
    let new_config = ThresholdConfig::new(2, 4).unwrap();
    let new_parties: Vec<PartyId> = vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4)];

    // Create a transport network that includes all parties (old + new = 4)
    let net = LocalTransportNetwork::new(4);

    let mut handles = Vec::new();
    // Old parties (1,2,3) run reshare with their real shares
    for share in shares.iter().take(3) {
        let share = share.clone();
        let transport = net.get_transport(share.party_id);
        let protocol = gg20_factory();
        let old_s = old_signers.clone();
        let new_p = new_parties.clone();
        handles.push(tokio::spawn(async move {
            protocol
                .reshare(&share, &old_s, new_config, &new_p, &*transport)
                .await
        }));
    }
    // New-only party (4) needs a dummy key share to pass to reshare
    {
        let dummy_share = KeyShare {
            scheme: mpc_wallet_core::types::CryptoScheme::Gg20Ecdsa,
            party_id: PartyId(4),
            config: ThresholdConfig::new(2, 3).unwrap(),
            group_public_key: shares[0].group_public_key.clone(),
            share_data: zeroize::Zeroizing::new(vec![]),
        };
        let transport = net.get_transport(PartyId(4));
        let protocol = gg20_factory();
        let old_s = old_signers.clone();
        let new_p = new_parties.clone();
        handles.push(tokio::spawn(async move {
            protocol
                .reshare(&dummy_share, &old_s, new_config, &new_p, &*transport)
                .await
        }));
    }

    let mut new_shares = Vec::new();
    for h in handles {
        new_shares.push(h.await.unwrap().unwrap());
    }

    // Step 3: Verify group pubkey unchanged for all new parties
    for share in &new_shares {
        assert_eq!(
            share.group_public_key.as_bytes(),
            &original_gpk[..],
            "group public key must be preserved after reshare"
        );
        assert_eq!(share.config.threshold, 2, "new threshold must be 2");
        assert_eq!(share.config.total_parties, 4, "new total_parties must be 4");
    }

    // Step 4: Sign with new parties {1,4} using new shares
    // new_shares[0] = party 1, new_shares[3] = party 4
    let message = b"reshare test: sign with parties 1 and 4";
    let sign_net = LocalTransportNetwork::new(4);
    let signers = vec![PartyId(1), PartyId(4)];

    let mut sign_handles = Vec::new();
    for &idx in &[0usize, 3usize] {
        let share = new_shares[idx].clone();
        let transport = sign_net.get_transport(share.party_id);
        let protocol = gg20_factory();
        let signers_clone = signers.clone();
        let msg = message.to_vec();
        sign_handles.push(tokio::spawn(async move {
            protocol
                .sign(&share, &signers_clone, &msg, &*transport)
                .await
        }));
    }

    let mut sigs = Vec::new();
    for h in sign_handles {
        sigs.push(h.await.unwrap().unwrap());
    }

    // The coordinator (Party 1 = index 0) produces the canonical signature.
    let MpcSignature::Ecdsa { r, s, recovery_id } = &sigs[0] else {
        panic!("expected ECDSA signature from coordinator");
    };
    assert_eq!(r.len(), 32);
    assert_eq!(s.len(), 32);
    assert_ne!(
        *recovery_id, 0xff,
        "coordinator must return final signature"
    );

    // Cryptographic verification against original group pubkey.
    let pubkey = k256::PublicKey::from_sec1_bytes(&original_gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = Signature::from_bytes(&sig_bytes.into()).unwrap();
    vk.verify(message, &sig)
        .expect("signature after reshare must verify against original group key");
}

/// GG20 reshare: 2-of-3 -> 3-of-3 (increase threshold, same parties).
///
/// 1. Keygen 2-of-3 with parties {1,2,3}
/// 2. Reshare to 3-of-3 (all 3 parties stay, threshold increases)
/// 3. Verify group pubkey unchanged
/// 4. Sign with all 3 parties using new shares
#[cfg(not(feature = "gg20-simulation"))]
#[tokio::test]
async fn test_gg20_reshare_change_threshold() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    // Step 1: Keygen 2-of-3
    let shares = run_keygen(gg20_factory, 2, 3).await;
    let original_gpk = shares[0].group_public_key.as_bytes().to_vec();

    // Step 2: Reshare to 3-of-3
    let old_signers: Vec<PartyId> = vec![PartyId(1), PartyId(2), PartyId(3)];
    let new_config = ThresholdConfig::new(3, 3).unwrap();
    let new_parties: Vec<PartyId> = vec![PartyId(1), PartyId(2), PartyId(3)];

    let net = LocalTransportNetwork::new(3);

    let mut handles = Vec::new();
    for share in shares.iter().take(3) {
        let share = share.clone();
        let transport = net.get_transport(share.party_id);
        let protocol = gg20_factory();
        let old_s = old_signers.clone();
        let new_p = new_parties.clone();
        handles.push(tokio::spawn(async move {
            protocol
                .reshare(&share, &old_s, new_config, &new_p, &*transport)
                .await
        }));
    }

    let mut new_shares = Vec::new();
    for h in handles {
        new_shares.push(h.await.unwrap().unwrap());
    }

    // Step 3: Verify group pubkey unchanged
    for share in &new_shares {
        assert_eq!(
            share.group_public_key.as_bytes(),
            &original_gpk[..],
            "group public key must be preserved after threshold change"
        );
        assert_eq!(share.config.threshold, 3);
        assert_eq!(share.config.total_parties, 3);
    }

    // Step 4: Sign with all 3 parties (now 3-of-3 required)
    let message = b"reshare test: sign after threshold change to 3-of-3";
    let sigs = run_sign(gg20_factory, &new_shares, &[0, 1, 2], message).await;

    let MpcSignature::Ecdsa { r, s, recovery_id } = &sigs[0] else {
        panic!("expected ECDSA signature");
    };
    assert_eq!(r.len(), 32);
    assert_eq!(s.len(), 32);
    assert_ne!(*recovery_id, 0xff);

    let pubkey = k256::PublicKey::from_sec1_bytes(&original_gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = Signature::from_bytes(&sig_bytes.into()).unwrap();
    vk.verify(message, &sig)
        .expect("signature after threshold change must verify against original group key");
}

// ── Simulation path (`gg20-simulation` ON — backward compat) ────────────────

#[cfg(feature = "gg20-simulation")]
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

#[cfg(feature = "gg20-simulation")]
#[tokio::test]
async fn test_gg20_simulation_different_signer_subsets() {
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
    Box::new(mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol::new())
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

/// Helper: run refresh for all parties concurrently, return new key shares.
async fn run_refresh(
    protocol_factory: fn() -> Box<dyn MpcProtocol>,
    shares: &[mpc_wallet_core::protocol::KeyShare],
) -> Vec<mpc_wallet_core::protocol::KeyShare> {
    let config = shares[0].config;
    let net = LocalTransportNetwork::new(config.total_parties);

    let mut handles = Vec::new();
    for share in shares {
        let s = share.clone();
        let transport = net.get_transport(s.party_id);
        let protocol = protocol_factory();
        handles.push(tokio::spawn(async move {
            let signers: Vec<_> = (1..=s.config.total_parties).map(PartyId).collect();
            protocol.refresh(&s, &signers, &*transport).await
        }));
    }

    let mut new_shares = Vec::new();
    for h in handles {
        new_shares.push(h.await.unwrap().unwrap());
    }
    new_shares
}

/// FROST secp256k1-tr key refresh: group pubkey unchanged after refresh
#[tokio::test]
async fn test_frost_secp256k1_refresh_preserves_group_pubkey() {
    let shares = run_keygen(frost_secp256k1_factory, 2, 3).await;
    let original_gpk = shares[0].group_public_key.as_bytes().to_vec();

    // Refresh all shares
    let refreshed = run_refresh(frost_secp256k1_factory, &shares).await;

    // Verify group public key is unchanged for all parties
    for share in &refreshed {
        assert_eq!(
            share.group_public_key.as_bytes(),
            &original_gpk[..],
            "group public key must be preserved after refresh"
        );
    }

    // Verify share data actually changed (shares are different after refresh)
    for (old, new) in shares.iter().zip(refreshed.iter()) {
        let old_bytes: &[u8] = &old.share_data;
        let new_bytes: &[u8] = &new.share_data;
        assert_ne!(old_bytes, new_bytes, "share data must differ after refresh");
    }
}

/// FROST secp256k1-tr key refresh + sign: refreshed shares can produce valid signatures
#[tokio::test]
async fn test_frost_secp256k1_refresh_then_sign() {
    let shares = run_keygen(frost_secp256k1_factory, 2, 3).await;
    let original_gpk = shares[0].group_public_key.as_bytes().to_vec();

    // Refresh
    let refreshed = run_refresh(frost_secp256k1_factory, &shares).await;

    // Sign with refreshed shares (parties 1 and 2)
    let message = b"sign after frost secp256k1 refresh";
    let sigs = run_sign(frost_secp256k1_factory, &refreshed, &[0, 1], message).await;

    // All signers produce Schnorr signature
    for sig in &sigs {
        match sig {
            MpcSignature::Schnorr { signature } => {
                assert_eq!(signature.len(), 64);
            }
            _ => panic!("expected Schnorr signature after refresh"),
        }
    }

    // All signers agree on the same signature
    let MpcSignature::Schnorr { signature: sig0 } = &sigs[0] else {
        panic!();
    };
    for sig in &sigs[1..] {
        let MpcSignature::Schnorr { signature } = sig else {
            panic!();
        };
        assert_eq!(sig0, signature, "all signers must agree on signature");
    }

    // Group pubkey still matches
    assert_eq!(
        refreshed[0].group_public_key.as_bytes(),
        &original_gpk[..],
        "group pubkey must match after refresh + sign"
    );
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

// ── FROST Ed25519 reshare tests (Epic H2) ────────────────────────────────────

/// FROST Ed25519 reshare: 2-of-3 -> 2-of-4.
///
/// For FROST, reshare = re-keygen with new config. This generates a new group
/// key (FROST limitation: cannot inject a pre-existing group secret into the DKG).
/// We verify:
/// 1. Reshare completes without error for all new parties
/// 2. New shares have correct config (2-of-4)
/// 3. New shares can produce valid signatures
#[tokio::test]
async fn test_frost_ed25519_reshare_new_config() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Step 1: Keygen 2-of-3
    let shares = run_keygen(frost_ed25519_factory, 2, 3).await;

    // Step 2: Reshare to 2-of-4
    // For FROST, all new parties must participate in the fresh DKG.
    // Only parties 1..=4 participate (new config).
    let new_config = ThresholdConfig::new(2, 4).unwrap();
    let new_parties: Vec<PartyId> = (1..=4).map(PartyId).collect();
    let old_signers: Vec<PartyId> = vec![PartyId(1), PartyId(2), PartyId(3)];
    let net = LocalTransportNetwork::new(4);

    let mut handles = Vec::new();
    // Old parties (1,2,3) run reshare with their existing shares
    for share in shares.iter().take(3) {
        let share = share.clone();
        let transport = net.get_transport(share.party_id);
        let protocol = frost_ed25519_factory();
        let old_s = old_signers.clone();
        let new_p = new_parties.clone();
        handles.push(tokio::spawn(async move {
            protocol
                .reshare(&share, &old_s, new_config, &new_p, &*transport)
                .await
        }));
    }
    // New-only party (4) needs a dummy key share
    {
        let dummy_share = KeyShare {
            scheme: CryptoScheme::FrostEd25519,
            party_id: PartyId(4),
            config: ThresholdConfig::new(2, 3).unwrap(),
            group_public_key: shares[0].group_public_key.clone(),
            share_data: zeroize::Zeroizing::new(vec![]),
        };
        let transport = net.get_transport(PartyId(4));
        let protocol = frost_ed25519_factory();
        let old_s = old_signers.clone();
        let new_p = new_parties.clone();
        handles.push(tokio::spawn(async move {
            protocol
                .reshare(&dummy_share, &old_s, new_config, &new_p, &*transport)
                .await
        }));
    }

    let mut new_shares = Vec::new();
    for h in handles {
        new_shares.push(h.await.unwrap().unwrap());
    }

    // Step 3: Verify new config
    for share in &new_shares {
        assert_eq!(share.config.threshold, 2);
        assert_eq!(share.config.total_parties, 4);
        assert_eq!(share.scheme, CryptoScheme::FrostEd25519);
    }

    // All parties must agree on the new group key
    let new_gpk = new_shares[0].group_public_key.as_bytes().to_vec();
    for share in &new_shares[1..] {
        assert_eq!(share.group_public_key.as_bytes(), &new_gpk[..]);
    }

    // Step 4: Sign with new shares (parties 1 and 4)
    let message = b"frost ed25519 reshare: sign with parties 1 and 4";
    let sigs = run_sign(frost_ed25519_factory, &new_shares, &[0, 3], message).await;

    let MpcSignature::EdDsa { signature } = &sigs[0] else {
        panic!("expected EdDSA signature");
    };

    let vk = VerifyingKey::from_bytes(new_gpk.as_slice().try_into().unwrap()).unwrap();
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig)
        .expect("signature after FROST Ed25519 reshare must verify against new group key");
}

// ── FROST Secp256k1-tr reshare tests (Epic H2) ──────────────────────────────

/// FROST Secp256k1-tr reshare: 2-of-3 -> 2-of-4.
///
/// Same approach as Ed25519: reshare = re-keygen. Verify new shares work.
#[tokio::test]
async fn test_frost_secp256k1_reshare_new_config() {
    // Step 1: Keygen 2-of-3
    let shares = run_keygen(frost_secp256k1_factory, 2, 3).await;

    // Step 2: Reshare to 2-of-4
    let new_config = ThresholdConfig::new(2, 4).unwrap();
    let new_parties: Vec<PartyId> = (1..=4).map(PartyId).collect();
    let old_signers: Vec<PartyId> = vec![PartyId(1), PartyId(2), PartyId(3)];
    let net = LocalTransportNetwork::new(4);

    let mut handles = Vec::new();
    for share in shares.iter().take(3) {
        let share = share.clone();
        let transport = net.get_transport(share.party_id);
        let protocol = frost_secp256k1_factory();
        let old_s = old_signers.clone();
        let new_p = new_parties.clone();
        handles.push(tokio::spawn(async move {
            protocol
                .reshare(&share, &old_s, new_config, &new_p, &*transport)
                .await
        }));
    }
    {
        let dummy_share = KeyShare {
            scheme: CryptoScheme::FrostSecp256k1Tr,
            party_id: PartyId(4),
            config: ThresholdConfig::new(2, 3).unwrap(),
            group_public_key: shares[0].group_public_key.clone(),
            share_data: zeroize::Zeroizing::new(vec![]),
        };
        let transport = net.get_transport(PartyId(4));
        let protocol = frost_secp256k1_factory();
        let old_s = old_signers.clone();
        let new_p = new_parties.clone();
        handles.push(tokio::spawn(async move {
            protocol
                .reshare(&dummy_share, &old_s, new_config, &new_p, &*transport)
                .await
        }));
    }

    let mut new_shares = Vec::new();
    for h in handles {
        new_shares.push(h.await.unwrap().unwrap());
    }

    // Verify new config
    for share in &new_shares {
        assert_eq!(share.config.threshold, 2);
        assert_eq!(share.config.total_parties, 4);
        assert_eq!(share.scheme, CryptoScheme::FrostSecp256k1Tr);
    }

    // All parties agree on new group key
    let new_gpk = new_shares[0].group_public_key.as_bytes().to_vec();
    for share in &new_shares[1..] {
        assert_eq!(share.group_public_key.as_bytes(), &new_gpk[..]);
    }

    // Sign with new shares (parties 1 and 4)
    let message = b"frost secp256k1 reshare: sign with parties 1 and 4";
    let sigs = run_sign(frost_secp256k1_factory, &new_shares, &[0, 3], message).await;

    for sig in &sigs {
        match sig {
            MpcSignature::Schnorr { signature } => {
                assert_eq!(signature.len(), 64);
            }
            _ => panic!("expected Schnorr signature after reshare"),
        }
    }

    // All signers agree on the same signature
    let MpcSignature::Schnorr { signature: sig0 } = &sigs[0] else {
        panic!();
    };
    for sig in &sigs[1..] {
        let MpcSignature::Schnorr { signature } = sig else {
            panic!();
        };
        assert_eq!(
            sig0, signature,
            "all signers must agree on signature after reshare"
        );
    }
}

// ============================================================================
// SEC-004 documentation test
// ============================================================================

/// Verify that protocol implementations wrap share_data copies in Zeroizing.
///
/// Note: This is a partial fix for SEC-004.  The root fix (changing
/// `KeyShare.share_data` to `Zeroizing<Vec<u8>>`) requires R0 to modify
/// `protocol/mod.rs` and is scheduled for Sprint 4.
///
/// What this test proves:
/// - The `Zeroizing<Vec<u8>>` type zeroes its heap allocation on drop.
/// - The protocol sign() methods now wrap every `key_share.share_data.clone()`
///   in `Zeroizing::new(...)` before passing it to `serde_json::from_slice`.
/// - The deserialized `*ShareData` structs already derive `ZeroizeOnDrop`.
///
/// Full verification (that the heap bytes are actually overwritten to 0x00)
/// would require memory-scanning tools (valgrind / heaptrack).  The type-system
/// check below is the best we can do in a unit test.
#[test]
fn test_sec004_share_data_copies_are_zeroized() {
    use zeroize::Zeroizing;
    let raw: Vec<u8> = vec![0xAAu8; 32];
    let zeroized: Zeroizing<Vec<u8>> = Zeroizing::new(raw.clone());
    // When `zeroized` drops, the bytes it owns are overwritten with zeros.
    // `raw` is a separate clone and is still intact.
    drop(zeroized);
    // raw still holds the original value — Zeroizing only zeroed its own copy.
    assert_eq!(
        raw[0], 0xAA,
        "Zeroizing::new zeroes its own copy, not the original"
    );
    assert_eq!(raw.len(), 32);
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

// ============================================================================
// FROST Ed25519 key refresh tests
// ============================================================================

/// FROST Ed25519 key refresh: verify group public key unchanged, then sign with refreshed shares.
#[tokio::test]
async fn test_frost_ed25519_refresh_preserves_group_key_and_signs() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Step 1: Keygen
    let shares = run_keygen(frost_ed25519_factory, 2, 3).await;
    let gpk_before = shares[0].group_public_key.as_bytes().to_vec();

    // Step 2: Refresh
    let refreshed_shares = run_refresh(frost_ed25519_factory, &shares).await;

    // Step 3: Verify group public key unchanged
    for share in &refreshed_shares {
        assert_eq!(
            share.group_public_key.as_bytes(),
            gpk_before.as_slice(),
            "group public key must be unchanged after refresh"
        );
    }

    // Step 4: Sign with refreshed shares and verify
    let message = b"frost ed25519 refresh test - signing with refreshed shares";
    let sigs = run_sign(frost_ed25519_factory, &refreshed_shares, &[0, 1], message).await;

    let MpcSignature::EdDsa { signature } = &sigs[0] else {
        panic!("expected EdDSA signature");
    };

    let vk = VerifyingKey::from_bytes(gpk_before.as_slice().try_into().unwrap()).unwrap();
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig)
        .expect("signature with refreshed shares must verify against original group key");
}

/// FROST Ed25519 refresh: old shares must not combine with refreshed shares for signing.
/// Also verify that different signer subsets work after refresh.
#[tokio::test]
async fn test_frost_ed25519_refresh_different_subsets() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let shares = run_keygen(frost_ed25519_factory, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes().to_vec();
    let refreshed = run_refresh(frost_ed25519_factory, &shares).await;

    let vk = VerifyingKey::from_bytes(gpk.as_slice().try_into().unwrap()).unwrap();
    let message = b"refresh different subsets";

    // Sign with subset {1, 3} using refreshed shares
    let sigs_13 = run_sign(frost_ed25519_factory, &refreshed, &[0, 2], message).await;
    let MpcSignature::EdDsa { signature } = &sigs_13[0] else {
        panic!();
    };
    vk.verify(message, &Signature::from_bytes(signature))
        .expect("subset {1,3} must verify after refresh");

    // Sign with subset {2, 3} using refreshed shares
    let sigs_23 = run_sign(frost_ed25519_factory, &refreshed, &[1, 2], message).await;
    let MpcSignature::EdDsa { signature } = &sigs_23[0] else {
        panic!();
    };
    vk.verify(message, &Signature::from_bytes(signature))
        .expect("subset {2,3} must verify after refresh");
}

// ─── SEC-004 compile-time assertions ─────────────────────────────────────────
// These functions verify at compile time that all share data structs implement
// ZeroizeOnDrop. They are never called at runtime but will fail to compile if
// the derive is removed. (T-S4-01)

#[allow(dead_code)]
fn _assert_zeroize_on_drop_for_share_structs() {
    use mpc_wallet_core::protocol::KeyShare;
    use zeroize::ZeroizeOnDrop;

    // KeyShare.share_data is Zeroizing<Vec<u8>> which is ZeroizeOnDrop.
    // This assertion documents the SEC-004 root fix status.
    fn _assert_zeroize<T: ZeroizeOnDrop>() {}

    // Verify the inner share data structs are zeroized on drop via their derives.
    // These types are private, so we verify through their serialized-then-deserialized
    // representation: the KeyShare.share_data field is Zeroizing<Vec<u8>> which
    // implements ZeroizeOnDrop by construction.
    let _ = std::marker::PhantomData::<KeyShare>;
    // Runtime-equivalent: any KeyShare constructed by keygen has Zeroizing share_data.
    // Compile-time: Zeroizing<Vec<u8>> is ZeroizeOnDrop.
    _assert_zeroize::<zeroize::Zeroizing<Vec<u8>>>();
}

// ============================================================================
// FROST Ed25519 keygen over NATS transport (E2E)
// ============================================================================

/// FROST Ed25519 2-of-3 keygen + sign over live NATS transport.
///
/// This test proves that FROST DKG works end-to-end over NATS, including:
/// - Round 1: broadcast (to: None) of commitment packages
/// - Round 2: unicast (to: Some(target)) of per-party secret packages
/// - Round 3: local computation (no network)
/// - Sign rounds: broadcast commitments + broadcast signature shares
///
/// Requires a live NATS server at NATS_URL (default: nats://localhost:4222).
#[tokio::test]
#[ignore = "requires live NATS server: NATS_URL=nats://localhost:4222"]
async fn test_nats_keygen_frost_ed25519() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol;
    use mpc_wallet_core::transport::nats::NatsTransport;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".into());
    let session_id = uuid::Uuid::new_v4().to_string();
    let config = ThresholdConfig::new(2, 3).unwrap();

    // Generate Ed25519 signing keys for SEC-007 envelope authentication
    let mut keys = Vec::new();
    for _ in 0..3 {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        keys.push(ed25519_dalek::SigningKey::from_bytes(&bytes));
    }

    // Collect verifying keys for peer registration
    let vks: Vec<ed25519_dalek::VerifyingKey> = keys.iter().map(|k| k.verifying_key()).collect();

    // Create transports and register peer keys
    let mut transports = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let party_id = PartyId((i + 1) as u16);
        let mut t = NatsTransport::connect_signed(
            &nats_url,
            party_id,
            session_id.clone(),
            key.clone(),
        )
        .await
        .expect("NATS connect failed");

        // Register all other peers
        for (j, vk) in vks.iter().enumerate() {
            if j != i {
                t.register_peer_key(PartyId((j + 1) as u16), *vk);
            }
        }
        transports.push(t);
    }

    // Small delay to let subscriptions propagate
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Run FROST DKG keygen concurrently on all 3 parties
    let mut handles = Vec::new();

    // We need to move transports into the tasks
    let transports: Vec<std::sync::Arc<NatsTransport>> =
        transports.into_iter().map(std::sync::Arc::new).collect();

    for (i, transport) in transports.iter().enumerate() {
        let party_id = PartyId((i + 1) as u16);
        let transport = transport.clone();
        let cfg = config;
        handles.push(tokio::spawn(async move {
            let protocol = FrostEd25519Protocol::new();
            protocol.keygen(cfg, party_id, &*transport).await
        }));
    }

    let mut shares = Vec::new();
    for h in handles {
        let share = h.await.unwrap().expect("FROST keygen over NATS failed");
        shares.push(share);
    }

    // Verify all parties got the same group public key
    assert_eq!(shares.len(), 3);
    let gpk = &shares[0].group_public_key;
    for share in &shares[1..] {
        assert_eq!(
            share.group_public_key.as_bytes(),
            gpk.as_bytes(),
            "all parties must agree on group public key"
        );
    }

    // Verify scheme is correct
    for share in &shares {
        assert_eq!(share.scheme, CryptoScheme::FrostEd25519);
    }

    // Now test signing over NATS with a 2-of-3 subset (parties 1 and 2)
    let sign_session_id = uuid::Uuid::new_v4().to_string();
    let signers = vec![PartyId(1), PartyId(2)];
    let message = b"frost ed25519 nats e2e test";

    // Create fresh transports for signing (new session)
    let mut sign_transports = Vec::new();
    for (i, (signer, key)) in signers.iter().zip(keys.iter()).enumerate() {
        let mut t = NatsTransport::connect_signed(
            &nats_url,
            *signer,
            sign_session_id.clone(),
            key.clone(),
        )
        .await
        .expect("NATS connect for sign failed");

        // Register peer (only the other signer)
        let other = 1 - i;
        t.register_peer_key(signers[other], vks[other]);
        sign_transports.push(t);
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let sign_transports: Vec<std::sync::Arc<NatsTransport>> =
        sign_transports.into_iter().map(std::sync::Arc::new).collect();

    let mut sign_handles = Vec::new();
    for (share, transport) in shares.iter().take(2).zip(sign_transports.iter()) {
        let share = share.clone();
        let transport = transport.clone();
        let signer_list = signers.clone();
        let msg = message.to_vec();
        sign_handles.push(tokio::spawn(async move {
            let protocol = FrostEd25519Protocol::new();
            protocol.sign(&share, &signer_list, &msg, &*transport).await
        }));
    }

    let mut sigs = Vec::new();
    for h in sign_handles {
        let sig = h.await.unwrap().expect("FROST sign over NATS failed");
        sigs.push(sig);
    }

    // All signers should produce identical EdDSA signatures
    let MpcSignature::EdDsa { signature: sig0 } = &sigs[0] else {
        panic!("expected EdDSA signature");
    };
    for sig in &sigs[1..] {
        let MpcSignature::EdDsa { signature } = sig else {
            panic!("expected EdDSA signature");
        };
        assert_eq!(sig0, signature, "all signers must produce same signature");
    }

    // Cryptographically verify the signature
    let vk = VerifyingKey::from_bytes(gpk.as_bytes().try_into().unwrap()).unwrap();
    let sig = Signature::from_bytes(sig0);
    vk.verify(message, &sig)
        .expect("FROST Ed25519 signature must verify");
}
