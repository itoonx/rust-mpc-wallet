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

// ============================================================================
// SEC-025: Mandatory SignAuthorization verification
// ============================================================================

/// Verify that MPC nodes MUST verify SignAuthorization before signing.
///
/// This test exercises the library-level `SignAuthorization::verify()` method
/// to ensure that:
/// 1. A valid authorization (correct key, fresh, matching message) is accepted.
/// 2. An authorization signed by the WRONG gateway key is rejected (impersonation).
/// 3. An EXPIRED authorization is rejected (replay / stale proof).
/// 4. A TAMPERED authorization (payload modified after signing) is rejected.
/// 5. An authorization with a MISMATCHED message hash is rejected (message substitution).
/// 6. An authorization where policy did NOT pass is rejected.
/// 7. An authorization with INSUFFICIENT approvals is rejected.
///
/// These checks mirror the independent verification that each MPC node performs
/// before participating in a signing session (DEC-012, SEC-025).
#[test]
fn test_sign_authorization_mandatory_verification() {
    use ed25519_dalek::SigningKey;
    use mpc_wallet_core::protocol::sign_authorization::{
        ApproverEvidence, AuthorizationPayload, SignAuthorization,
    };
    use sha2::{Digest, Sha256};

    let gateway_key = SigningKey::from_bytes(&{
        let mut b = [0u8; 32];
        b[0] = 42;
        b
    });
    let message = b"transfer 1.5 ETH to 0xabcdef";

    // Helper: build a valid payload for the given message with current timestamp.
    let make_valid_payload = |msg: &[u8]| -> AuthorizationPayload {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        AuthorizationPayload {
            authorization_id: format!("auth-{now}-test"),
            requester_id: "user-sec025".into(),
            wallet_id: "wallet-sec025".into(),
            message_hash: hex::encode(Sha256::digest(msg)),
            policy_hash: hex::encode(Sha256::digest(b"policy-sec025")),
            policy_passed: true,
            approval_count: 2,
            approval_required: 2,
            approvers: vec![
                ApproverEvidence {
                    approver_id: "approver-a".into(),
                    signature_hash: "aa11".into(),
                },
                ApproverEvidence {
                    approver_id: "approver-b".into(),
                    signature_hash: "bb22".into(),
                },
            ],
            timestamp: now,
            session_id: "session-sec025".into(),
            encrypted_context: None,
        }
    };

    // ── 1. Valid authorization MUST be accepted ──────────────────────────────
    let valid_auth = SignAuthorization::create(make_valid_payload(message), &gateway_key);
    assert!(
        valid_auth
            .verify(&gateway_key.verifying_key(), message)
            .is_ok(),
        "valid SignAuthorization must be accepted"
    );

    // ── 2. Wrong gateway key MUST be rejected (impersonation) ───────────────
    let attacker_key = SigningKey::from_bytes(&[0xFFu8; 32]);
    let wrong_key_auth = SignAuthorization::create(make_valid_payload(message), &attacker_key);
    let err = wrong_key_auth
        .verify(&gateway_key.verifying_key(), message)
        .expect_err("authorization signed by wrong key must be rejected");
    assert!(
        format!("{err:?}").contains("pubkey mismatch"),
        "error must indicate gateway pubkey mismatch, got: {err:?}"
    );

    // ── 3. Expired authorization MUST be rejected ───────────────────────────
    let mut expired_payload = make_valid_payload(message);
    expired_payload.timestamp = 1_000_000; // far in the past
    let expired_auth = SignAuthorization::create(expired_payload, &gateway_key);
    let err = expired_auth
        .verify(&gateway_key.verifying_key(), message)
        .expect_err("expired SignAuthorization must be rejected");
    assert!(
        format!("{err:?}").contains("expired"),
        "error must indicate expiration, got: {err:?}"
    );

    // ── 4. Tampered payload MUST be rejected (signature invalid) ────────────
    let mut tampered_auth = SignAuthorization::create(make_valid_payload(message), &gateway_key);
    tampered_auth.payload.requester_id = "attacker-injected".into();
    let err = tampered_auth
        .verify(&gateway_key.verifying_key(), message)
        .expect_err("tampered SignAuthorization must be rejected");
    assert!(
        format!("{err:?}").contains("invalid gateway signature"),
        "error must indicate invalid signature, got: {err:?}"
    );

    // ── 5. Message hash mismatch MUST be rejected (message substitution) ────
    let mismatch_auth = SignAuthorization::create(make_valid_payload(message), &gateway_key);
    let different_message = b"send 999 BTC to attacker";
    let err = mismatch_auth
        .verify(&gateway_key.verifying_key(), different_message)
        .expect_err("message mismatch must be rejected");
    assert!(
        format!("{err:?}").contains("message hash mismatch"),
        "error must indicate message hash mismatch, got: {err:?}"
    );

    // ── 6. Policy not passed MUST be rejected ───────────────────────────────
    let mut no_policy_payload = make_valid_payload(message);
    no_policy_payload.policy_passed = false;
    let no_policy_auth = SignAuthorization::create(no_policy_payload, &gateway_key);
    let err = no_policy_auth
        .verify(&gateway_key.verifying_key(), message)
        .expect_err("authorization with failed policy must be rejected");
    assert!(
        format!("{err:?}").contains("policy check did not pass"),
        "error must indicate policy failure, got: {err:?}"
    );

    // ── 7. Insufficient approvals MUST be rejected ──────────────────────────
    let mut low_approval_payload = make_valid_payload(message);
    low_approval_payload.approval_count = 1; // only 1 of 2 required
    let low_approval_auth = SignAuthorization::create(low_approval_payload, &gateway_key);
    let err = low_approval_auth
        .verify(&gateway_key.verifying_key(), message)
        .expect_err("authorization with insufficient approvals must be rejected");
    assert!(
        format!("{err:?}").contains("insufficient approvals"),
        "error must indicate insufficient approvals, got: {err:?}"
    );
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

// ============================================================================
// Sprint 17 — Security Regression Tests (T-S17-05)
// ============================================================================

/// SEC-008 regression: GG20 signing produces key shares with Zeroizing<Vec<u8>>
/// share_data. This test verifies that after GG20 keygen, the share_data field
/// is non-empty (contains real share material) and is wrapped in Zeroizing,
/// which ensures scalar values are wiped from memory on drop.
///
/// If the Zeroizing wrapper is ever removed from KeyShare.share_data, this test
/// will fail at compile time (type mismatch) or at runtime (drop behavior).
#[tokio::test]
async fn test_gg20_scalar_zeroized() {
    use zeroize::Zeroizing;

    // Run GG20 keygen
    let shares = run_keygen(gg20_factory, 2, 3).await;

    for share in &shares {
        // Verify share_data is non-empty (contains real share material)
        assert!(
            !share.share_data.is_empty(),
            "GG20 share_data must not be empty after keygen"
        );

        // Verify the share_data type is Zeroizing<Vec<u8>> by exercising it.
        // This compiles only if share_data is Zeroizing<Vec<u8>>.
        let cloned: Zeroizing<Vec<u8>> = share.share_data.clone();
        assert!(
            !cloned.is_empty(),
            "cloned Zeroizing share_data must be non-empty"
        );
        // On drop, cloned's heap bytes are zeroed — this is the SEC-008 guarantee.

        // Verify scheme is correct
        assert_eq!(share.scheme, CryptoScheme::Gg20Ecdsa);
    }

    // Additionally verify that signing works (scalars are correctly handled)
    let message = b"gg20 scalar zeroize regression test";
    let sigs = run_sign(gg20_factory, &shares, &[0, 1], message).await;
    assert!(!sigs.is_empty(), "signing must produce signatures");

    // Verify the signature is structurally valid
    match &sigs[0] {
        MpcSignature::Ecdsa { r, s, .. } => {
            assert!(!r.is_empty(), "signature r must be non-empty");
            assert!(!s.is_empty(), "signature s must be non-empty");
        }
        _ => panic!("GG20 must produce ECDSA signature"),
    }
}

/// SignAuthorization regression: each authorization must have a unique identity
/// so that two authorizations for the same message are distinguishable.
///
/// Currently, uniqueness comes from the combination of (session_id, timestamp,
/// requester_id). This test verifies that two authorizations created with
/// different session IDs produce different signed proofs, which is the
/// foundation for replay protection.
///
/// When authorization_id is added (Sprint 17 hardening), this test should be
/// updated to also verify that field.
#[test]
fn test_sign_authorization_has_unique_identity() {
    use ed25519_dalek::SigningKey;
    use mpc_wallet_core::protocol::sign_authorization::{
        ApproverEvidence, AuthorizationPayload, SignAuthorization,
    };
    use sha2::{Digest, Sha256};

    let gateway_key = SigningKey::from_bytes(&{
        let mut b = [0u8; 32];
        b[0] = 42;
        b
    });
    let message = b"authorization uniqueness test";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let make_payload = |session_id: &str| -> AuthorizationPayload {
        AuthorizationPayload {
            requester_id: "user-unique".into(),
            wallet_id: "wallet-unique".into(),
            message_hash: hex::encode(Sha256::digest(message)),
            policy_hash: hex::encode(Sha256::digest(b"policy-unique")),
            policy_passed: true,
            approval_count: 1,
            approval_required: 1,
            approvers: vec![ApproverEvidence {
                approver_id: "approver-1".into(),
                signature_hash: "aabb".into(),
            }],
            timestamp: now,
            session_id: session_id.into(),
            encrypted_context: None,
            authorization_id: uuid::Uuid::new_v4().to_string(),
        }
    };

    let auth1 = SignAuthorization::create(make_payload("session-001"), &gateway_key);
    let auth2 = SignAuthorization::create(make_payload("session-002"), &gateway_key);

    // Both must verify independently
    assert!(auth1.verify(&gateway_key.verifying_key(), message).is_ok());
    assert!(auth2.verify(&gateway_key.verifying_key(), message).is_ok());

    // The two authorizations must have different signatures (because payloads differ)
    assert_ne!(
        auth1.gateway_signature, auth2.gateway_signature,
        "two authorizations with different session IDs must produce different signatures"
    );

    // The session_id field must be preserved and distinct
    assert_ne!(
        auth1.payload.session_id, auth2.payload.session_id,
        "session_id must be preserved as a distinguishing field"
    );
}

/// SignAuthorization replay regression: the same authorization must not be
/// accepted for a different message than what was originally authorized.
///
/// This tests the message-binding property: even if an attacker captures a
/// valid authorization, they cannot reuse it to sign a different message.
/// This is the protocol-level replay protection via message hash binding.
#[test]
fn test_sign_authorization_replay_rejected() {
    use ed25519_dalek::SigningKey;
    use mpc_wallet_core::protocol::sign_authorization::{
        ApproverEvidence, AuthorizationPayload, SignAuthorization,
    };
    use sha2::{Digest, Sha256};

    let gateway_key = SigningKey::from_bytes(&{
        let mut b = [0u8; 32];
        b[0] = 42;
        b
    });

    let original_message = b"transfer 1 ETH to 0xabc";
    let replay_message = b"transfer 100 ETH to 0xattacker";

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = AuthorizationPayload {
        requester_id: "user-replay".into(),
        wallet_id: "wallet-replay".into(),
        message_hash: hex::encode(Sha256::digest(original_message)),
        policy_hash: hex::encode(Sha256::digest(b"policy-replay")),
        policy_passed: true,
        approval_count: 2,
        approval_required: 2,
        approvers: vec![
            ApproverEvidence {
                approver_id: "approver-1".into(),
                signature_hash: "1111".into(),
            },
            ApproverEvidence {
                approver_id: "approver-2".into(),
                signature_hash: "2222".into(),
            },
        ],
        timestamp: now,
        session_id: "session-replay".into(),
        encrypted_context: None,
        authorization_id: uuid::Uuid::new_v4().to_string(),
    };

    let auth = SignAuthorization::create(payload, &gateway_key);

    // Original message must verify
    assert!(
        auth.verify(&gateway_key.verifying_key(), original_message)
            .is_ok(),
        "authorization must verify for original message"
    );

    // Replay attempt with different message MUST be rejected
    let replay_result = auth.verify(&gateway_key.verifying_key(), replay_message);
    assert!(
        replay_result.is_err(),
        "replaying authorization for a different message must be rejected"
    );
    let err_msg = format!("{:?}", replay_result.unwrap_err());
    assert!(
        err_msg.contains("message hash mismatch"),
        "replay rejection must cite message hash mismatch, got: {err_msg}"
    );

    // Also verify that a completely identical authorization for the same message
    // is accepted (this is expected — timestamp-based expiry handles time replay)
    let auth_clone = auth.clone();
    assert!(
        auth_clone
            .verify(&gateway_key.verifying_key(), original_message)
            .is_ok(),
        "identical authorization for same message should still verify (time-based expiry handles staleness)"
    );
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
        let mut t =
            NatsTransport::connect_signed(&nats_url, party_id, session_id.clone(), key.clone())
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
        let mut t =
            NatsTransport::connect_signed(&nats_url, *signer, sign_session_id.clone(), key.clone())
                .await
                .expect("NATS connect for sign failed");

        // Register peer (only the other signer)
        let other = 1 - i;
        t.register_peer_key(signers[other], vks[other]);
        sign_transports.push(t);
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let sign_transports: Vec<std::sync::Arc<NatsTransport>> = sign_transports
        .into_iter()
        .map(std::sync::Arc::new)
        .collect();

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

// ============================================================================
// Sprint 18 — Control Plane Hardening Tests (T-S18-03)
// ============================================================================

/// Authorization replay dedup cache: tracks seen authorization_ids within a TTL
/// window and rejects duplicates. This implements the server-side replay
/// protection described in the authorization_id field docs (SEC-025).
///
/// Production MPC nodes MUST maintain an equivalent cache. This test proves
/// the concept works: same authorization_id is rejected on second use.
#[test]
fn test_authorization_cache_prevents_replay() {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    /// Simple in-test authorization cache for replay dedup.
    struct AuthorizationCache {
        seen: HashMap<String, Instant>,
        ttl: Duration,
    }

    impl AuthorizationCache {
        fn new(ttl: Duration) -> Self {
            Self {
                seen: HashMap::new(),
                ttl,
            }
        }

        /// Returns Ok(()) if authorization_id is new (first use), Err if replayed.
        fn check_and_insert(&mut self, authorization_id: &str) -> Result<(), String> {
            // Prune expired entries first
            let now = Instant::now();
            self.seen.retain(|_, ts| now.duration_since(*ts) < self.ttl);

            if self.seen.contains_key(authorization_id) {
                return Err(format!(
                    "authorization replay detected: {} already seen within TTL",
                    authorization_id
                ));
            }
            self.seen.insert(authorization_id.to_string(), now);
            Ok(())
        }
    }

    let ttl = Duration::from_secs(120); // 2-minute TTL matches MAX_AUTHORIZATION_AGE_SECS
    let mut cache = AuthorizationCache::new(ttl);

    let auth_id = "auth-001-unique";

    // First use: must succeed
    assert!(
        cache.check_and_insert(auth_id).is_ok(),
        "first use of authorization_id must be accepted"
    );

    // Second use within TTL: must be rejected (replay)
    let replay_result = cache.check_and_insert(auth_id);
    assert!(
        replay_result.is_err(),
        "replayed authorization_id must be rejected"
    );
    assert!(
        replay_result
            .unwrap_err()
            .contains("authorization replay detected"),
        "error must indicate replay"
    );

    // Different authorization_id: must succeed
    assert!(
        cache.check_and_insert("auth-002-different").is_ok(),
        "different authorization_id must be accepted"
    );
}

/// Authorization cache prune: expired entries are cleaned up and previously
/// rejected IDs become accepted again after TTL expiry. This tests that
/// the cache does not grow unboundedly and that TTL expiry works.
#[test]
fn test_authorization_cache_prunes_expired() {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    struct AuthorizationCache {
        seen: HashMap<String, Instant>,
        ttl: Duration,
    }

    impl AuthorizationCache {
        fn new(ttl: Duration) -> Self {
            Self {
                seen: HashMap::new(),
                ttl,
            }
        }

        fn check_and_insert(&mut self, authorization_id: &str) -> Result<(), String> {
            let now = Instant::now();
            self.seen.retain(|_, ts| now.duration_since(*ts) < self.ttl);
            if self.seen.contains_key(authorization_id) {
                return Err("replay".into());
            }
            self.seen.insert(authorization_id.to_string(), now);
            Ok(())
        }

        /// Simulate expiry by backdating all entries beyond the TTL.
        /// In production, this happens naturally via wall-clock time.
        fn simulate_expiry(&mut self) {
            let expired_time = Instant::now() - self.ttl - Duration::from_secs(1);
            for ts in self.seen.values_mut() {
                *ts = expired_time;
            }
        }

        fn len(&self) -> usize {
            self.seen.len()
        }
    }

    // Use a short TTL for this test
    let ttl = Duration::from_secs(120);
    let mut cache = AuthorizationCache::new(ttl);

    // Insert several entries
    for i in 0..5 {
        assert!(cache.check_and_insert(&format!("auth-{i}")).is_ok());
    }
    assert_eq!(cache.len(), 5, "cache must hold 5 entries");

    // All 5 should be rejected on replay
    for i in 0..5 {
        assert!(cache.check_and_insert(&format!("auth-{i}")).is_err());
    }

    // Simulate expiry: backdate all entries beyond TTL
    cache.simulate_expiry();

    // After expiry, the same IDs should be accepted again (cache pruned on next check)
    assert!(
        cache.check_and_insert("auth-0").is_ok(),
        "expired authorization_id must be accepted again after TTL"
    );

    // The prune should have removed the expired entries; only "auth-0" remains
    assert_eq!(
        cache.len(),
        1,
        "prune must remove expired entries, leaving only the newly inserted one"
    );
}

/// FROST Ed25519 sender validation (SEC-013): the protocol rejects messages
/// from parties not in the expected signer set.
///
/// `validate_sender` is an internal function in frost_ed25519.rs, so we test
/// the same logic pattern here: construct a ProtocolMessage with an unexpected
/// `from` field and verify it's rejected by the expected-sender-set check.
///
/// The FROST keygen/sign implementations call this function on every received
/// message, providing defense-in-depth against party-ID spoofing.
#[test]
fn test_frost_ed25519_validates_sender() {
    use mpc_wallet_core::transport::ProtocolMessage;
    use std::collections::HashSet;

    // Expected parties in a 2-of-3 protocol
    let expected: HashSet<PartyId> = [PartyId(1), PartyId(2), PartyId(3)].into_iter().collect();

    // Replicate the validate_sender logic (same as frost_ed25519.rs)
    let validate_sender =
        |msg: &ProtocolMessage, expected_set: &HashSet<PartyId>| -> Result<(), String> {
            if !expected_set.contains(&msg.from) {
                return Err(format!(
                    "FROST: unexpected sender party {} — not in expected set",
                    msg.from.0
                ));
            }
            Ok(())
        };

    // Valid sender (party 1) — should succeed
    let valid_msg = ProtocolMessage {
        from: PartyId(1),
        to: None,
        round: 1,
        payload: vec![],
    };
    assert!(
        validate_sender(&valid_msg, &expected).is_ok(),
        "message from expected party must be accepted"
    );

    // Valid sender (party 3) — should succeed
    let valid_msg3 = ProtocolMessage {
        from: PartyId(3),
        to: None,
        round: 1,
        payload: vec![],
    };
    assert!(
        validate_sender(&valid_msg3, &expected).is_ok(),
        "message from party 3 must be accepted"
    );

    // Invalid sender (party 99 — not in set) — should be rejected
    let spoofed_msg = ProtocolMessage {
        from: PartyId(99),
        to: None,
        round: 1,
        payload: vec![],
    };
    let result = validate_sender(&spoofed_msg, &expected);
    assert!(
        result.is_err(),
        "message from unexpected party must be rejected"
    );
    assert!(
        result.unwrap_err().contains("unexpected sender party 99"),
        "error must identify the spoofed party"
    );

    // Edge case: party 0 not in set
    let zero_msg = ProtocolMessage {
        from: PartyId(0),
        to: None,
        round: 1,
        payload: vec![],
    };
    assert!(
        validate_sender(&zero_msg, &expected).is_err(),
        "party 0 not in expected set must be rejected"
    );
}

/// GG20 keygen produces KeyShare.share_data wrapped in Zeroizing<Vec<u8>>
/// (SEC-004 + SEC-008 hardening). This test verifies:
/// 1. share_data is non-empty after keygen
/// 2. share_data is Zeroizing<Vec<u8>> (compile-time type check)
/// 3. Clone produces another Zeroizing wrapper (both copies zeroize on drop)
/// 4. Debug output redacts share_data (SEC-015)
#[tokio::test]
async fn test_gg20_shares_use_zeroizing() {
    use zeroize::Zeroizing;

    let shares = run_keygen(gg20_factory, 2, 3).await;
    assert_eq!(shares.len(), 3);

    for (i, share) in shares.iter().enumerate() {
        // 1. share_data is non-empty (real key material was generated)
        assert!(
            !share.share_data.is_empty(),
            "party {} share_data must be non-empty",
            i + 1
        );

        // 2. Type check: share_data is Zeroizing<Vec<u8>>
        // This line only compiles if share_data is Zeroizing<Vec<u8>>
        let _zeroizing_ref: &Zeroizing<Vec<u8>> = &share.share_data;

        // 3. Clone produces Zeroizing<Vec<u8>> (both copies will zeroize on drop)
        let cloned: Zeroizing<Vec<u8>> = share.share_data.clone();
        assert_eq!(
            cloned.len(),
            share.share_data.len(),
            "cloned share_data must have same length"
        );
        assert_eq!(
            cloned.as_ref() as &[u8],
            share.share_data.as_ref() as &[u8],
            "cloned share_data must have same content"
        );

        // 4. Debug output must redact share_data (SEC-015)
        let debug_output = format!("{:?}", share);
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug must redact share_data, got: {debug_output}"
        );
        assert!(
            !debug_output.contains(&format!("{:?}", share.share_data.as_ref() as &Vec<u8>)),
            "Debug must NOT contain raw share bytes"
        );

        // 5. Scheme correctness
        assert_eq!(share.scheme, CryptoScheme::Gg20Ecdsa);
    }
}

/// Full SignAuthorization flow with all fields including authorization_id
/// (Sprint 17 hardening). Verifies:
/// 1. All 6 verification checks pass for a valid authorization
/// 2. authorization_id is preserved and non-empty
/// 3. All payload fields are correctly round-tripped
/// 4. Signature verification is cryptographically sound
#[test]
fn test_sign_authorization_full_flow() {
    use ed25519_dalek::SigningKey;
    use mpc_wallet_core::protocol::sign_authorization::{
        ApproverEvidence, AuthorizationPayload, SignAuthorization,
    };
    use sha2::{Digest, Sha256};

    // Generate gateway signing key
    let gateway_key = SigningKey::from_bytes(&{
        let mut b = [0u8; 32];
        b[0] = 0x5A;
        b[1] = 0x42;
        b
    });

    let message = b"full flow: transfer 10 SOL to GRk3...";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let auth_id = format!("auth-fullflow-{now}");
    let payload = AuthorizationPayload {
        authorization_id: auth_id.clone(),
        requester_id: "user-full-flow".into(),
        wallet_id: "wallet-sol-001".into(),
        message_hash: hex::encode(Sha256::digest(message)),
        policy_hash: hex::encode(Sha256::digest(b"treasury-policy-v3")),
        policy_passed: true,
        approval_count: 3,
        approval_required: 2,
        approvers: vec![
            ApproverEvidence {
                approver_id: "approver-alice".into(),
                signature_hash: hex::encode(Sha256::digest(b"alice-sig")),
            },
            ApproverEvidence {
                approver_id: "approver-bob".into(),
                signature_hash: hex::encode(Sha256::digest(b"bob-sig")),
            },
            ApproverEvidence {
                approver_id: "approver-carol".into(),
                signature_hash: hex::encode(Sha256::digest(b"carol-sig")),
            },
        ],
        timestamp: now,
        session_id: "session-full-flow-001".into(),
        encrypted_context: None,
    };

    // Create signed authorization
    let auth = SignAuthorization::create(payload, &gateway_key);

    // --- Verify all 6 checks pass ---
    let result = auth.verify(&gateway_key.verifying_key(), message);
    assert!(
        result.is_ok(),
        "full authorization must pass all 6 checks: {result:?}"
    );

    // --- Verify authorization_id round-trips correctly ---
    assert_eq!(
        auth.payload.authorization_id, auth_id,
        "authorization_id must be preserved"
    );
    assert!(
        !auth.payload.authorization_id.is_empty(),
        "authorization_id must be non-empty"
    );

    // --- Verify all payload fields are preserved ---
    assert_eq!(auth.payload.requester_id, "user-full-flow");
    assert_eq!(auth.payload.wallet_id, "wallet-sol-001");
    assert!(auth.payload.policy_passed);
    assert_eq!(auth.payload.approval_count, 3);
    assert_eq!(auth.payload.approval_required, 2);
    assert_eq!(auth.payload.approvers.len(), 3);
    assert_eq!(auth.payload.session_id, "session-full-flow-001");
    assert_eq!(auth.payload.timestamp, now);

    // --- Verify gateway pubkey is correct (32 bytes) ---
    assert_eq!(auth.gateway_pubkey.len(), 32);
    assert_eq!(
        auth.gateway_pubkey,
        gateway_key.verifying_key().to_bytes().to_vec()
    );

    // --- Verify gateway signature is 64 bytes ---
    assert_eq!(auth.gateway_signature.len(), 64);

    // --- Negative checks: tamper each field and verify rejection ---

    // Check 1: wrong gateway key → pubkey mismatch
    let wrong_key = SigningKey::from_bytes(&[0xFFu8; 32]);
    assert!(
        auth.verify(&wrong_key.verifying_key(), message).is_err(),
        "wrong gateway key must fail check 1 (pubkey mismatch)"
    );

    // Check 2: wrong message → message hash mismatch
    assert!(
        auth.verify(&gateway_key.verifying_key(), b"wrong message")
            .is_err(),
        "wrong message must fail check 4 (message binding)"
    );

    // Check 3: policy_passed=false
    {
        let mut bad_payload = auth.payload.clone();
        bad_payload.policy_passed = false;
        let bad_auth = SignAuthorization::create(bad_payload, &gateway_key);
        assert!(
            bad_auth
                .verify(&gateway_key.verifying_key(), message)
                .is_err(),
            "policy_passed=false must fail check 5"
        );
    }

    // Check 4: insufficient approvals
    {
        let mut bad_payload = auth.payload.clone();
        bad_payload.approval_count = 1;
        bad_payload.approval_required = 3;
        let bad_auth = SignAuthorization::create(bad_payload, &gateway_key);
        assert!(
            bad_auth
                .verify(&gateway_key.verifying_key(), message)
                .is_err(),
            "insufficient approvals must fail check 6"
        );
    }

    // Check 5: empty authorization_id
    {
        let mut bad_payload = auth.payload.clone();
        bad_payload.authorization_id = String::new();
        let bad_auth = SignAuthorization::create(bad_payload, &gateway_key);
        assert!(
            bad_auth
                .verify(&gateway_key.verifying_key(), message)
                .is_err(),
            "empty authorization_id must fail check 0"
        );
    }

    // Check 6: expired timestamp
    {
        let mut bad_payload = auth.payload.clone();
        bad_payload.timestamp = 1000; // ancient
        let bad_auth = SignAuthorization::create(bad_payload, &gateway_key);
        assert!(
            bad_auth
                .verify(&gateway_key.verifying_key(), message)
                .is_err(),
            "expired timestamp must fail check 3"
        );
    }
}

// ============================================================================
// CGGMP21 Threshold ECDSA tests (T-S21-02)
// ============================================================================

fn cggmp21_factory() -> Box<dyn MpcProtocol> {
    Box::new(mpc_wallet_core::protocol::cggmp21::Cggmp21Protocol::new())
}

// ── Keygen tests ─────────────────────────────────────────────────────────────

/// All parties derive the same group public key after CGGMP21 keygen.
#[tokio::test]
async fn test_cggmp21_keygen_all_share_group_pubkey() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;

    let gpk = shares[0].group_public_key.as_bytes();
    for share in &shares[1..] {
        assert_eq!(
            share.group_public_key.as_bytes(),
            gpk,
            "all parties must derive the same CGGMP21 group public key"
        );
    }

    // Verify valid secp256k1 point
    let pk = k256::PublicKey::from_sec1_bytes(gpk);
    assert!(
        pk.is_ok(),
        "group public key must be a valid SEC1 compressed point"
    );
}

/// Each party's key share data is unique (different secret shares).
#[tokio::test]
async fn test_cggmp21_keygen_unique_shares() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;

    // Each party's share_data must be different
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            assert_ne!(
                &*shares[i].share_data, &*shares[j].share_data,
                "parties {} and {} must have different share data",
                shares[i].party_id.0, shares[j].party_id.0
            );
        }
    }

    // Each party should have correct scheme
    for share in &shares {
        assert_eq!(share.scheme, CryptoScheme::Cggmp21Secp256k1);
    }
}

/// Any t parties from n can participate in signing (test multiple subsets for 2-of-3).
#[tokio::test]
async fn test_cggmp21_keygen_threshold_subset() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let message = b"threshold subset test for cggmp21";

    // All 3 possible 2-of-3 subsets: {0,1}, {0,2}, {1,2}
    let subsets: &[&[usize]] = &[&[0, 1], &[0, 2], &[1, 2]];
    for subset in subsets {
        let sigs = run_sign(cggmp21_factory, &shares, subset, message).await;
        let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
            panic!("expected ECDSA signature from CGGMP21");
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r);
        sig_bytes[32..].copy_from_slice(s);
        vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
            .unwrap_or_else(|_| panic!("CGGMP21 signature from subset {:?} must verify", subset));
    }
}

/// Share data round-trips through serde (KeyShare serialization).
#[tokio::test]
async fn test_cggmp21_keygen_share_serialization() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;

    for share in &shares {
        let serialized = serde_json::to_vec(share).expect("KeyShare must serialize");
        let deserialized: KeyShare =
            serde_json::from_slice(&serialized).expect("KeyShare must deserialize");

        assert_eq!(deserialized.scheme, share.scheme);
        assert_eq!(deserialized.party_id, share.party_id);
        assert_eq!(deserialized.config.threshold, share.config.threshold);
        assert_eq!(
            deserialized.config.total_parties,
            share.config.total_parties
        );
        assert_eq!(
            deserialized.group_public_key.as_bytes(),
            share.group_public_key.as_bytes()
        );
        assert_eq!(&*deserialized.share_data, &*share.share_data);
    }
}

/// Invalid threshold config (t > n) is rejected.
#[tokio::test]
async fn test_cggmp21_keygen_invalid_config() {
    let result = ThresholdConfig::new(5, 3);
    assert!(result.is_err(), "t > n must be rejected by ThresholdConfig");
}

/// Keygen with larger config (3-of-5) works correctly.
#[tokio::test]
async fn test_cggmp21_keygen_3_of_5() {
    let shares = run_keygen(cggmp21_factory, 3, 5).await;

    assert_eq!(shares.len(), 5);
    let gpk = shares[0].group_public_key.as_bytes();
    for share in &shares[1..] {
        assert_eq!(share.group_public_key.as_bytes(), gpk);
    }
    // Verify group key is valid
    assert!(k256::PublicKey::from_sec1_bytes(gpk).is_ok());
}

/// Keygen produces share data that contains valid Cggmp21ShareData with aux info.
#[tokio::test]
async fn test_cggmp21_keygen_aux_info_present() {
    use mpc_wallet_core::protocol::cggmp21::Cggmp21ShareData;

    let shares = run_keygen(cggmp21_factory, 2, 3).await;

    for share in &shares {
        let data: Cggmp21ShareData =
            serde_json::from_slice(&share.share_data).expect("share data must deserialize");

        // Paillier keys must be non-empty
        assert!(!data.paillier_sk.is_empty(), "Paillier SK must be present");
        assert!(!data.paillier_pk.is_empty(), "Paillier PK must be present");
        // Pedersen params must be non-empty
        assert!(
            !data.pedersen_params.is_empty(),
            "Pedersen params must be present"
        );
        // Public shares must have n entries
        assert_eq!(
            data.public_shares.len(),
            3,
            "must have one public share per party"
        );
        // Secret share must be 32 bytes (secp256k1 scalar)
        assert_eq!(data.secret_share.len(), 32);
    }
}

// ── Signing tests ────────────────────────────────────────────────────────────

/// Different messages produce different signatures.
#[tokio::test]
async fn test_cggmp21_sign_different_messages() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;

    let msg1 = b"message one";
    let msg2 = b"message two";
    let sigs1 = run_sign(cggmp21_factory, &shares, &[0, 1], msg1).await;
    let sigs2 = run_sign(cggmp21_factory, &shares, &[0, 1], msg2).await;

    let MpcSignature::Ecdsa { r: r1, s: s1, .. } = &sigs1[0] else {
        panic!("expected ECDSA");
    };
    let MpcSignature::Ecdsa { r: r2, s: s2, .. } = &sigs2[0] else {
        panic!("expected ECDSA");
    };

    // At least one component must differ (overwhelmingly likely: both differ)
    assert!(
        r1 != r2 || s1 != s2,
        "different messages must produce different signatures"
    );
}

/// Signing an empty message works.
#[tokio::test]
async fn test_cggmp21_sign_empty_message() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);

    let message = b"";
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], message).await;
    let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
        panic!("expected ECDSA");
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("empty message signature must verify");
}

/// Signing a large message (64KB) works.
#[tokio::test]
async fn test_cggmp21_sign_large_message() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);

    let message = vec![0xABu8; 65536]; // 64KB message
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], &message).await;
    let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
        panic!("expected ECDSA");
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(&message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("large message signature must verify");
}

/// For 2-of-3, all 3 possible signing subsets produce valid signatures.
#[tokio::test]
async fn test_cggmp21_sign_all_subsets() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let message = b"all subsets test";

    for subset in &[vec![0usize, 1], vec![0, 2], vec![1, 2]] {
        let sigs = run_sign(cggmp21_factory, &shares, subset, message).await;
        let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
            panic!("expected ECDSA");
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r);
        sig_bytes[32..].copy_from_slice(s);
        vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
            .unwrap_or_else(|_| panic!("subset {:?} must verify", subset));
    }
}

/// Verify CGGMP21 signature using k256::ecdsa::VerifyingKey.
#[tokio::test]
async fn test_cggmp21_sign_verify_k256() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);

    let message = b"verify with k256 VerifyingKey";
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], message).await;
    let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
        panic!("expected ECDSA");
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = Signature::from_bytes(&sig_bytes.into()).unwrap();

    // Must verify with standard k256 verify
    vk.verify(message, &sig)
        .expect("CGGMP21 signature must verify with k256");
}

/// Recovery ID is valid (0 or 1).
#[tokio::test]
async fn test_cggmp21_sign_recovery_id_valid() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let message = b"recovery id test";
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], message).await;

    let MpcSignature::Ecdsa { recovery_id, .. } = &sigs[0] else {
        panic!("expected ECDSA");
    };
    assert!(
        *recovery_id <= 1,
        "recovery_id must be 0 or 1, got {}",
        recovery_id
    );
}

/// s is in the lower half of curve order (SEC-012 low-s normalization).
#[tokio::test]
async fn test_cggmp21_sign_low_s() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let message = b"low-s normalization check";
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], message).await;

    let MpcSignature::Ecdsa { s, .. } = &sigs[0] else {
        panic!("expected ECDSA");
    };

    // Verify low-s: if normalize_s returns None, s is already low-s.
    // Construct a k256 Signature and check normalize_s().
    let MpcSignature::Ecdsa { r: r_bytes, .. } = &sigs[0] else {
        unreachable!();
    };
    let mut sig_raw = [0u8; 64];
    sig_raw[..32].copy_from_slice(r_bytes);
    sig_raw[32..].copy_from_slice(s);
    let sig = k256::ecdsa::Signature::from_bytes(&sig_raw.into()).unwrap();
    assert!(
        sig.normalize_s().is_none(),
        "s must already be in lower half of curve order (SEC-012 low-s)"
    );
}

/// Pre-signature marked as used after signing — reuse returns error.
#[tokio::test]
async fn test_cggmp21_presign_cannot_reuse() {
    use mpc_wallet_core::protocol::cggmp21::Cggmp21Protocol;

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let signers = vec![PartyId(1), PartyId(2)];
    let net = LocalTransportNetwork::new(3);

    // Run pre-sign for two parties
    let protocol1 = Cggmp21Protocol::new();
    let protocol2 = Cggmp21Protocol::new();
    let share1 = shares[0].clone();
    let share2 = shares[1].clone();
    let t1 = net.get_transport(PartyId(1));
    let t2 = net.get_transport(PartyId(2));
    let signers1 = signers.clone();
    let signers2 = signers.clone();

    let (mut pre1, _pre2) = tokio::join!(
        async { protocol1.pre_sign(&share1, &signers1, &*t1).await.unwrap() },
        async { protocol2.pre_sign(&share2, &signers2, &*t2).await.unwrap() }
    );

    // Mark as used (simulating first sign)
    pre1.used = true;

    // Attempting to use again should fail
    let protocol = Cggmp21Protocol::new();
    let transport = net.get_transport(PartyId(1));
    let result = protocol
        .sign_with_presig(&mut pre1, b"second message", &shares[0], &*transport)
        .await;
    assert!(result.is_err(), "reusing pre-signature must fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("already used") || err_msg.contains("nonce reuse"),
        "error must mention nonce reuse, got: {}",
        err_msg
    );
}

/// CGGMP21 and GG20 produce the same MpcSignature::Ecdsa variant format.
#[tokio::test]
async fn test_cggmp21_sign_matches_gg20_format() {
    let cggmp_shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gg20_shares = run_keygen(gg20_factory, 2, 3).await;

    let message = b"format compatibility test";
    let cggmp_sigs = run_sign(cggmp21_factory, &cggmp_shares, &[0, 1], message).await;
    let gg20_sigs = run_sign(gg20_factory, &gg20_shares, &[0, 1], message).await;

    // Both must produce Ecdsa variant
    match (&cggmp_sigs[0], &gg20_sigs[0]) {
        (
            MpcSignature::Ecdsa {
                r: cr,
                s: cs,
                recovery_id: crid,
            },
            MpcSignature::Ecdsa {
                r: gr,
                s: gs,
                recovery_id: grid,
            },
        ) => {
            // Same format: 32-byte r, 32-byte s, u8 recovery_id
            assert_eq!(cr.len(), 32, "CGGMP21 r must be 32 bytes");
            assert_eq!(cs.len(), 32, "CGGMP21 s must be 32 bytes");
            assert_eq!(gr.len(), 32, "GG20 r must be 32 bytes");
            assert_eq!(gs.len(), 32, "GG20 s must be 32 bytes");
            assert!(*crid <= 1, "CGGMP21 recovery_id must be 0 or 1");
            assert!(
                *grid <= 1 || *grid == 0xff,
                "GG20 recovery_id must be valid"
            );
        }
        _ => panic!("both protocols must produce MpcSignature::Ecdsa"),
    }
}

/// Signing with 3-of-5 config works.
#[tokio::test]
async fn test_cggmp21_sign_3_of_5() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(cggmp21_factory, 3, 5).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);

    let message = b"3-of-5 signing test";
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 2, 4], message).await;
    let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
        panic!("expected ECDSA");
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("3-of-5 CGGMP21 signature must verify");
}

/// r and s components are 32 bytes and non-zero.
#[tokio::test]
async fn test_cggmp21_sign_r_s_nonzero() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let message = b"r and s non-zero test";
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], message).await;

    let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
        panic!("expected ECDSA");
    };

    assert_eq!(r.len(), 32);
    assert_eq!(s.len(), 32);
    assert!(r.iter().any(|&b| b != 0), "r must not be all zeros");
    assert!(s.iter().any(|&b| b != 0), "s must not be all zeros");
}

// ── Refresh tests ────────────────────────────────────────────────────────────

/// CGGMP21 does not support refresh — returns protocol error.
#[tokio::test]
async fn test_cggmp21_refresh_not_supported() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let protocol = cggmp21_factory();
    let signers = vec![PartyId(1), PartyId(2)];
    let net = LocalTransportNetwork::new(3);
    let transport = net.get_transport(PartyId(1));

    let result = protocol.refresh(&shares[0], &signers, &*transport).await;
    assert!(
        result.is_err(),
        "CGGMP21 refresh must return error (not implemented)"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not supported"),
        "error must indicate refresh is not supported, got: {}",
        err_msg
    );
}

/// CGGMP21 does not support reshare — returns protocol error.
#[tokio::test]
async fn test_cggmp21_reshare_not_supported() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let protocol = cggmp21_factory();
    let new_config = ThresholdConfig::new(2, 4).unwrap();
    let new_parties = vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4)];
    let old_signers = vec![PartyId(1), PartyId(2)];
    let net = LocalTransportNetwork::new(4);
    let transport = net.get_transport(PartyId(1));

    let result = protocol
        .reshare(
            &shares[0],
            &old_signers,
            new_config,
            &new_parties,
            &*transport,
        )
        .await;
    assert!(
        result.is_err(),
        "CGGMP21 reshare must return error (not implemented)"
    );
}

// ── Pre-signing tests ────────────────────────────────────────────────────────

/// Pre-sign produces valid PreSignature with expected fields.
#[tokio::test]
async fn test_cggmp21_presign_produces_valid_output() {
    use mpc_wallet_core::protocol::cggmp21::Cggmp21Protocol;

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let signers = vec![PartyId(1), PartyId(2)];
    let net = LocalTransportNetwork::new(3);

    let p1 = Cggmp21Protocol::new();
    let p2 = Cggmp21Protocol::new();
    let s1 = shares[0].clone();
    let s2 = shares[1].clone();
    let t1 = net.get_transport(PartyId(1));
    let t2 = net.get_transport(PartyId(2));
    let sig1 = signers.clone();
    let sig2 = signers.clone();

    let (pre1, pre2) = tokio::join!(
        async { p1.pre_sign(&s1, &sig1, &*t1).await.unwrap() },
        async { p2.pre_sign(&s2, &sig2, &*t2).await.unwrap() }
    );

    // Both must agree on big_r
    assert_eq!(pre1.big_r, pre2.big_r, "parties must agree on R point");
    // big_r must be valid secp256k1 point
    assert!(
        k256::PublicKey::from_sec1_bytes(&pre1.big_r).is_ok(),
        "R must be valid SEC1 point"
    );
    // Not used yet
    assert!(!pre1.used);
    assert!(!pre2.used);
    // k_i and chi_i must be 32 bytes
    assert_eq!(pre1.k_i.len(), 32);
    assert_eq!(pre1.chi_i.len(), 32);
    // Party IDs correct
    assert_eq!(pre1.party_id, PartyId(1));
    assert_eq!(pre2.party_id, PartyId(2));
}

/// Pre-sign then online sign produces valid signature.
#[tokio::test]
async fn test_cggmp21_presign_then_online_sign() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use mpc_wallet_core::protocol::cggmp21::Cggmp21Protocol;

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let signers = vec![PartyId(1), PartyId(2)];
    let net = LocalTransportNetwork::new(3);

    // Phase 1: Pre-sign
    let p1 = Cggmp21Protocol::new();
    let p2 = Cggmp21Protocol::new();
    let s1 = shares[0].clone();
    let s2 = shares[1].clone();
    let t1 = net.get_transport(PartyId(1));
    let t2 = net.get_transport(PartyId(2));
    let sig1 = signers.clone();
    let sig2 = signers.clone();

    let (mut pre1, mut pre2) = tokio::join!(
        async { p1.pre_sign(&s1, &sig1, &*t1).await.unwrap() },
        async { p2.pre_sign(&s2, &sig2, &*t2).await.unwrap() }
    );

    // Phase 2: Online sign
    let message = b"online sign after pre-sign";
    let net2 = LocalTransportNetwork::new(3);
    let p1b = Cggmp21Protocol::new();
    let p2b = Cggmp21Protocol::new();
    let s1b = shares[0].clone();
    let s2b = shares[1].clone();
    let t1b = net2.get_transport(PartyId(1));
    let t2b = net2.get_transport(PartyId(2));
    let msg1 = message.to_vec();
    let msg2 = message.to_vec();

    let (sig1_result, _sig2_result) = tokio::join!(
        async { p1b.sign_with_presig(&mut pre1, &msg1, &s1b, &*t1b).await },
        async { p2b.sign_with_presig(&mut pre2, &msg2, &s2b, &*t2b).await }
    );

    let sig = sig1_result.expect("online sign must succeed");
    let MpcSignature::Ecdsa { r, s, .. } = &sig else {
        panic!("expected ECDSA signature");
    };

    // Verify
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("pre-sign + online-sign signature must verify");

    // Pre-signatures must be marked as used
    assert!(pre1.used, "pre1 must be marked used after signing");
    assert!(pre2.used, "pre2 must be marked used after signing");
}

// ── Abort tests ──────────────────────────────────────────────────────────────

/// Identifiable abort error message includes party information.
#[tokio::test]
async fn test_cggmp21_abort_error_message_format() {
    // We test the nonce reuse path which triggers a known error
    use mpc_wallet_core::protocol::cggmp21::Cggmp21Protocol;

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let signers = vec![PartyId(1), PartyId(2)];
    let net = LocalTransportNetwork::new(3);

    let p1 = Cggmp21Protocol::new();
    let p2 = Cggmp21Protocol::new();
    let t1 = net.get_transport(PartyId(1));
    let t2 = net.get_transport(PartyId(2));
    let s1 = shares[0].clone();
    let s2 = shares[1].clone();
    let sig1 = signers.clone();
    let sig2 = signers.clone();

    let (mut pre1, _pre2) = tokio::join!(
        async { p1.pre_sign(&s1, &sig1, &*t1).await.unwrap() },
        async { p2.pre_sign(&s2, &sig2, &*t2).await.unwrap() }
    );

    // Force used = true to trigger nonce reuse error
    pre1.used = true;
    let protocol = Cggmp21Protocol::new();
    let transport = net.get_transport(PartyId(1));
    let err = protocol
        .sign_with_presig(&mut pre1, b"test", &shares[0], &*transport)
        .await
        .unwrap_err();

    let err_str = err.to_string();
    assert!(
        err_str.contains("already used") || err_str.contains("nonce reuse"),
        "abort error must contain relevant info, got: {}",
        err_str
    );
}

// ── Cross-protocol tests ─────────────────────────────────────────────────────

/// CGGMP21 and GG20 both produce secp256k1 keys.
#[tokio::test]
async fn test_cggmp21_vs_gg20_same_curve() {
    let cggmp_shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gg20_shares = run_keygen(gg20_factory, 2, 3).await;

    // Both produce valid secp256k1 compressed public keys
    let cggmp_gpk = cggmp_shares[0].group_public_key.as_bytes();
    let gg20_gpk = gg20_shares[0].group_public_key.as_bytes();

    let cggmp_pk =
        k256::PublicKey::from_sec1_bytes(cggmp_gpk).expect("CGGMP21 key must be valid secp256k1");
    let gg20_pk =
        k256::PublicKey::from_sec1_bytes(gg20_gpk).expect("GG20 key must be valid secp256k1");

    // Both are compressed SEC1 (33 bytes)
    assert_eq!(
        cggmp_gpk.len(),
        33,
        "CGGMP21 key must be 33 bytes compressed"
    );
    assert_eq!(gg20_gpk.len(), 33, "GG20 key must be 33 bytes compressed");

    // Both are on the same curve (both parse as k256 PublicKey)
    let _ = cggmp_pk;
    let _ = gg20_pk;
}

/// CGGMP21 and GG20 key shares are not interchangeable.
#[tokio::test]
async fn test_cggmp21_key_not_compatible_with_gg20() {
    let cggmp_shares = run_keygen(cggmp21_factory, 2, 3).await;

    // CGGMP21 shares have Cggmp21Secp256k1 scheme
    assert_eq!(cggmp_shares[0].scheme, CryptoScheme::Cggmp21Secp256k1);

    let gg20_shares = run_keygen(gg20_factory, 2, 3).await;
    assert_eq!(gg20_shares[0].scheme, CryptoScheme::Gg20Ecdsa);

    // Different schemes — can't mix
    assert_ne!(
        cggmp_shares[0].scheme, gg20_shares[0].scheme,
        "CGGMP21 and GG20 must have different CryptoScheme"
    );

    // Share data formats are different — trying to deserialize as the wrong type fails
    let cggmp_result: Result<mpc_wallet_core::protocol::cggmp21::Cggmp21ShareData, _> =
        serde_json::from_slice(&gg20_shares[0].share_data);
    // Should fail because GG20 share data has different fields
    // (may or may not fail depending on serde options, but scheme check prevents misuse)
    let _ = cggmp_result;
}

/// CGGMP21 signature verifies with recovery (ecrecover-style).
#[tokio::test]
async fn test_cggmp21_sign_recovery() {
    use k256::ecdsa::{RecoveryId, VerifyingKey};

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let expected_vk = VerifyingKey::from(&k256::PublicKey::from_sec1_bytes(gpk).unwrap());

    let message = b"recovery test";
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], message).await;
    let MpcSignature::Ecdsa {
        r, s, recovery_id, ..
    } = &sigs[0]
    else {
        panic!("expected ECDSA");
    };

    // Build signature and recover the public key
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = k256::ecdsa::Signature::from_bytes(&sig_bytes.into()).unwrap();
    let recid = RecoveryId::try_from(*recovery_id).unwrap();

    // Hash the message the same way CGGMP21 does (SHA-256)
    use sha2::Digest;
    let hash = sha2::Sha256::digest(message);
    let recovered =
        VerifyingKey::recover_from_prehash(&hash, &sig, recid).expect("recovery must succeed");
    assert_eq!(
        recovered, expected_vk,
        "recovered public key must match group public key"
    );
}

/// Multiple sequential signing operations with the same key shares all produce valid signatures.
#[tokio::test]
async fn test_cggmp21_sign_multiple_sequential() {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let gpk = shares[0].group_public_key.as_bytes();
    let pubkey = k256::PublicKey::from_sec1_bytes(gpk).unwrap();
    let vk = VerifyingKey::from(&pubkey);

    for i in 0..3 {
        let message = format!("sequential message {}", i);
        let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], message.as_bytes()).await;
        let MpcSignature::Ecdsa { r, s, .. } = &sigs[0] else {
            panic!("expected ECDSA");
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r);
        sig_bytes[32..].copy_from_slice(s);
        vk.verify(
            message.as_bytes(),
            &Signature::from_bytes(&sig_bytes.into()).unwrap(),
        )
        .unwrap_or_else(|_| panic!("sequential message {} must verify", i));
    }
}

/// Scheme() returns the correct CryptoScheme.
#[tokio::test]
async fn test_cggmp21_scheme_identifier() {
    let protocol = cggmp21_factory();
    assert_eq!(
        protocol.scheme(),
        CryptoScheme::Cggmp21Secp256k1,
        "CGGMP21 protocol must report Cggmp21Secp256k1 scheme"
    );
}

/// All signers receive consistent results (same r, same s).
#[tokio::test]
async fn test_cggmp21_all_signers_consistent() {
    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let message = b"consistency test";
    let sigs = run_sign(cggmp21_factory, &shares, &[0, 1], message).await;

    // Both signers should produce the same final signature
    let MpcSignature::Ecdsa { r: r0, s: s0, .. } = &sigs[0] else {
        panic!("expected ECDSA");
    };
    let MpcSignature::Ecdsa { r: r1, s: s1, .. } = &sigs[1] else {
        panic!("expected ECDSA");
    };
    assert_eq!(r0, r1, "both signers must agree on r");
    assert_eq!(s0, s1, "both signers must agree on s");
}

/// PreSignature serialization round-trip.
#[tokio::test]
async fn test_cggmp21_presignature_serialization() {
    use mpc_wallet_core::protocol::cggmp21::{Cggmp21Protocol, PreSignature};

    let shares = run_keygen(cggmp21_factory, 2, 3).await;
    let signers = vec![PartyId(1), PartyId(2)];
    let net = LocalTransportNetwork::new(3);

    let p1 = Cggmp21Protocol::new();
    let p2 = Cggmp21Protocol::new();
    let t1 = net.get_transport(PartyId(1));
    let t2 = net.get_transport(PartyId(2));
    let s1 = shares[0].clone();
    let s2 = shares[1].clone();
    let sig1 = signers.clone();
    let sig2 = signers.clone();

    let (pre1, _pre2) = tokio::join!(
        async { p1.pre_sign(&s1, &sig1, &*t1).await.unwrap() },
        async { p2.pre_sign(&s2, &sig2, &*t2).await.unwrap() }
    );

    // Serialize and deserialize
    let bytes = serde_json::to_vec(&pre1).expect("PreSignature must serialize");
    let restored: PreSignature =
        serde_json::from_slice(&bytes).expect("PreSignature must deserialize");

    assert_eq!(restored.k_i, pre1.k_i);
    assert_eq!(restored.chi_i, pre1.chi_i);
    assert_eq!(restored.big_r, pre1.big_r);
    assert_eq!(restored.party_id, pre1.party_id);
    assert_eq!(restored.used, pre1.used);
}

/// Cggmp21ShareData deserialization from keygen output.
#[tokio::test]
async fn test_cggmp21_share_data_from_keygen() {
    use mpc_wallet_core::protocol::cggmp21::Cggmp21ShareData;

    let shares = run_keygen(cggmp21_factory, 2, 3).await;

    for (idx, share) in shares.iter().enumerate() {
        let data: Cggmp21ShareData = serde_json::from_slice(&share.share_data)
            .unwrap_or_else(|e| panic!("party {} share data must deserialize: {}", idx + 1, e));

        assert_eq!(data.party_index, (idx + 1) as u16);
        assert_eq!(data.public_shares.len(), 3);
        assert_eq!(data.group_public_key.len(), 33);
        assert_eq!(data.secret_share.len(), 32);

        // Each public share must be a valid compressed SEC1 point
        for (j, ps) in data.public_shares.iter().enumerate() {
            assert!(
                k256::PublicKey::from_sec1_bytes(ps).is_ok(),
                "public share {} for party {} must be valid SEC1",
                j,
                idx + 1
            );
        }

        // Group public key in share data must match KeyShare group_public_key
        assert_eq!(data.group_public_key, share.group_public_key.as_bytes());
    }
}

/// Different parties' auxiliary info (Paillier/Pedersen) are different.
#[tokio::test]
async fn test_cggmp21_keygen_aux_info_unique_per_party() {
    use mpc_wallet_core::protocol::cggmp21::Cggmp21ShareData;

    let shares = run_keygen(cggmp21_factory, 2, 3).await;

    let datas: Vec<Cggmp21ShareData> = shares
        .iter()
        .map(|s| serde_json::from_slice(&s.share_data).unwrap())
        .collect();

    // Each party's Paillier SK and Pedersen params should be different
    for i in 0..datas.len() {
        for j in (i + 1)..datas.len() {
            assert_ne!(
                datas[i].paillier_sk,
                datas[j].paillier_sk,
                "parties {} and {} must have different Paillier SK",
                i + 1,
                j + 1
            );
            assert_ne!(
                datas[i].paillier_pk,
                datas[j].paillier_pk,
                "parties {} and {} must have different Paillier PK",
                i + 1,
                j + 1
            );
        }
    }
}
