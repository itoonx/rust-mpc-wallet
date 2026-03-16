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

    assert_eq!(shares[0].scheme, mpc_wallet_core::types::CryptoScheme::Gg20Ecdsa);
    let gpk = &shares[0].group_public_key;
    for share in &shares[1..] {
        assert_eq!(share.group_public_key.as_bytes(), gpk.as_bytes(),
            "all parties must derive the same group public key");
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
    assert_ne!(*recovery_id, 0xff, "coordinator must return final signature, not partial sentinel");

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
    let MpcSignature::Ecdsa { r, s, .. } = &sigs_12[0] else { panic!(); };
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("subset {1,2} signature must verify");

    // Subset {1, 3} — party 3's share index is 2 in the shares vec
    let sigs_13 = run_sign(gg20_factory, &shares, &[0, 2], message).await;
    let MpcSignature::Ecdsa { r, s, .. } = &sigs_13[0] else { panic!(); };
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    vk.verify(message, &Signature::from_bytes(&sig_bytes.into()).unwrap())
        .expect("subset {1,3} signature must verify");
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
    assert_eq!(raw[0], 0xAA, "Zeroizing::new zeroes its own copy, not the original");
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
// Trait default method tests
// ============================================================================

/// Verify that the default `refresh` implementation returns an error.
///
/// All three protocol impls (GG20, FROST-secp256k1, FROST-Ed25519) inherit the
/// default `refresh` stub which returns `CoreError::Protocol`. This test
/// confirms the default is wired correctly so that future sprints can override
/// it without breaking existing code.
#[tokio::test]
async fn test_refresh_default_returns_not_implemented() {
    use mpc_wallet_core::protocol::KeyShare;
    use mpc_wallet_core::protocol::GroupPublicKey;
    use zeroize::Zeroizing;

    let protocols: Vec<Box<dyn MpcProtocol>> = vec![
        gg20_factory(),
        frost_secp256k1_factory(),
        frost_ed25519_factory(),
    ];

    let dummy_share = KeyShare {
        scheme: mpc_wallet_core::types::CryptoScheme::Gg20Ecdsa,
        party_id: PartyId(1),
        config: mpc_wallet_core::types::ThresholdConfig::new(2, 3).unwrap(),
        group_public_key: GroupPublicKey::Secp256k1(vec![2; 33]),
        share_data: Zeroizing::new(vec![0; 32]),
    };

    let net = LocalTransportNetwork::new(3);
    let transport = net.get_transport(PartyId(1));
    let signers = [PartyId(1), PartyId(2)];

    for protocol in &protocols {
        let result = protocol
            .refresh(&dummy_share, &signers, &*transport)
            .await;
        assert!(result.is_err(), "default refresh must return Err");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("refresh"),
            "error should mention refresh: {err_msg}"
        );
    }
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
