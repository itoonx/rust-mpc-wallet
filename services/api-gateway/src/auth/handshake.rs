//! Server-side handshake implementation.
//!
//! **Key exchange alone is NOT authentication.**
//! Identity is bound to the handshake via Ed25519 signatures over the
//! transcript hash of all handshake messages.

use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use super::types::*;

/// Server-side handshake state machine.
pub struct ServerHandshake {
    server_signing_key: Arc<SigningKey>,
    ephemeral_secret: Option<StaticSecret>,
    server_nonce: Option<[u8; 32]>,
    /// Decoded client ephemeral pubkey bytes (stored to avoid re-decoding).
    client_ephemeral_bytes: Option<[u8; 32]>,
    /// Decoded client nonce bytes (stored to avoid re-decoding).
    client_nonce_bytes: Option<Vec<u8>>,
    /// Partial transcript hash (ClientHello + ServerHello_no_sig).
    partial_transcript: Option<[u8; 32]>,
    /// The ServerHello we sent (needed for full transcript).
    server_hello: Option<ServerHello>,
    state: HandshakeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Init,
    HelloSent,
    Authenticated,
    Failed,
}

impl ServerHandshake {
    /// Create a new server handshake. Accepts `Arc<SigningKey>` to avoid cloning key material.
    pub fn new_arc(server_signing_key: Arc<SigningKey>) -> Self {
        Self {
            server_signing_key,
            ephemeral_secret: None,
            server_nonce: None,
            client_ephemeral_bytes: None,
            client_nonce_bytes: None,
            partial_transcript: None,
            server_hello: None,
            state: HandshakeState::Init,
        }
    }

    /// Create a new server handshake (takes ownership for backward compat).
    pub fn new(server_signing_key: SigningKey) -> Self {
        Self::new_arc(Arc::new(server_signing_key))
    }

    pub fn process_client_hello(
        &mut self,
        client_hello: &ClientHello,
    ) -> Result<ServerHello, HandshakeError> {
        if self.state != HandshakeState::Init {
            return Err(HandshakeError::InvalidState);
        }

        if client_hello.protocol_version != PROTOCOL_VERSION {
            return Err(HandshakeError::UnsupportedVersion);
        }

        let now = unix_now();
        if now.abs_diff(client_hello.timestamp) > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(HandshakeError::TimestampDrift);
        }

        if !client_hello
            .supported_kex
            .contains(&KeyExchangeAlgorithm::X25519)
            || !client_hello
                .supported_sig
                .contains(&SignatureAlgorithm::Ed25519)
        {
            return Err(HandshakeError::NoCommonAlgorithm);
        }

        // Decode and validate client ephemeral pubkey.
        let client_eph = hex::decode(&client_hello.client_ephemeral_pubkey)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        if client_eph.len() != 32 {
            return Err(HandshakeError::MalformedMessage);
        }

        // Decode and validate client nonce.
        let client_nonce = hex::decode(&client_hello.client_nonce)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        if client_nonce.len() != 32 {
            return Err(HandshakeError::MalformedMessage);
        }

        // Generate server ephemeral X25519 key pair.
        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        let server_nonce = random_nonce();
        let server_challenge = random_nonce();

        let server_key_id = hex::encode(&self.server_signing_key.verifying_key().to_bytes()[..8]);

        let mut server_hello = ServerHello {
            protocol_version: PROTOCOL_VERSION.to_string(),
            selected_kex: KeyExchangeAlgorithm::X25519,
            selected_sig: SignatureAlgorithm::Ed25519,
            selected_aead: AeadAlgorithm::ChaCha20Poly1305,
            server_ephemeral_pubkey: hex::encode(ephemeral_public.as_bytes()),
            server_nonce: hex::encode(server_nonce),
            server_challenge: hex::encode(server_challenge),
            timestamp: now,
            server_key_id,
            server_signature: String::new(),
        };

        // Compute partial transcript hash and sign it.
        let partial_hash = compute_partial_transcript_hash(client_hello, &server_hello);
        let signature = self.server_signing_key.sign(&partial_hash);
        server_hello.server_signature = hex::encode(signature.to_bytes());

        // Store state (including decoded bytes to avoid re-decoding in process_client_auth).
        let mut client_eph_arr = [0u8; 32];
        client_eph_arr.copy_from_slice(&client_eph);
        self.client_ephemeral_bytes = Some(client_eph_arr);
        self.client_nonce_bytes = Some(client_nonce);
        self.ephemeral_secret = Some(ephemeral_secret);
        self.server_nonce = Some(server_nonce);
        self.partial_transcript = Some(partial_hash);
        self.server_hello = Some(server_hello.clone());
        self.state = HandshakeState::HelloSent;

        Ok(server_hello)
    }

    pub fn process_client_auth(
        &mut self,
        client_auth: &ClientAuth,
        client_hello: &ClientHello,
    ) -> Result<AuthenticatedSession, HandshakeError> {
        if self.state != HandshakeState::HelloSent {
            return Err(HandshakeError::InvalidState);
        }

        // Parse client's static Ed25519 public key.
        let client_pubkey_bytes = hex::decode(&client_auth.client_static_pubkey)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        if client_pubkey_bytes.len() != 32 {
            return Err(HandshakeError::MalformedMessage);
        }
        let client_pubkey_array: [u8; 32] = client_pubkey_bytes
            .try_into()
            .map_err(|_| HandshakeError::MalformedMessage)?;
        let client_verifying_key = VerifyingKey::from_bytes(&client_pubkey_array)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // Verify key_id matches pubkey.
        if client_hello.client_key_id != hex::encode(&client_pubkey_array[..8]) {
            return Err(HandshakeError::KeyIdMismatch);
        }

        // Compute full transcript hash using shared utility.
        let server_hello = self
            .server_hello
            .as_ref()
            .ok_or(HandshakeError::InvalidState)?;
        let transcript_hash = compute_transcript_hash(
            client_hello,
            server_hello,
            &client_auth.client_static_pubkey,
        );

        // Verify client's signature.
        let client_sig_bytes = hex::decode(&client_auth.client_signature)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        if client_sig_bytes.len() != 64 {
            return Err(HandshakeError::InvalidSignature);
        }
        let client_sig_array: [u8; 64] = client_sig_bytes
            .try_into()
            .map_err(|_| HandshakeError::InvalidSignature)?;
        let client_signature = Signature::from_bytes(&client_sig_array);
        client_verifying_key
            .verify(&transcript_hash, &client_signature)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // Derive session keys using stored decoded bytes (no re-decoding).
        let ephemeral_secret = self
            .ephemeral_secret
            .take()
            .ok_or(HandshakeError::InvalidState)?;
        let client_eph_arr = self
            .client_ephemeral_bytes
            .ok_or(HandshakeError::InvalidState)?;
        let client_nonce = self
            .client_nonce_bytes
            .take()
            .ok_or(HandshakeError::InvalidState)?;
        let server_nonce = self.server_nonce.ok_or(HandshakeError::InvalidState)?;

        let client_ephemeral_pubkey = X25519Public::from(client_eph_arr);
        let shared_secret = ephemeral_secret.diffie_hellman(&client_ephemeral_pubkey);

        let (client_write_key, server_write_key) =
            derive_session_keys(shared_secret.as_bytes(), &client_nonce, &server_nonce)
                .map_err(|_| HandshakeError::KeyDerivationFailed)?;

        let now = unix_now();
        let session_id = hex::encode(&Sha256::digest(transcript_hash)[..16]);

        self.state = HandshakeState::Authenticated;

        Ok(AuthenticatedSession {
            session_id,
            client_pubkey: client_pubkey_array,
            client_key_id: client_hello.client_key_id.clone(),
            client_write_key,
            server_write_key,
            expires_at: now + DEFAULT_SESSION_TTL_SECS,
            created_at: now,
        })
    }

    pub fn state(&self) -> HandshakeState {
        self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    UnsupportedVersion,
    TimestampDrift,
    NoCommonAlgorithm,
    MalformedMessage,
    InvalidSignature,
    KeyIdMismatch,
    KeyDerivationFailed,
    InvalidState,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion => write!(f, "unsupported protocol version"),
            Self::TimestampDrift => write!(f, "timestamp drift too large"),
            Self::NoCommonAlgorithm => write!(f, "no common algorithm"),
            Self::MalformedMessage => write!(f, "malformed message"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::KeyIdMismatch => write!(f, "key ID mismatch"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
            Self::InvalidState => write!(f, "invalid handshake state"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret as X25519Secret;

    fn make_client_hello(
        client_signing_key: &ed25519_dalek::SigningKey,
        client_ephemeral_pubkey: &X25519Public,
    ) -> ClientHello {
        let nonce = random_nonce();
        let client_key_id = hex::encode(&client_signing_key.verifying_key().to_bytes()[..8]);
        ClientHello {
            protocol_version: PROTOCOL_VERSION.to_string(),
            supported_kex: vec![KeyExchangeAlgorithm::X25519],
            supported_sig: vec![SignatureAlgorithm::Ed25519],
            client_ephemeral_pubkey: hex::encode(client_ephemeral_pubkey.as_bytes()),
            client_nonce: hex::encode(nonce),
            timestamp: unix_now(),
            client_key_id,
        }
    }

    fn make_client_auth(
        client_signing_key: &ed25519_dalek::SigningKey,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
    ) -> ClientAuth {
        let client_pubkey_hex = hex::encode(client_signing_key.verifying_key().to_bytes());
        let transcript_hash =
            compute_transcript_hash(client_hello, server_hello, &client_pubkey_hex);
        let signature = client_signing_key.sign(&transcript_hash);
        ClientAuth {
            client_signature: hex::encode(signature.to_bytes()),
            client_static_pubkey: client_pubkey_hex,
        }
    }

    #[test]
    fn test_full_handshake_success() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let client_eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let client_eph_pub = X25519Public::from(&client_eph);

        let client_hello = make_client_hello(&client_key, &client_eph_pub);
        let mut hs = ServerHandshake::new(server_key);
        assert_eq!(hs.state(), HandshakeState::Init);

        let server_hello = hs.process_client_hello(&client_hello).unwrap();
        assert_eq!(hs.state(), HandshakeState::HelloSent);

        let client_auth = make_client_auth(&client_key, &client_hello, &server_hello);
        let session = hs.process_client_auth(&client_auth, &client_hello).unwrap();
        assert_eq!(hs.state(), HandshakeState::Authenticated);

        assert!(!session.session_id.is_empty());
        assert!(session.expires_at > session.created_at);
        assert_ne!(session.client_write_key, session.server_write_key);
        assert_eq!(session.client_pubkey, client_key.verifying_key().to_bytes());
    }

    #[test]
    fn test_wrong_protocol_version_rejected() {
        let mut hello = make_client_hello(
            &gen_ed25519_key(),
            &X25519Public::from(&X25519Secret::random_from_rng(rand::rngs::OsRng)),
        );
        hello.protocol_version = "wrong-v999".into();
        let mut hs = ServerHandshake::new(gen_ed25519_key());
        assert_eq!(
            hs.process_client_hello(&hello).unwrap_err(),
            HandshakeError::UnsupportedVersion
        );
    }

    #[test]
    fn test_stale_timestamp_rejected() {
        let mut hello = make_client_hello(
            &gen_ed25519_key(),
            &X25519Public::from(&X25519Secret::random_from_rng(rand::rngs::OsRng)),
        );
        hello.timestamp = 1000;
        let mut hs = ServerHandshake::new(gen_ed25519_key());
        assert_eq!(
            hs.process_client_hello(&hello).unwrap_err(),
            HandshakeError::TimestampDrift
        );
    }

    #[test]
    fn test_wrong_client_signature_rejected() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let wrong_key = gen_ed25519_key();
        let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let hello = make_client_hello(&client_key, &X25519Public::from(&eph));

        let mut hs = ServerHandshake::new(server_key);
        let sh = hs.process_client_hello(&hello).unwrap();

        let mut bad_auth = make_client_auth(&wrong_key, &hello, &sh);
        bad_auth.client_static_pubkey = hex::encode(client_key.verifying_key().to_bytes());
        assert_eq!(
            hs.process_client_auth(&bad_auth, &hello).unwrap_err(),
            HandshakeError::InvalidSignature
        );
    }

    #[test]
    fn test_key_id_mismatch_rejected() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let other_key = gen_ed25519_key();
        let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let mut hello = make_client_hello(&client_key, &X25519Public::from(&eph));
        hello.client_key_id = hex::encode(&other_key.verifying_key().to_bytes()[..8]);

        let mut hs = ServerHandshake::new(server_key);
        let sh = hs.process_client_hello(&hello).unwrap();
        let auth = make_client_auth(&client_key, &hello, &sh);
        assert_eq!(
            hs.process_client_auth(&auth, &hello).unwrap_err(),
            HandshakeError::KeyIdMismatch
        );
    }

    #[test]
    fn test_double_hello_rejected() {
        let hello = make_client_hello(
            &gen_ed25519_key(),
            &X25519Public::from(&X25519Secret::random_from_rng(rand::rngs::OsRng)),
        );
        let mut hs = ServerHandshake::new(gen_ed25519_key());
        hs.process_client_hello(&hello).unwrap();
        assert_eq!(
            hs.process_client_hello(&hello).unwrap_err(),
            HandshakeError::InvalidState
        );
    }

    #[test]
    fn test_forward_secrecy_different_sessions_different_keys() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();

        let e1 = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let h1 = make_client_hello(&client_key, &X25519Public::from(&e1));
        let mut hs1 = ServerHandshake::new(server_key.clone());
        let sh1 = hs1.process_client_hello(&h1).unwrap();
        let a1 = make_client_auth(&client_key, &h1, &sh1);
        let s1 = hs1.process_client_auth(&a1, &h1).unwrap();

        let e2 = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let h2 = make_client_hello(&client_key, &X25519Public::from(&e2));
        let mut hs2 = ServerHandshake::new(server_key);
        let sh2 = hs2.process_client_hello(&h2).unwrap();
        let a2 = make_client_auth(&client_key, &h2, &sh2);
        let s2 = hs2.process_client_auth(&a2, &h2).unwrap();

        assert_ne!(s1.client_write_key, s2.client_write_key);
        assert_ne!(s1.session_id, s2.session_id);
    }
}
