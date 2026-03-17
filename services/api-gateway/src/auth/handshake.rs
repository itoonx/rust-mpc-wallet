//! Server-side handshake implementation.
//!
//! Implements the key-exchange + signed challenge-response protocol:
//! 1. Receive ClientHello → validate, generate ServerHello
//! 2. Receive ClientAuth → verify signature, establish session
//!
//! **Key exchange alone is NOT authentication.**
//! Identity is bound to the handshake via Ed25519 signatures over the
//! transcript hash of all handshake messages.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use super::types::*;

/// Server-side handshake state machine.
pub struct ServerHandshake {
    /// Server's static Ed25519 signing key.
    server_signing_key: SigningKey,
    /// Server's static Ed25519 public key.
    server_verifying_key: VerifyingKey,
    /// Ephemeral X25519 secret (kept until session is derived).
    ephemeral_secret: Option<StaticSecret>,
    /// Ephemeral X25519 public key.
    ephemeral_public: Option<X25519Public>,
    /// Server nonce.
    server_nonce: Option<[u8; 32]>,
    /// Server challenge.
    server_challenge: Option<[u8; 32]>,
    /// Transcript hash state.
    transcript: Sha256,
    /// State.
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
    /// Create a new server handshake with the given Ed25519 signing key.
    pub fn new(server_signing_key: SigningKey) -> Self {
        let server_verifying_key = server_signing_key.verifying_key();
        Self {
            server_signing_key,
            server_verifying_key,
            ephemeral_secret: None,
            ephemeral_public: None,
            server_nonce: None,
            server_challenge: None,
            transcript: Sha256::new(),
            state: HandshakeState::Init,
        }
    }

    /// Process ClientHello and generate ServerHello.
    ///
    /// Validates the client's message, generates ephemeral keys, and signs
    /// the transcript. Returns ServerHello on success.
    pub fn process_client_hello(
        &mut self,
        client_hello: &ClientHello,
    ) -> Result<ServerHello, HandshakeError> {
        if self.state != HandshakeState::Init {
            return Err(HandshakeError::InvalidState);
        }

        // Validate protocol version.
        if client_hello.protocol_version != PROTOCOL_VERSION {
            return Err(HandshakeError::UnsupportedVersion);
        }

        // Validate timestamp.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.abs_diff(client_hello.timestamp) > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(HandshakeError::TimestampDrift);
        }

        // Validate supported algorithms.
        if !client_hello
            .supported_kex
            .contains(&KeyExchangeAlgorithm::X25519)
        {
            return Err(HandshakeError::NoCommonAlgorithm);
        }
        if !client_hello
            .supported_sig
            .contains(&SignatureAlgorithm::Ed25519)
        {
            return Err(HandshakeError::NoCommonAlgorithm);
        }

        // Validate client ephemeral pubkey format.
        let client_ephemeral_bytes = hex::decode(&client_hello.client_ephemeral_pubkey)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        if client_ephemeral_bytes.len() != 32 {
            return Err(HandshakeError::MalformedMessage);
        }

        // Validate client nonce.
        let client_nonce_bytes = hex::decode(&client_hello.client_nonce)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        if client_nonce_bytes.len() != 32 {
            return Err(HandshakeError::MalformedMessage);
        }

        // Add ClientHello to transcript.
        let client_hello_bytes =
            serde_json::to_vec(client_hello).map_err(|_| HandshakeError::MalformedMessage)?;
        self.transcript.update(&client_hello_bytes);

        // Generate server ephemeral X25519 key pair.
        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        // Generate server nonce and challenge.
        let mut server_nonce = [0u8; 32];
        let mut server_challenge = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_nonce);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_challenge);

        let server_key_id = hex::encode(&self.server_verifying_key.to_bytes()[..8]);

        // Build ServerHello (without signature first, for transcript).
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
            server_signature: String::new(), // placeholder
        };

        // Add ServerHello fields (minus signature) to transcript.
        let hello_for_transcript = serde_json::json!({
            "protocol_version": server_hello.protocol_version,
            "selected_kex": server_hello.selected_kex,
            "selected_sig": server_hello.selected_sig,
            "selected_aead": server_hello.selected_aead,
            "server_ephemeral_pubkey": server_hello.server_ephemeral_pubkey,
            "server_nonce": server_hello.server_nonce,
            "server_challenge": server_hello.server_challenge,
            "timestamp": server_hello.timestamp,
            "server_key_id": server_hello.server_key_id,
        });
        let transcript_bytes = serde_json::to_vec(&hello_for_transcript)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        self.transcript.update(&transcript_bytes);

        // Sign the current transcript hash.
        let transcript_hash = self.transcript.clone().finalize();
        let signature = self.server_signing_key.sign(&transcript_hash);
        server_hello.server_signature = hex::encode(signature.to_bytes());

        // Store state.
        self.ephemeral_secret = Some(ephemeral_secret);
        self.ephemeral_public = Some(ephemeral_public);
        self.server_nonce = Some(server_nonce);
        self.server_challenge = Some(server_challenge);
        self.state = HandshakeState::HelloSent;

        Ok(server_hello)
    }

    /// Process ClientAuth and establish the session.
    ///
    /// Verifies the client's Ed25519 signature over the transcript hash,
    /// derives session keys via X25519 ECDH + HKDF, and returns the
    /// authenticated session.
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

        // Verify: client_key_id must match the provided pubkey.
        if client_hello.client_key_id != hex::encode(&client_pubkey_array[..8]) {
            return Err(HandshakeError::KeyIdMismatch);
        }

        // Add ClientAuth message to transcript (minus signature).
        let auth_for_transcript = serde_json::json!({
            "client_static_pubkey": client_auth.client_static_pubkey,
        });
        let auth_bytes = serde_json::to_vec(&auth_for_transcript)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        self.transcript.update(&auth_bytes);

        // Compute final transcript hash.
        let transcript_hash = self.transcript.clone().finalize();

        // Verify client's signature over transcript hash.
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

        // Derive session keys via X25519 ECDH + HKDF.
        let ephemeral_secret = self
            .ephemeral_secret
            .take()
            .ok_or(HandshakeError::InvalidState)?;

        let client_ephemeral_bytes = hex::decode(&client_hello.client_ephemeral_pubkey)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        let client_ephemeral_array: [u8; 32] = client_ephemeral_bytes
            .try_into()
            .map_err(|_| HandshakeError::MalformedMessage)?;
        let client_ephemeral_pubkey = X25519Public::from(client_ephemeral_array);

        let shared_secret = ephemeral_secret.diffie_hellman(&client_ephemeral_pubkey);

        // HKDF: salt = client_nonce || server_nonce, info = protocol context
        let client_nonce = hex::decode(&client_hello.client_nonce)
            .map_err(|_| HandshakeError::MalformedMessage)?;
        let server_nonce = self.server_nonce.ok_or(HandshakeError::InvalidState)?;
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(&client_nonce);
        salt.extend_from_slice(&server_nonce);

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());

        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];

        hk.expand(b"mpc-wallet-session-v1-client-write", &mut client_write_key)
            .map_err(|_| HandshakeError::KeyDerivationFailed)?;
        hk.expand(b"mpc-wallet-session-v1-server-write", &mut server_write_key)
            .map_err(|_| HandshakeError::KeyDerivationFailed)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

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

    /// Get the current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }
}

/// Handshake error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Protocol version mismatch.
    UnsupportedVersion,
    /// Timestamp too far from server time.
    TimestampDrift,
    /// No common algorithm between client and server.
    NoCommonAlgorithm,
    /// Invalid message format.
    MalformedMessage,
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// client_key_id doesn't match provided pubkey.
    KeyIdMismatch,
    /// HKDF key derivation failed.
    KeyDerivationFailed,
    /// Wrong handshake state for this operation.
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

    fn gen_ed25519_key() -> ed25519_dalek::SigningKey {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    }

    /// Helper: create a valid ClientHello.
    fn make_client_hello(
        client_signing_key: &ed25519_dalek::SigningKey,
        client_ephemeral_pubkey: &X25519Public,
    ) -> ClientHello {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let client_key_id = hex::encode(&client_signing_key.verifying_key().to_bytes()[..8]);

        ClientHello {
            protocol_version: PROTOCOL_VERSION.to_string(),
            supported_kex: vec![KeyExchangeAlgorithm::X25519],
            supported_sig: vec![SignatureAlgorithm::Ed25519],
            client_ephemeral_pubkey: hex::encode(client_ephemeral_pubkey.as_bytes()),
            client_nonce: hex::encode(nonce),
            timestamp: now,
            client_key_id,
        }
    }

    /// Helper: create ClientAuth by signing the transcript.
    fn make_client_auth(
        client_signing_key: &ed25519_dalek::SigningKey,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
    ) -> ClientAuth {
        // Reproduce the transcript hash that the server computes.
        let mut transcript = Sha256::new();

        // ClientHello
        let ch_bytes = serde_json::to_vec(client_hello).unwrap();
        transcript.update(&ch_bytes);

        // ServerHello fields (minus signature)
        let hello_for_transcript = serde_json::json!({
            "protocol_version": server_hello.protocol_version,
            "selected_kex": server_hello.selected_kex,
            "selected_sig": server_hello.selected_sig,
            "selected_aead": server_hello.selected_aead,
            "server_ephemeral_pubkey": server_hello.server_ephemeral_pubkey,
            "server_nonce": server_hello.server_nonce,
            "server_challenge": server_hello.server_challenge,
            "timestamp": server_hello.timestamp,
            "server_key_id": server_hello.server_key_id,
        });
        let sh_bytes = serde_json::to_vec(&hello_for_transcript).unwrap();
        transcript.update(&sh_bytes);

        // ClientAuth fields (minus signature)
        let client_pubkey_hex = hex::encode(client_signing_key.verifying_key().to_bytes());
        let auth_for_transcript = serde_json::json!({
            "client_static_pubkey": client_pubkey_hex,
        });
        let auth_bytes = serde_json::to_vec(&auth_for_transcript).unwrap();
        transcript.update(&auth_bytes);

        let transcript_hash = transcript.finalize();
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

        let client_ephemeral_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let client_ephemeral_public = X25519Public::from(&client_ephemeral_secret);

        let client_hello = make_client_hello(&client_key, &client_ephemeral_public);

        let mut handshake = ServerHandshake::new(server_key);
        assert_eq!(handshake.state(), HandshakeState::Init);

        // Step 1: ClientHello → ServerHello
        let server_hello = handshake
            .process_client_hello(&client_hello)
            .expect("ClientHello should succeed");
        assert_eq!(handshake.state(), HandshakeState::HelloSent);
        assert_eq!(server_hello.protocol_version, PROTOCOL_VERSION);
        assert!(!server_hello.server_signature.is_empty());

        // Step 2: ClientAuth → SessionEstablished
        let client_auth = make_client_auth(&client_key, &client_hello, &server_hello);
        let session = handshake
            .process_client_auth(&client_auth, &client_hello)
            .expect("ClientAuth should succeed");
        assert_eq!(handshake.state(), HandshakeState::Authenticated);

        // Session has valid properties.
        assert!(!session.session_id.is_empty());
        assert!(session.expires_at > session.created_at);
        assert_ne!(session.client_write_key, session.server_write_key);
        assert_eq!(session.client_pubkey, client_key.verifying_key().to_bytes());
    }

    #[test]
    fn test_wrong_protocol_version_rejected() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let client_eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let client_eph_pub = X25519Public::from(&client_eph);

        let mut hello = make_client_hello(&client_key, &client_eph_pub);
        hello.protocol_version = "wrong-v999".into();

        let mut hs = ServerHandshake::new(server_key);
        assert_eq!(
            hs.process_client_hello(&hello).unwrap_err(),
            HandshakeError::UnsupportedVersion
        );
    }

    #[test]
    fn test_stale_timestamp_rejected() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let client_eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let client_eph_pub = X25519Public::from(&client_eph);

        let mut hello = make_client_hello(&client_key, &client_eph_pub);
        hello.timestamp = 1000; // far in the past

        let mut hs = ServerHandshake::new(server_key);
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
        let client_eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let client_eph_pub = X25519Public::from(&client_eph);

        let client_hello = make_client_hello(&client_key, &client_eph_pub);

        let mut hs = ServerHandshake::new(server_key);
        let server_hello = hs.process_client_hello(&client_hello).unwrap();

        // Sign with wrong key
        let mut bad_auth = make_client_auth(&wrong_key, &client_hello, &server_hello);
        // But provide the real client's pubkey (mismatch)
        bad_auth.client_static_pubkey = hex::encode(client_key.verifying_key().to_bytes());

        assert_eq!(
            hs.process_client_auth(&bad_auth, &client_hello)
                .unwrap_err(),
            HandshakeError::InvalidSignature
        );
    }

    #[test]
    fn test_key_id_mismatch_rejected() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let other_key = gen_ed25519_key();
        let client_eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let client_eph_pub = X25519Public::from(&client_eph);

        let mut client_hello = make_client_hello(&client_key, &client_eph_pub);
        // Put wrong key_id
        client_hello.client_key_id = hex::encode(&other_key.verifying_key().to_bytes()[..8]);

        let mut hs = ServerHandshake::new(server_key);
        let server_hello = hs.process_client_hello(&client_hello).unwrap();

        let client_auth = make_client_auth(&client_key, &client_hello, &server_hello);
        assert_eq!(
            hs.process_client_auth(&client_auth, &client_hello)
                .unwrap_err(),
            HandshakeError::KeyIdMismatch
        );
    }

    #[test]
    fn test_double_hello_rejected() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let client_eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let client_eph_pub = X25519Public::from(&client_eph);

        let hello = make_client_hello(&client_key, &client_eph_pub);

        let mut hs = ServerHandshake::new(server_key);
        hs.process_client_hello(&hello).unwrap();

        // Second hello should fail — wrong state
        assert_eq!(
            hs.process_client_hello(&hello).unwrap_err(),
            HandshakeError::InvalidState
        );
    }

    #[test]
    fn test_forward_secrecy_different_sessions_different_keys() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();

        // Session 1
        let eph1 = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let eph1_pub = X25519Public::from(&eph1);
        let hello1 = make_client_hello(&client_key, &eph1_pub);
        let mut hs1 = ServerHandshake::new(server_key.clone());
        let sh1 = hs1.process_client_hello(&hello1).unwrap();
        let auth1 = make_client_auth(&client_key, &hello1, &sh1);
        let session1 = hs1.process_client_auth(&auth1, &hello1).unwrap();

        // Session 2 (same static keys, different ephemeral)
        let eph2 = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let eph2_pub = X25519Public::from(&eph2);
        let hello2 = make_client_hello(&client_key, &eph2_pub);
        let mut hs2 = ServerHandshake::new(server_key);
        let sh2 = hs2.process_client_hello(&hello2).unwrap();
        let auth2 = make_client_auth(&client_key, &hello2, &sh2);
        let session2 = hs2.process_client_auth(&auth2, &hello2).unwrap();

        // Session keys must differ (forward secrecy).
        assert_ne!(session1.client_write_key, session2.client_write_key);
        assert_ne!(session1.server_write_key, session2.server_write_key);
        assert_ne!(session1.session_id, session2.session_id);
    }
}
