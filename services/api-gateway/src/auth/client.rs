//! Client-side handshake SDK.
//!
//! Provides `HandshakeClient` for performing the key-exchange handshake.
//! Handles transcript hashing, Ed25519 signing, and key derivation automatically.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use super::types::*;

/// Error during client handshake.
#[derive(Debug)]
pub enum ClientHandshakeError {
    ServerError(String),
    InvalidServerSignature,
    VersionMismatch,
    KeyDerivationFailed,
    SerializationError(String),
}

impl std::fmt::Display for ClientHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerError(e) => write!(f, "server error: {e}"),
            Self::InvalidServerSignature => write!(f, "invalid server signature"),
            Self::VersionMismatch => write!(f, "protocol version mismatch"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
            Self::SerializationError(e) => write!(f, "serialization error: {e}"),
        }
    }
}

/// Client-side derived keys from handshake (excludes server-provided fields).
#[derive(Debug, Clone)]
pub struct DerivedSessionKeys {
    /// Session ID derived from transcript hash.
    pub session_id: String,
    /// Key fingerprint for verification.
    pub key_fingerprint: String,
    /// Derived client→server write key.
    pub client_write_key: [u8; 32],
    /// Derived server→client write key.
    pub server_write_key: [u8; 32],
}

/// Result of building a ClientHello.
pub struct ClientHelloBundle {
    pub client_hello: ClientHello,
    pub ephemeral_secret: StaticSecret,
    pub client_nonce: [u8; 32],
}

/// Client-side handshake helper.
pub struct HandshakeClient {
    signing_key: SigningKey,
    server_pubkey: Option<VerifyingKey>,
}

impl HandshakeClient {
    /// Create a new handshake client.
    ///
    /// `server_pubkey` is optional — if None, server signature is not verified (dev mode).
    pub fn new(signing_key: SigningKey, server_pubkey: Option<VerifyingKey>) -> Self {
        Self {
            signing_key,
            server_pubkey,
        }
    }

    /// Step 1: Build a ClientHello message.
    pub fn build_client_hello(&self) -> ClientHelloBundle {
        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);
        let nonce = random_nonce();
        let client_key_id = hex::encode(&self.signing_key.verifying_key().to_bytes()[..8]);

        ClientHelloBundle {
            client_hello: ClientHello {
                protocol_version: PROTOCOL_VERSION.to_string(),
                supported_kex: vec![KeyExchangeAlgorithm::X25519],
                supported_sig: vec![SignatureAlgorithm::Ed25519],
                client_ephemeral_pubkey: hex::encode(ephemeral_public.as_bytes()),
                client_nonce: hex::encode(nonce),
                timestamp: unix_now(),
                client_key_id,
            },
            ephemeral_secret,
            client_nonce: nonce,
        }
    }

    /// Step 2: Process ServerHello and build ClientAuth + derive session keys.
    pub fn process_server_hello(
        &self,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
        ephemeral_secret: StaticSecret,
        client_nonce: &[u8; 32],
    ) -> Result<(ClientAuth, DerivedSessionKeys), ClientHandshakeError> {
        if server_hello.protocol_version != PROTOCOL_VERSION {
            return Err(ClientHandshakeError::VersionMismatch);
        }

        // Verify server signature using shared transcript utility.
        if let Some(ref server_pk) = self.server_pubkey {
            let partial_hash = compute_partial_transcript_hash(client_hello, server_hello);
            let sig_bytes = hex::decode(&server_hello.server_signature)
                .map_err(|_| ClientHandshakeError::InvalidServerSignature)?;
            if sig_bytes.len() != 64 {
                return Err(ClientHandshakeError::InvalidServerSignature);
            }
            let sig_arr: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| ClientHandshakeError::InvalidServerSignature)?;
            server_pk
                .verify_strict(
                    &partial_hash,
                    &ed25519_dalek::Signature::from_bytes(&sig_arr),
                )
                .map_err(|_| ClientHandshakeError::InvalidServerSignature)?;
        }

        // Compute full transcript hash and sign using shared utility.
        let client_pubkey_hex = hex::encode(self.signing_key.verifying_key().to_bytes());
        let transcript_hash =
            compute_transcript_hash(client_hello, server_hello, &client_pubkey_hex);
        let client_sig = self.signing_key.sign(&transcript_hash);

        let client_auth = ClientAuth {
            client_signature: hex::encode(client_sig.to_bytes()),
            client_static_pubkey: client_pubkey_hex,
        };

        // Derive session keys using shared utility.
        let server_eph_bytes = hex::decode(&server_hello.server_ephemeral_pubkey)
            .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;
        let server_eph_arr: [u8; 32] = server_eph_bytes
            .try_into()
            .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;
        let shared_secret = ephemeral_secret.diffie_hellman(&X25519Public::from(server_eph_arr));

        let server_nonce_bytes = hex::decode(&server_hello.server_nonce)
            .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;

        let (client_write_key, server_write_key) =
            derive_session_keys(shared_secret.as_bytes(), client_nonce, &server_nonce_bytes)
                .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;

        let session_id = hex::encode(&Sha256::digest(transcript_hash)[..16]);
        let key_fingerprint = hex::encode(&Sha256::digest(client_write_key)[..16]);

        Ok((
            client_auth,
            DerivedSessionKeys {
                session_id,
                key_fingerprint,
                client_write_key,
                server_write_key,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::handshake::ServerHandshake;

    #[test]
    fn test_client_sdk_full_handshake() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let server_pubkey = server_key.verifying_key();

        let client = HandshakeClient::new(client_key, Some(server_pubkey));
        let bundle = client.build_client_hello();

        let mut server_hs = ServerHandshake::new(server_key);
        let server_hello = server_hs
            .process_client_hello(&bundle.client_hello)
            .unwrap();

        let (client_auth, derived) = client
            .process_server_hello(
                &bundle.client_hello,
                &server_hello,
                bundle.ephemeral_secret,
                &bundle.client_nonce,
            )
            .unwrap();

        let server_session = server_hs
            .process_client_auth(&client_auth, &bundle.client_hello)
            .unwrap();

        // Both sides derive the same keys.
        assert_eq!(derived.client_write_key, server_session.client_write_key);
        assert_eq!(derived.server_write_key, server_session.server_write_key);
        assert_eq!(derived.session_id, server_session.session_id);
    }

    #[test]
    fn test_client_sdk_rejects_wrong_server_key() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let wrong_server_pubkey = gen_ed25519_key().verifying_key();

        let client = HandshakeClient::new(client_key, Some(wrong_server_pubkey));
        let bundle = client.build_client_hello();

        let mut server_hs = ServerHandshake::new(server_key);
        let server_hello = server_hs
            .process_client_hello(&bundle.client_hello)
            .unwrap();

        let result = client.process_server_hello(
            &bundle.client_hello,
            &server_hello,
            bundle.ephemeral_secret,
            &bundle.client_nonce,
        );
        assert!(matches!(
            result,
            Err(ClientHandshakeError::InvalidServerSignature)
        ));
    }

    #[test]
    fn test_client_sdk_without_server_verification() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let client = HandshakeClient::new(client_key, None);

        let bundle = client.build_client_hello();
        let mut server_hs = ServerHandshake::new(server_key);
        let server_hello = server_hs
            .process_client_hello(&bundle.client_hello)
            .unwrap();

        let (client_auth, _) = client
            .process_server_hello(
                &bundle.client_hello,
                &server_hello,
                bundle.ephemeral_secret,
                &bundle.client_nonce,
            )
            .unwrap();

        assert!(server_hs
            .process_client_auth(&client_auth, &bundle.client_hello)
            .is_ok());
    }

    #[test]
    fn test_client_sdk_forward_secrecy() {
        let server_key = gen_ed25519_key();
        let client_key = gen_ed25519_key();
        let client = HandshakeClient::new(client_key, None);

        let b1 = client.build_client_hello();
        let mut hs1 = ServerHandshake::new(server_key.clone());
        let sh1 = hs1.process_client_hello(&b1.client_hello).unwrap();
        let (_, s1) = client
            .process_server_hello(
                &b1.client_hello,
                &sh1,
                b1.ephemeral_secret,
                &b1.client_nonce,
            )
            .unwrap();

        let b2 = client.build_client_hello();
        let mut hs2 = ServerHandshake::new(server_key);
        let sh2 = hs2.process_client_hello(&b2.client_hello).unwrap();
        let (_, s2) = client
            .process_server_hello(
                &b2.client_hello,
                &sh2,
                b2.ephemeral_secret,
                &b2.client_nonce,
            )
            .unwrap();

        assert_ne!(s1.client_write_key, s2.client_write_key);
        assert_ne!(s1.session_id, s2.session_id);
    }
}
