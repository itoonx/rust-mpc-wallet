//! Key-exchange-based authentication protocol.
//!
//! Implements a challenge-response + ephemeral X25519 ECDH handshake protocol
//! that establishes authenticated, encrypted sessions between clients and the
//! API gateway. See `docs/AUTH_SPEC.md` for the full specification.
//!
//! # Protocol Overview
//!
//! 1. **ClientHello**: client sends ephemeral X25519 pubkey + nonce
//! 2. **ServerHello**: server sends ephemeral X25519 pubkey + nonce + challenge
//! 3. **ClientAuth**: client signs transcript hash with Ed25519 static key
//! 4. **SessionEstablished**: server returns encrypted session token
//!
//! # Security Properties
//!
//! - **Forward secrecy**: ephemeral X25519 keys per session
//! - **Mutual authentication**: Ed25519 signatures over transcript hash
//! - **Replay protection**: random nonces + timestamp + challenge binding
//! - **Transcript binding**: all handshake messages hashed into auth proof
//! - **Key exchange alone is NOT authentication** — identity is bound via signatures

pub mod client;
pub mod handshake;
pub mod mtls;
pub mod session;
pub mod session_jwt;
pub mod types;
