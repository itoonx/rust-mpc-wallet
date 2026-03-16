//! # MPC Wallet Core
//!
//! Core library for the MPC Wallet SDK. Provides the foundational traits,
//! types, and error definitions used across all MPC protocol implementations,
//! transport layers, and key store backends.
//!
//! ## Architecture
//!
//! The library is structured around four public traits that define the boundaries
//! between subsystems:
//!
//! - [`protocol::MpcProtocol`] — threshold key generation and distributed signing
//! - [`transport::Transport`] — message passing between protocol parties
//! - [`key_store::KeyStore`] — encrypted persistent storage of key shares
//!
//! No single party ever holds a complete private key; all sensitive operations
//! are distributed across parties using threshold cryptography.

/// Error types returned by all core operations.
pub mod error;
/// Key share storage traits and encrypted file-based implementation.
pub mod key_store;
/// MPC protocol traits and implementations (GG20, FROST Ed25519, FROST secp256k1).
pub mod protocol;
/// Transport layer traits and implementations for inter-party messaging.
pub mod transport;
/// Shared primitive types: [`types::PartyId`], [`types::ThresholdConfig`], [`types::CryptoScheme`].
pub mod types;
/// Policy engine: signing policy schema, evaluator, and the "no policy → no sign" gate.
///
/// Use [`policy::PolicyStore`] to load a [`policy::Policy`] and call
/// [`policy::PolicyStore::check`] before creating any signing session (FR-B5).
pub mod policy;
/// Signing session manager: idempotent session lifecycle with `tx_fingerprint` lock.
///
/// Use [`session::SessionManager`] to create and track signing sessions.
/// Call [`session::SessionManager::create`] before initiating any MPC signing round.
pub mod session;
