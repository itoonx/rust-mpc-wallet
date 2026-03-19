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

/// Approval workflow: M-of-N quorum enforcement and maker/checker/approver SoD.
///
/// Use [`approvals::ApprovalStore`] to register sessions, assign roles,
/// collect Ed25519-signed approvals, and check quorum before signing (FR-C).
pub mod approvals;
/// Append-only hash-chained audit ledger with Ed25519 service signatures (FR-F).
///
/// Use [`audit::AuditLedger`] to record every signing event. Call
/// [`audit::AuditLedger::verify`] to check tamper-evident chain integrity.
pub mod audit;
/// SGX/TDX enclave abstraction for hardware-isolated MPC signing (DEC-017).
///
/// Defines the [`enclave::EnclaveProvider`] trait that abstracts over hardware
/// enclave operations. Key share plaintext and secret scalars never leave the
/// enclave boundary. See `docs/SGX_DESIGN.md` for the full design document.
pub mod enclave;
/// Error types returned by all core operations.
pub mod error;
/// JWT-based identity validation (Epic A).
///
/// Provides [`identity::JwtValidator`] to decode and validate JWTs, extracting
/// RBAC roles and ABAC attributes into an [`rbac::AuthContext`].
pub mod identity;
/// Key share storage traits and encrypted file-based implementation.
pub mod key_store;
/// Multi-cloud operations: node distribution constraints and health monitoring (Epic I).
///
/// Use [`ops::validate_distribution`] to enforce that MPC parties are spread across
/// distinct cloud providers and regions. Use [`ops::assess_quorum_risk`] to evaluate
/// signing quorum availability from node health reports.
pub mod ops;
/// Policy engine: signing policy schema, evaluator, and the "no policy → no sign" gate.
///
/// Use [`policy::PolicyStore`] to load a [`policy::Policy`] and call
/// [`policy::PolicyStore::check`] before creating any signing session (FR-B5).
pub mod policy;
/// MPC protocol traits and implementations (GG20, FROST Ed25519, FROST secp256k1).
pub mod protocol;
/// Role-based and attribute-based access control (Epic A).
///
/// Provides [`rbac::ApiRole`] for RBAC, [`rbac::AbacAttributes`] for ABAC,
/// [`rbac::AuthContext`] combining both, and [`rbac::Permissions`] for authorization gates.
pub mod rbac;
/// NATS RPC protocol messages for Gateway ↔ MPC Node communication (DEC-015).
pub mod rpc;
/// Signing session manager: idempotent session lifecycle with `tx_fingerprint` lock.
///
/// Use [`session::SessionManager`] to create and track signing sessions.
/// Call [`session::SessionManager::create`] before initiating any MPC signing round.
pub mod session;
/// Transport layer traits and implementations for inter-party messaging.
pub mod transport;
/// Shared primitive types: [`types::PartyId`], [`types::ThresholdConfig`], [`types::CryptoScheme`].
pub mod types;
