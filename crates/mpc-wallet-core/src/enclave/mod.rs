//! SGX/TDX enclave abstraction for hardware-isolated MPC signing (DEC-017).
//!
//! This module defines the [`EnclaveProvider`] trait that abstracts over
//! hardware enclave operations. The enclave boundary ensures that key share
//! plaintext and secret scalars (`k_i`, `x_i`, `chi_i`) never exist in
//! host memory — only opaque handles and partial signatures cross the boundary.
//!
//! ## Implementations
//!
//! - **Mock (Sprint 23):** [`mock::MockEnclaveProvider`] for testing without SGX hardware.
//! - **Attestation:** [`attestation::AttestationVerifier`] for verifying enclave reports.

pub mod attestation;
pub mod mock;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::types::PartyId;

/// Opaque handle to a loaded key share inside the enclave.
///
/// The actual share plaintext never leaves the enclave. Callers use this
/// handle to reference the share in subsequent [`EnclaveProvider::sign`] calls.
/// The handle is invalidated by [`EnclaveProvider::destroy`].
#[derive(Debug, Clone)]
pub struct EnclaveHandle {
    /// Unique identifier for this loaded share within the enclave.
    pub id: String,
}

/// SGX/TDX remote attestation report.
///
/// Proves that code is running inside a genuine Intel SGX enclave.
/// Verifiers should check `mrenclave` and `mrsigner` against pinned
/// (known-good) values before trusting the enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// SHA-256 hash of the enclave code and initial data (code identity).
    /// Changes whenever the enclave binary is rebuilt.
    pub mrenclave: [u8; 32],

    /// SHA-256 hash of the enclave signing key (developer identity).
    /// Stable across enclave binary updates by the same developer.
    pub mrsigner: [u8; 32],

    /// Product identifier assigned by the enclave developer.
    pub isv_prod_id: u16,

    /// Security version number. Must be monotonically increasing to
    /// prevent rollback to older (potentially vulnerable) enclave versions.
    pub isv_svn: u16,

    /// Unix timestamp (seconds since epoch) when the report was generated.
    /// Used by [`attestation::AttestationVerifier`] for freshness checking.
    pub timestamp: u64,

    /// User-defined data bound to this attestation (64 bytes in SGX).
    /// Typically: `SHA-256(session_id || node_pubkey || timestamp)`.
    pub report_data: Vec<u8>,

    /// Raw attestation report bytes (EPID or DCAP format).
    /// Passed to the attestation verification service for validation.
    pub raw_report: Vec<u8>,
}

/// Partial signature produced inside the enclave.
///
/// Contains only the partial signature bytes — no secret material.
/// Safe to transmit over the network to other MPC parties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    /// The party that produced this partial signature.
    pub party_id: PartyId,

    /// Serialized partial signature bytes.
    pub data: Vec<u8>,
}

/// Abstraction over SGX/TDX enclave operations for MPC signing.
///
/// The enclave boundary ensures that key share plaintext and secret scalars
/// never exist in host memory. Only opaque [`EnclaveHandle`]s and
/// [`PartialSignature`]s cross the boundary.
///
/// # Implementations
///
/// - `MockEnclaveProvider` (feature `mock-enclave`): no hardware, for testing.
///   R1/R2 will provide this in a future sprint.
/// - `GramineEnclaveProvider` (feature `sgx-gramine`): real SGX via Gramine.
///   Planned for Phase 2.
///
/// # Example (conceptual)
///
/// ```ignore
/// let enclave: Box<dyn EnclaveProvider> = /* ... */;
///
/// // Verify attestation before trusting this node
/// let report = enclave.attestation_report()?;
/// assert_eq!(report.mrenclave, EXPECTED_MRENCLAVE);
///
/// // Load share into enclave (plaintext never in host memory)
/// let handle = enclave.load_share(&encrypted_blob, password).await?;
///
/// // Sign inside enclave
/// let partial_sig = enclave.sign(&handle, &message_hash).await?;
///
/// // Clean up
/// enclave.destroy(handle);
/// ```
#[async_trait]
pub trait EnclaveProvider: Send + Sync {
    /// Load an encrypted key share into the enclave.
    ///
    /// The share is decrypted **inside** the enclave using the provided
    /// password (Argon2id KDF + AES-256-GCM). The plaintext share never
    /// leaves enclave memory.
    ///
    /// Returns an opaque [`EnclaveHandle`] that references the loaded share.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Encryption`] if decryption fails (wrong password or corrupt data).
    /// - [`CoreError::Other`] if the enclave is not available or out of memory.
    async fn load_share(
        &self,
        encrypted_share: &[u8],
        password: &[u8],
    ) -> Result<EnclaveHandle, CoreError>;

    /// Compute a partial signature inside the enclave.
    ///
    /// Uses the key share referenced by `handle` to compute a partial
    /// signature over `message`. All secret scalars (`k_i`, `x_i`, `chi_i`)
    /// are zeroized inside the enclave after computation.
    ///
    /// # Errors
    ///
    /// - [`CoreError::Protocol`] if the MPC computation fails.
    /// - [`CoreError::NotFound`] if the handle is invalid or has been destroyed.
    async fn sign(
        &self,
        handle: &EnclaveHandle,
        message: &[u8],
    ) -> Result<PartialSignature, CoreError>;

    /// Retrieve the enclave's remote attestation report.
    ///
    /// The report cryptographically proves that this code is running inside
    /// a genuine SGX/TDX enclave. Callers should verify:
    /// - `mrenclave` matches the expected enclave code hash
    /// - `mrsigner` matches the expected developer signing key
    /// - `isv_svn` >= minimum required security version
    /// - `report_data` binds to the current session
    ///
    /// # Errors
    ///
    /// - [`CoreError::Other`] if attestation generation fails (e.g., no SGX hardware).
    fn attestation_report(&self) -> Result<AttestationReport, CoreError>;

    /// Destroy a loaded key share, zeroizing all enclave-side state.
    ///
    /// After this call, the handle is invalid and must not be reused.
    /// Calling `sign()` with a destroyed handle returns [`CoreError::NotFound`].
    fn destroy(&self, handle: EnclaveHandle);
}
