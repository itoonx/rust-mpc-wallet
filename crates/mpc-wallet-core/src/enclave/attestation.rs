//! Enclave attestation verification.
//!
//! Provides [`AttestationVerifier`] which validates remote attestation reports
//! against a set of trusted enclave measurements (MRENCLAVE / MRSIGNER) and
//! enforces report freshness via a configurable maximum age.
//!
//! For testing and CI environments where no real TEE is available, use
//! [`MockAttestationVerifier`] which accepts any report unconditionally.

use crate::enclave::AttestationReport;
use crate::error::CoreError;

/// Default maximum age for attestation reports: 300 seconds (5 minutes).
const DEFAULT_MAX_AGE_SECS: u64 = 300;

/// Verifies enclave attestation reports against trusted measurements.
///
/// # Security model
///
/// Before an MPC node participates in a protocol round with a peer, it should
/// verify the peer's attestation report to confirm:
///
/// 1. The peer is running a trusted enclave binary (MRENCLAVE check).
/// 2. The binary was built by a trusted signer (MRSIGNER check).
/// 3. The report is recent enough to prevent replay (timestamp check).
/// 4. The report contains bound user data (non-empty report_data check).
///
/// Both `trusted_mrenclave` and `trusted_mrsigner` lists must contain at
/// least one entry for verification to succeed.
#[derive(Debug, Clone)]
pub struct AttestationVerifier {
    /// List of trusted enclave code measurement hashes.
    pub trusted_mrenclave: Vec<[u8; 32]>,
    /// List of trusted enclave signer identity hashes.
    pub trusted_mrsigner: Vec<[u8; 32]>,
    /// Maximum allowed age of an attestation report in seconds.
    pub max_age_secs: u64,
}

impl AttestationVerifier {
    /// Create a new verifier with the given trusted measurements.
    ///
    /// Uses [`DEFAULT_MAX_AGE_SECS`] (300s) as the default report age limit.
    pub fn new(trusted_mrenclave: Vec<[u8; 32]>, trusted_mrsigner: Vec<[u8; 32]>) -> Self {
        Self {
            trusted_mrenclave,
            trusted_mrsigner,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
        }
    }

    /// Override the maximum report age (in seconds).
    pub fn with_max_age(mut self, max_age_secs: u64) -> Self {
        self.max_age_secs = max_age_secs;
        self
    }

    /// Verify a single attestation report.
    ///
    /// Checks:
    /// 1. `mrenclave` is in the trusted list.
    /// 2. `mrsigner` is in the trusted list.
    /// 3. `timestamp` is not older than `max_age_secs` from `now`.
    /// 4. `report_data` is not empty.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Crypto` if any check fails.
    pub fn verify(&self, report: &AttestationReport) -> Result<(), CoreError> {
        self.verify_at(report, current_timestamp())
    }

    /// Verify a report against an explicit reference timestamp.
    ///
    /// This is the testable core of [`Self::verify`].
    fn verify_at(&self, report: &AttestationReport, now: u64) -> Result<(), CoreError> {
        // 1. MRENCLAVE must be in trusted list
        if !self.trusted_mrenclave.contains(&report.mrenclave) {
            return Err(CoreError::Crypto(
                "attestation: mrenclave not in trusted list".into(),
            ));
        }

        // 2. MRSIGNER must be in trusted list
        if !self.trusted_mrsigner.contains(&report.mrsigner) {
            return Err(CoreError::Crypto(
                "attestation: mrsigner not in trusted list".into(),
            ));
        }

        // 3. Report must not be expired
        if now > report.timestamp && (now - report.timestamp) > self.max_age_secs {
            return Err(CoreError::Crypto(format!(
                "attestation: report expired (age {}s > max {}s)",
                now - report.timestamp,
                self.max_age_secs,
            )));
        }

        // 4. report_data must not be empty
        if report.report_data.is_empty() {
            return Err(CoreError::Crypto(
                "attestation: report_data is empty".into(),
            ));
        }

        Ok(())
    }

    /// Verify mutual attestation between two nodes.
    ///
    /// Both reports must individually pass [`Self::verify`], and additionally:
    /// - Both must have the **same** `mrenclave` (identical code).
    /// - Their timestamps must be within `max_age_secs` of each other.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Crypto` if any check fails.
    pub fn verify_mutual(
        &self,
        my_report: &AttestationReport,
        peer_report: &AttestationReport,
    ) -> Result<(), CoreError> {
        let now = current_timestamp();
        self.verify_mutual_at(my_report, peer_report, now)
    }

    /// Testable core of [`Self::verify_mutual`].
    fn verify_mutual_at(
        &self,
        my_report: &AttestationReport,
        peer_report: &AttestationReport,
        now: u64,
    ) -> Result<(), CoreError> {
        // Both must individually pass verification
        self.verify_at(my_report, now)?;
        self.verify_at(peer_report, now)?;

        // Both must run the same enclave code
        if my_report.mrenclave != peer_report.mrenclave {
            return Err(CoreError::Crypto(
                "attestation: mutual verification failed — mrenclave mismatch".into(),
            ));
        }

        // Timestamps must be within max_age_secs of each other
        let time_diff = my_report.timestamp.abs_diff(peer_report.timestamp);

        if time_diff > self.max_age_secs {
            return Err(CoreError::Crypto(format!(
                "attestation: mutual verification failed — timestamp drift {}s > max {}s",
                time_diff, self.max_age_secs,
            )));
        }

        Ok(())
    }
}

/// Mock attestation verifier that accepts any report.
///
/// **WARNING:** This is intended for tests and CI only. Never use in production.
#[derive(Debug, Clone, Default)]
pub struct MockAttestationVerifier;

impl MockAttestationVerifier {
    /// Create a new mock verifier.
    pub fn new() -> Self {
        Self
    }

    /// Always returns `Ok(())`.
    pub fn verify(&self, _report: &AttestationReport) -> Result<(), CoreError> {
        Ok(())
    }

    /// Always returns `Ok(())`.
    pub fn verify_mutual(
        &self,
        _my_report: &AttestationReport,
        _peer_report: &AttestationReport,
    ) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Return the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUSTED_MRENCLAVE: [u8; 32] = [0xAA; 32];
    const TRUSTED_MRSIGNER: [u8; 32] = [0xBB; 32];
    const UNTRUSTED_MRENCLAVE: [u8; 32] = [0xCC; 32];

    fn make_verifier() -> AttestationVerifier {
        AttestationVerifier::new(vec![TRUSTED_MRENCLAVE], vec![TRUSTED_MRSIGNER]).with_max_age(300)
    }

    fn make_report(mrenclave: [u8; 32], mrsigner: [u8; 32], timestamp: u64) -> AttestationReport {
        AttestationReport {
            mrenclave,
            mrsigner,
            timestamp,
            report_data: vec![0x01, 0x02, 0x03],
        }
    }

    #[test]
    fn test_attestation_valid_report() {
        let verifier = make_verifier();
        let now = 1_000_000u64;
        let report = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 10);
        assert!(verifier.verify_at(&report, now).is_ok());
    }

    #[test]
    fn test_attestation_untrusted_mrenclave() {
        let verifier = make_verifier();
        let now = 1_000_000u64;
        let report = make_report(UNTRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 10);
        let err = verifier.verify_at(&report, now).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("mrenclave not in trusted list"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_attestation_untrusted_mrsigner() {
        let verifier = make_verifier();
        let now = 1_000_000u64;
        let unknown_signer = [0xDD; 32];
        let report = make_report(TRUSTED_MRENCLAVE, unknown_signer, now - 10);
        let err = verifier.verify_at(&report, now).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("mrsigner not in trusted list"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_attestation_expired_report() {
        let verifier = make_verifier();
        let now = 1_000_000u64;
        // Report is 500s old, max is 300s
        let report = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 500);
        let err = verifier.verify_at(&report, now).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("report expired"), "unexpected error: {msg}");
    }

    #[test]
    fn test_attestation_empty_report_data() {
        let verifier = make_verifier();
        let now = 1_000_000u64;
        let mut report = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 10);
        report.report_data = vec![];
        let err = verifier.verify_at(&report, now).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("report_data is empty"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_mutual_attestation_same_enclave() {
        let verifier = make_verifier();
        let now = 1_000_000u64;
        let my_report = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 10);
        let peer_report = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 20);
        assert!(verifier
            .verify_mutual_at(&my_report, &peer_report, now)
            .is_ok());
    }

    #[test]
    fn test_mutual_attestation_different_enclave() {
        let verifier = AttestationVerifier::new(
            vec![TRUSTED_MRENCLAVE, UNTRUSTED_MRENCLAVE],
            vec![TRUSTED_MRSIGNER],
        )
        .with_max_age(300);
        let now = 1_000_000u64;
        let my_report = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 10);
        let peer_report = make_report(UNTRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 20);
        let err = verifier
            .verify_mutual_at(&my_report, &peer_report, now)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("mrenclave mismatch"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_mutual_attestation_timestamp_drift() {
        let verifier = make_verifier();
        let now = 1_000_000u64;
        let my_report = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 10);
        // Peer report is 400s older than mine — exceeds max_age_secs (300)
        let peer_report = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 410);
        // peer_report itself is expired (410s old > 300s max)
        let err = verifier
            .verify_mutual_at(&my_report, &peer_report, now)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("expired") || msg.contains("timestamp drift"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_mock_verifier_accepts_everything() {
        let mock = MockAttestationVerifier::new();
        let report = AttestationReport {
            mrenclave: [0xFF; 32],
            mrsigner: [0xFF; 32],
            timestamp: 0, // ancient
            report_data: vec![],
        };
        assert!(mock.verify(&report).is_ok());
        assert!(mock.verify_mutual(&report, &report).is_ok());
    }

    #[test]
    fn test_verifier_multiple_trusted_measurements() {
        let second_mrenclave = [0xEE; 32];
        let second_mrsigner = [0xFF; 32];
        let verifier = AttestationVerifier::new(
            vec![TRUSTED_MRENCLAVE, second_mrenclave],
            vec![TRUSTED_MRSIGNER, second_mrsigner],
        )
        .with_max_age(300);
        let now = 1_000_000u64;

        // First measurement pair works
        let r1 = make_report(TRUSTED_MRENCLAVE, TRUSTED_MRSIGNER, now - 10);
        assert!(verifier.verify_at(&r1, now).is_ok());

        // Second measurement pair works
        let r2 = make_report(second_mrenclave, second_mrsigner, now - 10);
        assert!(verifier.verify_at(&r2, now).is_ok());
    }
}
