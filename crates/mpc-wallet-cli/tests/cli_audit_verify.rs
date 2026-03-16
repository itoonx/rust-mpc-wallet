//! Integration tests for the `audit-verify` CLI command.

/// Helper: create a valid evidence pack JSON by using the core audit module directly.
fn create_valid_pack() -> String {
    use mpc_wallet_core::audit::{AuditLedger, EventKind};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let ledger = AuditLedger::new(SigningKey::from_bytes(&bytes));

    ledger
        .append(EventKind::SessionCreated, Some("test-session".into()), None)
        .unwrap();
    ledger
        .append(
            EventKind::SigningCompleted,
            Some("test-session".into()),
            Some("0xabc".into()),
        )
        .unwrap();

    ledger.export_evidence_pack().unwrap()
}

#[test]
fn test_verify_valid_pack_file() {
    let pack = create_valid_pack();

    // Verify the pack using the core module directly
    let result = mpc_wallet_core::audit::AuditLedger::verify_pack(&pack);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 2);
}

#[test]
fn test_verify_tampered_pack_fails() {
    let pack = create_valid_pack();
    let mut parsed: serde_json::Value = serde_json::from_str(&pack).unwrap();
    parsed["entries"][0]["details"] = serde_json::json!("TAMPERED");
    let tampered = serde_json::to_string(&parsed).unwrap();

    let result = mpc_wallet_core::audit::AuditLedger::verify_pack(&tampered);
    assert!(result.is_err());
}

#[test]
fn test_verify_invalid_json_fails() {
    let result = mpc_wallet_core::audit::AuditLedger::verify_pack("not valid json {{{");
    assert!(result.is_err());
}
