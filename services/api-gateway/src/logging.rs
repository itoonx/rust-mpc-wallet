//! Structured logging with secret field redaction.
//!
//! Provides custom `FormatEvent` implementations that redact values of fields
//! whose names contain sensitive keywords (`secret`, `key`, `password`, `token`,
//! `share_data`). Supports both human-readable and JSON output formats.

use std::fmt;
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// Field names containing any of these substrings will have their values replaced
/// with `[REDACTED]` in log output.
const SENSITIVE_KEYWORDS: &[&str] = &["secret", "key", "password", "token", "share_data"];

/// Returns true if a field name looks sensitive and should be redacted.
pub fn is_sensitive_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

// ── Redacting Field Visitor ────────────────────────────────────────────

/// A tracing field visitor that redacts sensitive values.
struct RedactingVisitor<'a> {
    writer: &'a mut dyn fmt::Write,
    first: bool,
    is_json: bool,
}

impl<'a> RedactingVisitor<'a> {
    fn new(writer: &'a mut dyn fmt::Write, is_json: bool) -> Self {
        Self {
            writer,
            first: true,
            is_json,
        }
    }

    fn write_field(&mut self, field: &tracing::field::Field, value: &dyn fmt::Display) {
        let sep = if self.first {
            ""
        } else if self.is_json {
            ", "
        } else {
            " "
        };
        self.first = false;

        if is_sensitive_field(field.name()) {
            if self.is_json {
                let _ = write!(self.writer, "{sep}\"{}\": \"[REDACTED]\"", field.name());
            } else {
                let _ = write!(self.writer, "{sep}{}=[REDACTED]", field.name());
            }
        } else if self.is_json {
            let _ = write!(self.writer, "{sep}\"{}\": \"{}\"", field.name(), value);
        } else {
            let _ = write!(self.writer, "{sep}{}={}", field.name(), value);
        }
    }
}

impl tracing::field::Visit for RedactingVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.write_field(field, &format_args!("{:?}", value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.write_field(field, &value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.write_field(field, &value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.write_field(field, &value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.write_field(field, &value);
    }
}

// ── Redacting Text Format ──────────────────────────────────────────────

/// Human-readable log format with secret redaction.
pub struct RedactingTextFormat;

impl<S, N> FormatEvent<S, N> for RedactingTextFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let now = chrono_lite_now();
        let meta = event.metadata();
        write!(
            writer,
            "{now} {level:>5} {target}: ",
            level = meta.level(),
            target = meta.target()
        )?;

        // Write message field first.
        let mut visitor = RedactingVisitor::new(&mut writer, false);
        event.record(&mut visitor);
        writeln!(writer)
    }
}

// ── Redacting JSON Format ──────────────────────────────────────────────

/// JSON log format with secret redaction.
pub struct RedactingJsonFormat;

impl<S, N> FormatEvent<S, N> for RedactingJsonFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let now = chrono_lite_now();
        let meta = event.metadata();
        write!(
            writer,
            "{{\"timestamp\": \"{now}\", \"level\": \"{level}\", \"target\": \"{target}\"",
            level = meta.level(),
            target = meta.target(),
        )?;

        let mut fields_buf = String::new();
        let mut visitor = RedactingVisitor::new(&mut fields_buf, true);
        event.record(&mut visitor);

        if !fields_buf.is_empty() {
            write!(writer, ", {fields_buf}")?;
        }
        writeln!(writer, "}}")
    }
}

/// Simple timestamp without pulling in chrono. Uses seconds since epoch.
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", d.as_secs(), d.subsec_millis())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sensitive_field_detects_secret() {
        assert!(is_sensitive_field("jwt_secret"));
        assert!(is_sensitive_field("SECRET_KEY"));
        assert!(is_sensitive_field("session_token"));
        assert!(is_sensitive_field("password"));
        assert!(is_sensitive_field("share_data"));
        assert!(is_sensitive_field("encryption_key"));
        assert!(is_sensitive_field("server_signing_key"));
    }

    #[test]
    fn test_is_sensitive_field_allows_safe_names() {
        assert!(!is_sensitive_field("party_id"));
        assert!(!is_sensitive_field("group_id"));
        assert!(!is_sensitive_field("nats_url"));
        assert!(!is_sensitive_field("status"));
        assert!(!is_sensitive_field("bind_address"));
    }

    #[test]
    fn test_redacting_visitor_text_mode() {
        let mut buf = String::new();
        {
            let mut visitor = RedactingVisitor::new(&mut buf, false);
            // Simulate recording fields
            use tracing::field::Visit;
            let field_set = tracing::field::FieldSet::new(
                &["status", "jwt_secret"],
                tracing::callsite::Identifier(&DUMMY_CALLSITE),
            );
            let status_field = field_set.field("status").unwrap();
            let secret_field = field_set.field("jwt_secret").unwrap();
            visitor.record_str(&status_field, "ok");
            visitor.record_str(&secret_field, "super-secret-value");
        }
        assert!(buf.contains("status=ok"));
        assert!(buf.contains("jwt_secret=[REDACTED]"));
        assert!(!buf.contains("super-secret-value"));
    }

    #[test]
    fn test_redacting_visitor_json_mode() {
        let mut buf = String::new();
        {
            let mut visitor = RedactingVisitor::new(&mut buf, true);
            use tracing::field::Visit;
            let field_set = tracing::field::FieldSet::new(
                &["party_id", "password"],
                tracing::callsite::Identifier(&DUMMY_CALLSITE),
            );
            let party_field = field_set.field("party_id").unwrap();
            let pass_field = field_set.field("password").unwrap();
            visitor.record_u64(&party_field, 1);
            visitor.record_str(&pass_field, "hunter2");
        }
        assert!(buf.contains("\"party_id\": \"1\""));
        assert!(buf.contains("\"password\": \"[REDACTED]\""));
        assert!(!buf.contains("hunter2"));
    }

    // Dummy callsite for tests
    static DUMMY_CALLSITE: DummyCallsite = DummyCallsite;
    struct DummyCallsite;
    impl tracing::callsite::Callsite for DummyCallsite {
        fn set_interest(&self, _: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            static META: tracing::Metadata<'static> = tracing::Metadata::new(
                "test",
                "test",
                tracing::Level::INFO,
                None,
                None,
                None,
                tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&DummyCallsite)),
                tracing::metadata::Kind::EVENT,
            );
            &META
        }
    }
}
