//! E2E test suite entry point.
//!
//! All tests are `#[ignore]` by default — they require live infrastructure.
//!
//! # Quick start
//! ```bash
//! ./scripts/local-infra.sh up
//! cargo test --test e2e_tests -- --ignored --test-threads=1
//! ./scripts/local-infra.sh down
//! ```
//!
//! # Or use the convenience command
//! ```bash
//! ./scripts/local-infra.sh test
//! ```

mod e2e;
