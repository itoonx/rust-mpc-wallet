# DEC-009: Work on dev Branch, PR to main

- **Date:** 2026-03-15
- **Status:** Decided (enforced)
- **Context:** Need a stable main branch for CI and releases while allowing active development.
- **Decision:** All work happens on `dev` branch. PRs to `main` only after CI is green (fmt + clippy + test + audit).
- **Consequences:** Main is always deployable. Dev can have WIP commits. Merge requires CI green.
