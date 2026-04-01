# MPC Wallet SDK — Roadmap

> Updated: 2026-04-01

## Current State
- 882 tests, 54K LOC, 68/68 security findings resolved
- 7 production threshold protocols
- PR #22 merged to main (Sprint 29-31b)

## Sprint 32: Merge and Document (Current)
- [x] Merge PR #22
- [ ] Rewrite SPRINT.md
- [ ] Update EPICS.md
- [ ] Benchmark baseline

## Sprint 33: Test Gaps + Benchmarks
- mpc-node: 0 → 40 tests
- Benchmark all 7 protocols
- CI benchmark gate

## Sprint 34: Deployment Readiness
- mpc-node /health endpoint
- Prometheus metrics
- Helm chart
- Docker compose E2E

## Sprint 35: SDK & Developer Experience
- OpenAPI spec export
- TypeScript + Python client types
- SDK quickstart guide

## Sprint 36: Audit Preparation
- Threat model refresh
- Security regression test suite
- v0.1.0-audit tag
