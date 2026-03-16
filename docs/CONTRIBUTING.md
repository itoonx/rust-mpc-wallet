# Contributing

We welcome contributions from humans and LLMs alike.

## For Humans

```bash
# 1. Fork & clone
git clone https://github.com/<you>/vaultex-mpc-rust.git
cd vaultex-mpc-rust

# 2. Create a feature branch
git checkout -b feat/your-feature

# 3. Make changes & test
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

# 4. Open a PR against `main`
```

## For LLMs / AI Agents

This project was built by a team of AI agents using Claude Code. If you're an LLM:

1. **Read `CLAUDE.md`** first — shared agent memory with full project context
2. **Read `docs/AGENTS.md`** — find which files you're allowed to touch
3. **Read `LESSONS.md`** — learn from past bugs so you don't repeat them
4. **Follow the checkpoint commit rule:**
   ```
   [R{N}] checkpoint: {what changed} — tests pass
   ```
5. **Never** commit without `cargo test` passing first
6. **Never** modify files outside your owned list

## Agent Roles

| Role | ID | Owns |
|------|----|------|
| Architect | R0 | traits, types, error, Cargo.toml |
| Crypto | R1 | protocol/*.rs |
| Infra | R2 | transport/, key_store/, audit/, ops/ |
| EVM | R3a | chains/evm/ |
| Bitcoin | R3b | chains/bitcoin/ |
| Solana | R3c | chains/solana/ |
| Sui | R3d | chains/sui/ |
| Service | R4 | services/, cli/, policy/, identity/, rbac/ |
| QA | R5 | tests/, .github/workflows/ |
| Security | R6 | docs/SECURITY*.md |
| PM | R7 | docs/PRD.md, EPICS.md, SPRINT.md |

## Good First Issues

- [ ] Add Avalanche C-Chain support (EVM-compatible, follow `evm/` pattern)
- [ ] Add Cosmos/IBC chain adapter
- [ ] Implement FROST Ed25519 reshare with group key preservation
- [ ] Add `--output json` flag to all CLI commands
- [ ] Write integration test with live NATS server
- [ ] Add Prometheus metrics export for quorum risk monitoring

## CI Requirements

All PRs must pass:

```
cargo fmt --all -- --check      # formatting
cargo clippy --workspace -- -D warnings  # lint
cargo test --workspace          # 233+ tests
cargo audit                     # security advisory check
```

## Branch Workflow

- Work on `dev` branch
- Push to `dev`, wait for CI green
- Create PR from `dev` to `main`
- Never push directly to `main`
