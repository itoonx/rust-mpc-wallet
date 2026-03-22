.PHONY: test test-property bench coverage fmt clippy audit check \
       local-up local-down local-status local-test demo

# ── Development ──────────────────────────────────────────────────────

test:
	cargo test --workspace --features local-transport

test-property:
	cargo test --test property_tests --features local-transport

bench:
	cargo bench --workspace --features local-transport

coverage:
	cargo tarpaulin --workspace --features local-transport --skip-clean

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

audit:
	cargo audit

check: fmt clippy test audit

# ── Local Infrastructure ─────────────────────────────────────────────

local-up:
	./scripts/local-infra.sh up

local-down:
	./scripts/local-infra.sh down

local-status:
	./scripts/local-infra.sh status

local-test:
	./scripts/local-infra.sh test

demo:
	./scripts/demo.sh
