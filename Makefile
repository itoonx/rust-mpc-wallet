.PHONY: test test-property bench coverage fmt clippy audit check \
       security-test sbom openapi \
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

security-test:
	@echo "Running security regression tests..."
	cargo test --workspace --features local-transport -- \
		--test-threads=4 \
		zk_proofs \
		paillier \
		sign_authorization \
		identifiable_abort \
		pimod \
		pifac \
		pienc \
		piaffg \
		pilogstar \
		schnorr \
		zeroiz \
		rate_limit \
		presignature_store \
		auth_security \
		signed_message \
		2>&1 | tail -5
	@echo "Security tests complete."

sbom:
	cargo tree --workspace --depth 1 --format "{p} {l}" > docs/SBOM.txt
	@echo "SBOM generated: docs/SBOM.txt ($$(wc -l < docs/SBOM.txt) packages)"

openapi:
	cargo test -p mpc-wallet-api export_openapi_spec -- --ignored --nocapture
	@echo "OpenAPI spec exported to docs/openapi.json"

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
