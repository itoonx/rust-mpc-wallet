# MPC Wallet API — Multi-stage Rust build
# Usage: docker build -f infra/docker/Dockerfile -t mpc-wallet-api .

# ── Stage 1: Build ──────────────────────────────────────────────────
FROM rust:1.82-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY services/ services/

# Build release binary
RUN cargo build --release -p mpc-wallet-api

# ── Stage 2: Runtime ────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN groupadd -r mpc && useradd -r -g mpc -m mpc
USER mpc

COPY --from=builder /build/target/release/mpc-wallet-api /usr/local/bin/mpc-wallet-api

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/v1/health || exit 1

ENTRYPOINT ["mpc-wallet-api"]
