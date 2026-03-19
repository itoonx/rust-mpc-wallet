# MPC Wallet — Multi-stage build for Gateway + MPC Node
# Builds both binaries in one stage, copies to separate runtime targets.
#
# Usage:
#   docker build -f infra/docker/Dockerfile --target gateway -t mpc-gateway .
#   docker build -f infra/docker/Dockerfile --target node -t mpc-node .

# ── Stage 1: Build both binaries ──────────────────────────────────────
FROM rust:1.82-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY services/ services/

RUN cargo build --release -p mpc-wallet-api -p mpc-wallet-node

# ── Stage 2a: Gateway runtime ─────────────────────────────────────────
FROM debian:bookworm-slim AS gateway

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r mpc && useradd -r -g mpc -m mpc
USER mpc

COPY --from=builder /build/target/release/mpc-wallet-api /usr/local/bin/mpc-wallet-api

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/v1/health || exit 1

ENTRYPOINT ["mpc-wallet-api"]

# ── Stage 2b: MPC Node runtime ────────────────────────────────────────
FROM debian:bookworm-slim AS node

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r mpc && useradd -r -g mpc -m mpc

# Key store directory (persistent volume in production)
RUN mkdir -p /data/keys && chown mpc:mpc /data/keys
VOLUME /data/keys

USER mpc

COPY --from=builder /build/target/release/mpc-node /usr/local/bin/mpc-node

ENTRYPOINT ["mpc-node"]
