# Multi-stage production build for Fly.io.
#
# This Dockerfile lives at the repo root (no fly.toml — Fly's web UI auto-
# detects `Dockerfile` here) and pulls in both web/ (SPA) and api/ (server)
# from a single build context.

# --- web build ---------------------------------------------------------
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

# --- api build ---------------------------------------------------------
FROM rust:1.88-slim AS api
WORKDIR /api
# Pre-warm the cargo dep cache as its own layer so source-only edits
# don't trigger a from-scratch rebuild of dependencies.
COPY api/Cargo.toml api/Cargo.lock ./
RUN mkdir -p src src/bin \
    && echo '' > src/lib.rs \
    && echo 'fn main(){}' > src/main.rs \
    && echo 'fn main(){}' > src/bin/seed.rs \
    && echo 'fn main(){}' > src/bin/dump_bootstrap.rs \
    && cargo build --release --bin fira-api --no-default-features \
    && rm -rf src
COPY api/ ./
# `--no-default-features` strips the `dev_auth` feature so /auth/dev-login
# and /auth/dev-seed don't exist in the prod binary.
#
# `touch` is load-bearing: Docker COPY preserves the build context's mtimes,
# which are usually OLDER than the dummy build's fingerprint above. Without
# this, cargo sees "source older than cache" and skips rebuilding, leaving
# the placeholder `fn main(){}` binary in target/release/fira-api.
RUN find src -name '*.rs' -exec touch {} + \
    && cargo build --release --bin fira-api --no-default-features \
    && { grep -q "fira-api: starting" /api/target/release/fira-api \
         || { echo "ERROR: built binary is missing expected startup string — cargo likely served the cached dummy build"; exit 1; }; }

# --- runtime ----------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=api /api/target/release/fira-api /app/fira-api
COPY --from=api /api/migrations /app/migrations
COPY --from=web /web/dist /app/dist
ENV STATIC_ROOT=/app/dist \
    API_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
CMD ["/app/fira-api"]
