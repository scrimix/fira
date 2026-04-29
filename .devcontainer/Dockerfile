# Dev shell image: Rust + Node + Postgres client + general tooling.
# This is the container VS Code attaches to. The api/ and web/ services from
# docker-compose.yml still run independently — this is a workbench, not a
# replacement for those.

FROM mcr.microsoft.com/devcontainers/base:bookworm

ARG RUST_VERSION=1.88
ARG NODE_VERSION=22

ENV DEBIAN_FRONTEND=noninteractive \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev ca-certificates curl git \
        postgresql-client jq \
    && rm -rf /var/lib/apt/lists/*

# Node + pnpm via corepack
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && corepack enable \
    && corepack prepare pnpm@9.15.0 --activate \
    && rm -rf /var/lib/apt/lists/*

# Rust toolchain via rustup as the vscode user (so cargo writes are owned correctly)
USER vscode
ENV CARGO_HOME=/home/vscode/.cargo \
    RUSTUP_HOME=/home/vscode/.rustup \
    PATH=/home/vscode/.cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal \
        --component rustfmt --component clippy --component rust-src \
    && cargo install --locked cargo-watch sqlx-cli --no-default-features \
        --features postgres,rustls 2>/dev/null || true

USER root
WORKDIR /workspace
