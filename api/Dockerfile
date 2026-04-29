FROM rust:1-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-watch --locked

WORKDIR /app

# Pre-warm dep cache so cold starts are bearable
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --quiet 2>/dev/null || true && \
    rm -rf src

ENV CARGO_TARGET_DIR=/app/target
EXPOSE 3000
CMD ["cargo", "run"]
