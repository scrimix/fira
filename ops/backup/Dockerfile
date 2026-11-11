# Backup job image: the `fira-backup` Rust binary (same crate and S3 client as
# the API) plus the Postgres client tools only — no server, no Python.
#
# Build context is the REPO ROOT (it needs api/). Deploy with:
#   ops/backup/deploy.sh
#
# PG_MAJOR must match the production server's major version.
ARG PG_MAJOR=17

# --- build ------------------------------------------------------------
FROM rust:1.96-slim-bookworm AS build
WORKDIR /api
COPY api/ ./
RUN cargo build --release --bin fira-backup --no-default-features

# --- runtime ----------------------------------------------------------
FROM debian:bookworm-slim
ARG PG_MAJOR
# PGDG repo for the matching client version; Debian bookworm only ships 15.
ADD https://www.postgresql.org/media/keys/ACCC4CF8.asc /usr/share/keyrings/pgdg.asc
RUN chmod 644 /usr/share/keyrings/pgdg.asc \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && echo "deb [signed-by=/usr/share/keyrings/pgdg.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
         > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-${PG_MAJOR} \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/usr/lib/postgresql/${PG_MAJOR}/bin:$PATH
COPY --from=build /api/target/release/fira-backup /usr/local/bin/fira-backup
ENTRYPOINT ["/usr/local/bin/fira-backup"]
