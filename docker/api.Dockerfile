# Build from server/: docker build -f docker/api.Dockerfile .
# The image runs the API and also carries the `sieve` admin CLI (docker compose exec api sieve ...).
FROM docker.io/library/node:22-trixie-slim AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./
RUN npm run build

FROM docker.io/library/rust:1.96-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY migrations migrations
# Compose builds the Rust images in parallel over these shared caches, and Cargo's own registry
# lock lives outside them, so BuildKit has to serialise access (sharing=locked).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p sieve-api -p sieve-cli \
    && cp target/release/sieve-api target/release/sieve /usr/local/bin/

FROM docker.io/library/debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin sieve
COPY --from=build /usr/local/bin/sieve-api /usr/local/bin/sieve /usr/local/bin/
COPY --from=frontend /src/dist /usr/share/sieve/frontend
ENV BIND_ADDRESS=0.0.0.0:8080 \
    FRONTEND_DIR=/usr/share/sieve/frontend \
    ICON_DIR=/var/lib/sieve/icons
USER sieve
EXPOSE 8080
CMD ["sieve-api"]
