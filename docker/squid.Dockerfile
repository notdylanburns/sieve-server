# Build from server/: docker build -f docker/squid.Dockerfile .
FROM docker.io/library/rust:1.96-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY migrations migrations
# Compose builds the Rust images in parallel over these shared caches, and Cargo's own registry
# lock lives outside them, so BuildKit has to serialise access (sharing=locked).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p sieve-squid-helpers \
    && cp target/release/sieve-acl-helper target/release/sieve-proxy-auth /usr/local/bin/

FROM docker.io/library/debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends squid-openssl openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/sieve-acl-helper /usr/local/bin/sieve-proxy-auth /usr/local/bin/
COPY docker/squid/squid.conf /etc/squid/squid.conf
COPY --chmod=0755 docker/squid/entrypoint.sh /usr/local/bin/sieve-squid-entrypoint
EXPOSE 3128
VOLUME ["/var/lib/squid-ca", "/var/lib/squid-ca-public"]
ENTRYPOINT ["/usr/local/bin/sieve-squid-entrypoint"]
