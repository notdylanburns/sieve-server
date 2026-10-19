# Build from server/: docker build -f docker/metadata-cache.Dockerfile .
FROM docker.io/library/rust:1.96-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY migrations migrations
# Compose builds the Rust images in parallel over these shared caches, and Cargo's own registry
# lock lives outside them, so BuildKit has to serialise access (sharing=locked).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p sieve-metadata-cache \
    && cp target/release/sieve-metadata-cache /usr/local/bin/

# The official yt-dlp executable bundles the EJS component; YouTube extraction also needs a
# JavaScript runtime, and Deno is the one yt-dlp enables by default.
FROM docker.io/library/debian:trixie-slim AS tools
ARG YT_DLP_VERSION=2026.08.19
ARG DENO_VERSION=v2.9.7
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && curl -fsSL -o /usr/local/bin/yt-dlp \
        "https://github.com/yt-dlp/yt-dlp/releases/download/${YT_DLP_VERSION}/yt-dlp_linux" \
    && curl -fsSL -o /tmp/deno.zip \
        "https://github.com/denoland/deno/releases/download/${DENO_VERSION}/deno-x86_64-unknown-linux-gnu.zip" \
    && unzip /tmp/deno.zip -d /usr/local/bin \
    && chmod 0755 /usr/local/bin/yt-dlp /usr/local/bin/deno

FROM docker.io/library/debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin sieve \
    && mkdir -p /var/lib/sieve/icons \
    && chown sieve:sieve /var/lib/sieve/icons
COPY --from=tools /usr/local/bin/yt-dlp /usr/local/bin/deno /usr/local/bin/
COPY --from=build /usr/local/bin/sieve-metadata-cache /usr/local/bin/
ENV ICON_DIR=/var/lib/sieve/icons \
    YT_DLP_BIN=/usr/local/bin/yt-dlp
USER sieve
VOLUME ["/var/lib/sieve/icons"]
CMD ["sieve-metadata-cache", "run"]
