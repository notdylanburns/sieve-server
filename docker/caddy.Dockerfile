# Build from server/: docker build -f docker/caddy.Dockerfile .
# Caddy with the layer4 app, which terminates TLS for the proxy port (see PLAN.md).
FROM docker.io/library/caddy:2.11.7-builder AS build
ARG CADDY_L4_VERSION=51b35f570db10c02893b912c21343dd9c14f59f4
RUN xcaddy build --with "github.com/mholt/caddy-l4@${CADDY_L4_VERSION}"

FROM docker.io/library/caddy:2.11.7
COPY --from=build /usr/bin/caddy /usr/bin/caddy
COPY docker/Caddyfile /etc/caddy/Caddyfile
