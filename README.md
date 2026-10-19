# Sieve server

The Sieve API, web console, filtering proxy and metadata cache, run with Docker Compose. Client
machines (the NixOS config in `../client`) sign in to the API and send their browsing through the
proxy, which only allows what their workspace approves.

| Service | What it does |
|---|---|
| `caddy` | HTTPS for the web console and API, and the TLS-wrapped proxy port 3129 |
| `api` | Web console, REST API, live updates; also carries the `sieve` admin CLI |
| `squid` | The filtering proxy: device login, HTTPS inspection, per-workspace rules |
| `metadata-cache` | Fetches titles, icons and video details for approved sites and videos |
| `postgres` | All state, including the audit log |

See `../PLAN.md` for the design.

## First run

You need Docker with Compose, a DNS name pointing at the host, and ports 80, 443 and 3129
reachable. Caddy gets a certificate from Let's Encrypt automatically.

1. Configure:

   ```sh
   cp .env.example .env
   openssl rand -base64 32   # use for POSTGRES_PASSWORD
   openssl rand -base64 32   # use for JWT_SECRET
   $EDITOR .env              # set DOMAIN and the two secrets
   ```

2. Start everything:

   ```sh
   docker compose up -d --build
   ```

3. Create the first user and workspace with the admin CLI:

   ```sh
   docker compose exec api sieve user create alice          # prompts for a password
   docker compose exec api sieve workspace create "Home"    # prints the workspace id
   docker compose exec api sieve workspace add-member <workspace-id> alice --role owner
   ```

4. Sign in at `https://$DOMAIN`. Owners can invite other people from the **Invites** page.

5. Add a device on the **Devices** page (or `sieve device create <workspace-id> <name>`). Copy
   its token and proxy credentials; they aren't shown again.

6. On the device, configure:

   - The proxy `https://$DOMAIN:3129`, with the device's proxy username and password.
   - Trust for the proxy's CA certificate, from `https://$DOMAIN/api/proxy-ca.crt`. The proxy
     inspects HTTPS traffic, so browsers on the device must trust this CA.
   - The device token, for the desktop manager to fetch the application list and live updates.

Check the proxy from any machine:

```sh
curl -fsSL -o sieve-ca.crt https://$DOMAIN/api/proxy-ca.crt
curl --proxy https://$DOMAIN:3129 --proxy-user '<proxy username>:<proxy password>' \
     --cacert sieve-ca.crt -I https://example.com
```

Sites the workspace hasn't approved get `403`; wrong credentials get `407`.

## Operations

- **Logs:** `docker compose logs -f api` (or `squid`, `metadata-cache`, `caddy`). Squid's
  access log shows each request with the device's proxy username.
- **Audit log:** owners see their workspace's log in the console. Everything, including failed
  logins, is in `docker compose exec api sieve audit list [--workspace <id>] [--since 2026-01-01]`.
  Set `AUDIT_RETENTION_DAYS` to purge old entries daily.
- **Revoking a device** cuts off the API and live updates immediately. The proxy keeps accepting
  it for up to 5 minutes while Squid's login and decision caches expire.
- **Approving a site** takes effect at once for URLs the device hasn't just tried. One that was
  denied in the last 10 seconds stays denied until Squid's deny cache expires.
- **Client IPs in the audit log** come from Caddy's `X-Forwarded-For`. Under rootless Podman,
  published ports hide the client address, so every request appears to come from Caddy; rootful
  Docker passes the real address through.
- **Reading the database over the network:** set `POSTGRES_BIND=0.0.0.0` (and firewall the
  port). Connect as user `sieve` to database `sieve`.
- **Backups:** `docker compose exec postgres pg_dump -U sieve sieve > sieve.sql`. Also keep the
  `squid-ca` volume, or every device will need the new CA after a restore.
- **Upgrading:** `git pull && docker compose up -d --build`. The API and metadata cache apply
  database migrations at startup.
- **`JWT_SECRET`** signs sessions, device tokens and invite links. Changing it signs everyone
  out and invalidates every device token and invite link.
- **Stopping:** the services shut down on `docker compose stop`; Rust services run under an init
  process (`init: true`) so they receive the signal.

## Development

Tests need a PostgreSQL server where the user can create databases (each test gets its own):

```sh
docker run --rm -d -e POSTGRES_USER=sieve -e POSTGRES_PASSWORD=sieve -p 127.0.0.1:55432:5432 postgres:17-alpine
DATABASE_URL=postgres://sieve:sieve@127.0.0.1:55432/sieve cargo test --workspace
```

Run the API locally against that database, and the frontend dev server, which proxies `/api`
(including the events WebSocket) to it:

```sh
DATABASE_URL=postgres://sieve:sieve@127.0.0.1:55432/sieve JWT_SECRET=$(openssl rand -base64 32) \
  ICON_DIR=/tmp/sieve-icons FRONTEND_DIR=frontend/dist BIND_ADDRESS=127.0.0.1:8080 \
  cargo run -p sieve-api
(cd frontend && npm ci && npm run dev)
```
