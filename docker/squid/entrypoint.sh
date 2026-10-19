#!/bin/sh
set -eu

# The CA persists in a volume so clients only install it once. The key stays in this container;
# only the certificate is copied to the volume the API serves it from.
CA_DIR=/var/lib/squid-ca
PUBLIC_DIR=/var/lib/squid-ca-public
SSL_DB=/var/spool/squid/ssl_db

if [ ! -s "$CA_DIR/ca.key" ] || [ ! -s "$CA_DIR/ca.crt" ]; then
    echo "generating Sieve proxy CA"
    openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
        -subj "/CN=Sieve Proxy CA" \
        -keyout "$CA_DIR/ca.key" \
        -out "$CA_DIR/ca.crt" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

chown proxy:proxy "$CA_DIR/ca.key" "$CA_DIR/ca.crt"
chmod 0400 "$CA_DIR/ca.key"
chmod 0444 "$CA_DIR/ca.crt"
cp "$CA_DIR/ca.crt" "$PUBLIC_DIR/ca.crt"
chmod 0444 "$PUBLIC_DIR/ca.crt"

# Generated host certificates are signed by the CA, so they are rebuilt rather than kept.
rm -rf "$SSL_DB"
mkdir -p "$(dirname "$SSL_DB")"
/usr/lib/squid/security_file_certgen -c -s "$SSL_DB" -M 4MB
chown -R proxy:proxy "$(dirname "$SSL_DB")"

# Squid opens /dev/stdout and /dev/stderr by path after switching to the proxy user, and under
# Docker those are root-only pipes. Squid keeps these descriptors across exec, so hand them over.
# Rootless Podman refuses the chown, but its pipes are already world-writable.
chown proxy:proxy /proc/self/fd/1 /proc/self/fd/2 2>/dev/null || true

# The helpers inherit this environment, including DATABASE_URL.
exec squid -N -f /etc/squid/squid.conf
