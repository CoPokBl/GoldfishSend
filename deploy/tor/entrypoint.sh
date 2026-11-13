#!/bin/sh
# Writes the torrc into tmpfs (the root filesystem is read-only) and starts Tor in the foreground.
# Hidden-service keys live in /var/lib/tor/goldfish on the tor_data volume: back it up, because it IS
# the onion address. Print the address with:
#   docker compose --profile onion exec tor cat /var/lib/tor/goldfish/hostname
set -eu

: "${GOLDFISH_ONION_CADDY_IP:=172.30.251.2}"

umask 077
cat > /tmp/torrc <<EOF
DataDirectory /var/lib/tor
# Server-side onion service only: no SOCKS proxy, no relaying.
SocksPort 0
ClientOnly 1
HiddenServiceDir /var/lib/tor/goldfish
HiddenServicePort 80 ${GOLDFISH_ONION_CADDY_IP}:8081
# Built-in defences against introduction-point flooding.
HiddenServiceEnableIntroDoSDefense 1
HiddenServicePoWDefensesEnabled 1
# Notices only, to stdout. Tor doesn't log client data.
Log notice stdout
SafeLogging 1
EOF

exec tor -f /tmp/torrc
