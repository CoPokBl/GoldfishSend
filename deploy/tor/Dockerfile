# Optional GoldfishSend onion service (compose profile "onion").
# Publishes a v3 onion address whose port 80 forwards to Caddy's onion-only listener.
FROM docker.io/library/alpine:3.22

RUN apk add --no-cache tor \
    && mkdir -p /var/lib/tor \
    && chown -R tor:tor /var/lib/tor \
    && chmod 0700 /var/lib/tor

COPY --chmod=0755 entrypoint.sh /usr/local/bin/goldfish-tor

USER tor
ENTRYPOINT ["/usr/local/bin/goldfish-tor"]
