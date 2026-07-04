# Runtime image for the REALITY-enabled 2cha (glibc + embedded Go xtls/reality
# core). The binary is cross-built ahead of time and copied in per architecture,
# so this image runs on any host with a container runtime — Alpine, NixOS,
# Debian, Ubuntu — where the raw glibc binary would not (e.g. NixOS has no
# /lib64 loader).
#
#   docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
#     -v /etc/2cha:/etc/2cha ghcr.io/keepinfov/2cha:<tag> server --config /etc/2cha/server.toml
FROM debian:bookworm-slim

ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# dist/<arch>/2cha is staged by the release workflow (amd64, arm64).
COPY dist/${TARGETARCH}/2cha /usr/local/bin/2cha
RUN chmod +x /usr/local/bin/2cha

ENTRYPOINT ["/usr/local/bin/2cha"]
