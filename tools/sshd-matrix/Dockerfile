# Real-OpenSSH test matrix for conch integration tests.
#
# One image recipe, many bases: BASE selects the distro (and therefore the
# OpenSSH version and userland — glibc vs busybox, procps vs busybox free/df)
# the app is exercised against. The default is Debian bookworm because
# lrzsz (rz/sz) was removed from every alpine repo and bookworm still ships
# it, enabling ZMODEM integration tests against the real binaries.
# install-packages.sh degrades gracefully on bases that lack an optional
# package.
#
# The docker CLI (static binary) is copied in so the in-session Docker tab
# can be tested against a real `docker ps` when run.sh mounts the host's
# docker socket into the default container.
ARG BASE=debian:bookworm-slim
FROM docker:27-cli AS dockercli

FROM ${BASE}
ARG DEBIAN_FRONTEND=noninteractive
COPY install-packages.sh /install-packages.sh
RUN sh /install-packages.sh && rm /install-packages.sh
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 2223 pw+pubkey · 2224 pubkey-only · 2225 forwarding · 2226 keyboard-interactive
# (PAM) · 2228 hardened · 2229 strict · 2230 ecdsa-only · 2231 rsa-only ·
# 2232 legacy · 2270/2271 silent-accept and banner-stall fixtures
EXPOSE 2223 2224 2225 2226 2228 2229 2230 2231 2232 2270 2271
ENTRYPOINT ["/entrypoint.sh"]
