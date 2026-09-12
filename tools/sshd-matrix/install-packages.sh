#!/bin/sh
# Installs the matrix toolset on whichever distro BASE resolved to.
# Required everywhere: sshd + ssh client, pgrep (readiness probe), nc,
# iproute2 (`tc netem` slow-network tests), tmux, shadow tools (useradd /
# chpasswd -e). Optional, best-effort: lrzsz (ZMODEM) — only the default
# Debian image is expected to have it.
set -eu

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        openssh-server openssh-client procps netcat-openbsd iproute2 iptables tmux
    for p in lrzsz; do
        apt-get install -y --no-install-recommends "$p" || echo "optional package $p unavailable"
    done
    rm -rf /var/lib/apt/lists/*
elif command -v apk >/dev/null 2>&1; then
    # busybox userland: `free -b` works, `df -B1` does not (Monitor probe
    # degrades to no disk figures — exactly what the parser must tolerate)
    apk add --no-cache \
        openssh-server openssh-client openssh-sftp-server procps iproute2 iptables tmux \
        netcat-openbsd shadow
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y --setopt=install_weak_deps=False \
        openssh-server openssh-clients procps-ng iproute iptables tmux nmap-ncat shadow-utils
    dnf clean all
else
    echo "unsupported base image: no apt-get, apk or dnf" >&2
    exit 1
fi
