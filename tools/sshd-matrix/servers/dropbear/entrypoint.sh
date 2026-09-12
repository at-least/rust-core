#!/bin/sh
# Dropbear matrix: :2223 pw+key, :2224 key-only, :2225 forwarding allowed.
# pwuser/conch-pw-1, bothuser/conch-pw-2 or keyA, keyuser keyB.
set -eu
ensure_user() { id "$1" >/dev/null 2>&1 || useradd -m -s /bin/sh "$1"; }
ensure_user pwuser; ensure_user bothuser; ensure_user keyuser
echo 'pwuser:conch-pw-1' | chpasswd
echo 'bothuser:conch-pw-2' | chpasswd
echo 'keyuser:*' | chpasswd -e

setup_ak() {
    install -d -m 700 -o "$1" -g "$1" "/home/$1/.ssh"
    cat "$2" > "/home/$1/.ssh/authorized_keys"
    chown "$1:$1" "/home/$1/.ssh/authorized_keys"
    chmod 600 "/home/$1/.ssh/authorized_keys"
}
setup_ak bothuser /keys/keyA.pub
setup_ak keyuser /keys/keyB.pub

mkdir -p /etc/dropbear /run
# One host key per algorithm, generated once and persisted across restarts
[ -f /etc/dropbear/dropbear_ed25519_host_key ] || dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >/dev/null 2>&1
[ -f /etc/dropbear/dropbear_rsa_host_key ] || dropbearkey -t rsa -s 3072 -f /etc/dropbear/dropbear_rsa_host_key >/dev/null 2>&1
KEYS='-r /etc/dropbear/dropbear_ed25519_host_key -r /etc/dropbear/dropbear_rsa_host_key'

# -F foreground, -E stderr, -s no-password not used (we want pw on :2223),
# -g disable password logins for root, -j/-k disable local/remote forwarding.
# shellcheck disable=SC2086
dropbear -p 2223 $KEYS -F -E -j -k -P /run/db_pw.pid &
# shellcheck disable=SC2086
dropbear -p 2224 $KEYS -s -g -F -E -j -k -P /run/db_key.pid &
# :2225 allows forwarding (no -j -k)
# shellcheck disable=SC2086
exec dropbear -p 2225 $KEYS -F -E
