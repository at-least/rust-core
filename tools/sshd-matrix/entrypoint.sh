#!/bin/sh
# Sets up auth-scenario users and runs the sshd instances of the matrix:
#   :2223 pw+pubkey, :2224 pubkey-only, :2225 pw+pubkey with forwarding,
#   :2226 keyboard-interactive via PAM (only where PAM is installed),
#   :2228 "hardened": Banner, MaxSessions 2, PermitOpen to the inner sshd
#         only, a CA-trusted certificate user, authorized_keys option users
#         (forced command / restrict / no-pty) and a chrooted SFTP-only user,
#   :2229 "strict": MaxAuthTries 1, shell channels reaped after 12 s idle
#         (ChannelTimeouts, OpenSSH ≥ 9.2) and idle transports 5 s later,
#   :2230 ecdsa host key only, :2231 rsa host key only (DEBUG1 log),
#   :2232 "legacy": SHA-1 kex + CBC ciphers + ssh-rsa only, the shape of an
#         old appliance,
#   :2270 accepts TCP and never speaks, :2271 sends an SSH banner and then
#         stalls forever (handshake-timeout fixtures; plain nc, no sshd).
# Expects /keys/{keyA.pub,keyB.pub,keyRSA.pub,keyECDSA.pub,ca.pub} mounted
# read-only; optional keySK.pub.
#
# Idempotent: `docker restart` re-runs this on a filesystem where the users
# and host keys already exist — the reconnect tests depend on the host keys
# SURVIVING a restart (a changed key must fail TOFU, a restart must not).
set -eu

mkdir -p /run/sshd

ensure_user() {
    id "$1" >/dev/null 2>&1 || useradd -m -s /bin/sh "$1"
}
for u in pwuser bothuser keyuser skuser certuser cmduser restrictuser noptyuser sftponly; do
    ensure_user "$u"
done

# An account with no password set would be "locked" ('!' in shadow); sshd
# then refuses even pubkey auth ("account is locked"). Set an
# unmatchable-but-unlocked hash instead — same as real hardened servers.
for u in keyuser skuser certuser cmduser restrictuser noptyuser; do
    echo "$u:*" | chpasswd -e
done

echo 'pwuser:conch-pw-1' | chpasswd
echo 'bothuser:conch-pw-2' | chpasswd
echo 'sftponly:conch-pw-3' | chpasswd

# setup_ak USER [OPTIONS] KEY.pub...  — OPTIONS (may be empty) is the
# authorized_keys option prefix applied to every listed key.
setup_ak() {
    user="$1"; opts="$2"; shift 2
    install -d -m 700 -o "$user" -g "$user" "/home/$user/.ssh"
    : > "/home/$user/.ssh/authorized_keys"
    for key in "$@"; do
        [ -f "$key" ] || continue
        if [ -n "$opts" ]; then printf '%s ' "$opts"; fi >> "/home/$user/.ssh/authorized_keys"
        cat "$key" >> "/home/$user/.ssh/authorized_keys"
    done
    chown "$user:$user" "/home/$user/.ssh/authorized_keys"
    chmod 600 "/home/$user/.ssh/authorized_keys"
}
setup_ak bothuser "" /keys/keyA.pub
# keyuser accepts every client key algorithm the app can generate/import
setup_ak keyuser "" /keys/keyB.pub /keys/keyRSA.pub /keys/keyECDSA.pub
# FIDO2 scenario: a security-key public key (sk-ssh-ed25519@openssh.com) in
# authorized_keys. No token exists in the test harness, so nobody can log in
# as skuser — what is exercised is that sshd accepts the key type without
# choking and that the app's failure path is a clean auth rejection.
setup_ak skuser "" /keys/keySK.pub
# authorized_keys option users (hardened-server shapes), all with keyA:
#   cmduser      command="..."  every exec/shell runs the forced command
#   restrictuser restrict,pty   pty allowed, no forwarding / agent / X11
#   noptyuser    no-pty         exec works, pty-req is refused
setup_ak cmduser 'command="echo FORCED_COMMAND_ONLY"' /keys/keyA.pub
setup_ak restrictuser 'restrict,pty' /keys/keyA.pub
setup_ak noptyuser 'no-pty' /keys/keyA.pub
# certuser has NO authorized_keys: only a certificate signed by /keys/ca
# (TrustedUserCAKeys on :2228, principal "certuser") gets in.

# Chrooted SFTP-only account (:2228 Match block): the chroot itself must be
# root-owned and not group/world-writable; the user writes under /upload.
install -d -m 755 -o root -g root /srv/sftp /srv/sftp/sftponly
install -d -m 755 -o sftponly -g sftponly /srv/sftp/sftponly/upload
[ -f /srv/sftp/sftponly/upload/README ] || echo "chroot upload dir" > /srv/sftp/sftponly/upload/README
chown sftponly:sftponly /srv/sftp/sftponly/upload/README

printf 'conch matrix banner line 1\nauthorized use only\n' > /etc/ssh/banner.txt

# Docker tab tests: the host's docker socket may be mounted in. Give the
# test users access via the socket's group (root on Docker Desktop, docker
# on Linux) rather than chmod-ing a host-owned socket.
if [ -S /var/run/docker.sock ]; then
    gid=$(stat -c %g /var/run/docker.sock)
    getent group "$gid" >/dev/null || groupadd -g "$gid" dockersock
    gname=$(getent group "$gid" | cut -d: -f1)
    for u in pwuser bothuser keyuser; do usermod -aG "$gname" "$u"; done
fi

ssh-keygen -A

# Everything below is what every instance shares; instance-specific lines
# come FIRST in each file because OpenSSH is first-match-wins.
common_cfg='
PermitRootLogin no
AllowUsers pwuser bothuser keyuser skuser certuser cmduser restrictuser noptyuser sftponly
PubkeyAuthentication yes
StrictModes yes
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
Subsystem sftp internal-sftp
LogLevel INFO
'
hostkeys_all='
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
'

# write_cfg NAME PORT PASSWORD_AUTH [DIRECTIVE...] → /etc/ssh/sshd_config_NAME:
# Port, the instance's own directives, then the defaults every instance
# shares unless a DIRECTIVE already set them (keyboard-interactive off, all
# host keys), the shared block and the PidFile. Instance lines come before
# the shared block because OpenSSH is first-match-wins. A Match block, which
# must end the file, is appended by the caller.
write_cfg() {
    name=$1; port=$2; pwauth=$3; shift 3
    own_hostkey=0; own_kbd=0
    {
        echo "Port $port"
        echo "PasswordAuthentication $pwauth"
        for d in "$@"; do
            case "$d" in
                HostKey*) own_hostkey=1 ;;
                KbdInteractiveAuthentication*) own_kbd=1 ;;
            esac
            echo "$d"
        done
        [ "$own_kbd" = 1 ] || echo 'KbdInteractiveAuthentication no'
        [ "$own_hostkey" = 1 ] || echo "$hostkeys_all"
        echo "$common_cfg"
        echo "PidFile /run/sshd_$name.pid"
    } > "/etc/ssh/sshd_config_$name"
}

write_cfg pwpub 2223 yes
write_cfg keyonly 2224 no
write_cfg fwd 2225 yes 'AllowTcpForwarding yes'

# Keyboard-interactive ONLY (the shape of every 2FA / PAM-prompt server):
# plain "password" auth is refused; the client must answer the PAM prompt.
write_cfg kbd 2226 no 'UsePAM yes' 'KbdInteractiveAuthentication yes'

# Hardened: the policy knobs real admins turn. PermitOpen lets tunnels reach
# only the inner sshd; MaxSessions 2 = shell + one more channel; the CA
# makes certificate auth possible for certuser; the Match block turns
# sftponly into a chrooted SFTP-only account.
write_cfg hardened 2228 yes \
    'AllowTcpForwarding yes' \
    'PermitOpen 127.0.0.1:2223' \
    'MaxSessions 2' \
    'Banner /etc/ssh/banner.txt' \
    'TrustedUserCAKeys /keys/ca.pub'
cat >> /etc/ssh/sshd_config_hardened <<'MATCH'
Match User sftponly
    ChrootDirectory /srv/sftp/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    PermitTTY no
MATCH

# Strict: one auth attempt, idle shells reaped by the server, idle
# transports closed. ChannelTimeouts / UnusedConnectionTimeout need
# OpenSSH 9.2; on older bases the instance runs without them. Support is
# probed by validating the FULL config with `sshd -t` (host keys already
# exist from ssh-keygen -A above) — `sshd -T -f /dev/null` is unreliable
# because it fails for reasons unrelated to the option under test.
write_cfg strict 2229 yes \
    'MaxAuthTries 1' \
    'ChannelTimeout session:shell=12s session:command=12s' \
    'UnusedConnectionTimeout 5s'
if ! /usr/sbin/sshd -t -f /etc/ssh/sshd_config_strict >/dev/null 2>&1; then
    echo "strict: ChannelTimeout/UnusedConnectionTimeout unsupported by $(sshd -V 2>&1 | head -1) — dropped"
    grep -vE 'ChannelTimeout|UnusedConnectionTimeout' /etc/ssh/sshd_config_strict > /etc/ssh/sshd_config_strict.tmp
    mv /etc/ssh/sshd_config_strict.tmp /etc/ssh/sshd_config_strict
fi

write_cfg ecdsa 2230 yes 'HostKey /etc/ssh/ssh_host_ecdsa_key'
write_cfg rsa 2231 yes 'HostKey /etc/ssh/ssh_host_rsa_key' 'LogLevel DEBUG1'

# Legacy appliance: SHA-1 kex, CBC ciphers, SHA-1 MAC, SHA-1 RSA host-key
# signature — every algorithm modern sshd disables by default. OpenSSH 10
# has dropped some of them entirely; the instance then does not start.
write_cfg legacy 2232 yes \
    'HostKey /etc/ssh/ssh_host_rsa_key' \
    'KexAlgorithms diffie-hellman-group14-sha1' \
    'Ciphers aes256-cbc,aes128-cbc' \
    'MACs hmac-sha1' \
    'HostKeyAlgorithms ssh-rsa'

for i in pwpub fwd hardened strict ecdsa rsa; do
    /usr/sbin/sshd -f "/etc/ssh/sshd_config_$i" -E "/var/log/sshd_$i.log"
done
/usr/sbin/sshd -f /etc/ssh/sshd_config_legacy -E /var/log/sshd_legacy.log \
    || echo "legacy instance (:2232) not started: this OpenSSH no longer offers SHA-1/CBC"

if [ -f /etc/pam.d/sshd ]; then
    /usr/sbin/sshd -f /etc/ssh/sshd_config_kbd -E /var/log/sshd_kbd.log
else
    echo "no PAM on this base: keyboard-interactive instance (:2226) not started"
fi

# Handshake-timeout fixtures: a port that accepts and never speaks, and one
# that sends a banner and then stalls. stdin never reaches EOF so nc never
# half-closes the socket — the client must give up on its own.
#
# DURABILITY: these must survive every client, because when they die the
# port stays PUBLISHED and Docker's proxy answers it with an instant EOF —
# which looks like a fast, clean failure and makes a "gives up quickly"
# assertion pass while testing nothing. (Seen 2026-08-31: both loops were
# gone after a few runs, and conch-ios's two stall tests had been "passing"
# in 5 ms against exactly that.) :2270 therefore uses nc's own -k
# (keep listening) rather than a restart loop; :2271 must re-send its
# banner per client so it keeps the loop, with a guard sleep so a failed
# bind cannot spin.
# :2270 — nc -k accepts client after client from ONE process.
sleep 2147483647 | nc -lk 2270 >/dev/null 2>&1 &
# :2271 — must re-send its banner per client, which a single nc stdin cannot
# do, and a `while :; do ... nc -l ...; done` loop does NOT recycle: with
# stdin held open by a sleep, nc never exits after its client leaves, so the
# loop is stuck on iteration 1 with the port bound but no longer accepting
# (verified 2026-08-31 — neither -w nor a guard sleep changes it). perl is in
# the debian/rocky bases that publish these ports; the nc loop stays as the
# fallback so a base without perl is no worse off than before.
if command -v perl >/dev/null 2>&1; then
    perl -MIO::Socket::INET -e '
        my $l = IO::Socket::INET->new(LocalPort => 2271, Listen => 16,
                                      ReuseAddr => 1, Proto => "tcp") or exit 1;
        my @held;
        while (my $c = $l->accept) {
            $c->autoflush(1);
            print {$c} "SSH-2.0-OpenSSH_9.2 conch-stall\r\n";
            # never close: the client must give up on its own. Bounded so a
            # long run cannot exhaust file descriptors.
            push @held, $c;
            (shift @held)->close if @held > 32;
        }
    ' >/dev/null 2>&1 &
else
    (while :; do { printf 'SSH-2.0-OpenSSH_9.2 conch-stall\r\n'; sleep 2147483647; } | nc -l 2271 >/dev/null 2>&1; sleep 1; done) &
fi

exec /usr/sbin/sshd -D -f /etc/ssh/sshd_config_keyonly -E /var/log/sshd_keyonly.log
