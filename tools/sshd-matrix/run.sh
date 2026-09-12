#!/bin/sh
# Starts conch-android's OWN SSH test matrix — deliberately independent of
# the conch-ios harness (scripts/sshd-matrix there): separate image tag,
# container name, host ports and keys, so both projects' matrices can run
# side by side.
#
# Default container (conch-android-sshd, debian bookworm, OpenSSH 9.2):
#   host 2233 → 2223  password + pubkey   pwuser/conch-pw-1, bothuser/conch-pw-2 (keyA)
#   host 2234 → 2224  pubkey only         keyuser (keyB, keyRSA, keyECDSA), bothuser (keyA)
#   host 2235 → 2225  password + pubkey   forwarding allowed (tunnels, agent, jump, SOCKS)
#   host 2236 → 2226  keyboard-interactive only (PAM)   same users as :2233
#   host 2238 → 2228  hardened: Banner, MaxSessions 2, PermitOpen 127.0.0.1:2223,
#                     CA-trusted certuser (keyA-cert.pub), cmduser (forced
#                     command), restrictuser (restrict,pty), noptyuser (no-pty),
#                     sftponly/conch-pw-3 (chroot, internal-sftp only)
#   host 2239 → 2229  strict: MaxAuthTries 1, idle shells reaped after 12 s
#   host 2240 → 2230  ecdsa host key only
#   host 2241 → 2231  rsa host key only
#   host 2242 → 2232  legacy: SHA-1 kex, CBC, ssh-rsa
#   host 2270 → 2270  accepts TCP, never sends a byte
#   host 2271 → 2271  sends an SSH banner, then stalls
#   [::1]:2233 → 2223 the password instance over IPv6
#   + host docker socket mounted (Docker tab tests), NET_ADMIN (tc netem /
#     iptables blackhole tests), a 1 MB tmpfs at /mnt/tiny (disk-full SFTP)
#
# Distro variants (--variants / --variant NAME): same recipe on other bases,
# only the three base instances, host ports BASE..BASE+2 → 2223..2225:
#   ubuntu2004  ubuntu:20.04        OpenSSH 8.2   2243-2245
#   ubuntu2404  ubuntu:24.04        OpenSSH 9.6   2246-2248
#   alpine      alpine:3.20         OpenSSH 9.7, busybox userland   2249-2251
#   trixie      debian:trixie-slim  OpenSSH 10.0 (post-quantum kex default)  2252-2254
#   rocky9      rockylinux:9        OpenSSH 8.7, RHEL crypto policies  2255-2257
#
# Other SSH implementations (--servers / --server NAME), see servers/*:
#   dropbear   2263 pw+key (no forwarding) · 2264 key-only · 2265 forwarding
#   tinyssh    2266 key-only (ed25519, no password, no forwarding)
#   gossh      2267 pw+key + forwarding + sftp (golang.org/x/crypto/ssh)
#   paramiko   2268 pw+key + pty/exec (python paramiko server)
#
# Keys: keyA/keyB/keyC ed25519, keyRSA (3072), keyECDSA (P-256), ca (+ keyA
# signed as keyA-cert.pub for principal certuser). keyC is generated but
# never installed — the "unknown client key" scenario. keySK.pub is a
# synthetic sk-ssh-ed25519@openssh.com public key (no token exists)
# installed for skuser — the FIDO2 authorized_keys scenario.
#
# Idempotent: reuses a running container as-is. --rebuild force-recreates
# (drops active sessions; host keys change). --stop removes everything.
# Keys live in ${CONCH_ANDROID_MATRIX_KEYS:-~/.cache/conch-android/sshd-matrix/keys},
# generated once and reused.
#
# Opt-in JVM tests run against it with:
#   ./gradlew testFossDebugUnitTest -Dconch.localSshdTest=true --tests '*.Docker*Test'
# and, with the variants/servers up, additionally -Dconch.distroMatrix=true
set -eu

NAME=conch-android-sshd
IMAGE=conch-android-sshd:latest
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KEYS_DIR=${CONCH_ANDROID_MATRIX_KEYS:-"${XDG_CACHE_HOME:-$HOME/.cache}/conch-android/sshd-matrix/keys"}
DOCKER_SOCK=${CONCH_ANDROID_DOCKER_SOCK:-/var/run/docker.sock}

# name=base=first-host-port
VARIANTS="ubuntu2004=ubuntu:20.04=2243
ubuntu2404=ubuntu:24.04=2246
alpine=alpine:3.20=2249
trixie=debian:trixie-slim=2252
rocky9=rockylinux:9=2255"

# name=host-port-spec (docker -p arguments, space separated)
SERVERS="dropbear=127.0.0.1:2263-2265:2223-2225
tinyssh=127.0.0.1:2266:2224
gossh=127.0.0.1:2267:2223
paramiko=127.0.0.1:2268:2223"

log() { printf '%s\n' "$*"; }

generate_keys() {
    mkdir -p "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"
    for k in keyA keyB keyC ca; do
        [ -f "$KEYS_DIR/$k" ] && continue
        log "generating $KEYS_DIR/$k (ed25519)"
        ssh-keygen -q -t ed25519 -N '' -C "conch-android-test-$k" -f "$KEYS_DIR/$k"
    done
    if [ ! -f "$KEYS_DIR/keyRSA" ]; then
        log "generating $KEYS_DIR/keyRSA (rsa 3072)"
        ssh-keygen -q -t rsa -b 3072 -N '' -C conch-android-test-keyRSA -f "$KEYS_DIR/keyRSA"
    fi
    if [ ! -f "$KEYS_DIR/keyECDSA" ]; then
        log "generating $KEYS_DIR/keyECDSA (ecdsa p256)"
        ssh-keygen -q -t ecdsa -b 256 -N '' -C conch-android-test-keyECDSA -f "$KEYS_DIR/keyECDSA"
    fi
    # A DEDICATED key for the certificate scenario: sshj (like the OpenSSH
    # client) auto-loads a sibling <key>-cert.pub and then presents the
    # CERTIFICATE, so signing keyA would break every plain-keyA login. keyCert
    # is used only by the cert test; keyA/keyB stay pristine.
    if [ ! -f "$KEYS_DIR/keyCert" ]; then
        log "generating $KEYS_DIR/keyCert (ed25519) for the certificate scenario"
        ssh-keygen -q -t ed25519 -N '' -C conch-android-test-keyCert -f "$KEYS_DIR/keyCert"
    fi
    if [ ! -f "$KEYS_DIR/keyCert-cert.pub" ]; then
        log "signing keyCert with ca for principal certuser → keyCert-cert.pub"
        ssh-keygen -q -s "$KEYS_DIR/ca" -I conch-android-test-cert -n certuser -V -1d:+3650d "$KEYS_DIR/keyCert.pub"
    fi
    # A syntactically valid sk-ssh-ed25519 public key: type, 32-byte key,
    # application string "ssh:". Made from keyC's raw public key so it is
    # stable per keys dir; there is no matching token anywhere.
    if [ ! -f "$KEYS_DIR/keySK.pub" ]; then
        log "generating $KEYS_DIR/keySK.pub (synthetic sk-ssh-ed25519)"
        "$HERE/make-sk-pubkey.sh" "$KEYS_DIR/keyC.pub" > "$KEYS_DIR/keySK.pub"
    fi
}

variant_field() { # name field(2=base,3=port)
    printf '%s\n' "$VARIANTS" | awk -F= -v n="$1" -v f="$2" '$1 == n { print $f }'
}

server_ports() { # name
    printf '%s\n' "$SERVERS" | awk -F= -v n="$1" '$1 == n { print $2 }'
}

names_of() { # table  — the name column, space separated
    printf '%s\n' "$1" | cut -d= -f1 | tr '\n' ' '
}

running_mount_source() {
    docker inspect "$1" --format '{{range .Mounts}}{{if eq .Destination "/keys"}}{{.Source}}{{end}}{{end}}' 2>/dev/null
}

is_running() {
    [ "$(docker inspect "$1" --format '{{.State.Running}}' 2>/dev/null)" = "true" ]
}

wait_ready() { # container
    i=0
    while [ "$i" -lt 100 ]; do
        if docker exec "$1" sh -c \
            'pgrep -f sshd_config_pwpub >/dev/null && pgrep -f sshd_config_keyonly >/dev/null && pgrep -f sshd_config_fwd >/dev/null'; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.2
    done
    return 1
}

wait_port_answers() { # container port  — a process listens on the port inside the container
    i=0
    while [ "$i" -lt 100 ]; do
        if docker exec "$1" sh -c "nc -z 127.0.0.1 $2" >/dev/null 2>&1; then
            return 0
        fi
        i=$((i + 1))
        sleep 0.2
    done
    return 1
}

build_image() { # image base
    log "building $1 (BASE=$2)"
    docker build -q --build-arg "BASE=$2" -t "$1" "$HERE" >/dev/null
}

start_default() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    log "starting container $NAME with keys from $KEYS_DIR"
    sock_mount=""
    if [ -S "$DOCKER_SOCK" ]; then
        sock_mount="-v $DOCKER_SOCK:/var/run/docker.sock"
    else
        log "no docker socket at $DOCKER_SOCK — Docker tab tests will skip"
    fi
    # Opt-in real-device testing: CONCH_MATRIX_BIND accepts a space-separated
    # list of host addresses to publish the fixtures on (a USB-attached phone
    # cannot reach the host's loopback, so pass the LAN IP alongside it). The
    # default stays loopback-only — the fixtures carry fixed test credentials
    # and must not silently face the LAN.
    BINDS="${CONCH_MATRIX_BIND:-127.0.0.1}"
    case " $BINDS " in *" 127.0.0.1 "*) ;; *)
        log "CONCH_MATRIX_BIND=$BINDS — fixtures exposed beyond loopback; undo with ./run.sh --stop"
    ;; esac
    port_args=()
    for bind in $BINDS; do
        port_args+=(-p "$bind":2233-2236:2223-2226)
        port_args+=(-p "$bind":2238-2242:2228-2232)
        port_args+=(-p "$bind":2270-2271:2270-2271)
    done
    # shellcheck disable=SC2086
    docker run -d --init --name "$NAME" \
        --cap-add NET_ADMIN \
        "${port_args[@]}" \
        -p '[::1]:2233:2223' \
        --tmpfs /mnt/tiny:size=1m,mode=1777 \
        -v "$KEYS_DIR":/keys:ro \
        $sock_mount \
        "$IMAGE" >/dev/null
    if wait_ready "$NAME"; then
        log "ready:"
        log "  127.0.0.1:2233  pwuser/conch-pw-1 | bothuser: pw conch-pw-2 or keyA   (also [::1]:2233)"
        log "  127.0.0.1:2234  key-only: keyuser with keyB/keyRSA/keyECDSA, bothuser with keyA"
        log "  127.0.0.1:2235  forwarding allowed (same users as :2233)"
        log "  127.0.0.1:2236  keyboard-interactive only (same users as :2233)"
        log "  127.0.0.1:2238  hardened — banner, MaxSessions 2, PermitOpen, certuser, cmduser, restrictuser, noptyuser, sftponly/conch-pw-3"
        log "  127.0.0.1:2239  strict — MaxAuthTries 1, idle shell reaped after 12 s"
        log "  127.0.0.1:2240  ecdsa-only host key · 2241 rsa-only · 2242 legacy SHA-1/CBC"
        log "  127.0.0.1:2270  silent accept · 2271 banner then stall"
        log "  rejected-by-design: any password on :2234, keyC anywhere, forwarding on :2233/:2234"
    else
        log "container did not become ready; logs:"
        docker logs "$NAME" || true
        exit 1
    fi
}

# start_aux NAME PORT_SPEC READY_FN READY_ARG BUILD_ARG...  — one auxiliary
# container (variant or alternate server): reuse it if running, else build
# its image from BUILD_ARGs, start it with PORT_SPEC and the keys mount, and
# wait until READY_FN CNAME READY_ARG succeeds.
start_aux() {
    cname="$NAME-$1"
    image="conch-android-sshd:$1"
    ports=$2
    ready_fn=$3
    ready_arg=$4
    shift 4
    if [ "$FORCE" != 1 ] && is_running "$cname"; then
        log "reusing running $cname ($ports)"
        return 0
    fi
    log "building $image"
    docker build -q "$@" -t "$image" >/dev/null
    docker rm -f "$cname" >/dev/null 2>&1 || true
    log "starting $cname on $ports"
    docker run -d --init --name "$cname" \
        -p "$ports" \
        -v "$KEYS_DIR":/keys:ro \
        "$image" >/dev/null
    # shellcheck disable=SC2086
    if ! "$ready_fn" "$cname" $ready_arg; then
        log "$cname did not become ready; logs:"
        docker logs "$cname" || true
        exit 1
    fi
}

start_variant() { # name
    base=$(variant_field "$1" 2)
    port=$(variant_field "$1" 3)
    [ -n "$base" ] || { log "unknown variant '$1'"; exit 2; }
    start_aux "$1" "127.0.0.1:$port-$((port + 2)):2223-2225" wait_ready "" --build-arg "BASE=$base" "$HERE"
}

start_server() { # name
    ports=$(server_ports "$1")
    [ -n "$ports" ] || { log "unknown server '$1'"; exit 2; }
    inner_port=${ports##*:}
    inner_port=${inner_port%%-*}
    start_aux "$1" "$ports" wait_port_answers "$inner_port" "$HERE/servers/$1"
}

stop_all() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    for v in $(names_of "$VARIANTS") $(names_of "$SERVERS"); do
        docker rm -f "$NAME-$v" >/dev/null 2>&1 || true
    done
    log "matrix stopped"
}

FORCE=0
WANT_DEFAULT=1
WANT_VARIANTS=""
WANT_SERVERS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --rebuild) FORCE=1 ;;
        --stop) stop_all; exit 0 ;;
        --variants) WANT_VARIANTS=$(names_of "$VARIANTS") ;;
        --variant) shift; WANT_VARIANTS="$WANT_VARIANTS $1"; WANT_DEFAULT=0 ;;
        --servers) WANT_SERVERS=$(names_of "$SERVERS") ;;
        --server) shift; WANT_SERVERS="$WANT_SERVERS $1"; WANT_DEFAULT=0 ;;
        --no-default) WANT_DEFAULT=0 ;;
        *) log "usage: $0 [--rebuild] [--variants | --variant NAME]... [--servers | --server NAME]... [--no-default] [--stop]"; exit 2 ;;
    esac
    shift
done

generate_keys

if [ "$WANT_DEFAULT" = 1 ]; then
    if [ "$FORCE" != 1 ] && is_running "$NAME"; then
        mounted=$(running_mount_source "$NAME")
        if [ "$mounted" = "$KEYS_DIR" ]; then
            log "reusing running container $NAME (ports 127.0.0.1:2233-2242)"
        else
            log "WARNING: running $NAME mounts keys from '${mounted:-none}', not '$KEYS_DIR'."
            log "         Fix with: $0 --rebuild"
        fi
    else
        build_image "$IMAGE" debian:bookworm-slim
        start_default
    fi
fi

for v in $WANT_VARIANTS; do
    start_variant "$v"
done

for s in $WANT_SERVERS; do
    start_server "$s"
done
