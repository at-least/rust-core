#!/bin/sh
# Prints a syntactically valid sk-ssh-ed25519@openssh.com public key line
# built from an ordinary ed25519 public key ($1). Wire format of the blob:
#   string "sk-ssh-ed25519@openssh.com"  string key(32)  string application
# No hardware token can sign for it — it exists so sshd parses a security-
# key entry in authorized_keys and so the app's key-line parser sees one.
set -eu
raw=$(awk '{print $2}' "$1" | base64 -d | od -An -v -tx1 | tr -d ' \n')
# ssh-ed25519 blob: 00000000b ssh-ed25519 00000020 <32 bytes>
key=$(printf '%s' "$raw" | cut -c 39-102)
type="sk-ssh-ed25519@openssh.com"
app="ssh:"
hex_str() { # length-prefixed string, hex
    s="$1"; n=${#s}
    printf '%08x' "$n"
    printf '%s' "$s" | od -An -v -tx1 | tr -d ' \n'
}
blob="$(hex_str "$type")00000020${key}$(hex_str "$app")"
b64=$(perl -e 'print pack("H*", $ARGV[0])' "$blob" | base64 | tr -d '\n')
printf '%s %s conch-android-test-sk\n' "$type" "$b64"
