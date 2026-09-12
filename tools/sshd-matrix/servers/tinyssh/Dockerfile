# tinyssh — a minimal, ed25519-only server (no RSA, no password auth, no
# port forwarding). Exercises the app against a deliberately tiny algorithm
# set: if conch assumed RSA host keys or offered password first, it breaks
# here. One instance, key-only on :2224 (keyB). tinysshd is inetd-style, so
# tcpserver (ucspi-tcp) accepts connections and hands each to a fresh
# tinysshd — exactly the deployment tinyssh documents.
FROM alpine:3.20
RUN apk add --no-cache tinyssh ucspi-tcp6 openssh-sftp-server shadow netcat-openbsd
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 2224
ENTRYPOINT ["/entrypoint.sh"]
