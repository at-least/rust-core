# Dropbear — what routers, OpenWrt, embedded boxes and many NAS units run.
# Different kex/hostkey negotiation, its own SFTP is absent (uses the
# OpenSSH sftp-server binary if present), no server-side keep-alive
# extensions. Three instances mirror the OpenSSH matrix's base three.
FROM alpine:3.20
RUN apk add --no-cache dropbear dropbear-ssh openssh-sftp-server shadow netcat-openbsd
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 2223 2224 2225
ENTRYPOINT ["/entrypoint.sh"]
