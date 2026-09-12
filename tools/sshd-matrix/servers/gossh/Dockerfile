# A server built on golang.org/x/crypto/ssh — the stack behind Gitea, Gogs,
# gliderlabs/ssh and many bespoke git/bastion servers. Its banner, kex and
# channel handling differ from OpenSSH; this catches OpenSSH-only
# assumptions. pw+key, exec + pty + SFTP + direct-tcpip on :2223.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -o /gossh .

FROM alpine:3.20
RUN apk add --no-cache netcat-openbsd
COPY --from=build /gossh /gossh
EXPOSE 2223
ENTRYPOINT ["/gossh"]
