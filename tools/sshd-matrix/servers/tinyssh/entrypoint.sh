#!/bin/sh
# tinyssh key-only on :2224 — keyuser with keyB.
set -eu
id keyuser >/dev/null 2>&1 || useradd -m -s /bin/sh keyuser
echo 'keyuser:*' | chpasswd -e
install -d -m 700 -o keyuser -g keyuser /home/keyuser/.ssh
cat /keys/keyB.pub > /home/keyuser/.ssh/authorized_keys
chown keyuser:keyuser /home/keyuser/.ssh/authorized_keys
chmod 600 /home/keyuser/.ssh/authorized_keys

mkdir -p /etc/tinyssh
[ -d /etc/tinyssh/sshkeydir ] || tinysshd-makekey /etc/tinyssh/sshkeydir >/dev/null 2>&1

# tcpserver accepts on 2224 and execs tinysshd per connection (inetd style).
exec tcpserver -HRl0 0.0.0.0 2224 /usr/sbin/tinysshd -v /etc/tinyssh/sshkeydir
