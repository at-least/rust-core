"""Minimal Paramiko SSH server for the conch matrix.

Auth: password (pwuser/conch-pw-1, bothuser/conch-pw-2) and public key
(bothuser = keyA). Channels: exec (runs /bin/sh -c), pty-req + shell (echoes
TERM, then line-echoes). One ed25519 host key, generated on boot.
"""
import os
import socket
import subprocess
import threading

import paramiko

HOST_KEY = paramiko.RSAKey.generate(3072)


def load_authorized(path):
    keys = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                keys.append(paramiko.PKey.from_type_string(parts[0], __import__("base64").b64decode(parts[1])))
    except (OSError, Exception):
        pass
    return keys


KEY_A = load_authorized("/keys/keyA.pub")


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.command = None
        self.term = "vt100"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username == "pwuser" and password == "conch-pw-1":
            return paramiko.AUTH_SUCCESSFUL
        if username == "bothuser" and password == "conch-pw-2":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username == "bothuser" and any(key == k for k in KEY_A):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_pty_request(self, channel, term, w, h, pw, ph, modes):
        self.term = term.decode() if isinstance(term, bytes) else term
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode() if isinstance(command, bytes) else command
        self.event.set()
        return True


def handle(client):
    t = paramiko.Transport(client)
    t.add_server_key(HOST_KEY)
    server = Server()
    try:
        t.start_server(server=server)
    except Exception:
        return
    chan = t.accept(20)
    if chan is None:
        t.close()
        return
    server.event.wait(20)
    if server.command is not None:
        proc = subprocess.run(["/bin/sh", "-c", server.command], capture_output=True)
        chan.sendall(proc.stdout)
        if proc.stderr:
            chan.sendall_stderr(proc.stderr)
        chan.send_exit_status(proc.returncode)
    else:
        chan.sendall(("TERM=%s\r\n" % server.term).encode())
        try:
            while True:
                data = chan.recv(4096)
                if not data:
                    break
                chan.sendall(data)
        except Exception:
            pass
    chan.close()
    t.close()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 2223))
    sock.listen(100)
    while True:
        client, _ = sock.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
