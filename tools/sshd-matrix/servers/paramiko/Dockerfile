# A server built on Paramiko — Python's SSH stack, used by Fabric, pysftp,
# many CI runners and network-automation tools. Different again from OpenSSH
# and x/crypto in kex ordering and channel timing. pw+key with exec + pty on
# :2223 (pwuser/conch-pw-1, bothuser/conch-pw-2 or keyA).
FROM python:3.12-alpine
RUN pip install --no-cache-dir "paramiko==3.5.0"
COPY server.py /server.py
EXPOSE 2223
ENTRYPOINT ["python", "/server.py"]
