#!/usr/bin/env python3
"""The minimal IPv6 TCP echo endpoint used in the iPhone bring-up test."""
import socket

with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("::", 8000))
    server.listen(4)
    while True:
        client, address = server.accept()
        with client:
            client.settimeout(10)
            data = client.recv(256)
            print(f"peer={address} bytes={len(data)} payload={data!r}", flush=True)
            if data == b"NAN-PING\n":
                client.sendall(b"NAN-PONG\n")
