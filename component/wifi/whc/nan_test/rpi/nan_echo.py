#!/usr/bin/env python3
"""IPv6 NAN test endpoint; one stalled client must not stop other probes."""
import socket
import socketserver
import time

REQUEST = b"NAN-PING\n"
REPLY = b"NAN-PONG\n"


class ProbeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        deadline = time.monotonic() + self.server.client_timeout
        data = bytearray()
        try:
            # TCP may split even this short request across multiple reads.
            while len(data) < len(REQUEST):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("request deadline")
                self.request.settimeout(remaining)
                part = self.request.recv(len(REQUEST) - len(data))
                if not part:
                    print(f"peer={self.client_address} closed bytes={len(data)}", flush=True)
                    return
                data.extend(part)
            valid = data == REQUEST
            print(f"peer={self.client_address} bytes={len(data)} valid={valid}", flush=True)
            if valid:
                self.request.settimeout(self.server.client_timeout)
                self.request.sendall(REPLY)
        except OSError as error:
            # Includes TimeoutError and reset/broken-pipe errors. The listener
            # and other clients remain alive after any per-connection failure.
            print(f"peer={self.client_address} error={type(error).__name__} bytes={len(data)}", flush=True)


class ProbeServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8
    client_timeout = 10


if __name__ == "__main__":
    with ProbeServer(("::", 8000), ProbeHandler) as server:
        server.serve_forever()
