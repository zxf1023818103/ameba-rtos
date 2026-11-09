#!/usr/bin/env python3
"""IPv6 NAN echo and framed TCP goodput tests (protocol NAN-THROUGHPUT/1).

The TCP endpoint runs on the WHC Linux host; payload travels through Green2's
NDP. Frame headers and control messages are excluded from the byte counters.
"""
import json
import socket
import socketserver
import struct
import time

REQUEST = b"NAN-PING\n"
REPLY = b"NAN-PONG\n"
PROTOCOL = "NAN-THROUGHPUT/1"
BLOCK_SIZE = 64 * 1024
MAX_FRAME_SIZE = 256 * 1024
MAX_SECONDS = 60
FRAME = struct.pack("!I", BLOCK_SIZE) + bytes(range(256)) * (BLOCK_SIZE // 256)
END = b"\0\0\0\0"


class ProtocolError(ValueError):
    pass


class ProbeHandler(socketserver.BaseRequestHandler):
    def remaining(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("operation deadline")
        self.request.settimeout(min(remaining, self.server.client_timeout))

    def read_exact(self, size, deadline):
        data = bytearray()
        while len(data) < size:
            self.remaining(deadline)
            part = self.request.recv(size - len(data))
            if not part:
                raise EOFError("truncated stream")
            data.extend(part)
        return data

    def read_line(self, deadline, limit=256):
        data = bytearray()
        while len(data) < limit:
            data.extend(self.read_exact(1, deadline))
            if data[-1] == 10:
                return bytes(data)
        raise ProtocolError("command too long")

    def send(self, data, deadline):
        self.remaining(deadline)
        self.request.sendall(data)

    def throughput(self, command):
        fields = command.decode("ascii").strip().split()
        if len(fields) != 4 or fields[0] != PROTOCOL:
            raise ProtocolError("unsupported command")
        _, test_id, direction, duration = fields
        if not 1 <= len(test_id) <= 64 or not all(c.isalnum() or c == "-" for c in test_id):
            raise ProtocolError("invalid test id")
        seconds = int(duration)
        if direction not in ("UPLOAD", "DOWNLOAD") or not 1 <= seconds <= MAX_SECONDS:
            raise ProtocolError("invalid direction or duration")
        # Bound stalled clients and allow queued TCP data to drain after the
        # sender's timed interval. Timing starts after READY, before payload.
        deadline = time.monotonic() + seconds + 30
        self.send(b"READY\n", deadline)
        started = time.monotonic()
        count = 0
        if direction == "UPLOAD":
            while True:
                size, = struct.unpack("!I", self.read_exact(4, deadline))
                if size == 0:
                    break
                if size > MAX_FRAME_SIZE:
                    raise ProtocolError("frame too large")
                self.read_exact(size, deadline)
                count += size
        else:
            while time.monotonic() - started < seconds:
                self.send(FRAME, deadline)
                count += BLOCK_SIZE
            self.send(END, deadline)
        elapsed = time.monotonic() - started
        result = {"version": 1, "test_id": test_id, "direction": direction.lower(),
                  "bytes": count, "seconds": elapsed, "mbps": count * 8 / elapsed / 1e6,
                  "counter": "received" if direction == "UPLOAD" else "submitted"}
        self.send(json.dumps(result, separators=(",", ":")).encode() + b"\n", deadline)
        # No payload, pairing material or per-frame logging in the timed path.
        print("throughput=" + json.dumps(result, separators=(",", ":")), flush=True)

    def handle(self):
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            while True:
                deadline = time.monotonic() + self.server.client_timeout
                command = self.read_line(deadline)
                if command == REQUEST:
                    self.send(REPLY, deadline)
                    print(f"peer={self.client_address} bytes={len(command)} valid=True", flush=True)
                    return
                if not command.startswith(PROTOCOL.encode() + b" "):
                    return
                self.throughput(command)
        except (OSError, EOFError, ValueError) as error:
            # Bad/truncated frames, cancellation and idle connections only end
            # this client. Keep the listener and other clients alive.
            print(f"peer={self.client_address} error={type(error).__name__}", flush=True)


class ProbeServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8
    client_timeout = 10



if __name__ == "__main__":
    with ProbeServer(("::", 8000), ProbeHandler) as server:
        server.serve_forever()
