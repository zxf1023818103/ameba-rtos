#!/usr/bin/env python3
"""Regression: stalled/fragmented/reset TCP clients cannot kill the endpoint."""
import importlib.util
import json
import pathlib
import socket
import struct
import threading
import time
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / "nan_test/rpi/nan_echo.py"
spec = importlib.util.spec_from_file_location("nan_echo", path)
echo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(echo)


class EchoTest(unittest.TestCase):
    def setUp(self):
        self.server = echo.ProbeServer(("::1", 0), echo.ProbeHandler)
        self.server.client_timeout = 0.2
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def connect(self):
        return socket.create_connection(self.server.server_address[:2], timeout=1)

    def probe(self, fragmented=False):
        with self.connect() as client:
            if fragmented:
                client.sendall(b"NAN-")
                time.sleep(0.02)
                client.sendall(b"PING\n")
            else:
                client.sendall(echo.REQUEST)
            with client.makefile("rb") as stream:
                self.assertEqual(stream.readline(), echo.REPLY)

    def test_idle_client_does_not_block_or_kill_server(self):
        with self.connect() as idle:
            self.probe(fragmented=True)
            time.sleep(0.25)
            self.assertEqual(idle.recv(1), b"")
        self.probe()
        self.assertTrue(self.thread.is_alive())

    def test_partial_close_and_bad_request_are_isolated(self):
        with self.connect() as client:
            client.sendall(b"NAN-")
        with self.connect() as client:
            client.sendall(b"BAD-PING\n")
            self.assertEqual(client.recv(1), b"")
        self.probe()

    def test_upload_and_download_share_connection_and_count_payload_only(self):
        with self.connect() as client, client.makefile("rb") as stream:
            # A fragmented header and payload must be parsed as a TCP stream.
            client.sendall(b"NAN-THROUGHPUT/1 regression UP")
            client.sendall(b"LOAD 1\n")
            self.assertEqual(stream.readline(), b"READY\n")
            payload = b"payload\x00with\ncontrol-like bytes" * 100
            frame = struct.pack("!I", len(payload)) + payload
            for start in range(0, len(frame), 17):
                client.sendall(frame[start:start + 17])
            client.sendall(b"\0\0\0\0")
            result = json.loads(stream.readline())
            self.assertEqual(result["bytes"], len(payload))
            self.assertEqual(result["counter"], "received")
            self.assertEqual(result["test_id"], "regression")
            self.assertAlmostEqual(result["mbps"], len(payload) * 8 / result["seconds"] / 1e6)

            client.sendall(b"NAN-THROUGHPUT/1 regression DOWNLOAD 1\n")
            self.assertEqual(stream.readline(), b"READY\n")
            received = 0
            while True:
                header = stream.read(4)
                self.assertEqual(len(header), 4)
                size, = struct.unpack("!I", header)
                if not size:
                    break
                self.assertLessEqual(size, 256 * 1024)
                data = stream.read(size)
                self.assertEqual(len(data), size)
                self.assertEqual(data, bytes(range(256)) * (size // 256))
                received += size
            result = json.loads(stream.readline())
            self.assertGreater(received, 0)
            self.assertEqual(result["bytes"], received)
            self.assertEqual(result["counter"], "submitted")
            self.assertGreaterEqual(result["seconds"], 1)

    def test_oversized_and_truncated_frames_do_not_kill_listener(self):
        for frame in [struct.pack("!I", 256 * 1024 + 1), struct.pack("!I", 20) + b"short"]:
            with self.connect() as client:
                client.sendall(b"NAN-THROUGHPUT/1 bad-frame UPLOAD 1\n")
                self.assertEqual(client.recv(6), b"READY\n")
                client.sendall(frame)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(client.recv(1), b"")
            self.probe()

    def test_invalid_duration_and_cancelled_download_are_isolated(self):
        with self.connect() as client:
            client.sendall(b"NAN-THROUGHPUT/1 bad-duration DOWNLOAD 999\n")
            self.assertEqual(client.recv(1), b"")
        with self.connect() as client:
            client.sendall(b"NAN-THROUGHPUT/1 cancel DOWNLOAD 1\n")
            self.assertTrue(client.recv(64).startswith(b"READY\n"))
        self.probe()


if __name__ == "__main__":
    unittest.main()
