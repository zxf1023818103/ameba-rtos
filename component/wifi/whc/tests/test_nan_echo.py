#!/usr/bin/env python3
"""Regression: stalled/fragmented/reset TCP clients cannot kill the endpoint."""
import importlib.util
import pathlib
import socket
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


if __name__ == "__main__":
    unittest.main()
