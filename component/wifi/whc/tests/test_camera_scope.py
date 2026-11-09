#!/usr/bin/env python3
"""The same link-local address on a recreated NAN interface needs a new socket."""
import importlib.machinery
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'nan_test/ubuntu-core/run-camera'
runner = importlib.machinery.SourceFileLoader('camera_runner', str(source)).load_module()


class ScopeTests(unittest.TestCase):
    def test_endpoint_requires_usable_link_local_address(self):
        address = {'scope': 'link', 'local': 'fe80::1234'}
        iface = {'ifindex': 21, 'flags': ['UP'], 'addr_info': [address]}
        def query(value, code=0):
            result = subprocess.CompletedProcess([], code, json.dumps(value), '')
            with patch.object(runner.subprocess, 'run', return_value=result):
                return runner.nan_endpoint()
        self.assertEqual(query([iface]), (21, 'fe80::1234'))
        self.assertIsNone(query([], 1))
        self.assertIsNone(query([{**iface, 'flags': []}]))
        for flag in ('tentative', 'dadfailed'):
            self.assertIsNone(query([{**iface, 'addr_info': [{**address, flag: True}]}]))
            self.assertIsNone(query([{**iface, 'addr_info': [{**address, 'flags': [flag]}]}]))
        self.assertIsNone(query([{**iface, 'addr_info': [{**address, 'scope': 'global'}]}]))

    def test_interface_recreated_with_same_address_replaces_live_sender(self):
        children = []
        endpoints = iter([(20, 'fe80::1234'), (21, 'fe80::1234')])
        previous = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        def query():
            try:
                return next(endpoints)
            except StopIteration:
                signal.raise_signal(signal.SIGTERM)
                return (21, 'fe80::1234')
        def launch(command):
            self.assertEqual(command[-2:], ['/dev/video0', 'fe80::1234'])
            if children:
                self.assertIsNotNone(children[-1].poll(), 'old socket owner must exit before rebinding')
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
            children.append(child)
            return child
        try:
            with patch.dict(os.environ, {'SNAP': '/test-snap'}):
                self.assertEqual(runner.supervise('/dev/video0', query, launch), 0)
            self.assertEqual(len(children), 2)
            self.assertTrue(all(p.poll() is not None for p in children))
        finally:
            for s, handler in previous.items():
                signal.signal(s, handler)
            for child in children:
                runner.stop_child(child)


if __name__ == '__main__':
    unittest.main()
