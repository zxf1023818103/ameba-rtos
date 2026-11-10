#!/usr/bin/env python3
"""A recreated nan0 is not the interface held by old vendor-event sockets."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

source = Path(__file__).resolve().parents[1] / 'nan_test/rpi/watch-radio.py'
spec = importlib.util.spec_from_file_location('watch_radio', source)
watch_radio = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch_radio)


class RadioGenerationTests(unittest.TestCase):
    def test_removal_and_same_name_replacement_end_old_generation(self):
        for change in ('remove', 'index', 'phy'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                phy = root / 'phy1'; phy.mkdir()
                next_phy = root / 'phy2'; next_phy.mkdir()
                for name, index in [('wlan0', 5), ('nan0', 7)]:
                    node = root / name; node.mkdir()
                    (node / 'ifindex').write_text(str(index))
                    (node / 'phy80211').symlink_to(phy)
                expected = {n: watch_radio.identity(n, root) for n in ('wlan0', 'nan0')}
                ticks = []
                def disconnect(_):
                    ticks.append(1)
                    self.assertEqual(len(ticks), 1, 'watcher kept the stale generation')
                    node = root / 'nan0'
                    if change == 'remove':
                        (node / 'ifindex').unlink()
                    elif change == 'index':
                        (node / 'ifindex').write_text('8')
                    else:
                        (node / 'phy80211').unlink()
                        (node / 'phy80211').symlink_to(next_phy)
                self.assertEqual(watch_radio.watch(expected, root, disconnect), 1)
                self.assertEqual(len(ticks), 1)


if __name__ == '__main__':
    unittest.main()
