#!/usr/bin/env python3
"""End a NAN service generation when its kernel interfaces disappear/change."""
from pathlib import Path
import argparse
import time


def identity(name, root=Path('/sys/class/net')):
    try:
        node = root / name
        return int((node / 'ifindex').read_text()), str((node / 'phy80211').resolve(strict=True))
    except (FileNotFoundError, ValueError):
        return None


def watch(expected, root=Path('/sys/class/net'), pause=time.sleep):
    while True:
        for name, original in expected.items():
            current = identity(name, root)
            if current != original:
                print(f'NAN radio changed: {name} {original} -> {current}; restarting services', flush=True)
                return 1
        pause(0.25)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base')
    parser.add_argument('base_index', type=int)
    parser.add_argument('nan_index', type=int)
    parser.add_argument('phy')
    args = parser.parse_args()
    return watch({args.base: (args.base_index, args.phy),
                  'nan0': (args.nan_index, args.phy)})


if __name__ == '__main__':
    raise SystemExit(main())
