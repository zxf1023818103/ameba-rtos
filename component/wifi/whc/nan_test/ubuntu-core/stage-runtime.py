#!/usr/bin/env python3
"""Stage installed Ubuntu runtime packages without following host symlinks.

Run inside the Ubuntu 26.04 builder, with its runtime dependencies installed.
The package list and exact versions are retained alongside the resulting snap.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
packages = ['python3', 'python3-dbus', 'python3-gi', 'gir1.2-glib-2.0',
            'iw', 'iproute2', 'libjson-c5', 'libnl-genl-3-200', 'libssl3t64',
            'procps', 'util-linux', 'coreutils', 'udev', 'ffmpeg', 'v4l-utils', 'libsrt1.5-openssl']
depends = subprocess.check_output([
    'apt-cache', 'depends', '--recurse', '--no-recommends', '--no-suggests',
    '--no-conflicts', '--no-breaks', '--no-replaces', '--no-enhances', *packages
], text=True)
names = sorted({line for line in depends.splitlines()
                if line and not line[0].isspace() and not line.startswith('<')})
manifest = []
for name in names:
    result = subprocess.run(['dpkg-query', '-W', '-f=${db:Status-Status} ${Version}', name],
                            text=True, capture_output=True)
    if result.returncode or not result.stdout.startswith('installed '):
        continue
    manifest.append(name + ' ' + result.stdout.split(' ', 1)[1])
    paths = subprocess.check_output(['dpkg-query', '-L', name], text=True).splitlines()
    for item in paths:
        if not item.startswith(('/usr/bin/', '/usr/sbin/', '/usr/lib/', '/usr/libexec/', '/usr/share/zoneinfo/')):
            continue
        source = Path(item)
        if not source.exists() and not source.is_symlink():
            continue
        dest = root / item.lstrip('/')
        if not dest.parent.resolve().is_relative_to(root):
            raise RuntimeError(f'Symlink escapes stage root: {dest}')
        dest.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            if dest.is_symlink() or dest.exists():
                dest.unlink()
            dest.symlink_to(os.readlink(source))
        elif source.is_dir():
            dest.mkdir(exist_ok=True)
        else:
            if dest.is_symlink():
                dest.unlink()
            shutil.copy2(source, dest)
(root / 'runtime-packages.txt').write_text('\n'.join(manifest) + '\n')
print(f'Staged {len(manifest)} runtime packages')
