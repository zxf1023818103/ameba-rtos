#!/bin/bash
# Build a development image; SSH public keys are local inputs, never repository data.
set -euo pipefail
[[ $# == 3 && $EUID == 0 ]] || {
    echo "usage: sudo $0 WORK_DIR SSH_PUBLIC_KEY NEW_IMAGE_WORK_DIR" >&2
    exit 2
}
work=$(realpath "$1")
key=$(realpath "$2")
image_work=$(realpath -m "$3")
[[ ! -e $image_work ]] || { echo 'Image work directory must be new' >&2; exit 1; }
cd "$work"
python3 - "$key" <<'PY'
from pathlib import Path
import sys
import yaml
key = Path(sys.argv[1]).read_text().strip()
if '\n' in key or len(key.split()) < 2:
    raise SystemExit('Expected a single OpenSSH public key')
userdata = {
    'hostname': 'green2-core26', 'manage_etc_hosts': True,
    'ssh_pwauth': False, 'disable_root': True,
    'users': [{'name': 'zxf', 'groups': ['adm', 'sudo'], 'shell': '/bin/bash',
               'lock_passwd': True, 'sudo': 'ALL=(ALL) NOPASSWD:ALL',
               'ssh_authorized_keys': [key]}],
    'write_files': [{
        'path': '/etc/udev/rules.d/80-green2-test.rules', 'permissions': '0644',
        'content': 'SUBSYSTEM=="net", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="f851", ENV{NM_UNMANAGED}="1"\n',
    }, {
        # Core's /etc is read-only except specific writable paths. Stage in
        # cloud-init's writable data directory, outside snap revision links.
        'path': '/var/lib/cloud/green2-bluez-main.conf', 'permissions': '0644',
        # This image is a GATT peripheral. Reverse discovery of protected
        # iPhone characteristics otherwise triggers an unwanted pairing attempt.
        'content': '[General]\nReverseServiceDiscovery=false\n\n[GATT]\nClient=false\n',
    }],
    'runcmd': [
        ['snap', 'connect', 'green2-nan-ble:bluez', 'bluez:service'],
        ['snap', 'connect', 'bluez:network-control'],
        ['snap', 'stop', 'green2-nan-ble.ble'],
        # bluez is pinned to revision 410 below. Do not create current before
        # snap run has set up that symlink; use its actual SNAP_DATA directory.
        ['install', '-D', '-m644', '/var/lib/cloud/green2-bluez-main.conf',
         '/var/snap/bluez/410/etc/main.conf'],
        ['snap', 'restart', 'bluez.bluez'],
        ['snap', 'start', 'green2-nan-ble.ble'],
        ['snap', 'refresh', '--hold=forever'],
    ],
}
cloud = {'datasource': {'NoCloud': {
    'meta-data': {'instance-id': 'green2-core26', 'local-hostname': 'green2-core26'},
    'user-data': '#cloud-config\n' + yaml.safe_dump(userdata, sort_keys=False),
}}}
Path('pc-tree/cloud.conf').write_text(
    '#cloud-config\ndatasource_list: [NoCloud]\n' + yaml.safe_dump(cloud, sort_keys=False))
Path('pc-tree/cmdline.extra').write_text(
    'console=tty0 console=ttyS0,115200n8 earlycon=uart8250,io,0x3f8,115200n8 panic=0\n')
p = Path('pc-tree/meta/gadget.yaml')
gadget = yaml.safe_load(p.read_text())
for structure in gadget['volumes']['pc']['structure']:
    if structure.get('role') == 'system-seed':
        structure['size'] = '2G'
# Hostname is set by cloud-init; snapd has no supported system.hostname option.
gadget['defaults'] = {'system': {'service': {'console-conf': {'disable': True}}}}
p.write_text(yaml.safe_dump(gadget, sort_keys=False))
p = Path('pc-tree/meta/snap.yaml')
meta = yaml.safe_load(p.read_text())
meta.update(version='26-0.1-green2.2', grade='devel')
p.write_text(yaml.safe_dump(meta, sort_keys=False))
PY
snap pack pc-tree . --filename pc-green2.snap
snap pack pc-kernel-tree . --filename pc-kernel-green2.snap
snap pack app-tree . --filename green2-nan-ble.snap
# UC20+ does not accept ubuntu-image --cloud-init/--disable-console-conf;
# the gadget above provides those settings instead.
/snap/bin/ubuntu-image snap ubuntu-core-26-amd64-dangerous.model \
    --snap "$work/pc-green2.snap" --snap "$work/pc-kernel-green2.snap" \
    --snap "$work/green2-nan-ble.snap" --snap "$work/bluez_410.snap" \
    --snap "$work/core26_468.snap" --snap "$work/snapd_28332.snap" \
    --image-size 16G --workdir "$image_work" --output-dir "$work/image" \
    --validation=enforce
sha256sum pc-green2.snap pc-kernel-green2.snap green2-nan-ble.snap > artifacts.sha256
sha256sum image/pc.img > image.sha256
