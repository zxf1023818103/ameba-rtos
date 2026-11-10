#!/bin/bash
# Run in an Ubuntu 26.04 builder; /repo is read-only and /work is disposable.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
source_dir=/repo/component/wifi/whc/nan_test/ubuntu-core
case ${1:-all} in
    all|userspace) ;;
    *) echo "usage: $0 [all|userspace]" >&2; exit 2 ;;
esac
kver=7.0.0-38-generic
kdir=/usr/src/linux-headers-$kver
test -d "$kdir"
test -f /work/hostap/wpa_supplicant/.config
test -f /work/pc-kernel-tree/config-$kver
cmp /work/pc-kernel-tree/config-$kver "$kdir/.config"

cd /work
if [[ ${1:-all} == all ]]; then
tar -xf /usr/src/linux-source-7.0.0.tar.bz2 linux-source-7.0.0/drivers/bluetooth
patch -d linux-source-7.0.0 -p1 < /repo/component/wifi/whc/nan_test/rpi/patches/0001-btusb-green2-flash-boot.patch
printf 'obj-m += btusb.o\n' > linux-source-7.0.0/drivers/bluetooth/Makefile
make -C "$kdir" M=/work/linux-source-7.0.0/drivers/bluetooth CC=gcc-15 -j8 modules
make -C /work/whc_host_linux amebagreen2_usb_nan_defconfig
make -C "$kdir" M=/work/whc_host_linux/driver/usb clean
make -C /work/whc_host_linux KDIR="$kdir" CC=gcc-15 -j8
# Core's generated drivers tree maps the kernel/ directory from the kernel snap;
# top-level updates/ is reserved for kernel-module components and is not mapped.
install -Dm644 whc_host_linux/driver/usb/whc_usb.ko "pc-kernel-tree/modules/$kver/kernel/drivers/net/wireless/realtek/whc_usb.ko"
rm -f "pc-kernel-tree/modules/$kver/kernel/drivers/bluetooth/btusb.ko.zst"
install -Dm644 linux-source-7.0.0/drivers/bluetooth/btusb.ko "pc-kernel-tree/modules/$kver/kernel/drivers/bluetooth/btusb.ko"
# depmod expects /lib/modules; the kernel snap's runtime mount uses /modules.
mkdir -p pc-kernel-tree/lib
ln -s ../modules pc-kernel-tree/lib/modules
depmod -b /work/pc-kernel-tree "$kver"
rm pc-kernel-tree/lib/modules
rmdir pc-kernel-tree/lib
python3 - <<'PY'
from pathlib import Path
p = Path('/work/pc-kernel-tree/meta/snap.yaml')
import re
s = re.sub(r'^version: .*$', 'version: 7.0.0-38.38r1-green2.6', p.read_text(), flags=re.M)
p.write_text(s)
PY
fi

make -C hostap/wpa_supplicant clean
make -C hostap/wpa_supplicant -j8 libpasn.so
/repo/component/wifi/whc/nan_test/rpi/build-services.sh /work/hostap /work/services
python3 "$source_dir/stage-runtime.py" /work/app-tree
mkdir -p app-tree/services app-tree/meta app-tree/bin
c++ -std=c++17 -O2 -Wall -Wextra -Werror "$source_dir/camera-srt.cpp" \
    -o app-tree/bin/camera-srt $(pkg-config --cflags --libs srt) -pthread
cp -a services/. app-tree/services/
cp /repo/component/wifi/whc/nan_test/rpi/ble_gatt.py app-tree/services/
cp "$source_dir/snap.yaml" app-tree/meta/snap.yaml
for script in environment run-nan run-ble run-camera status; do
    install -m755 "$source_dir/$script" "app-tree/bin/$script"
done
python3 - <<'PY'
import json
from pathlib import Path
services = Path('/work/app-tree/services')
for name in ('prepare-radio.sh', 'run-services.sh'):
    p = services / name
    s = p.read_text().replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin',
        'export PATH="$SNAP/usr/sbin:$SNAP/usr/bin:$SNAP/bin:/usr/sbin:/usr/bin:/sbin:/bin"')
    s = s.replace('/run/green2-nan', '$SNAP_COMMON/run')
    p.write_text(s)
p = services / 'aware_green2.conf'
config = json.loads(p.read_text())
pub = config['dns_sd_record']['publish1']
pub['name_of_service_instance'] = 'Green2 Core26'
pub['hostname'] = 'green2-core26'
pub['textinfo'] = '0x0E | vendorName=RTK | 0x18 | pairingName=Green2Core26 | 0x13 | modelName=RTL8711Dx'
udp = dict(pub)
udp.update(publish_id='2', service_name='_flashstudio._udp', port_number='9000')
config['dns_sd_record']['publish2'] = udp
p.write_text(json.dumps(config, indent=2) + '\n')
p = services / 'run-services.sh'
p.write_text(p.read_text().replace('-r publish -n 1', '-r publish -n 2'))
PY
echo 'Kernel modules and application staging completed.'
