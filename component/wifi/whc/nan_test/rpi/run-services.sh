#!/usr/bin/env bash
# Foreground supervisor for a dedicated, already configured Green2 test PHY.
set -euo pipefail
umask 077
base=${1:-wlan0}
[[ $EUID == 0 && $base =~ ^[[:alnum:]_.:-]+$ ]] || {
    echo "usage: sudo $0 GREEN2_BASE_INTERFACE" >&2; exit 2;
}
bundle=$(cd -- "$(dirname -- "$0")" && pwd)
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
driver=$(basename "$(readlink -f "/sys/class/net/$base/device/driver")")
# WHC_USB parents netdevs to the USB device; its driver binds the child interface.
if [[ $driver == usb ]]; then
    for binding in "$(readlink -f "/sys/class/net/$base/device")"/*:*/driver; do
        if [[ $(basename "$(readlink -f "$binding")") == WHC_USB ]]; then
            driver=WHC_USB
            break
        fi
    done
fi
[[ $driver == WHC_SDIO || $driver == WHC_USB ]] || {
    echo "$base is not a WHC_SDIO/WHC_USB interface" >&2; exit 1;
}
phy=$(readlink -f "/sys/class/net/$base/phy80211")
[[ -n $phy && $(readlink -f /sys/class/net/nan0/phy80211) == "$phy" ]] || {
    echo "Create nan0 on the Green2 PHY first (see README)." >&2; exit 1;
}
iw dev nan0 info | grep -q 'type NAN' || { echo "nan0 is not NAN" >&2; exit 1; }
base_index=$(cat "/sys/class/net/$base/ifindex")
nan_index=$(cat /sys/class/net/nan0/ifindex)
if pgrep -f '(^|/)(rtw_aware[^ /]*|pasn_live)( |$)' >/dev/null; then
    echo "Stop the existing NAN publisher/responder before starting this bundle." >&2
    exit 1
fi
if command -v nmcli >/dev/null && systemctl is-active --quiet NetworkManager; then
    for node in /sys/class/net/*; do
        if [[ $(readlink -f "$node/phy80211") == "$phy" ]]; then
            state=$(nmcli -g GENERAL.NM-MANAGED device show "${node##*/}" 2>/dev/null || true)
            [[ $state != yes ]] || {
                echo "Set ${node##*/} unmanaged in NetworkManager first." >&2; exit 1;
            }
        fi
    done
fi
install -d -m 700 /run/green2-nan /var/lib/nan
exec 9>/run/green2-nan/service.lock
flock -n 9 || { echo "NAN bundle already running" >&2; exit 1; }
cd /run/green2-nan
export GREEN2_EXTERNAL_PASN=1
export GREEN2_NPK_FILE=/var/lib/nan/pasn_npk
export GREEN2_PASN_RESULT_FILE=/run/green2-nan/pasn-result
rm -f "$GREEN2_PASN_RESULT_FILE"
python3 - "$bundle/aware_green2.conf" "$base" <<'PY'
import json, pathlib, shutil, sys
config = json.loads(pathlib.Path(sys.argv[1]).read_text())
config['basic']['mac_addr'] = pathlib.Path('/sys/class/net', sys.argv[2], 'address').read_text().strip()
config['bin_path']['iw']['iw_path'] = shutil.which('iw')
pathlib.Path('aware.conf').write_text(json.dumps(config, indent=2) + '\n')
PY

children=()
cleanup() {
    trap - EXIT INT TERM
    if (( ${#children[@]} )); then
        kill -TERM "${children[@]}" 2>/dev/null || true
        wait "${children[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Netlink event sockets can survive USB removal without delivering an error.
# Retire the entire publisher/PASN generation when its interface identity changes;
# the supervisor then discovers the new PHY and recreates NAN before publishing.
python3 -u "$bundle/watch-radio.py" "$base" "$base_index" "$nan_index" "$phy" & children+=("$!")
# A FIFO lets the supervisor own both processes and never log raw PASN payloads.
rm -f pasn-events
mkfifo -m 600 pasn-events
"$bundle/pasn_vendor_events" nan0 >pasn-events & children+=("$!")
"$bundle/pasn_live" nan0 2437 <pasn-events & children+=("$!")
sleep 1
kill -0 "${children[@]}"
python3 -u "$bundle/nan_echo.py" & children+=("$!")
stdbuf -oL -eL "$bundle/rtw_aware" -r publish -n 1 -f aware.conf -t 0 & children+=("$!")
wait -n "${children[@]}"
