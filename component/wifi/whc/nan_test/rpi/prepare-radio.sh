#!/usr/bin/env bash
# Configure a dedicated Green2 NAN interface before starting the test services.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
base=${1:-wlan0}
band=${2:-2GHz}
[[ $# -le 2 && $EUID == 0 && $base =~ ^[[:alnum:]_.:-]+$ ]] || {
    echo "usage: sudo $0 GREEN2_BASE_INTERFACE [2GHz|dual]" >&2; exit 2;
}
case "$band" in
    2GHz) bands=(2GHz) ;;
    dual) bands=(2GHz 5GHz) ;;
    *) echo "band must be 2GHz or dual" >&2; exit 2 ;;
esac
driver=$(basename "$(readlink -f "/sys/class/net/$base/device/driver")")
[[ $driver == WHC_SDIO ]] || { echo "$base is not WHC_SDIO" >&2; exit 1; }
phy=$(readlink -f "/sys/class/net/$base/phy80211")
[[ -n $phy && $(readlink -f /sys/class/net/nan0/phy80211) == "$phy" ]] || {
    echo "Create nan0 on the Green2 PHY first." >&2; exit 1;
}
info=$(iw dev nan0 info)
grep -q 'type NAN' <<< "$info" || { echo "nan0 is not NAN" >&2; exit 1; }
wdev=$(awk '$1 == "wdev" { print $2 }' <<< "$info")
[[ $wdev =~ ^0x[[:xdigit:]]+$ ]] || { echo "Invalid NAN wdev ID" >&2; exit 1; }
if pgrep -f '(^|/)(rtw_aware[^ /]*|pasn_live)( |$)' >/dev/null; then
    echo "Stop the NAN publisher and PASN responder before changing bands." >&2
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
install -d -m 700 /run/green2-nan
exec 9>/run/green2-nan/service.lock
flock -n 9 || { echo "NAN service bundle is running" >&2; exit 1; }
printf 'Green2 %s, nan0 %s, bands %s\n' "$base" "$wdev" "${bands[*]}"
stop_status=0
iw wdev "$wdev" nan stop || stop_status=$?
# A newly created NAN netdev has never been started: nl80211 returns
# -ENETDOWN (shell status 156). Other stop failures must not be ignored.
if (( stop_status != 0 && stop_status != 156 )); then
    echo "NAN stop failed ($stop_status); refusing to restart." >&2
    exit "$stop_status"
fi
# This vendor driver attaches a netdev to NAN. cfg80211's wdev_running()
# still sees that netdev UP after NAN stop and rejects start with EEXIST.
ip link set nan0 down
iw wdev "$wdev" nan start pref 112 bands "${bands[@]}"
ip link set nan0 up
echo "NAN radio configured; pairing cache preserved. Start run-services.sh next."
