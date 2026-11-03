#!/usr/bin/env bash
# Build into a separate directory; do not install or restart running services.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "usage: $0 HOSTAP_CHECKOUT OUTPUT_DIR" >&2
    exit 2
fi
scripts=$(cd -- "$(dirname -- "$0")" && pwd)
utility=$(cd "$scripts/../../whc_host_linux/app/wifi_nan_utility" && pwd)
hostap=$(realpath "$1")
mkdir -p "$2"
output=$(realpath "$2")
test -f "$hostap/wpa_supplicant/libpasn.so"
cc=${CC:-cc}
pkg=${PKG_CONFIG:-pkg-config}
"$pkg" --exists json-c libnl-3.0 libnl-genl-3.0
read -r -a json_flags <<< "$("$pkg" --cflags --libs json-c)"
read -r -a nl_flags <<< "$("$pkg" --cflags --libs libnl-3.0 libnl-genl-3.0)"

"$cc" -fPIC -shared -pthread -I"$utility/src/rtw_nan_api" \
    "$utility"/src/rtw_nan_api/*.c -o "$output/libnanapi.so"
"$cc" -I"$utility/src/rtw_nan_api" "$utility/rtw_aware/rtw_aware.c" \
    -L"$output" -Wl,-rpath,'$ORIGIN' -lnanapi -pthread \
    "${json_flags[@]}" -o "$output/rtw_aware"
"$cc" -std=gnu11 -O2 -Wall -DCONFIG_SAE -DCONFIG_PASN \
    -I"$hostap/src" -I"$hostap/src/utils" "$utility/pasn_probe/pasn_live.c" \
    -L"$hostap/wpa_supplicant" -Wl,-rpath,'$ORIGIN' -lpasn -lcrypto \
    "${nl_flags[@]}" -o "$output/pasn_live"
"$cc" -std=gnu11 -O2 -Wall -Wextra -Werror \
    "$utility/pasn_probe/pasn_vendor_events.c" "${nl_flags[@]}" \
    -o "$output/pasn_vendor_events"
cp "$hostap/wpa_supplicant/libpasn.so" "$output/"
cp "$scripts/aware_green2.conf" "$scripts/nan_echo.py" "$scripts/run-services.sh" "$output/"
echo "Services built in $output"
