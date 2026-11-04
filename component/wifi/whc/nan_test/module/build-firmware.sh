#!/usr/bin/env bash
# Requires the SDK's ASDK 12.3.1 and host build dependencies.
set -euo pipefail
[[ $# == 1 ]] || { echo "usage: $0 OUTPUT_WORK_DIRECTORY" >&2; exit 2; }
scripts=$(cd -- "$(dirname -- "$0")" && pwd)
repo=$(cd "$scripts/../../../../.." && pwd)
mkdir -p "$1"
work=$(realpath "$1")
python3 "$repo/tools/scripts/menuconfig.py" \
    -proj "$repo/component/soc/amebagreen2/project" -d "$work" \
    --apply-file "$scripts/green2_nan_sdio.config"
printf '{"soc":{"name":"RTL8711Dx"}}\n' > "$work/soc_info.json"
toolchain=()
if [[ -n ${TOOLCHAIN_DIR:-} ]]; then
    toolchain+=("-DTOOLCHAIN_DIR=$TOOLCHAIN_DIR")
fi
cmake -S "$repo/component/soc/amebagreen2/project" -B "$work/build" -G Ninja \
    "-DEXTERN_DIR=$work" "${toolchain[@]}" \
    -DAMEBA_GREEN2_NAN_PASN_CIPHER_FIX=ON \
    "-DAMEBA_GREEN2_NAN_2G_ONLY=${NAN_2G_ONLY:-OFF}" \
    "-DAMEBA_GREEN2_NAN_PREBUILT_LIBRARY=${NAN_PREBUILT_LIBRARY:-ON}"
cmake --build "$work/build" -j"${JOBS:-8}"
