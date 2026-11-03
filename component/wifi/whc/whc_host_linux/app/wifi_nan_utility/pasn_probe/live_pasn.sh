#!/usr/bin/env bash
# Run the stateful PASN responder on a Raspberry Pi as root.
set -euo pipefail
umask 077

root=${GREEN2_TEST_ROOT:?Set GREEN2_TEST_ROOT to the diagnostic directory}
log="$root/nan_supplicant.log"
bridge="$root/pasn_probe/pasn_live"

if [[ $EUID -ne 0 || ! -x $bridge || ! -r $log ]]; then
	echo 'root access, PASN bridge, and supplicant log are required' >&2
	exit 1
fi

tail -n 0 -F "$log" | "$bridge" nan0 2437
