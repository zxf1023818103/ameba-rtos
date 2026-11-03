#!/usr/bin/env bash
# Experimental Auth2 responder. Run as root on the Pi only while testing.
set -u -o pipefail
umask 077

root=${GREEN2_TEST_ROOT:?Set GREEN2_TEST_ROOT to the diagnostic directory}
log="$root/nan_supplicant.log"
probe="$root/pasn_probe/pasn_probe"
sender="$root/pasn_probe/send_auth2"
auth2=/run/green2-pasn-auth2.bin
pending=0

if [[ $EUID -ne 0 || ! -x $probe || ! -x $sender || ! -r $log ]]; then
	echo 'root access, PASN tools, and supplicant log are required' >&2
	exit 1
fi

tail -n 0 -F "$log" | while IFS= read -r line; do
	if [[ $line == *'Vendor event: wiphy='* ]]; then
		pending=0
		if [[ $line == *'vendor_id=0xe04c subcmd=29'* ]]; then
			pending=1
		fi
		continue
	fi
	if (( pending )) && [[ $line == *'Vendor data - hexdump(len=645):'* ]]; then
		pending=0
		if printf '%s\n' "$line" | "$probe" "$auth2"; then
			"$sender" nan0 2437 "$auth2"
		else
			echo 'Auth1 rejected by PASN probe' >&2
		fi
		rm -f "$auth2"
	fi
done
