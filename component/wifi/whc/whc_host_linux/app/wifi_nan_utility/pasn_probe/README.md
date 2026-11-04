# Green2 NAN PASN responder and diagnostic probes

For the complete firmware, Raspberry Pi driver and service build/run procedure,
see [NAN test bundle](../../../../nan_test/README.md).

`pasn_probe` takes Realtek's 645-byte `NAN_EVENT_PASN_START` vendor payload,
validates the embedded Auth1, and uses hostap's PASN responder to generate
Auth2. `send_auth2` transmits that frame through `NL80211_CMD_FRAME` on `nan0`.
`live_auth2.sh` watches a debug `wpa_supplicant` log for fresh `subcmd=29`
events and runs the two programs. `pasn_live` and `live_pasn.sh` replace this
with a persistent process that keeps the PASN state, verifies Auth3 events
(`subcmd=30`), derives ND-PMK, and submits TK, KDK, peer NMI, and ND-PMK via
Realtek's `NAN_SUBCMD_PASN_SET_KEY`. The 86-byte command layout was recovered
from `rtw_cfgvendor_nan_pasn_setkeys`, `rtw_nan_kdk_to_kek`, and
`rtw_nan_kdk_to_pmk` in the matching Green2 firmware archive.
The bridge logs no key bytes. Successful vendor command submission alone does
not prove that firmware accepted the keys. The Green2 responder omits event 33;
the optional `GREEN2_PASN_RESULT_FILE` bridge notifies `rtw_aware` after verified
Auth3 and command acknowledgement so the host can send its NIK follow-up.
Confirm completion independently in the peer UI and firmware logs.

`GREEN2_NPK_FILE` retains the setup NPK in a mode-0600 file. Verification checks
the incoming NIRA against `/var/lib/nan/nik_cache`, then uses the saved NPK in
hostap's PMKSA cache. The custom PMKID callback accepts only that authenticated
peer and PMKID. Omitting this callback caused a NULL call in
`handle_auth_pasn_1`; the corrected responder has completed verification Auth3
with the test iPhone. This experimental cache stores only the latest NPK and
is intended for the current single-peer test.

At 22:26 CST on 2026-11-03 the iPhone completed NDP establishment and TCP
echo after both firmware replacements described below. Raspberry Pi received
`NAN-PING\n` on `nan0`, and the user confirmed the app received the reply.
Three subsequent reconnections also reached NDP established and TCP input.
Earlier, an authenticated air capture showed an iPhone request with cipher 7,
a Green2 response with cipher 1, and iPhone Confirm status 2/reason 10.
Status and reason are distinct fields. A later firmware experiment reached
another failure: Green2 Response status 2/reason 2 (RESOURCE_LIMITATION).
Clearing the firmware NIK cache with all zeros breaks subsequent pairing:
preserve or securely initialize `own_nik` while clearing peer entries.

The PASN library is built from
[`zephyrproject-rtos/hostap`](https://github.com/zephyrproject-rtos/hostap)
commit `1ce844ea5a9d8860d8690a125925fcc7274461df`, with `CONFIG_SAE`,
`CONFIG_PASN`, `CONFIG_NAN`, and `CONFIG_BUILD_PASN_SO`. Set `HOSTAP_DIR` to
the checkout when building. `send_auth2` also needs libnl headers and libraries;
set `LIBNL_CFLAGS` and `LIBNL_LIBS` for nonstandard paths. Copy `libpasn.so`
next to the executables, or set `LD_LIBRARY_PATH` to its directory.

The vendor event ABI is taken from
`src/vendor_wrapper/rtw_nan_vender_ioctrl_struc.h` and checked for its exact
size and Auth frame offset at compile time. The probe prints no passphrase or
derived keys. Debug supplicant logs contain secret data and should stay private.

## Direct vendor event input

`pasn_vendor_events.c` subscribes to the nl80211 vendor multicast group and
filters by the NAN interface index, Realtek OUI, event ID and exact ABI size.
Its stdout carries authentication material in the input format of `pasn_live`;
pipe it directly to that process. Its stderr only reports event IDs and sizes.

```sh
gcc -O2 -g -Wall -Wextra -Werror pasn_vendor_events.c \
  $(pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0) -o pasn_vendor_events
set -o pipefail
./pasn_vendor_events nan0 | ./pasn_live nan0 2437
```

Create `nan0` on the actual `iw dev` PHY before starting the reader. For this
standalone responder set `GREEN2_EXTERNAL_PASN=1` in the publisher environment;
the patched scenario library then skips launching or stopping a NAN
`wpa_supplicant`. The dedicated Green2 interfaces must also be unmanaged by
NetworkManager during this test. Ethernet remains managed. The direct input
completed iPhone verification Auth1/2/3 on 2026-11-03. The normal supplicant
path is unchanged unless this environment variable is set. The publisher's
event receiver now uses its own persistent libnl subscription. This replaces
the former text log reader, whose 100 KiB rotation killed `iw` and lost NDP
Confirm/Established events during repeated connections. Command invocations
of `iw` remain available; the event receiver never kills them.

## Experimental firmware function replacements

Configure Green2 NAN/WHC/SPDIO with `-DAMEBA_GREEN2_NAN_PASN_CIPHER_FIX=ON`.
The option defaults to OFF and rejects unverified vendor objects by SHA-256.
It currently enables two replacements without modifying the SDK archive:

- `rtw_nan_ndp_response_prehandle`: preserve requested PASN-128 cipher 7
  instead of the vendor's hard-coded SK-128 cipher 1 on successful responses.
  The adapter changes only the pinned entry byte before MIC construction.
- `rtw_nan_schdl_faw_act_add`: return the full 32-bit firmware schedule bitmap.
  The vendor loads a 32-bit ID but ends with `UXTB r0,r6`; an allocated
  `0x100` becomes zero, is misclassified as failure and escapes rollback.
  `make_nan_faw_id_fix.py` extracts the pinned function and changes only that
  instruction to `MOV r0,r6`. `--wrap` redirects the callers, which already
  compare and store all 32 bits. The object hash and opcode are checked before
  extraction; its internal duration helper still links to the original code.

The first replacement ran on hardware (`[NANFIX] NDP responder cipher 1 -> 7`).
The FAW defect was correlated with `Add fw_schedule_id=100`, immediately
followed by `schdl_faw_act_add fail!` and rejection reason 2. The combined
firmware built and passed flash checksum verification. In the successful run
`0x100` was accepted, NDP progressed through Confirm and Security Install,
both hosts reported datapath established, and TCP echo completed. Subsequent
scheduling used IDs through `0x8000` and removed them correctly. Long-duration,
throughput and multi-peer behavior have not been tested.
