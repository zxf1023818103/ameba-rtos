#!/usr/bin/env python3
"""Green2 iBeacon advertisement for Flash Studio background tests.

Uses BlueZ management, not raw HCI. Keeps existing NAN service state unchanged.
Loads an optional adjacent ibeacon-calibration.json for this controller/beacon.
Without calibration or an explicit override, the RSSI reference is a placeholder.
"""
import argparse
import datetime
import json
from pathlib import Path
import re
import signal
import struct
import subprocess
import threading
import uuid

BEACON_UUID = "7b183224-9168-443e-a927-7aeea07e1001"


def manufacturer_ad(beacon_uuid, major, minor, measured_power):
    payload = b"\x4c\x00\x02\x15" + uuid.UUID(beacon_uuid).bytes
    payload += struct.pack(">HHb", major, minor, measured_power)
    return bytes([len(payload) + 1, 0xff]) + payload


def event(kind, **fields):
    print(json.dumps({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "kind": kind, **fields}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", default="hci1")
    parser.add_argument("--uuid", default=BEACON_UUID)
    parser.add_argument("--major", type=int, default=1)
    parser.add_argument("--minor", type=int, default=1)
    parser.add_argument("--measured-power", type=int,
                        help="override the RSSI reference in dBm at 1 meter")
    parser.add_argument("--calibration", type=Path,
                        help="calibration JSON (default: adjacent ibeacon-calibration.json if present)")
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--duration", type=int, default=180,
                        help="seconds to advertise; 0 runs until stopped (default: 180)")
    args = parser.parse_args()
    if not re.fullmatch(r"hci[0-9]+", args.adapter):
        parser.error("adapter must be hciN")
    if not 0 <= args.duration <= 3600 or not 20 <= args.interval_ms <= 10240:
        parser.error("duration must be 0 (continuous) or 1..3600 seconds, interval 20..10240 ms")
    index = args.adapter[3:]

    def mgmt(*command):
        # BlueZ 5.82 attaches stdin to epoll before dispatching the command.
        # systemd supplies /dev/null, which cannot be attached; use a pipe.
        proc = subprocess.run(["/usr/bin/btmgmt", "-i", index, *command],
                              input="", capture_output=True, text=True, timeout=15)
        output = proc.stdout + proc.stderr
        if proc.returncode or re.search(r"\b(failed|invalid|unknown command)\b", output, re.I):
            raise RuntimeError(f"btmgmt {' '.join(command)}: {output.strip()}")
        return output

    info = mgmt("info")
    if "manufacturer 93" not in info or "current settings: powered" not in info:
        raise RuntimeError("Selected adapter is not a powered Realtek controller")
    device = (Path("/sys/class/bluetooth") / args.adapter / "device").resolve()
    if "ttyAMA5" not in str(device):
        raise RuntimeError(f"Expected Green2 on UART5, found {device}")
    power_source = "explicit_override"
    if args.measured_power is None:
        calibration_path = args.calibration or Path(__file__).with_name("ibeacon-calibration.json")
        if args.calibration is not None or calibration_path.exists():
            calibration = json.loads(calibration_path.read_text())
            address = re.search(r"\baddr ([0-9A-Fa-f:]{17})\b", info)
            if (address is None or
                    calibration.get("controller_address", "").upper() != address.group(1).upper() or
                    calibration.get("uuid", "").lower() != str(uuid.UUID(args.uuid)) or
                    calibration.get("major") != args.major or calibration.get("minor") != args.minor or
                    calibration.get("reference_distance_meters") != 1.0):
                raise RuntimeError("Calibration does not match this controller, beacon, or 1 meter reference")
            power = calibration.get("measured_power_dbm")
            if type(power) is not int or not -127 <= power < 0:
                raise RuntimeError("Calibration measured_power_dbm must be an integer in -127..-1")
            args.measured_power = power
            power_source = "calibration_file"
        else:
            args.measured_power = -59
            power_source = "uncalibrated_placeholder"
    try:
        data = manufacturer_ad(args.uuid, args.major, args.minor, args.measured_power)
    except (ValueError, struct.error) as exc:
        parser.error(str(exc))
    advinfo = mgmt("advinfo")
    if "Instances list with 0 items" not in advinfo:
        raise RuntimeError("Existing advertisements present; refusing to replace them")
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    interval = hex(round(args.interval_ms / 0.625))
    allocated = False
    try:
        # No secondary PHY flag: request legacy advertising on channels 37/38/39.
        mgmt("add-ext-adv-params", "-g", "-r", interval, "-x", interval, "1")
        allocated = True
        mgmt("add-ext-adv-data", "-d", data.hex(), "1")
        event("advertising_on", adapter=args.adapter, uuid=str(uuid.UUID(args.uuid)),
              major=args.major, minor=args.minor, interval_ms=args.interval_ms,
              measured_power_dbm=args.measured_power, measured_power_source=power_source, ad_hex=data.hex(),
              duration_seconds=args.duration, continuous=args.duration == 0)
        stopped.wait(None if args.duration == 0 else args.duration)
    finally:
        if allocated:
            mgmt("rm-adv", "1")
            event("advertising_off", adapter=args.adapter)


if __name__ == "__main__":
    main()
