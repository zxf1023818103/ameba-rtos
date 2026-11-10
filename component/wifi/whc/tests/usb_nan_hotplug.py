#!/usr/bin/env python3
"""Disruptive, root-only USB/NAN lifecycle regression on an isolated Linux host.

Stop NAN/BLE/camera services first. This deauthorizes the explicitly identified
USB composite device (or unbinds WHC_USB), races NAN creation against disconnect,
and restores the binding.
It is not an electrical unplug/power-cycle test and does not clear pairing keys.
Capture the VM serial console externally when testing an unfixed kernel driver.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--usb-device', required=True, help='sysfs USB name, e.g. 2-4.1')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--mac', required=True, help='Green2 managed-interface MAC')
    parser.add_argument('--iw', default='iw')
    parser.add_argument('--ip', default='ip')
    parser.add_argument('--rounds', type=int, default=20)
    parser.add_argument('--active', action='store_true', help='start 2.4 GHz NAN before removal')
    parser.add_argument('--mode', choices=('device', 'interface'), default='device',
                        help='deauthorize the composite device, or unbind only WHC_USB')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, 'Run as root on the test host'
    assert re.fullmatch(r'\d+-\d+(?:\.\d+)*', args.usb_device)
    assert re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', args.mac)
    assert 1 <= args.rounds <= 1000
    usb = Path('/sys/bus/usb/devices') / args.usb_device
    assert (usb/'idVendor').read_text().strip() == '0bda'
    assert (usb/'idProduct').read_text().strip() == 'f851'
    assert (usb/'serial').read_text().strip() == args.serial
    auth = usb/'authorized'
    assert auth.read_text().strip() == '1'
    bindings = [p for p in usb.glob(args.usb_device+':*')
                if (p/'driver').resolve().name == 'WHC_USB']
    assert len(bindings) == 1, 'Expected one WHC_USB interface on the selected device'
    binding = bindings[0]
    driver = (binding/'driver').resolve()
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    device_number = (usb/'devnum').read_text().strip()
    result = {'boot_id': boot_id, 'usb': args.usb_device, 'active_nan': args.active,
              'mode': args.mode, 'usb_device_number': device_number, 'rounds': []}
    # A netdev can exist even when an API wrapper ignored a transport timeout.
    # Observe fresh kernel records as well as interface lifecycle assertions.
    kmsg = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK)
    fatal = re.compile(r'BUG:|Oops:|WARNING:|Kernel panic|'
                       r'wait ret value timeout|Host API .*timeout|'
                       r'Host API .*ret too short|Host API return value|llhw init fail')

    def kernel_errors():
        errors = []
        while True:
            try:
                line = os.read(kmsg, 65536).decode(errors='replace')
            except BlockingIOError:
                break
            except OSError as exc:
                raise RuntimeError('Kernel log overrun; regression evidence incomplete') from exc
            if fatal.search(line):
                errors.append(line.strip())
        return errors

    kernel_errors()  # discard records preceding this run

    def run(*cmd, check=True, timeout=15):
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        if check and p.returncode:
            raise RuntimeError(f'{cmd}: {p.returncode}: {p.stderr.strip()}')
        return p

    def radio():
        for net in Path('/sys/class/net').iterdir():
            try:
                if ((net/'address').read_text().strip() == args.mac.lower() and
                        (net/'device').resolve(strict=True) == usb.resolve(strict=True)):
                    # udev can rename the netdev between directory reads.
                    # A missing symlink must not resolve to the literal name
                    # "phy80211" and be mistaken for a newly registered PHY.
                    return (net/'phy80211').resolve(strict=True).name
            except FileNotFoundError:
                pass
        return None

    def nan_name(phy):
        for net in Path('/sys/class/net').iterdir():
            if (net/'phy80211').resolve().name == phy:
                p = run(args.iw, 'dev', net.name, 'info', check=False)
                if p.returncode == 0 and re.search(r'\btype NAN\b', p.stdout):
                    return net.name
        return None

    def create(phy):
        run(args.iw, 'phy', phy, 'interface', 'add', 'nan0', 'type', '__nan')
        run('udevadm', 'settle')
        name = nan_name(phy)
        assert name, 'NAN interface missing after successful creation'
        return name

    def authorize(value):
        # An external process makes a blocked kernel operation observable via
        # timeout. Pass the path as an argument, not interpolated shell code.
        path = auth
        if args.mode == 'interface':
            path = driver/('bind' if value == '1' else 'unbind')
            value = binding.name
        run('/bin/sh', '-c', 'printf "%s" "$1" > "$2"', 'sh', value, str(path))

    def save():
        Path(args.output).write_text(json.dumps(result, indent=2)+'\n')

    try:
        phy = radio()
        assert phy, 'No managed interface matching this USB device and MAC'
        assert not nan_name(phy), 'Stop services and remove the existing NAN interface first'
        for number in range(1, args.rounds+1):
            started = time.monotonic()
            phy = radio()
            assert phy
            name = create(phy)
            if args.active:
                info = run(args.iw, 'dev', name, 'info').stdout
                wdev = re.search(r'\bwdev (0x[0-9a-f]+)', info).group(1)
                run(args.iw, 'wdev', wdev, 'nan', 'start', 'pref', '112', 'bands', '2GHz')
                run(args.ip, 'link', 'set', name, 'up')
            errors = []

            def detach():
                try:
                    authorize('0')
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=detach, daemon=True)
            thread.start()
            codes = {}
            for _ in range(200):
                p = run(args.iw, 'phy', phy, 'interface', 'add', 'nan0', 'type', '__nan',
                        check=False, timeout=4)
                # Before the gate closes: EBUSY. During removal: ENODEV.
                # After nl80211 removes the phy name: ENOENT/ENODEV.
                assert p.returncode in {240, 237, 254}, (p.returncode, p.stderr)
                codes[str(p.returncode)] = codes.get(str(p.returncode), 0)+1
                if not thread.is_alive():
                    break
            thread.join(timeout=16)
            assert not thread.is_alive() and not errors, errors or 'USB disconnect hung'
            assert not Path('/sys/class/ieee80211', phy).exists(), 'Stale wiphy after USB removal'
            assert radio() is None, 'Stale managed interface after USB removal'
            assert not nan_name(phy), 'Stale NAN interface after USB removal'
            p = run(args.iw, 'phy', phy, 'interface', 'add', 'nan0', 'type', '__nan', check=False)
            assert p.returncode in {237, 254}, 'Removed PHY accepted a new NAN interface'
            authorize('1')
            deadline = time.monotonic()+10
            fresh = radio()
            while not fresh:
                assert time.monotonic() < deadline, 'USB reprobe did not restore managed interface'
                time.sleep(0.05)  # wait for enumeration, not a delay between test rounds
                fresh = radio()
            assert fresh != phy
            assert (usb/'devnum').read_text().strip() == device_number, 'Unexpected USB reset/re-enumeration'
            name = create(fresh)
            run(args.iw, 'dev', name, 'del')
            assert not nan_name(fresh)
            assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id
            errors = kernel_errors()
            if errors:
                result['kernel_errors'] = errors
                raise AssertionError('Kernel/WHC transport errors during this round')
            row = {'round': number, 'old_phy': phy, 'new_phy': fresh,
                   'race_exit_codes': codes, 'removed_phy_exit_code': p.returncode,
                   'seconds': round(time.monotonic()-started, 3), 'passed': True}
            result['rounds'].append(row)
            save()
            print(json.dumps(row), flush=True)
    except Exception as exc:
        result['error'] = str(exc)
        raise
    finally:
        os.close(kmsg)
        result['success'] = len(result['rounds']) == args.rounds and 'error' not in result
        save()
        try:
            if (args.mode == 'interface' and binding.exists() and
                    not (binding/'driver').exists()):
                authorize('1')
            elif args.mode == 'device' and auth.exists() and auth.read_text().strip() != '1':
                authorize('1')
        except Exception as exc:
            result['restore_error'] = str(exc)
            result['success'] = False
            save()


if __name__ == '__main__':
    main()
