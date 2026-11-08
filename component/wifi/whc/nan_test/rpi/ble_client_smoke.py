#!/usr/bin/env python3
"""Test Green2 GATT over the air using a second, explicitly selected adapter."""
import argparse
import time

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from ble_gatt import CHAR_UUID, SERVICE_UUID, CHAR, OBJECTS, PROPS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True, help="peer adapter, not the Green2 controller")
    parser.add_argument("--rounds", type=int, default=10)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("rounds must be positive")
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    manager = dbus.Interface(bus.get_object("org.bluez", "/"), OBJECTS)
    adapter_path = "/org/bluez/" + args.adapter
    adapter_obj = bus.get_object("org.bluez", adapter_path)
    adapter = dbus.Interface(adapter_obj, "org.bluez.Adapter1")
    dbus.Interface(adapter_obj, PROPS).Set("org.bluez.Adapter1", "Powered", True)
    context = GLib.MainContext.default()

    def until(predicate, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            while context.pending():
                context.iteration(False)
            result = predicate()
            if result:
                return result
            time.sleep(0.02)
        raise TimeoutError("BLE operation timed out")

    def find_device():
        for path, interfaces in manager.GetManagedObjects().items():
            props = interfaces.get("org.bluez.Device1", {})
            if str(path).startswith(adapter_path + "/") and SERVICE_UUID in props.get("UUIDs", []):
                return str(path)
        return None

    adapter.SetDiscoveryFilter({"Transport": "le", "UUIDs": dbus.Array([SERVICE_UUID], signature="s")})
    adapter.StartDiscovery()
    try:
        device_path = until(find_device)
    finally:
        adapter.StopDiscovery()
    device_obj = bus.get_object("org.bluez", device_path)
    device = dbus.Interface(device_obj, "org.bluez.Device1")
    props = dbus.Interface(device_obj, PROPS)
    if props.Get("org.bluez.Device1", "Connected"):
        raise RuntimeError("Peer already connected; refusing to take over its connection")
    print(f"discovered via {args.adapter}: {device_path}", flush=True)
    device.Connect(timeout=30)
    try:
        until(lambda: props.Get("org.bluez.Device1", "ServicesResolved"))
        char_path = next(str(path) for path, interfaces in manager.GetManagedObjects().items()
                         if str(path).startswith(device_path + "/") and
                         interfaces.get(CHAR, {}).get("UUID") == CHAR_UUID)
        char = dbus.Interface(bus.get_object("org.bluez", char_path), CHAR)
        initial = bytes(char.ReadValue({}))
        if initial not in (b"NAN-READY\n", b"BLE-PONG\n"):
            raise RuntimeError(f"Unexpected GATT value: {initial!r}")
        values = []

        def changed(interface, changed, invalidated):
            if interface == CHAR and "Value" in changed:
                values.append(bytes(changed["Value"]))

        match = bus.add_signal_receiver(changed, signal_name="PropertiesChanged",
                                        dbus_interface=PROPS, path=char_path)
        char.StartNotify()
        try:
            for number in range(1, args.rounds + 1):
                while context.pending():
                    context.iteration(False)
                values.clear()
                start = time.monotonic()
                char.WriteValue(dbus.Array(b"BLE-PING\n", signature="y"), {"type": "request"})
                until(lambda: b"BLE-PONG\n" in values, 10)
                print(f"BLE-PONG {number}/{args.rounds} {time.monotonic() - start:.3f}s", flush=True)
        finally:
            char.StopNotify()
            match.remove()
    finally:
        device.Disconnect()
    print(f"PASS {args.rounds} BLE request/notification exchanges", flush=True)


if __name__ == "__main__":
    main()
