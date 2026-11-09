#!/usr/bin/env python3
"""Green2 USB BLE smoke-test service; SIGUSR1 sends a NAN-READY notification.

Requires BlueZ, python3-dbus and python3-gi. This does not implement iOS
AccessorySetupKit authorization or app background restoration.
"""
import argparse
from pathlib import Path
import signal

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

SERVICE_UUID = "7b183224-9168-443e-a927-7aeea07e0001"
CHAR_UUID = "7b183224-9168-443e-a927-7aeea07e0002"
ROOT = "/com/flashstudio/green2"
PROPS = "org.freedesktop.DBus.Properties"
OBJECTS = "org.freedesktop.DBus.ObjectManager"
SERVICE = "org.bluez.GattService1"
CHAR = "org.bluez.GattCharacteristic1"
ADV = "org.bluez.LEAdvertisement1"


class Properties(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)
        self.path = path

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != self.interface:
            raise dbus.exceptions.DBusException(
                "Unknown interface", name="org.freedesktop.DBus.Error.InvalidArgs")
        return self.properties()

    @dbus.service.method(PROPS, in_signature="ss", out_signature="v")
    def Get(self, interface, name):
        return self.GetAll(interface)[name]

    @dbus.service.signal(PROPS, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass


class Service(Properties):
    interface = SERVICE

    def properties(self):
        return {"UUID": SERVICE_UUID, "Primary": dbus.Boolean(True)}


class Characteristic(Properties):
    interface = CHAR

    def __init__(self, bus, path, service):
        super().__init__(bus, path)
        self.service = service
        self.value = b"NAN-READY\n"
        self.notifying = False

    def properties(self):
        return {"UUID": CHAR_UUID, "Service": dbus.ObjectPath(self.service),
                "Flags": dbus.Array(["read", "write", "notify"], signature="s"),
                "Value": dbus.Array(self.value, signature="y"),
                "Notifying": dbus.Boolean(self.notifying)}

    def update(self, value):
        self.value = value
        if self.notifying:
            self.PropertiesChanged(CHAR, {"Value": dbus.Array(value, signature="y")}, [])
            print(f"notify bytes={len(value)}", flush=True)

    @dbus.service.method(CHAR, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        offset = int(options.get("offset", 0))
        if offset > len(self.value):
            raise dbus.exceptions.DBusException("Invalid offset", name="org.bluez.Error.InvalidOffset")
        print("read", flush=True)
        return dbus.Array(self.value[offset:], signature="y")

    @dbus.service.method(CHAR, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        if int(options.get("offset", 0)):
            raise dbus.exceptions.DBusException("Invalid offset", name="org.bluez.Error.InvalidOffset")
        # ATT preserves write boundaries; interactive clients may omit a line
        # ending. Keep accepting the newline used by the automated client.
        if bytes(value) not in (b"BLE-PING", b"BLE-PING\n", b"BLE-PING\r\n"):
            raise dbus.exceptions.DBusException("Expected BLE-PING", name="org.bluez.Error.NotSupported")
        print("BLE-PING received", flush=True)
        self.update(b"BLE-PONG\n")

    @dbus.service.method(CHAR)
    def StartNotify(self):
        self.notifying = True
        self.PropertiesChanged(CHAR, {"Notifying": dbus.Boolean(True)}, [])
        print("notify subscribed", flush=True)

    @dbus.service.method(CHAR)
    def StopNotify(self):
        self.notifying = False
        self.PropertiesChanged(CHAR, {"Notifying": dbus.Boolean(False)}, [])
        print("notify unsubscribed", flush=True)


class Application(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, ROOT)
        self.service = Service(bus, ROOT + "/service0")
        self.characteristic = Characteristic(bus, ROOT + "/service0/char0", self.service.path)

    @dbus.service.method(OBJECTS, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        return {obj.path: {obj.interface: obj.properties()}
                for obj in (self.service, self.characteristic)}


class Advertisement(Properties):
    interface = ADV

    def __init__(self, bus, path, name):
        super().__init__(bus, path)
        self.name = name

    def properties(self):
        return {"Type": "peripheral", "ServiceUUIDs": dbus.Array([SERVICE_UUID], signature="s"),
                "LocalName": self.name}

    @dbus.service.method(ADV)
    def Release(self):
        print("advertisement released", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True, help="Green2 USB HCI, for example hci1")
    parser.add_argument("--name", default="Green2 BLE", help="advertised name for this board")
    args = parser.parse_args()
    device = (Path("/sys/class/bluetooth") / args.adapter / "device").resolve()
    if not any((p / "idVendor").exists() and
               (p / "idVendor").read_text().strip() == "0bda" and
               (p / "idProduct").read_text().strip() == "f851" for p in device.parents):
        parser.error("adapter is not the Green2 0bda:f851 USB device")

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter = bus.get_object("org.bluez", "/org/bluez/" + args.adapter)
    dbus.Interface(adapter, PROPS).Set("org.bluez.Adapter1", "Powered", dbus.Boolean(True))
    app = Application(bus)
    advertisement = Advertisement(bus, ROOT + "_advertisement", args.name)
    loop = GLib.MainLoop()
    failed = []

    def error(exc):
        failed.append(exc)
        print(f"registration failed: {exc}", flush=True)
        loop.quit()

    def app_ready():
        dbus.Interface(adapter, "org.bluez.LEAdvertisingManager1").RegisterAdvertisement(
            advertisement.path, {},
            reply_handler=lambda: print(f"BLE ready adapter={args.adapter} service={SERVICE_UUID}", flush=True),
            error_handler=error)

    def notify_ready():
        app.characteristic.update(b"NAN-READY\n")
        return GLib.SOURCE_CONTINUE

    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGUSR1, notify_ready)
    for sig in (signal.SIGTERM, signal.SIGINT):
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, lambda: loop.quit())
    dbus.Interface(adapter, "org.bluez.GattManager1").RegisterApplication(
        ROOT, {}, reply_handler=app_ready, error_handler=error)
    loop.run()
    # BlueZ removes the application and advertisements when the bus owner exits.
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
