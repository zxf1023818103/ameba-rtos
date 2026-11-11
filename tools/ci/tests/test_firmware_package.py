import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('firmware', Path(__file__).parents[1] / 'package-firmware.py')
firmware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firmware)


class FirmwarePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / 'build'
        (self.build / 'menuconfig').mkdir(parents=True)
        (self.build / 'menuconfig/.config').write_text('CONFIG_WHC_INTF_USB=y\n')
        self.config = self.root / 'seed.config'
        self.config.write_text('CONFIG_WIFI_NAN_ENABLE=y\n')
        for name, data in [('boot.bin', b'boot\0' * 11), ('app.bin', b'app\0' * 17),
                           ('ota_all.bin', b'ota header'), ('RTL8851FU_FW_1.bin', b'fullmac')]:
            (self.build / name).write_bytes(data)

    def package(self):
        return firmware.package(self.build, self.root / 'dist', 'test-green2', self.config)

    def test_layout_originals_and_checksums(self):
        with zipfile.ZipFile(self.package()) as archive:
            files = {name.removeprefix('test-green2/'): archive.read(name) for name in archive.namelist()}
        merged = files['Image_All.bin']
        boot, app = files['original/boot.bin'], files['original/app.bin']
        self.assertEqual(merged[:len(boot)], boot)
        self.assertEqual(merged[len(boot):0x40000], b'\xff' * (0x40000 - len(boot)))
        self.assertEqual(merged[0x40000:], app)
        self.assertEqual(files['original/ota_all.bin'], b'ota header')
        self.assertEqual(files['original/RTL8851FU_FW_1.bin'], b'fullmac')
        for entry in files['SHA256SUMS'].decode().splitlines():
            digest, name = entry.split('  ', 1)
            self.assertEqual(hashlib.sha256(files[name]).hexdigest(), digest)
        with self.assertRaises(FileExistsError):
            self.package()

    def test_missing_image_fails_without_archive(self):
        (self.build / 'app.bin').unlink()
        with self.assertRaises(ValueError):
            self.package()
        self.assertFalse((self.root / 'dist/test-green2.zip').exists())

    def test_oversized_bootloader_is_rejected(self):
        (self.build / 'boot.bin').write_bytes(b'\0' * (0x40000 + 1))
        with self.assertRaises(ValueError):
            self.package()
        self.assertFalse((self.root / 'dist/test-green2.zip').exists())
