#!/usr/bin/env python3
"""Package Green2 NOR firmware using the SDK's own flash layout and combiner."""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[2]
PROFILE = REPO / 'tools/ameba/Flash/Devices/Profiles/RTL8711F_NOR.rdev'


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def package(build_dir, output_dir, name, config):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name):
        raise ValueError('Invalid package name')
    build_dir, output_dir, config = map(Path, (build_dir, output_dir, config))
    resolved_config = build_dir / 'menuconfig/.config'
    for path in [config, resolved_config, *(build_dir / n for n in ('boot.bin', 'app.bin', 'ota_all.bin'))]:
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f'Missing or empty build input: {path}')
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / (name + '.zip')
    checksum = archive.with_suffix('.zip.sha256')
    if archive.exists() or checksum.exists():
        raise FileExistsError('Refusing to overwrite an existing firmware package')

    sys.path.insert(0, str(REPO / 'tools/ameba/Flash'))
    from base.json_utils import JsonUtils
    from base.device_profile import RtkDeviceProfile
    from base.combine import combine_profile_images
    profile = RtkDeviceProfile(**JsonUtils.load_from_file(str(PROFILE)))
    layout = [{'file': image.image_name, 'offset': image.start_address - profile.flash_start_address,
               'partition_size': image.end_address - image.start_address}
              for image in profile.images if image.mandatory]
    with tempfile.TemporaryDirectory(prefix='green2-package-', dir=output_dir) as temporary:
        root = Path(temporary) / name
        raw = root / 'original'
        raw.mkdir(parents=True)
        # Keep all top-level SDK output binaries, including optional fullmac files.
        for source in sorted(build_dir.glob('*.bin')):
            if source.name.lower() != 'image_all.bin':
                shutil.copy2(source, raw / source.name)
        combine_profile_images(profile, str(raw), logging.getLogger('firmware'), output_dir=str(root))
        (root / 'image_all.bin').rename(root / 'Image_All.bin')
        combined = (root / 'Image_All.bin').read_bytes()
        previous_end = 0
        for item in sorted(layout, key=lambda item: item['offset']):
            data = (raw / item['file']).read_bytes()
            offset = item['offset']
            if combined[offset:offset + len(data)] != data:
                raise ValueError('Combined image does not match original: ' + item['file'])
            if combined[previous_end:offset] != b'\xff' * (offset - previous_end):
                raise ValueError('Combined image gap must contain erased flash bytes')
            previous_end = offset + len(data)
        shutil.copy2(config, root / 'firmware.config')
        shutil.copy2(resolved_config, root / 'build.config')
        (root / 'flash-layout.json').write_text(json.dumps({
            'profile': PROFILE.name, 'flash_base_address': profile.flash_start_address,
            'combined_flash_offset': 0, 'padding_byte': 255, 'images': layout,
        }, indent=2) + '\n')
        revision = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
        manifest = {
            'source_commit': revision, 'configuration': config.name,
            'toolchain': 'ASDK 12.3.1 build 4600',
            'files': {str(p.relative_to(root)): {'bytes': p.stat().st_size, 'sha256': sha256(p)}
                      for p in sorted(root.rglob('*')) if p.is_file()},
        }
        (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        (root / 'README.txt').write_text(
            'Green2 NOR firmware\n\n'
            'Image_All.bin: combined flash image, program at flash offset 0.\n'
            'original/boot.bin: bootloader, flash offset 0.\n'
            'original/app.bin: application, flash offset 0x40000.\n'
            'original/ota_all.bin: SDK OTA package; do not write it as Image_All.bin.\n'
            'Gaps in Image_All.bin are filled with 0xFF; efuse/system data are not bundled.\n'
            'Verify SHA256SUMS after extracting. Configuration and source commit are included.\n'
            'Compilation/package validation does not replace a hardware regression test.\n')
        (root / 'SHA256SUMS').write_text(''.join(
            f'{sha256(p)}  {p.relative_to(root)}\n' for p in sorted(root.rglob('*')) if p.is_file()))
        staged_archive = Path(temporary) / archive.name
        with zipfile.ZipFile(staged_archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for path in sorted(root.rglob('*')):
                if path.is_file():
                    z.write(path, arcname=str(Path(name) / path.relative_to(root)))
        staged_archive.replace(archive)
    checksum.write_text(f'{sha256(archive)}  {archive.name}\n')
    print(f'Packaged {archive} ({archive.stat().st_size} bytes)')
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    package(args.build_dir, args.output_dir, args.name, args.config)
