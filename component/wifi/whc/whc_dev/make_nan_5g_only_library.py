#!/usr/bin/env python3
"""Isolated 5 GHz NAN experiment for two verified Green2 archives.

Does not modify vendor inputs. Instructions are replaced only after archive,
member and old-byte verification; output contains a machine-readable manifest.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from elftools.elf.elffile import ELFFile

ARCHIVES = {
    '5f56e4d4cf7d7d9af44b162f23bf4f5185bca3b26b88a91cbaf175cfcdef96d2',
    '682488343c85376be24be761e3d8f500425c3a9787557003cade520be1cfbcaa',
}
MEMBERS = {
    'wifi_hal_halinit.o': {
        '44d143647fd336eaaf81238a50d45c49f58eaa879670770b5ef621535f5f430f',
        '69c4abbd8b902e91993f75eabb4ee561e3433e75a2bf2398e5278fe4ee7a431c',
    },
    'rtw_nan.o': {'3a5a398384cf6d366e00b64b17b84e238c1c3c3426347ecf2c5b733fb09eb607'},
}
PATCHES = {
    'wifi_hal_halinit.o': [
        # BMI -> B: never restore the 2.4 GHz capability bit during init.
        ('.text.wifi_hal_read_adapterinfo', 0x214, '09d4', '09e0'),
    ],
    'rtw_nan.o': [
        # Both auto-band branches select 5 GHz, never 2.4 GHz or dual.
        ('.text.rtw_nan_start_api', 0x54, '0121', '0221'),
        ('.text.rtw_nan_start_api', 0x56, '0321', '0221'),
        # The legacy primary discovery slot must not retune to channel 6.
        # Both stored discovery channels are 149 in this experiment.
        ('.text._rtw_nan_mac_info_init', 0x46, '0623', '9523'),
    ],
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def patch_member(name, data):
    if digest(data) not in MEMBERS[name]:
        raise ValueError('Unverified member: ' + name)
    elf = ELFFile(io.BytesIO(data))
    out = bytearray(data)
    changes = []
    for section_name, offset, before, after in PATCHES[name]:
        section = elf.get_section_by_name(section_name)
        before, after = bytes.fromhex(before), bytes.fromhex(after)
        if section is None or offset + len(before) > section['sh_size']:
            raise ValueError('Missing/short section: ' + section_name)
        start = section['sh_offset'] + offset
        if data[start:start + len(before)] != before or len(before) != len(after):
            raise ValueError('Instruction mismatch: ' + section_name)
        out[start:start + len(before)] = after
        changes.append({'section': section_name, 'offset': hex(offset),
                        'before': before.hex(), 'after': after.hex()})
    return bytes(out), changes


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ar', required=True)
    p.add_argument('source', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    if a.source.resolve() == a.output.resolve():
        p.error('Output must differ from vendor input')
    sha = digest(a.source.read_bytes())
    if sha not in ARCHIVES:
        p.error('Unverified archive; refusing private ABI patch')
    a.output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {'experimental': True, 'source_sha256': sha, 'members': {}}
    with tempfile.TemporaryDirectory(prefix='nan5g-') as tmp:
        members = []
        for name in MEMBERS:
            original = subprocess.check_output([a.ar, 'p', str(a.source), name])
            data, changes = patch_member(name, original)
            member = Path(tmp) / name
            member.write_bytes(data)
            members.append(str(member))
            manifest['members'][name] = {'source_sha256': digest(original),
                'output_sha256': digest(data), 'changes': changes}
        staged = Path(tmp) / a.output.name
        shutil.copy2(a.source, staged)
        subprocess.run([a.ar, 'rD', str(staged), *members], check=True)
        manifest['output_sha256'] = digest(staged.read_bytes())
        shutil.copy2(staged, a.output)
    a.output.with_suffix(a.output.suffix + '.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Experimental 5 GHz-only archive:', a.output)


if __name__ == '__main__':
    main()
