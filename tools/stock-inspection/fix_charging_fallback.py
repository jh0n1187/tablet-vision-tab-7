"""Prepare/apply four static charging graphics, using the validated FAT-only writer."""
import json
import struct
import sys
from pathlib import Path
from patch_boot_resource import patch
import replace_orange_resource as writer

BASE = writer.BASE
OUT = BASE / 'carga-fallback'
SOURCE = BASE / 'aviso-boot/bootloader_a.img'
EXPECTED = '3464d6a536201337b5c81eb7c46ffb7b81148e846182e905dd2ad692ba2dda49'
ALLOWED = {'bat/battery_charge.bmp', 'bat/battery.bmp', 'bat/bempty.bmp', 'bat/bootlogo.bmp'}


def main():
    assert writer.sha(SOURCE) == EXPECTED
    if sys.argv[1:] == ['--prepare']:
        assert {p.relative_to(OUT / 'replacement').as_posix() for p in (OUT / 'replacement').rglob('*.bmp')} == ALLOWED
        for name in ALLOWED:
            old = (BASE / 'aviso-boot/recursos-v3' / name).read_bytes()
            new = (OUT / 'replacement' / name).read_bytes()
            offset = struct.unpack_from('<I', old, 10)[0]
            assert len(new) == len(old) and new[:offset] == old[:offset]
        patch(SOURCE, OUT / 'replacement', OUT / 'bootloader_a.img', expected_count=4)
        report = json.loads((OUT / 'bootloader_a.validation.json').read_text())
        assert {e['path'] for e in report['changed_files']} == ALLOWED
        # Warning replacement and all animation/temperature/error frames stay intact.
        assert report['all_files_checked'] == 32
    elif sys.argv[1:] == ['--execute']:
        writer.OUT = OUT
        writer.install(SOURCE, EXPECTED, 'mmcblk0p1 FAT: four static charging fallback BMPs only')
    else:
        raise SystemExit('Use --prepare or --execute')


if __name__ == '__main__':
    main()
