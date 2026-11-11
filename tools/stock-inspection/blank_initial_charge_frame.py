"""Blank only the initial charging BMP, retaining its native header and FAT layout."""
import json
import struct
import sys
from patch_boot_resource import patch
import replace_orange_resource as writer

BASE = writer.BASE
OUT = BASE / 'carga-preta'
SOURCE = BASE / 'carga-fallback/bootloader_a.img'
EXPECTED = '92c2ff83f6e439d26debcfce2ae41750a5141e457c64f54b425a5b8301301145'
NAME = 'bat/battery_charge.bmp'


def main():
    assert writer.sha(SOURCE) == EXPECTED
    if sys.argv[1:] == ['--prepare']:
        previous = (BASE / 'carga-fallback/boot-resource-verificacao' / NAME).read_bytes()
        assert struct.unpack_from('<iiHHI', previous, 18) == (186, 120, 1, 24, 0)
        offset = struct.unpack_from('<I', previous, 10)[0]
        image = previous[:offset] + bytes(len(previous) - offset)
        assets = OUT / 'replacement'
        (assets / 'bat').mkdir(parents=True, exist_ok=False)
        (assets / NAME).write_bytes(image)
        patch(SOURCE, assets, OUT / 'bootloader_a.img', expected_count=1)
        actual = (OUT / 'boot-resource-verificacao' / NAME).read_bytes()
        assert actual == image and actual[:offset] == previous[:offset]
        assert not any(actual[offset:])
        report = json.loads((OUT / 'bootloader_a.validation.json').read_text())
        assert {e['path'] for e in report['changed_files']} == {NAME}
        assert report['all_files_checked'] == 32
    elif sys.argv[1:] == ['--execute']:
        writer.OUT = OUT
        writer.install(SOURCE, EXPECTED, 'mmcblk0p1 FAT: black pixels in initial bat/battery_charge.bmp only')
    else:
        raise SystemExit('Use --prepare or --execute')


if __name__ == '__main__':
    main()
