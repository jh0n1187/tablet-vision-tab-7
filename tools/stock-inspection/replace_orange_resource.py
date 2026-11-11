"""Replace only the unlocked-state graphic; never modify executable boot code."""
from pathlib import Path
import datetime
import hashlib
import json
import struct
import subprocess
import sys
import time
from patch_boot_resource import patch
from write_resource_fat_dsu import shell, sha, ADB

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'analise-firmware/central-inteligente'
OUT = BASE / 'aviso-boot'
V3 = BASE / 'candidato-2025-v3'
EXPECTED = '9ba3c6486c7f33f9ea3dd5696c7c4277346d803d271b8c9ae891385089a5b6b7'


def prepare():
    source = V3 / 'bootloader_a.img'
    assert sha(source) == EXPECTED
    resources = OUT / 'recursos-v3'
    old = (resources / 'orange_warning.bmp').read_bytes()
    splash = (resources / 'bootlogo.bmp').read_bytes()
    for data in (old, splash):
        assert data[:2] == b'BM'
        assert struct.unpack_from('<iiHHI', data, 18) == (1024, 600, 1, 24, 0)
    # Preserve the original warning's full V5 header, size and pixel layout.
    offset = struct.unpack_from('<I', old, 10)[0]
    splash_offset = struct.unpack_from('<I', splash, 10)[0]
    pixels = splash[splash_offset:splash_offset + 1024 * 600 * 3]
    assert len(old) - offset == len(pixels)
    assets = OUT / 'replacement'
    assets.mkdir(exist_ok=False)
    (assets / 'orange_warning.bmp').write_bytes(old[:offset] + pixels)
    patch(source, assets, OUT / 'bootloader_a.img', expected_count=1)
    report = json.loads((OUT / 'bootloader_a.validation.json').read_text())
    assert report['changed_files'][0]['path'] == 'orange_warning.bmp'
    assert (OUT / 'boot-resource-verificacao/orange_warning.bmp').read_bytes()[offset:] == pixels
    print('Only orange_warning.bmp pixels changed; all 32 FAT files verified.')


def install(source=None, expected_hash=EXPECTED, scope='mmcblk0p1 FAT: orange_warning.bmp pixels only'):
    source = source or V3 / 'bootloader_a.img'
    receipt_path = OUT / 'installation.json'
    assert not receipt_path.exists(), 'Inspect previous attempt before repeating'
    assert shell('gsi_tool status').startswith('running')
    subprocess.run(ADB + ['root'], check=True, capture_output=True, timeout=15)
    time.sleep(2)
    assert shell('id -u') == '0' and shell('getprop ro.adb.secure') == '1'
    assert shell('getenforce') == 'Enforcing'
    assert shell('getprop ro.boot.slot_suffix') == '_a'
    backup = ROOT / 'backup/firmware-2025-dsu-20261111T012532Z'
    originals = {e['file']: e for e in json.loads((backup / 'manifest.json').read_text())['entries']}
    for name in ('bootloader_a.img', 'bootloader_b.img', 'pre-partition-area.bin'):
        assert sha(backup / name) == originals[name]['sha256']
    dsu = ROOT / 'analise-firmware/desbloqueio-T307F/dsu'
    assert json.loads((dsu / 'restore-identical-test.json').read_text())['post_write_hash_verified']
    assert json.loads((dsu / 'bootloader-restore-identical-test.json').read_text())['readback_verified']
    assert json.loads((V3 / 'resource-fat-installation.json').read_text())['readback_verified']
    for number, name, start in [(1, 'bootloader_a', '73728'), (2, 'bootloader_b', '139264')]:
        node = '/dev/block/mmcblk0p' + str(number)
        assert shell('readlink -f /dev/block/by-name/' + name) == node
        assert shell('cat /sys/class/block/mmcblk0p' + str(number) + '/start') == start
        assert shell('cat /sys/class/block/mmcblk0p' + str(number) + '/size') == '65536'
        assert shell('blockdev --getsize64 ' + node) == '33554432'
        assert node not in shell('cat /proc/mounts')
    assert shell('blockdev --getro /dev/block/mmcblk0p1') == '0'
    assert sha(source) == expected_hash
    assert shell('sha256sum /dev/block/mmcblk0p1').split()[0] == expected_hash
    inactive = shell('sha256sum /dev/block/mmcblk0p2').split()[0]
    assert inactive == originals['bootloader_b.img']['sha256']
    image = OUT / 'bootloader_a.img'
    report = json.loads((OUT / 'bootloader_a.validation.json').read_text())
    assert report['passed'] and report['fat_and_directories_unchanged']
    assert image.stat().st_size == 33554432 and sha(image) == report['sha256']
    prefix_cmd = 'dd if=/dev/block/mmcblk0 bs=1048576 count=36 2>/dev/null | sha256sum'
    prefix = shell(prefix_cmd).split()[0]
    stage = '/data/local/tmp/central-orange-resource'
    shell('mkdir -m 700 ' + stage)
    receipt = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': scope,
               'old_sha256': expected_hash, 'expected_sha256': sha(image),
               'backups_rehashed': True, 'readback_verified': False}
    def save():
        receipt_path.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    attempted = False
    try:
        for name, file in [('previous.img', source), ('new.img', image)]:
            subprocess.run(ADB + ['push', str(file), stage + '/' + name], check=True, capture_output=True, timeout=60)
            assert shell('sha256sum ' + stage + '/' + name).split()[0] == sha(file)
        save()
        attempted = True
        receipt['write_output'] = shell('dd if=' + stage + '/new.img of=/dev/block/mmcblk0p1 bs=1048576 conv=fsync')
        receipt['actual_sha256'] = shell('sha256sum /dev/block/mmcblk0p1').split()[0]
        assert receipt['actual_sha256'] == receipt['expected_sha256']
        assert shell(prefix_cmd).split()[0] == prefix
        assert shell('sha256sum /dev/block/mmcblk0p2').split()[0] == inactive
        receipt.update(readback_verified=True, prefix_gpt_uboot_unchanged=True,
                       inactive_resource_unchanged=True, prefix_sha256=prefix,
                       bootloader_relocked=False, executable_boot_code_modified=False)
        save()
    except Exception as error:
        receipt['error'] = str(error)
        if attempted:
            shell('dd if=' + stage + '/previous.img of=/dev/block/mmcblk0p1 bs=1048576 conv=fsync')
            receipt['rollback_verified'] = shell('sha256sum /dev/block/mmcblk0p1').split()[0] == expected_hash
        save()
        raise
    finally:
        shell('rm -f ' + stage + '/previous.img ' + stage + '/new.img')
        shell('rmdir ' + stage)
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare']:
        prepare()
    elif sys.argv[1:] == ['--execute']:
        install()
    else:
        raise SystemExit('Use --prepare or --execute')
