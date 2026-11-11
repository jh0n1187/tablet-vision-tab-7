"""Write only audited resource FAT bytes, using authenticated DSU root.

Exact GPT locations, capacities, original hashes and an inactive-partition
idempotent write are checked first. No U-Boot/TOC/RPMB/GPT writes are permitted.
"""
import os
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analise-firmware/central-inteligente/candidato-2025-v2'
DSU = ROOT / 'analise-firmware/desbloqueio-T307F/dsu'
ADB = ['adb', '-s', os.environ.get('T307F_SERIAL', 'SET_T307F_SERIAL_BEFORE_DEVICE_ACCESS')]


def shell(command, timeout=60):
    r = subprocess.run(ADB + ['shell', command], capture_output=True, timeout=timeout)
    s = (r.stdout + r.stderr).decode(errors='replace').replace('\r', '').strip()
    if r.returncode:
        raise RuntimeError(s)
    return s


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.parse_args()
    for _ in range(30):
        devices = subprocess.check_output(['adb', 'devices'], timeout=5).decode()
        if '\tdevice' in devices:
            try:
                if shell('gsi_tool status', 15).startswith('running'):
                    break
            except RuntimeError:
                pass
        time.sleep(3)
    else:
        raise RuntimeError('Authenticated DSU not detected')
    subprocess.run(ADB + ['root'], check=True, capture_output=True, timeout=15)
    time.sleep(1)
    assert shell('id -u') == '0' and shell('getprop ro.adb.secure') == '1'
    assert shell('getenforce') == 'Enforcing' and shell('getprop ro.boot.slot_suffix') == '_a'
    backup = Path((DSU / 'firmware-backup-path.txt').read_text())
    manifest = json.loads((backup / 'manifest.json').read_text())
    originals = {e['file']: e for e in manifest['entries']}
    sources = {'original-a.img': backup / 'bootloader_a.img',
               'original-b.img': backup / 'bootloader_b.img',
               'custom-a.img': OUT / 'bootloader_a.img'}
    expected = {'original-a.img': originals['bootloader_a.img']['sha256'],
                'original-b.img': originals['bootloader_b.img']['sha256'],
                'custom-a.img': json.loads((OUT / 'bootloader_a.validation.json').read_text())['sha256']}
    for name, path in sources.items():
        assert path.stat().st_size == 33554432 and sha(path) == expected[name]
    assert sources['original-a.img'].read_bytes()[:62][54:62] == b'FAT16   '
    nodes = {1: ('bootloader_a', '73728'), 2: ('bootloader_b', '139264')}
    for number, (name, start) in nodes.items():
        path = '/dev/block/mmcblk0p' + str(number)
        assert shell('readlink -f /dev/block/by-name/' + name) == path
        assert shell('cat /sys/class/block/mmcblk0p' + str(number) + '/start') == start
        assert shell('cat /sys/class/block/mmcblk0p' + str(number) + '/size') == '65536'
        assert shell('blockdev --getsize64 ' + path) == '33554432'
        assert shell('blockdev --getro ' + path) == '0'
        assert path not in shell('cat /proc/mounts')
    assert shell('sha256sum /dev/block/mmcblk0p1').split()[0] == expected['original-a.img']
    assert shell('sha256sum /dev/block/mmcblk0p2').split()[0] == expected['original-b.img']
    receipt_path = OUT / 'resource-fat-installation.json'
    assert not receipt_path.exists(), 'Inspect previous resource write before retrying'
    receipt = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Only mmcblk0p1 resource FAT; byte-identical writer test on inactive mmcblk0p2',
               'code_partitions_modified': False, 'readback_verified': False,
               'expected_custom_sha256': expected['custom-a.img']}
    def save():
        receipt_path.write_text(json.dumps(receipt, indent=2))
    save()
    prefix_command = 'dd if=/dev/block/mmcblk0 bs=1048576 count=36 2>/dev/null | sha256sum'
    prefix_before = shell(prefix_command).split()[0]
    stage = '/data/local/tmp/t307-fat-' + datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S')
    shell('mkdir -m 700 ' + stage)
    active_attempt = False
    try:
        for name, source in sources.items():
            r = subprocess.run(ADB + ['push', str(source), stage + '/' + name],
                               capture_output=True, timeout=60)
            assert r.returncode == 0, (r.stdout + r.stderr).decode(errors='replace')
            assert shell('sha256sum ' + stage + '/' + name).split()[0] == expected[name]
        receipt['inactive_writer_output'] = shell(
            'dd if=' + stage + '/original-b.img of=/dev/block/mmcblk0p2 bs=1048576 conv=fsync')
        receipt['inactive_writer_verified'] = shell('sha256sum /dev/block/mmcblk0p2').split()[0] == expected['original-b.img']
        assert receipt['inactive_writer_verified']
        save()
        print('Inactive resource FAT writer/read-back test PASS', flush=True)
        active_attempt = True
        receipt['active_writer_output'] = shell(
            'dd if=' + stage + '/custom-a.img of=/dev/block/mmcblk0p1 bs=1048576 conv=fsync')
        receipt['actual_custom_sha256'] = shell('sha256sum /dev/block/mmcblk0p1').split()[0]
        assert receipt['actual_custom_sha256'] == expected['custom-a.img']
        assert shell(prefix_command).split()[0] == prefix_before
        receipt.update({'readback_verified': True, 'prefix_gpt_uboot_unchanged': True,
                        'prefix_sha256_during_session': prefix_before})
        save()
        print('Custom resource FAT written and read back; preceding GPT/U-Boot area unchanged', flush=True)
    except Exception as error:
        receipt['error'] = str(error)
        if active_attempt:
            receipt['rollback_output'] = shell(
                'dd if=' + stage + '/original-a.img of=/dev/block/mmcblk0p1 bs=1048576 conv=fsync')
            receipt['rollback_verified'] = shell('sha256sum /dev/block/mmcblk0p1').split()[0] == expected['original-a.img']
        save()
        raise
    finally:
        for name in sources:
            shell('rm -f ' + stage + '/' + name)
        shell('rmdir ' + stage)


if __name__ == '__main__':
    main()
