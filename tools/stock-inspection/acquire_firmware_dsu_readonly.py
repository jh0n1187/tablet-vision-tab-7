"""Read T307F firmware to host files and verify with a second device read.

No device writes, partition flashing, RPMB access, or bootloader modifications.
Mutable partitions are captured but explicitly excluded from stable-hash claims.
"""
from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
DSU = ROOT / 'analise-firmware/desbloqueio-T307F/dsu'


def shell(command, timeout=60):
    r = subprocess.run(['adb', 'shell', command], capture_output=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors='replace'))
    return r.stdout.decode(errors='replace').replace('\r', '').strip()


def acquire(folder, name, command, expected_size, verify_command, stable=True):
    dest = folder / name
    digest = hashlib.sha256()
    count = 0
    with dest.open('xb') as out:
        # exec-out merges the remote stderr stream: discard dd's textual summary
        # remotely so it cannot become part of the binary image.
        p = subprocess.Popen(['adb', 'exec-out', command + ' 2>/dev/null'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        while data := p.stdout.read(4 * 1024 * 1024):
            out.write(data)
            digest.update(data)
            count += len(data)
        stderr = p.stderr.read()
        code = p.wait(timeout=30)
        out.flush()
        os.fsync(out.fileno())
    assert code == 0 and count == expected_size, (name, code, count, expected_size)
    second = shell(verify_command, timeout=300).split()[0]
    assert re.fullmatch('[a-f0-9]{64}', second)
    result = {'file': name, 'size': count, 'sha256': digest.hexdigest(),
              'second_device_read_sha256': second,
              'two_reads_match': second == digest.hexdigest(), 'stable_expected': stable}
    if stable:
        assert result['two_reads_match'], name + ': firmware changed between reads'
    # Also verify the complete host file after closing it.
    with dest.open('rb') as f:
        assert hashlib.file_digest(f, 'sha256').hexdigest() == result['sha256']
    print(name, count, 'bytes;', 'two reads match' if result['two_reads_match'] else 'mutable snapshot', flush=True)
    return result


def main():
    assert shell('id -u') == '0'
    assert shell('getprop ro.gsid.image_running') == '1'
    assert shell('getprop ro.boot.flash.locked') == '0'
    assert shell('getenforce') == 'Enforcing'
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder = ROOT / 'backup' / ('firmware-2025-dsu-' + stamp)
    folder.mkdir()
    DSU.joinpath('firmware-backup-path.txt').write_text(str(folder))
    manifest = {'source': 'T307F original eMMC, read from temporary DSU userdebug',
                'time_utc': stamp, 'entries': [],
                'limits': ['No RPMB acquisition; no claim of FBE/key portability',
                           'No exposed mmcblk0boot0/boot1 block nodes',
                           'Mutable partition snapshots are not a consistent whole-device backup',
                           'Restore not validated by this read-only script']}
    def save():
        (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    for name, command in {
        'identity': 'getprop ro.build.display.id; getprop ro.gsid.image_running; id; getenforce',
        'partition-links': 'ls -l /dev/block/by-name',
        'proc-partitions': 'cat /proc/partitions',
        'mounts': 'cat /proc/mounts',
        'sysfs-layout': 'for p in /sys/class/block/mmcblk0p*; do echo ${p##*/}; cat $p/start; cat $p/size; done',
        'mmc-properties': 'cat /sys/class/block/mmcblk0/device/cid; cat /sys/class/block/mmcblk0/device/csd; cat /sys/class/block/mmcblk0/device/life_time; cat /sys/class/block/mmcblk0/device/pre_eol_info',
        'gsi-status': 'gsi_tool status',
    }.items():
        (folder / (name + '.txt')).write_text(shell(command))
    sectors = int(shell('cat /sys/class/block/mmcblk0/size'))
    first = int(shell('cat /sys/class/block/mmcblk0p1/start'))
    assert sectors == 122159104 and first == 73728
    manifest['emmc_user_area_size'] = sectors * 512
    save()
    for name, dd, size in [
        ('pre-partition-area.bin', f'dd if=/dev/block/mmcblk0 bs=512 count={first}', first * 512),
        ('last-1MiB.bin', f'dd if=/dev/block/mmcblk0 bs=512 skip={sectors-2048} count=2048', 1048576),
    ]:
        manifest['entries'].append(acquire(folder, name, dd, size, dd + ' 2>/dev/null | sha256sum'))
        save()
    names = ['boot_a', 'boot_b', 'init_boot_a', 'init_boot_b', 'vendor_boot_a', 'vendor_boot_b',
             'vbmeta_a', 'vbmeta_b', 'vbmeta_system_a', 'vbmeta_system_b',
             'vbmeta_vendor_a', 'vbmeta_vendor_b', 'dtbo_a', 'dtbo_b',
             'bootloader_a', 'bootloader_b', 'env_a', 'env_b',
             'frp', 'private', 'media_data', 'empty', 'super', 'treadahead',
             'misc', 'metadata', 'pstore']
    for name in names:
        path = '/dev/block/by-name/' + name
        size = int(shell('blockdev --getsize64 ' + path))
        assert size > 0 and size <= 5 * 1024**3
        stable = name not in {'metadata', 'misc', 'pstore', 'treadahead'}
        manifest['entries'].append(acquire(folder, name + '.img',
            'dd if=' + path + ' bs=1048576', size, 'sha256sum ' + path, stable))
        save()
    manifest['acquisition_complete'] = True
    save()
    print('Firmware acquisition complete:', folder, flush=True)


if __name__ == '__main__':
    main()
