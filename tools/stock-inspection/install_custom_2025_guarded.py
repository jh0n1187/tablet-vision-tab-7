"""Install the audited 2025 images on the single authorized T307F.

Explicit --execute required. Never erases userdata, changes slots, locks the
bootloader, or writes TOC/U-Boot/RPMB/eFuses. Preserves OEM recovery/kernel.
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
SERIAL = os.environ.get('T307F_SERIAL', 'SET_T307F_SERIAL_BEFORE_DEVICE_ACCESS')
FB = ['fastboot', '-s', SERIAL]


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def fb(*args, timeout=20):
    r = subprocess.run(FB + list(map(str, args)), capture_output=True, timeout=timeout)
    text = (r.stdout + r.stderr).decode(errors='replace')
    if r.returncode or 'FAILED' in text:
        raise RuntimeError(text)
    return text


def getvar(name):
    text = fb('getvar', name)
    for line in text.splitlines():
        if line.startswith(name + ': '):
            return line[len(name) + 2:].strip()
    raise RuntimeError('Missing getvar ' + name + ': ' + text)


def main():
    global OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--revision', choices=['v2','v3'], default='v2')
    args = parser.parse_args()
    if not args.execute:
        parser.error('Review artifacts first; --execute is required')
    if args.revision == 'v3':
        OUT = ROOT / 'analise-firmware/central-inteligente/candidato-2025-v3'
    acceptance = read(OUT / 'key-acceptance-runtime-test.json')
    assert acceptance['runtime_accepted'] and acceptance['metadata_readback_verified']
    assert acceptance['prearmed_dsu_survived_fastbootd']
    resources = read(OUT / 'resource-fat-installation.json')
    assert resources['readback_verified'] and resources['normal_android_boot_after_resource_write']
    assert read(DSU / 'restore-identical-test.json')['post_write_hash_verified']
    assert read(DSU / 'bootloader-restore-identical-test.json')['readback_verified']
    manifest = read(OUT / 'signed-manifest.json')
    assert manifest['removed_packages'] == 49
    assert manifest['avb_flags'] == 0 and not manifest['verification_disabled']
    assert not manifest['hashtree_disabled']
    assert manifest['physical_key_acceptance'].startswith('PASS')
    backup = Path((DSU / 'firmware-backup-path.txt').read_text())
    original_files = {e['file']: e for e in read(backup / 'manifest.json')['entries']}
    layout = {e['name']: e for e in read(DSU / 'super-layout-verified.json')['partitions']}
    entries = []
    for name in ['system', 'product', 'vendor', 'vbmeta_system', 'vbmeta_vendor', 'vbmeta']:
        target = name + '_a'
        source = OUT / 'signed' / (name + '.img')
        expected = manifest['parts'][name]['sha256']
        if name in {'system', 'product', 'vendor'}:
            original = DSU / 'stock-2025-verified-parts' / (target + '.img')
            old_hash = layout[target]['sha256']
        else:
            original = backup / (target + '.img')
            old_hash = original_files[original.name]['sha256']
        assert source.stat().st_size == original.stat().st_size
        assert sha(source) == expected and sha(original) == old_hash
        entries.append({'target': target, 'source': str(source), 'sha256': expected,
                        'size': source.stat().st_size, 'original': str(original),
                        'original_sha256': old_hash, 'status': 'prepared'})
    receipt_file = OUT / 'custom-installation-receipt.json'
    if receipt_file.exists():
        raise RuntimeError('Receipt exists; inspect prior execution before attempting another flash')
    for _ in range(20):
        if SERIAL.encode() in subprocess.check_output(['fastboot', 'devices'], timeout=5):
            break
        time.sleep(2)
    else:
        raise RuntimeError('Authorized tablet not detected')
    guards = {k: getvar(k) for k in ['is-userspace', 'unlocked', 'current-slot',
                                    'product', 'snapshot-update-status']}
    assert guards == {'is-userspace': 'yes', 'unlocked': 'yes', 'current-slot': 'a',
                      'product': 'T307F', 'snapshot-update-status': 'none'}
    for entry in entries:
        assert int(getvar('partition-size:' + entry['target']), 16) == entry['size']
    receipt = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Only six audited slot-A OS/AVB partitions; resource FAT handled separately',
               'preflight': guards, 'entries': entries, 'complete': False,
               'first_boot': 'Prearmed authenticated DSU for read-back verification',
               'userdata_erased': False, 'kernel_or_recovery_replaced': False}
    def save():
        receipt_file.write_text(json.dumps(receipt, indent=2))
    save()
    try:
        for entry in entries:
            entry['status'] = 'writing'
            save()
            print('Writing ' + entry['target'] + ' (' + str(entry['size']) + ' bytes)', flush=True)
            entry['output'] = fb('flash', entry['target'], entry['source'], timeout=600)
            entry['status'] = 'written'
            save()
            print(entry['output'].strip(), flush=True)
    except Exception as error:
        receipt['error'] = str(error)
        save()
        if SERIAL.encode() not in subprocess.check_output(['fastboot', 'devices'], timeout=5):
            raise RuntimeError('USB unavailable; preserve recovery state and use recorded stock images') from error
        # Restore all matching OEM contents and metadata, root vbmeta last.
        for entry in entries:
            entry['rollback_output'] = fb('flash', entry['target'], entry['original'], timeout=600)
            entry['status'] = 'restored_original'
            save()
        receipt['rollback_complete'] = True
        save()
        print(fb('reboot'), flush=True)
        raise
    receipt['complete'] = True
    save()
    print(fb('reboot'), flush=True)
    print('Custom firmware written; next validate every image from authenticated DSU', flush=True)


if __name__ == '__main__':
    main()
