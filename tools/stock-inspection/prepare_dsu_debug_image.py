"""Enable authenticated ADB in the verified, local-only DSU research image.

Never accesses the tablet. Preserves the ext4 inode, xattrs and allocation;
changes both ADB properties, trusts this PC's public USB key, then verifies AVB.
"""
from pathlib import Path
import gzip
import base64
import hashlib
import json
import re
import shutil
import subprocess
import uuid
import struct


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analise-firmware/desbloqueio-T307F/dsu'
IMAGE = OUT / 'system.img'
AVB = ROOT / 'tools/stock-inspection/vendor/avbtool.py'


def linux(path):
    p = Path(path).resolve()
    return '/mnt/' + p.drive[0].lower() + p.as_posix()[2:]


def wsl(*args):
    result = subprocess.run(['wsl', '-d', 'Ubuntu', '-e', *args],
                            capture_output=True, timeout=240)
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr).decode(errors='replace'))
    return result.stdout


def avb(*args):
    return wsl('python3', linux(AVB), *args)


def main():
    if not IMAGE.exists():
        source = OUT / 'lineage-23.0-20251019-UNOFFICIAL-gsi_arm64.img.gz'
        with source.open('rb') as f:
            assert hashlib.file_digest(f, 'sha1').hexdigest() == '50605b921b88ac8d7b6950a7cd2ede7e53a5138b'
        with gzip.open(source, 'rb') as src, IMAGE.open('xb') as out:
            shutil.copyfileobj(src, out, 4 * 1024 * 1024)
    assert IMAGE.stat().st_size == 2434785280
    before = avb('verify_image', '--image', linux(IMAGE))
    (OUT / 'lineage-original-avb-verification.txt').write_bytes(before)
    with IMAGE.open('rb') as f:
        f.seek(1024 + 24)
        assert struct.unpack('<I', f.read(4))[0] == 2  # 4096-byte ext4 blocks.
    patched = {}
    for path in ['/system/build.prop', '/system/system_ext/etc/build.prop']:
        original = wsl('/usr/sbin/debugfs', '-R', 'cat ' + path, linux(IMAGE))
        assert original.count(b'ro.adb.secure=0\n') == 1
        stat = wsl('/usr/sbin/debugfs', '-R', 'stat ' + path, linux(IMAGE))
        pos = original.index(b'ro.adb.secure=0\n') + len(b'ro.adb.secure=')
        logical, within = divmod(pos, 4096)
        block = int(wsl('/usr/sbin/debugfs', '-R', f'bmap {path} {logical}', linux(IMAGE)))
        assert block > 0
        with IMAGE.open('r+b') as stream:
            stream.seek(block * 4096 + within)
            assert stream.read(1) == b'0'
            stream.seek(block * 4096 + within)
            stream.write(b'1')
        changed = wsl('/usr/sbin/debugfs', '-R', 'cat ' + path, linux(IMAGE))
        assert changed == original.replace(b'ro.adb.secure=0\n', b'ro.adb.secure=1\n')
        assert wsl('/usr/sbin/debugfs', '-R', 'stat ' + path, linux(IMAGE)) == stat
        patched[path] = changed
        (OUT / (path.replace('/', '_').strip('_') + '.authenticated')).write_bytes(changed)
    # Only the public key is included. The private host ADB key is never read.
    public = (Path.home() / '.android/adbkey.pub').read_bytes().split()[0]
    decoded = base64.b64decode(public, validate=True)
    assert len(decoded) == 524 and struct.unpack_from('<I', decoded)[0] == 64
    keyfile = OUT / 'dsu-usb-authorized.pub'
    keyfile.write_bytes(public + b' t307-backup-pc\n')
    context = OUT / 'dsu-adb-key-context.bin'
    context.write_bytes(b'u:object_r:system_file:s0\0')
    original_key_stat = wsl('/usr/sbin/debugfs', '-R', 'stat /adb_keys', linux(IMAGE))
    assert b'Type: symlink' in original_key_stat
    assert b'/product/etc/security/adb_keys' in original_key_stat
    for command in ['rm /adb_keys', f'write {linux(keyfile)} /adb_keys',
                    'set_inode_field /adb_keys uid 0',
                    'set_inode_field /adb_keys gid 0',
                    'set_inode_field /adb_keys mode 0100644',
                    f'ea_set -f {linux(context)} /adb_keys security.selinux']:
        wsl('/usr/sbin/debugfs', '-w', '-R', command, linux(IMAGE))
    assert wsl('/usr/sbin/debugfs', '-R', 'cat /adb_keys', linux(IMAGE)) == keyfile.read_bytes()
    key_stat = wsl('/usr/sbin/debugfs', '-R', 'stat /adb_keys', linux(IMAGE))
    assert b'Mode:  0644' in key_stat and b'system_file:s0' in key_stat
    (OUT / 'dsu-adb-key-stat.txt').write_bytes(key_stat)
    wsl('/usr/sbin/e2fsck', '-fn', linux(IMAGE))
    keydir = '/tmp/t307-dsu-' + uuid.uuid4().hex
    wsl('mkdir', '-m', '700', keydir)
    key = keydir + '/avb.pem'
    try:
        wsl('openssl', 'genrsa', '-out', key, '2048')
        avb('erase_footer', '--image', linux(IMAGE))
        avb('add_hashtree_footer', '--image', linux(IMAGE),
            '--partition_name', 'system', '--partition_size', '2434785280',
            '--algorithm', 'SHA256_RSA2048', '--key', key,
            '--hash_algorithm', 'sha256', '--do_not_generate_fec',
            '--rollback_index', '1759276800',
            '--prop', 'com.android.build.system.os_version:16',
            '--prop', 'com.android.build.system.security_patch:2025-10-01',
            '--prop', 'com.android.build.system.fingerprint:generic/lineage_gsi_arm64/generic_arm64:16/BP2A.250605.031.A2/eng.crossg:userdebug/test-keys')
        verification = avb('verify_image', '--image', linux(IMAGE), '--key', key)
        (OUT / 'authenticated-v2-avb-verification.txt').write_bytes(verification)
        (OUT / 'authenticated-v2-avb-info.txt').write_bytes(avb('info_image', '--image', linux(IMAGE)))
    finally:
        wsl('rm', '--', key)
        wsl('rmdir', '--', keydir)
    for path, changed in patched.items():
        assert wsl('/usr/sbin/debugfs', '-R', 'cat ' + path, linux(IMAGE)) == changed
    dst = OUT / 'dsu-authenticated-v2-system.img.gz'
    with IMAGE.open('rb') as src, dst.open('xb') as out, gzip.GzipFile(fileobj=out, mode='wb', mtime=0) as gz:
        shutil.copyfileobj(src, gz, 4 * 1024 * 1024)
    manifest = {'raw_size': IMAGE.stat().st_size,
                'raw_sha256': hashlib.file_digest(IMAGE.open('rb'), 'sha256').hexdigest(),
                'gzip_size': dst.stat().st_size,
                'gzip_sha256': hashlib.file_digest(dst.open('rb'), 'sha256').hexdigest(),
                'change': 'Two build.prop bytes: ro.adb.secure 0 -> 1; original inode metadata unchanged; add /adb_keys with this PC public key',
                'adb_public_key_sha256': hashlib.sha256(decoded).hexdigest(),
                'avb': 'Fresh local key, SHA256_RSA2048, verified hashtree; no FEC',
                'private_signing_key': 'Temporary key removed after verification',
                'target': 'DSU temporary slot only; never flash this to a physical partition'}
    (OUT / 'authenticated-v2-image-manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
