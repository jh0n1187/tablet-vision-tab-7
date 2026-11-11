"""Offline-only debug boot preparation; no USB or device-write operations.

Run under WSL for the existing liblz4/libsepol dependencies. Keep the certified
GKI kernel unchanged and add the AOSP debug-ramdisk mechanism to generic init.
"""
import ctypes as c
import gzip
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'analise-firmware/desbloqueio-T307F/temporary-recovery'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unpack_legacy_lz4(data):
    if data[:4] != bytes.fromhex('02214c18'):
        raise ValueError('Expected legacy LZ4')
    lib = c.CDLL('liblz4.so.1')
    fn = lib.LZ4_decompress_safe
    fn.argtypes = [c.c_void_p, c.c_void_p, c.c_int, c.c_int]
    fn.restype = c.c_int
    pos = 4
    result = bytearray()
    while pos < len(data):
        if pos + 4 > len(data):
            raise ValueError('Truncated LZ4 block size')
        size = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if size == 0 and pos == len(data):
            break
        if not 0 < size <= 9 * 1024 * 1024 or pos + size > len(data):
            raise ValueError('Invalid LZ4 block size')
        source = c.create_string_buffer(data[pos:pos + size])
        dest = c.create_string_buffer(8 * 1024 * 1024)
        count = fn(source, dest, size, len(dest))
        if count < 0:
            raise ValueError('LZ4 decompression failed')
        result.extend(dest.raw[:count])
        if len(result) > 64 * 1024 * 1024:
            raise ValueError('Ramdisk decompression limit')
        pos += size
    return bytes(result)


def parse_cpio(data):
    pos = 0
    entries = []
    names = set()
    while pos + 110 <= len(data):
        start = pos
        if data[pos:pos + 6] != b'070701':
            raise ValueError('Expected newc CPIO')
        fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        size, name_size = fields[6], fields[11]
        if not 1 <= name_size <= 4096 or size > 64 * 1024 * 1024:
            raise ValueError('CPIO bounds')
        pos += 110
        raw_name = data[pos:pos + name_size]
        if len(raw_name) != name_size or raw_name[-1:] != b'\0':
            raise ValueError('Invalid CPIO name')
        name = raw_name[:-1].decode()
        pos = (pos + name_size + 3) & ~3
        payload = data[pos:pos + size]
        if len(payload) != size:
            raise ValueError('Truncated CPIO payload')
        pos = (pos + size + 3) & ~3
        if name == 'TRAILER!!!':
            if any(data[pos:]):
                raise ValueError('Unexpected CPIO trailing data')
            return entries
        if name in names or name.startswith('/') or '..' in Path(name).parts:
            raise ValueError('Duplicate/unsafe CPIO name')
        names.add(name)
        entries.append({'name': name, 'fields': fields, 'data': payload,
                        'raw': data[start:pos]})
    raise ValueError('CPIO trailer missing')


def newc(name, payload, ino):
    fields = [ino, 0o100644, 0, 0, 1, 0, len(payload), 0, 0, 0, 0,
              len(name.encode()) + 1, 0]
    data = b'070701' + b''.join(f'{v:08x}'.encode() for v in fields)
    data += name.encode() + b'\0'
    data += bytes(-len(data) % 4)
    data += payload
    return data + bytes(-len(data) % 4)


def compile_policy(platform):
    """Compile the same vendor-33/platform-34 split inputs as Android init."""
    base = OUT / 'policy-current'
    paths = [base / p for p in (
        'system/mapping/33.0.cil', 'system/mapping/33.0.compat.cil',
        'system_ext/system_ext_sepolicy.cil', 'system_ext/mapping/33.0.compat.cil',
        'product/product_sepolicy.cil', 'vendor/plat_pub_versioned.cil',
        'vendor/vendor_sepolicy.cil')]
    lib = c.CDLL('libsepol.so.2')
    lib.cil_db_init.argtypes = [c.POINTER(c.c_void_p)]
    lib.cil_db_destroy.argtypes = [c.POINTER(c.c_void_p)]
    lib.cil_add_file.argtypes = [c.c_void_p, c.c_char_p, c.c_void_p, c.c_size_t]
    lib.cil_add_file.restype = c.c_int
    lib.cil_compile.argtypes = [c.c_void_p]
    lib.cil_compile.restype = c.c_int
    lib.cil_build_policydb.argtypes = [c.c_void_p, c.POINTER(c.c_void_p)]
    lib.cil_build_policydb.restype = c.c_int
    lib.sepol_policydb_free.argtypes = [c.c_void_p]
    db = c.c_void_p()
    lib.cil_db_init(c.byref(db))
    policydb = c.c_void_p()
    try:
        for name, value in [('cil_set_mls', 1), ('cil_set_multiple_decls', 1),
                            ('cil_set_disable_neverallow', 1),
                            ('cil_set_attrs_expand_generated', 1),
                            ('cil_set_policy_version', 33)]:
            fn = getattr(lib, name)
            fn.argtypes = [c.c_void_p, c.c_int]
            fn(db, value)
        inputs = [('platform', platform)] + [(str(p), p.read_bytes()) for p in paths]
        for name, data in inputs:
            if lib.cil_add_file(db, name.encode(), data, len(data)):
                raise ValueError('CIL input rejected: ' + name)
        if lib.cil_compile(db) or lib.cil_build_policydb(db, c.byref(policydb)):
            raise ValueError('Split policy compilation failed')
    finally:
        if policydb:
            lib.sepol_policydb_free(policydb)
        lib.cil_db_destroy(c.byref(db))
    return [{'name': name, 'sha256': sha(data)} for name, data in inputs]


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gzip-kernel', action='store_true')
    args = parser.parse_args()
    source = OUT / ('official-gki-boot-gz.img' if args.gzip_kernel else 'official-gki-boot.img')
    boot = source.read_bytes()
    if boot[:8] != b'ANDROID!' or struct.unpack_from('<I', boot, 40)[0] != 4:
        raise ValueError('GKI boot header mismatch')
    kernel_size, old_ramdisk = struct.unpack_from('<II', boot, 8)
    if old_ramdisk != 0:
        raise ValueError('Certified source unexpectedly contains ramdisk')
    kernel = boot[4096:4096 + kernel_size]
    raw_kernel = gzip.decompress(kernel) if args.gzip_kernel else kernel
    if args.gzip_kernel and raw_kernel != (OUT / 'official-gki-Image').read_bytes():
        raise ValueError('Compressed certified kernel differs from uncompressed source')
    expected = b'5.15.167-android13-8-00017-gb1f32b310a30-ab12826353'
    if expected not in raw_kernel:
        raise ValueError('Kernel build identity mismatch')
    start = raw_kernel.index(b'IKCFG_ST') + 8
    end = raw_kernel.index(b'IKCFG_ED', start)
    if gzip.decompress(raw_kernel[start:end]) != gzip.decompress((OUT / 'current-kernel-config.gz').read_bytes()):
        raise ValueError('Current and certified kernel configs differ')
    original = unpack_legacy_lz4((OUT / 'init_boot.fex.ramdisk').read_bytes())
    entries = parse_cpio(original)
    # AOSP debug builds make only the privileged debugging domain permissive.
    # The normal Android domains remain enforcing; USB authentication stays on.
    delta = b'\n(allow adbd su (process (dyntransition)))\n(typepermissive su)\n'
    platform = (OUT / 'current-plat_sepolicy.cil').read_bytes()
    baseline_inputs = compile_policy(platform)
    debug_inputs = compile_policy(platform + delta)
    additions = {'force_debuggable': b'',
                 'adb_debug.prop': b'ro.adb.secure=1\nro.debuggable=1\nro.force.debuggable=1\n',
                 'userdebug_plat_sepolicy.cil': platform + delta}
    if any(e['name'] in additions for e in entries):
        raise ValueError('Debug additions already present')
    cpio = b''.join(e['raw'] for e in entries)
    for i, (name, payload) in enumerate(additions.items(), 10000):
        cpio += newc(name, payload, i)
    cpio += newc('TRAILER!!!', b'', 20000)
    parsed = parse_cpio(cpio)
    assert len(parsed) == len(entries) + 3
    for before, after in zip(entries, parsed):
        assert before['raw'] == after['raw']
    ramdisk = gzip.compress(cpio, mtime=0)
    header = bytearray(boot[:4096])
    struct.pack_into('<I', header, 12, len(ramdisk))
    struct.pack_into('<I', header, 1580, 0)  # No stale GKI boot signature.
    result = bytes(header) + kernel + bytes(-len(kernel) % 4096)
    result += ramdisk + bytes(-len(ramdisk) % 4096)
    if args.gzip_kernel and len(result) > 0x2000000:
        raise ValueError('Image exceeds confirmed bootloader download buffer')
    destination = OUT / 'temporary-debug-boot.img'
    destination.write_bytes(result)
    (OUT / 'debug-ramdisk.cpio').write_bytes(cpio)
    (OUT / 'debug-policy.delta.cil').write_bytes(delta)
    report = {'offline_only': True, 'kernel_unchanged': True,
              'kernel_compression': 'gzip' if args.gzip_kernel else 'none',
              'kernel_build': expected.decode(), 'kernel_config_identical': True,
              'source_sha256': sha(boot), 'output_sha256': sha(result),
              'output_bytes': len(result), 'original_cpio_entries': len(entries),
              'preserved_original_cpio_entries': True,
              'added_files': list(additions), 'adb_authentication': True,
              'temporary_permissive_domain': 'su', 'global_selinux_enforcing': True,
              'baseline_policy_compiled': True, 'debug_policy_compiled': True,
              'baseline_policy_inputs': baseline_inputs, 'debug_policy_inputs': debug_inputs,
              'physical_boot_compatibility_tested': False,
              'partition_flash_allowed': False}
    (OUT / 'preparation.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if not k.endswith('_inputs')}, indent=2))


if __name__ == '__main__':
    main()
