"""Build a diagnostic legacy uImage, offline only. Never opens USB."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).with_name('ram-adapter')
OUT = ROOT / 'analise-firmware/desbloqueio-T307F/legacy-adapter'
LLVM = Path(r'C:\Users\Jonathan\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin')

def run(args):
    r = subprocess.run([str(x) for x in args], capture_output=True)
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors='replace'))
    return r.stdout

def main():
    OUT.mkdir(exist_ok=True)
    stock = (ROOT / 'analise-firmware/desbloqueio-T307F/u-boot.fex').read_bytes()
    if hashlib.sha256(stock).hexdigest() != 'ae69037c35ffaf45345074a116ba904e232a40899d5624c604ebbbc2e5119143':
        raise ValueError('Reference bootloader changed')
    # This is a code signature, not a runtime address. It must match live bytes.
    start, size = 0x15244, 92
    signature = stock[start:start + size]
    mask = bytearray(b'\xff' * size)
    for offset in (0x14, 0x1c, 0x36, 0x3c, 0x4e):
        first, second = struct.unpack_from('<HH', signature, offset)
        assert first & 0xf800 == 0xf000 and second & 0xd000 == 0xd000
        mask[offset:offset + 4] = bytes(4)
    assert struct.unpack_from('<H', signature, 86)[0] & 0xff00 == 0x4b00
    arrays = '\n'.join('const unsigned char ' + name + '[] = {' + ','.join(str(b) for b in data) + '};'
                       for name, data in [('init_cache_pattern', signature), ('init_cache_mask', mask)])
    (OUT / 'signature.c').write_text(arrays)
    flags = ['--target=armv7a-none-eabi', '-marm', '-mfloat-abi=soft', '-mfpu=none',
             '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-vectorize',
             '-fno-slp-vectorize', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
             '-Wall', '-Wextra', '-Werror', '-O2']
    objects = []
    for file in (SOURCE / 'adapter.c', SOURCE / 'entry.S', OUT / 'signature.c'):
        obj = OUT / (file.stem + '.o')
        run([LLVM / 'clang.exe', *flags, '-c', file, '-o', obj])
        objects.append(obj)
    elf = OUT / 'probe.elf'
    run([LLVM / 'clang.exe', '--target=armv7a-none-eabi', '-nostdlib', '-fuse-ld=lld',
         '-Wl,-T,' + str(SOURCE / 'link.ld'), *objects, '-o', elf])
    binary = OUT / 'probe.bin'
    run([LLVM / 'llvm-objcopy.exe', '-O', 'binary', elf, binary])
    (OUT / 'probe.disassembly.txt').write_bytes(run([LLVM / 'llvm-objdump.exe', '-d', elf]))
    (OUT / 'probe.symbols.txt').write_bytes(run([LLVM / 'llvm-nm.exe', '-n', elf]))
    data = binary.read_bytes()
    # OS U-Boot / architecture ARM / standalone / uncompressed. The entry's
    # byte-swap is also valid DRAM because this vendor path treats it as a
    # legacy Android ramdisk address before processing the uImage.
    fields = [0x27051956, 0, 0, len(data), 0x60600000, 0x60600060, zlib.crc32(data)]
    header = struct.pack('>7I4B32s', *fields, 17, 2, 1, 0, b'T307F read-only RAM probe')
    crc = zlib.crc32(header)
    header = header[:4] + struct.pack('>I', crc) + header[8:]
    # Mark the 2048-byte prefix as an actual v0 Android boot image. Otherwise
    # the SDK CLI would wrap it again and move the uImage to the wrong offset.
    prefix = bytearray(2048)
    prefix[:8] = b'ANDROID!'
    struct.pack_into('<10I', prefix, 8, len(header) + len(data), 0x60600000,
                     0, 0x60006060, 0, 0, 0, 2048, 0, 0)
    result = bytes(prefix) + header + data
    assert result[2048:2052] == bytes.fromhex('27051956')
    check_header = bytearray(result[2048:2112])
    check_header[4:8] = bytes(4)
    assert zlib.crc32(check_header) == struct.unpack_from('>I', result, 2052)[0]
    assert zlib.crc32(result[2112:]) == struct.unpack_from('>I', result, 2072)[0]
    (OUT / 'probe-fastboot.img').write_bytes(result)
    report = {'offline_only': True, 'flash_allowed': False, 'purpose': 'boot original kernel via runtime command registry',
              'bytes': len(result), 'sha256': hashlib.sha256(result).hexdigest(),
              'load': '0x60600000', 'entry': '0x60600060',
              'legacy_ramdisk_copy_target': '0x60006060',
              'firmware_offset_calls': False, 'boot_partition_read_only': 'boot_a',
              'boot_read_destination': '0x70000000', 'boot_read_bytes': 0x4000000,
              'physical_execution_validated': False}
    (OUT / 'build.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
