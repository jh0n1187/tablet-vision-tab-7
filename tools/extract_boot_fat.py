"""Read FAT16 boot-resource data offline; extract files into a fresh directory."""
import json
from pathlib import Path
import re
import struct
import sys


def extract(source, output):
    data = Path(source).read_bytes()
    output = Path(output)
    output.mkdir(exist_ok=False)
    u16 = lambda offset: struct.unpack_from('<H', data, offset)[0]
    sector, cluster_sectors, reserved, fats, roots, fat_sectors = (
        u16(11), data[13], u16(14), data[16], u16(17), u16(22))
    if sector != 512 or cluster_sectors not in (1, 2, 4, 8, 16, 32, 64) or data[54:62] != b'FAT16   ':
        raise ValueError('Expected FAT16 resource profile')
    root_offset = (reserved + fats * fat_sectors) * sector
    data_offset = root_offset + ((roots * 32 + sector - 1) // sector) * sector
    cluster_size = cluster_sectors * sector
    fat_offset = reserved * sector
    entries = []

    def chain(first):
        chunks, seen = [], set()
        while 2 <= first < 0xfff8:
            if first in seen or fat_offset + first * 2 + 2 > root_offset:
                raise ValueError('Invalid/cyclic FAT chain')
            seen.add(first)
            offset = data_offset + (first - 2) * cluster_size
            if offset >= len(data):
                raise ValueError('Referenced cluster beyond stored resource')
            chunks.append(data[offset:offset + cluster_size])
            first = u16(fat_offset + first * 2)
        if first < 0xfff8:
            raise ValueError('Unexpected FAT chain termination')
        return b''.join(chunks)

    def walk(raw, parent, depth=0):
        if depth > 8:
            raise ValueError('Directory depth limit')
        long = {}
        for pos in range(0, len(raw), 32):
            entry = raw[pos:pos + 32]
            if len(entry) != 32 or entry[0] == 0:
                break
            if entry[0] == 0xe5:
                long = {}
                continue
            attr = entry[11]
            if attr == 0x0f:
                long[entry[0] & 31] = entry[1:11] + entry[14:26] + entry[28:32]
                continue
            short = entry[:8].decode('ascii').rstrip() + ('.' + entry[8:11].decode('ascii').rstrip() if entry[8:11].strip() else '')
            name = b''.join(long[i] for i in sorted(long)).decode('utf-16-le').split('\0', 1)[0] if long else short
            long = {}
            if name in ('.', '..') or attr & 8:
                continue
            if not re.fullmatch(r'[A-Za-z0-9_. -]+', name) or name.endswith(('.', ' ')):
                raise ValueError('Unsafe FAT filename')
            target = parent / name
            cluster = struct.unpack_from('<H', entry, 26)[0]
            size = struct.unpack_from('<I', entry, 28)[0]
            if attr & 16:
                target.mkdir(exist_ok=False)
                walk(chain(cluster), target, depth + 1)
            else:
                content = chain(cluster)[:size] if size else b''
                if len(content) != size:
                    raise ValueError('FAT file shorter than declared')
                with target.open('xb') as stream:
                    stream.write(content)
                entries.append({'file': str(target.relative_to(output)), 'size': size})
    walk(data[root_offset:root_offset + roots * 32], output)
    return entries


if __name__ == '__main__':
    print(json.dumps(extract(sys.argv[1], sys.argv[2]), indent=2))
