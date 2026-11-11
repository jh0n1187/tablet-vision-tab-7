"""Offline Android sparse + LP reader. New output files only; no device access.

LP layout/checksums follow AOSP system/core fs_mgr/liblp/metadata_format.h.
Supports the single-source linear/zero extents needed for static inspection.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct


class Sparse:
    def __init__(self, path):
        self.stream = Path(path).open('rb')
        self.file_size = Path(path).stat().st_size
        header = self.stream.read(28)
        magic, major, minor, fh, ch, block, blocks, chunks, checksum = struct.unpack('<IHHHHIIII', header)
        if (magic, major, minor, fh, ch, block) != (0xed26ff3a, 1, 0, 28, 12, 4096) or not 0 < chunks < 100000:
            raise ValueError('Unsupported sparse header')
        self.size = blocks * block
        if self.size > 64 * 1024**3:
            raise ValueError('Sparse image outside analysis size bound')
        self.map = []
        logical, cursor = 0, fh
        for index in range(chunks):
            self.stream.seek(cursor)
            kind, reserved, count, total = struct.unpack('<HHII', self.stream.read(ch))
            length = count * block
            payload = total - ch
            if total < ch or cursor + total > self.file_size:
                raise ValueError('Sparse chunk outside source')
            if kind == 0xcac1 and payload != length:
                raise ValueError('Invalid sparse RAW length')
            if kind == 0xcac2 and payload != 4:
                raise ValueError('Invalid sparse FILL length')
            if kind == 0xcac3 and payload != 0:
                raise ValueError('Invalid sparse DONT_CARE length')
            if kind == 0xcac4:
                if count or payload != 4:
                    raise ValueError('Invalid sparse CRC chunk')
            elif kind not in (0xcac1, 0xcac2, 0xcac3):
                raise ValueError('Unknown sparse chunk')
            if length:
                self.map.append((logical, logical + length, kind, cursor + ch))
                logical += length
            cursor += total
        self.container_padding = self.file_size - cursor
        self.stream.seek(cursor)
        if logical != self.size or not 0 <= self.container_padding < 16 or any(self.stream.read(16)):
            raise ValueError('Sparse size/trailing data mismatch')
        self.starts = [row[0] for row in self.map]

    def read(self, offset, size):
        if not 0 <= offset <= offset + size <= self.size or size > 1048576:
            raise ValueError('Out-of-range sparse read')
        result = []
        while size:
            start, end, kind, physical = self.map[bisect.bisect_right(self.starts, offset) - 1]
            n = min(size, end - offset)
            if kind == 0xcac1:
                self.stream.seek(physical + offset - start)
                data = self.stream.read(n)
            elif kind == 0xcac2:
                self.stream.seek(physical)
                pattern = self.stream.read(4)
                shift = (offset - start) % 4
                data = (pattern * ((n + shift + 3) // 4))[shift:shift + n]
            else:
                data = bytes(n)
            if len(data) != n:
                raise ValueError('Short sparse read')
            result.append(data)
            offset += n
            size -= n
        return b''.join(result)


class Raw:
    """Read-only view of a byte-for-byte super partition acquired from eMMC."""
    def __init__(self, path):
        self.stream = Path(path).open('rb')
        self.size = Path(path).stat().st_size
        self.container_padding = 0
        if not 12288 <= self.size <= 64 * 1024**3:
            raise ValueError('Raw super outside analysis size bound')

    def read(self, offset, size):
        if not 0 <= offset <= offset + size <= self.size or size > 1048576:
            raise ValueError('Out-of-range raw read')
        self.stream.seek(offset)
        result = self.stream.read(size)
        if len(result) != size:
            raise ValueError('Short raw read')
        return result


def open_image(path):
    with Path(path).open('rb') as stream:
        magic = stream.read(4)
    return Sparse(path) if magic == struct.pack('<I', 0xed26ff3a) else Raw(path)


def metadata(reader):
    geometry = reader.read(4096, 52)
    magic, size = struct.unpack_from('<II', geometry)
    if (magic, size) != (0x616c4467, 52):
        raise ValueError('Unsupported LP geometry')
    if hashlib.sha256(geometry[:8] + bytes(32) + geometry[40:]).digest() != geometry[8:40]:
        raise ValueError('LP geometry SHA256 mismatch')
    maximum, slots, block = struct.unpack_from('<III', geometry, 40)
    if not 128 <= maximum <= 1048576 or slots not in (1, 2, 3) or block != 4096:
        raise ValueError('Unexpected LP bounds')
    first = reader.read(12288, 128)
    magic, major, minor, size = struct.unpack_from('<IHHI', first)
    if magic != 0x414c5030 or major != 10 or minor > 2 or size not in (128, 256):
        raise ValueError('Unsupported LP metadata header')
    header = reader.read(12288, size)
    if hashlib.sha256(header[:12] + bytes(32) + header[44:]).digest() != header[12:44]:
        raise ValueError('LP header SHA256 mismatch')
    table_size = struct.unpack_from('<I', header, 44)[0]
    if table_size > maximum - size:
        raise ValueError('LP tables exceed allocation')
    tables = reader.read(12288 + size, table_size)
    if hashlib.sha256(tables).digest() != header[48:80]:
        raise ValueError('LP tables SHA256 mismatch')
    def table(position, expected):
        offset, count, stride = struct.unpack_from('<III', header, position)
        if stride != expected or count > 4096 or offset + count * stride > len(tables):
            raise ValueError('Bad LP table bounds')
        return [tables[i:i + stride] for i in range(offset, offset + count * stride, stride)]
    parts, extents = table(80, 52), table(92, 24)
    if len(table(116, 64)) != 1:
        raise ValueError('Only single-source super images supported')
    result = []
    for row in parts:
        name = row[:36].split(b'\0', 1)[0].decode('ascii')
        if not re.fullmatch('[A-Za-z0-9_]+', name):
            raise ValueError('Unsafe LP name')
        attrs, first, count, group = struct.unpack_from('<IIII', row, 36)
        if first + count > len(extents):
            raise ValueError('Extents outside table')
        decoded = []
        for raw in extents[first:first + count]:
            sectors, kind, target, source = struct.unpack('<QIQI', raw)
            if source != 0 or kind not in (0, 1) or kind == 1 and target != 0:
                raise ValueError('Unsupported extent mapping')
            if kind == 0 and (target + sectors) * 512 > reader.size:
                raise ValueError('Extent outside super')
            decoded.append({'size': sectors * 512, 'offset': target * 512, 'kind': kind})
        result.append({'name': name, 'size': sum(e['size'] for e in decoded), 'extents': decoded})
    return {'lp_checksums_valid': True, 'raw_size': reader.size,
            'container_zero_padding': reader.container_padding, 'partitions': result}


def extract(reader, partition, output):
    with (Path(output) / (partition['name'] + '.img')).open('xb') as stream:
        digest = hashlib.sha256()
        for extent in partition['extents']:
            position, remaining = extent['offset'], extent['size']
            while remaining:
                count = min(1048576, remaining)
                data = reader.read(position, count) if extent['kind'] == 0 else bytes(count)
                stream.write(data)
                digest.update(data)
                position += count
                remaining -= count
    return digest.hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--extract', action='append', default=[])
    args = parser.parse_args()
    reader = open_image(args.image)
    report = metadata(reader)
    selected = [p for p in report['partitions'] if p['name'] in args.extract]
    if len(selected) != len(set(args.extract)) or selected and (not args.output or not args.output.is_dir()):
        raise ValueError('Explicit existing output and unique present partitions required')
    for partition in selected:
        partition['sha256'] = extract(reader, partition, args.output)
    print(json.dumps(report, indent=2))
