"""Offline, read-only IMAGEWTY v3 listing and bounded extraction to new files."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def directory(path):
    path = Path(path)
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(1024)
        if header[:8] != b'IMAGEWTY' or struct.unpack_from('<I', header, 8)[0] != 0x300:
            raise ValueError('Expected reviewed IMAGEWTY v3')
        declared = struct.unpack_from('<Q', header, 24)[0]
        stride = struct.unpack_from('<I', header, 32)[0]
        count = struct.unpack_from('<I', header, 60)[0]
        if declared != size or stride != 1024 or not 1 <= count <= 1024:
            raise ValueError('Invalid file size/table geometry')
        items = []
        for index in range(count):
            stream.seek(stride * (index + 1))
            raw = stream.read(stride)
            name_length, record_size = struct.unpack_from('<II', raw)
            if name_length != 256 or record_size != stride:
                raise ValueError('Unexpected item header geometry')
            name = raw[36:292].split(b'\0', 1)[0].decode('ascii')
            if not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
                raise ValueError('Unsafe/unreviewed item name')
            stored, original, offset = struct.unpack_from('<QQQ', raw, 292)
            if offset < stride * (count + 1) or stored > size or offset + stored > size:
                raise ValueError('Item outside image')
            items.append({'index': index, 'name': name, 'stored': stored,
                          'original': original, 'offset': offset,
                          'main': raw[8:16].rstrip(b'\0').decode('ascii'),
                          'subtype': raw[16:32].rstrip(b'\0').decode('ascii')})
    return {'format': 'IMAGEWTY v3', 'size': size, 'items': items}


def extract(source, item, output):
    destination = Path(output) / item['name']
    digest = hashlib.sha256()
    with Path(source).open('rb') as stream, destination.open('xb') as target:
        stream.seek(item['offset'])
        remaining = item['stored']
        while remaining:
            data = stream.read(min(1048576, remaining))
            if not data:
                raise ValueError('Unexpected source EOF')
            target.write(data)
            digest.update(data)
            remaining -= len(data)
    return {'file': str(destination), 'size': item['stored'], 'sha256': digest.hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--extract', action='append', default=[])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    manifest = directory(args.image)
    selected = [item for item in manifest['items'] if item['name'] in args.extract]
    if len(selected) != len(set(args.extract)):
        raise ValueError('Selected items absent or ambiguous')
    if selected:
        if not args.output or not args.output.is_dir():
            raise ValueError('Explicit existing output directory required')
        manifest['extracted'] = [extract(args.image, item, args.output) for item in selected]
    print(json.dumps(manifest, indent=2))
