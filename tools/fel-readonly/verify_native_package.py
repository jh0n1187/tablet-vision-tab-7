"""Verify validation-kit files only. No extraction, installation or device I/O."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat


def verify(root):
    root = Path(root).resolve()
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    for item in manifest['files']:
        relative = PurePosixPath(item['path'])
        if relative.is_absolute() or '..' in relative.parts or '\\' in item['path']:
            raise ValueError('Unsafe manifest path')
        path = root.joinpath(*relative.parts)
        if root not in path.resolve().parents or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError('Non-regular file or path outside kit')
        data = path.read_bytes()
        if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Integrity mismatch: ' + item['path'])
    return {'integrity': 'PASS', 'files_verified': len(manifest['files']), 'USB_access': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    print(json.dumps(verify(parser.parse_args().root), indent=2))
