"""Verify and restore private build inputs from the consolidated external backup.

Never accesses a tablet. Existing different files are never overwritten.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import shutil
import subprocess


def safe_path(root, relative):
    path = PurePosixPath(relative)
    if path.is_absolute() or '..' in path.parts or not path.parts or any(':' in p or '\\' in p for p in path.parts):
        raise ValueError('Unsafe backup path')
    result = root.joinpath(*path.parts)
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError('Backup path escapes destination')
    return result


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def verify(backup, index):
    checked = {}
    targets = set()
    for item in index['entries']:
        source = safe_path(backup, item['stored'])
        safe_path(Path.cwd(), item['target'])
        if item['target'] in targets:
            raise ValueError('Duplicate restore target')
        targets.add(item['target'])
        if item['stored'] not in checked:
            digest = sha(source)
            if source.stat().st_size != item['size'] or digest != item['sha256']:
                raise ValueError('Backup content differs: ' + item['stored'])
            checked[item['stored']] = digest
        elif checked[item['stored']] != item['sha256']:
            raise ValueError('Conflicting content mapping')
    for extra in index.get('extras', []):
        if sha(safe_path(backup, extra['stored'])) != extra['sha256']:
            raise ValueError('Backup auxiliary file differs: ' + extra['stored'])
    return len(checked)


def restore(backup, destination, index):
    # Preflight the entire destination before making any changes.
    files = []
    old_root = index['source_workspace']
    for item in index['entries']:
        source = safe_path(backup, item['stored'])
        target = safe_path(destination, item['target'])
        rewritten = None
        if target.name in {'firmware-backup-path.txt', 'pre-dsu-backup-path.txt'}:
            text = source.read_text(encoding='utf-8').strip()
            if text.startswith(old_root):
                rewritten = (str(destination) + text[len(old_root):]).encode('utf-8')
        expected = hashlib.sha256(rewritten).hexdigest() if rewritten is not None else item['sha256']
        if target.exists() and sha(target) != expected:
            raise FileExistsError('Existing file differs; nothing overwritten: ' + item['target'])
        files.append((source, target, rewritten, expected))
    written = 0
    for source, target, rewritten, expected in files:
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if rewritten is not None:
            with target.open('xb') as f:
                f.write(rewritten)
        else:
            shutil.copyfile(source, target)
        if sha(target) != expected:
            raise ValueError('Restored file hash differs: ' + str(target))
        written += 1
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', required=True, type=Path)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    backup = args.backup.resolve()
    index = json.loads((backup / 'MANIFESTO-COMPLETO.json').read_text(encoding='utf-8'))
    if not index.get('complete', False):
        raise ValueError('Backup consolidation is incomplete; check the pending items in its manifest')
    count = verify(backup, index)
    print(f'Verified {count} distinct private payloads and auxiliary files.')
    if not args.execute:
        return
    if args.destination is None:
        parser.error('--destination required with --execute')
    destination = args.destination.resolve()
    if destination == backup or destination.is_relative_to(backup) or backup.is_relative_to(destination):
        raise ValueError('Workspace and external backup must not overlap')
    if not destination.exists():
        bundle = safe_path(backup, '05-REPRODUCAO/projeto-fontes.bundle')
        subprocess.run(['git', 'clone', str(bundle), str(destination)], check=True)
    if not (destination / 'tools/stock-inspection').is_dir():
        raise ValueError('Expected a clone of the tablet project')
    written = restore(backup, destination, index)
    print(f'Restored {written} files; no device commands executed.')
    print('Restore encrypted keys separately with portable_private_keys.ps1 -Mode Restore.')


if __name__ == '__main__':
    main()
