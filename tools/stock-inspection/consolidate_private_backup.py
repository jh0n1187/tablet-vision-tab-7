"""Consolidate all private reproduction inputs, deduplicating by SHA256.

Keeps working originals in place; creates no independent backup on this disk.
"""
from pathlib import Path
import datetime
import hashlib
import json
import os
import shutil

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / 'PARA-BACKUP'
CENTRAL = ROOT / 'analise-firmware/central-inteligente'
SKIP_DIRS = {'__pycache__', 'overlay-build', 'video-boot', 'video-carga', 'limpeza'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def selected():
    bases = [ROOT / 'backup', ROOT / 'analise-firmware/desbloqueio-T307F/dsu']
    bases += [CENTRAL / name for name in ['aprovado-v2', 'candidato-2025-v2', 'candidato-2025-v3',
                                         'aviso-boot', 'carga-fallback', 'carga-preta', 'FINAL']]
    for base in bases:
        for directory, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d not in {'private-signing', 'publicacao'}]
            for name in sorted(files):
                path = Path(directory) / name
                if path.suffix in {'.pyc', '.log', '.tmp'} or name.endswith(('.aligned.apk', '.unsigned.apk')):
                    continue
                if path.is_symlink():
                    raise ValueError('Unexpected link: ' + str(path.relative_to(ROOT)))
                yield path
    for path in ROOT.glob('*.md'):
        if path.name != 'README.md':
            yield path
    for name in ['METODO-E-RECUPERACAO.md', 'u-boot.fex']:
        path = ROOT / 'analise-firmware/desbloqueio-T307F' / name
        if path.exists():
            yield path
    yield ROOT / 'tools/stock-inspection/erofs-builder/erofs-utils-v1.7.1.tar.gz'
    for relative in ['tools/winusb-1010/package', 'tools/google-usb-fastbootd/package']:
        for path in (ROOT / relative).rglob('*'):
            if path.is_file():
                yield path
    for relative in ['tools/winusb-1010/signing/homelab-fastboot-1010-public.cer',
                     'tools/winusb-1010/manifest.json']:
        yield ROOT / relative


def main():
    if (DEST / 'MANIFESTO-COMPLETO.json').exists():
        raise FileExistsError('Inspect existing consolidated manifest before repeating')
    initial = json.loads((DEST / 'MANIFESTO-BACKUP.json').read_text(encoding='utf-8'))
    canonical = {}
    identity_hash = {}
    # Validate the prior 41-file export before using it as a deduplication seed.
    for item in initial['files']:
        path = DEST / item['file']
        stat = path.stat()
        digest = sha(path)
        if digest != item['sha256'] or stat.st_size != item['size']:
            raise ValueError('Initial backup differs: ' + item['file'])
        canonical.setdefault(digest, item['file'])
        identity_hash[(stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)] = digest
    entries = []
    for path in sorted(set(selected())):
        stat = path.stat()
        identity = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        digest = identity_hash.get(identity)
        if digest is None:
            digest = sha(path)
            identity_hash[identity] = digest
        if digest not in canonical:
            relative = '05-REPRODUCAO/objetos/' + digest[:2] + '/' + digest
            target = DEST / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if sha(target) != digest:
                    raise ValueError('Object store collision')
            else:
                try:
                    if stat.st_size < 16 * 1024 * 1024:
                        raise OSError('Freeze small mutable inputs as independent snapshots')
                    os.link(path, target)
                    if not os.path.samefile(path, target):
                        raise ValueError('Hardlink verification failed')
                except OSError:
                    shutil.copyfile(path, target)
                    if sha(target) != digest:
                        raise ValueError('Copied payload differs')
            canonical[digest] = relative
        entries.append(dict(target=path.relative_to(ROOT).as_posix(), stored=canonical[digest],
                            size=stat.st_size, sha256=digest))
    manifest = dict(format=1, complete=False, source_workspace=str(ROOT),
                    created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    content_deduplicated=True, independent_backup=False,
                    entries=entries, extras=[], pending=['Encrypted portable keys', 'Offline Git bundle'])
    (DEST / 'MANIFESTO-COMPLETO.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(dict(restorable_files=len(entries), unique_payloads=len(set(e['stored'] for e in entries)),
                          mapped_bytes=sum(e['size'] for e in entries)), indent=2))


if __name__ == '__main__':
    main()
