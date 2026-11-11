"""Materialize a filtered inspection tree in a fresh output, never an installed OS.

Run in a device-free, network-free Linux container. EROFS originals remain the
authority for ownership/SELinux/capabilities; this NTFS-derived tree is not a
metadata-safe source for making a flashable Android image.
"""
import hashlib
import json
from pathlib import Path
import shutil

source = Path('/source')
output = Path('/out')
plan = json.loads((output / 'plano-limpeza.json').read_text())
destination = output / 'aplicativos-retidos'
if destination.exists():
    raise ValueError('Refuse to overwrite an existing worktree')
excluded = set(plan['excluded_roots'])
rows = json.loads((output / 'inventario-apks.json').read_text())


def app_root(path):
    p = Path(path)
    for folder in ('app', 'priv-app'):
        if folder in p.parts:
            n = p.parts.index(folder)
            return Path(*p.parts[:n + 2]).as_posix()
    return p.as_posix() if p.parent.name == 'overlay' else p.parent.as_posix()


destination.mkdir()
retained_rows = [row for row in rows if not any(row['path'] == p or row['path'].startswith(p + '/') for p in excluded)]
roots = sorted({app_root(row['path']) for row in retained_rows}, key=lambda p: (len(Path(p).parts), p))
copied_roots = []
for relative in roots:
    if any(relative == p or relative.startswith(p + '/') for p in copied_roots):
        continue
    original, copied = source / relative, destination / relative
    copied.parent.mkdir(parents=True, exist_ok=True)
    if original.is_dir():
        shutil.copytree(original, copied, symlinks=True)
    else:
        shutil.copy2(original, copied)
    copied_roots.append(relative)
for relative in excluded:
    path = destination / relative
    if path.exists() or path.is_symlink():
        raise ValueError('Excluded application remains: ' + relative)
checked = []
for row in rows:
    relative = row['path']
    if any(relative == p or relative.startswith(p + '/') for p in excluded):
        continue
    original = source / relative
    copied = destination / relative
    a = hashlib.file_digest(original.open('rb'), 'sha256').hexdigest()
    b = hashlib.file_digest(copied.open('rb'), 'sha256').hexdigest()
    if a != b:
        raise ValueError('Retained APK changed: ' + relative)
    checked.append({'package': row['package'], 'path': relative, 'sha256': b})
report = {'state': 'FILTERED_APPLICATION_TREE_CREATED', 'removed_packages': plan['removed_packages'],
          'removed_bytes_with_sidecars': plan['removed_bytes_with_sidecars'],
          'excluded_roots_absent': len(excluded), 'retained_apks_hash_checked': len(checked),
          'retained': checked, 'original_images_modified': False, 'device_accessed': False,
          'flashable_image_created': False, 'linux_metadata_roundtrip_validated': False,
          'complete_system_tree': False,
          'note': 'Application tree only. Rebuild must preserve metadata from original EROFS images, not NTFS defaults.'}
(output / 'resultado-copia.json').write_text(json.dumps(report, indent=2))
print(json.dumps({k: v for k, v in report.items() if k != 'retained'}))
