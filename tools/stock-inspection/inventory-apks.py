"""Offline APK inventory from the stock copies, using installed SDK aapt2."""
import concurrent.futures
import csv
import json
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
source = root / 'analise-firmware/stock-URBR2024101701/erofs-extracted'
output = root / 'analise-firmware/central-inteligente/limpeza'
output.mkdir(exist_ok=True)
aapt = Path.home() / 'AppData/Local/Android/Sdk/build-tools/36.0.0/aapt2.exe'


def inspect(path):
    result = subprocess.run([str(aapt), 'dump', 'badging', str(path)], capture_output=True, timeout=30)
    try:
        result.stdout = result.stdout.decode('utf-8')
    except UnicodeDecodeError:
        result.stdout = result.stdout.decode('cp1252')
    if result.returncode:
        raise RuntimeError(str(path) + ': ' + result.stderr[:300].decode('utf-8', errors='replace'))
    match = re.search(r"^package: name='([^']+)'[^\n]*", result.stdout, re.M)
    if not match:
        raise ValueError('No package identity: ' + str(path))
    labels = dict(re.findall(r"^application-label([^:]*):'([^']*)'", result.stdout, re.M))
    label = next((labels[k] for k in ('-pt-BR', '-pt', '', '-en') if k in labels), '')
    relative = path.relative_to(source)
    partition = relative.parts[0]
    row = {'partition': partition, 'path': relative.as_posix(), 'package': match[1],
           'label': label, 'bytes': path.stat().st_size,
           'shared_libraries': re.findall(r"^uses-library:'([^']+)'", result.stdout, re.M),
           'native_code': re.findall(r"^native-code:(.*)$", result.stdout, re.M),
           'launchable': bool(re.search('^launchable-activity:', result.stdout, re.M)),
           'package_line': match[0]}
    return row


with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    rows = sorted(executor.map(inspect, source.rglob('*.apk')), key=lambda r: r['path'])
(output / 'inventario-apks.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
with (output / 'inventario-apks.csv').open('w', newline='', encoding='utf-8-sig') as stream:
    writer = csv.DictWriter(stream, fieldnames=['partition', 'path', 'package', 'label', 'bytes', 'launchable'])
    writer.writeheader()
    writer.writerows({k: r[k] for k in writer.fieldnames} for r in rows)
print(json.dumps({'apk_files': len(rows), 'unique_packages': len({r['package'] for r in rows}),
                  'manufacturer_apps': [{k: r[k] for k in ('path', 'package', 'label', 'bytes')}
                                        for r in rows if r['package'].startswith(('com.softwinner.', 'com.positivo.', 'com.dajingtech.', 'com.clock.'))]}, ensure_ascii=False, indent=2))
