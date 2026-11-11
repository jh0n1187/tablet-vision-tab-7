"""Read removed app manifests to identify declared startup/background work."""
import concurrent.futures
import json
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[2]
folder = root / 'analise-firmware/central-inteligente/limpeza'
plan = json.loads((folder / 'plano-limpeza.json').read_text(encoding='utf-8'))
source = root / 'analise-firmware/stock-URBR2024101701/erofs-extracted'
aapt = Path.home() / 'AppData/Local/Android/Sdk/build-tools/36.0.0/aapt2.exe'


def inspect(row):
    result = subprocess.run([str(aapt), 'dump', 'xmltree', str(source / row['path']),
                             '--file', 'AndroidManifest.xml'], capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('Manifest inspection failed: ' + row['package'])
    text = result.stdout.decode('utf-8', errors='replace')
    actions = {'BOOT_COMPLETED': 'android.intent.action.BOOT_COMPLETED',
               'LOCKED_BOOT_COMPLETED': 'android.intent.action.LOCKED_BOOT_COMPLETED',
               'MY_PACKAGE_REPLACED': 'android.intent.action.MY_PACKAGE_REPLACED',
               'CONNECTIVITY_CHANGE': 'android.net.conn.CONNECTIVITY_CHANGE',
               'USER_PRESENT': 'android.intent.action.USER_PRESENT'}
    signals = [signal for signal, action in actions.items() if '"' + action + '"' in text]
    (folder / 'manifestos').mkdir(exist_ok=True)
    (folder / 'manifestos' / (row['package'] + '.txt')).write_text(text, encoding='utf-8')
    return {'package': row['package'], 'category': row['category'], 'startup_signals': signals,
            'declared_services': len(re.findall(r'\bE: service\b', text)),
            'declared_receivers': len(re.findall(r'\bE: receiver\b', text)),
            'has_jobs_or_workmanager': any(x in text for x in ('JobService', 'WorkManager', 'SystemJobService'))}


with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    rows = list(executor.map(inspect, plan['removed']))
report = {'scope': 'Static manifest evidence, not proof of active processes or measured speed',
          'removed_apps_with_startup_signals': sum(bool(r['startup_signals']) for r in rows),
          'removed_declared_services': sum(r['declared_services'] for r in rows), 'apps': rows}
(folder / 'auditoria-background.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps({k: v for k, v in report.items() if k != 'apps'}, ensure_ascii=False))
