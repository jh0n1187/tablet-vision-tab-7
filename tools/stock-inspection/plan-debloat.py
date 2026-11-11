"""Explicit offline removal policy; never uninstall packages on a device."""
import json
from pathlib import Path, PurePosixPath

root = Path(__file__).resolve().parents[2]
out = root / 'analise-firmware/central-inteligente/limpeza'
rows = json.loads((out / 'inventario-apks.json').read_text(encoding='utf-8'))

oem = {
    'com.softwinner.camera2': 'Aplicativo de câmera local; HAL e drivers preservados',
    'com.softwinner.camera2.config': 'Overlay específico da câmera removida',
    'com.softwinner.awsysteminfo': 'Diagnóstico do fabricante',
    'com.softwinner.awlogsettings': 'Interface de logs/diagnóstico de fábrica',
    'com.softwinner.dragonatt': 'Automação de testes de fábrica',
    'com.clock.pt1.keeptesting': 'Teste de fábrica',
    'com.softwinner.qrscanner': 'Scanner de QR independente',
    'com.softwinner.runin.res': 'Recursos do teste Runin',
    'com.softwinner.runin': 'Teste prolongado de fábrica',
    'com.softwinner.timerswitch': 'Agendamento de ligar/desligar',
    'com.softwinner.update': 'Atualizador local OEM; já desativado no backup',
    'com.dajingtech.update': 'Atualizador Wi-Fi OEM; já desativado no backup',
    'com.positivo.fota': 'Atualizador Positivo; já desativado no backup',
    'com.softwinner.android.gmsintegration': 'Tela inicial de demonstração do fabricante',
}
consumer = {
    'com.google.android.apps.books': 'Leitura de livros',
    'com.google.android.calculator': 'Calculadora independente',
    'com.android.calculator2': 'Calculadora independente duplicada',
    'com.google.android.calendar': 'Agenda independente; provider preservado',
    'com.google.android.deskclock': 'Relógio independente',
    'com.google.android.apps.docs': 'Google Drive',
    'com.google.android.apps.photosgo': 'Galeria independente',
    'com.google.android.gm': 'Gmail',
    'com.google.android.contacts': 'Contatos independentes; provider preservado',
    'com.google.android.apps.maps': 'Google Maps independente',
    'com.google.android.apps.tachyon': 'Google Meet independente',
    'com.google.android.play.games': 'Google Play Games',
    'com.google.android.videos': 'Google TV/filmes',
    'com.google.android.apps.youtube.music': 'YouTube Music',
    'com.google.android.youtube': 'YouTube independente; reprodução WebView preservada',
    'com.google.android.apps.assistant': 'Assistant Go independente; TTS preservado',
    'com.google.android.apps.searchlite': 'Google Go; já desativado no backup',
    'com.google.android.gms.supervision': 'Interface de supervisão familiar',
    'com.google.android.apps.nbu.files': 'Files by Google independente',
    'com.google.android.apps.adm': 'Localizador independente',
    'com.google.android.apps.safetyhub': 'App de segurança pessoal móvel independente',
    'com.google.android.apps.wellbeing': 'Bem-estar digital',
    'com.google.android.feedback': 'Interface de envio de feedback',
    'com.google.android.gms.location.history': 'Histórico de localização',
    'com.android.egg': 'Easter egg',
    'com.android.soundrecorder': 'Gravador independente',
    'com.android.dreams.basic': 'Protetor de tela de demonstração',
}
remove = dict(oem, **consumer)
protected = {
    'android', 'com.android.systemui', 'com.android.settings', 'com.android.providers.settings',
    'com.android.chrome', 'com.google.android.webview', 'com.google.android.trichromelibrary',
    'com.google.android.gms', 'com.google.android.gms.policy_sidecar_aps', 'com.google.android.gsf',
    'com.android.vending', 'com.google.android.configupdater',
    'com.android.managedprovisioning', 'com.google.android.setupwizard',
    'com.android.launcher3', 'com.google.android.inputmethod.latin', 'com.google.android.tts',
    'com.google.android.go.networkstack', 'com.google.android.go.captiveportallogin',
    'com.google.android.packageinstaller', 'com.android.permissioncontroller',
    'com.android.keychain', 'com.android.certinstaller', 'com.android.credentialmanager',
    'com.android.providers.downloads', 'com.android.providers.media',
    'com.android.providers.contacts', 'com.android.providers.calendar',
    'com.softwinner.awmanager', 'com.softwinner.settingssetup', 'com.softwinner.screenshot',
    'br.homelab.central',
}
if protected.intersection(remove):
    raise ValueError('Policy attempts to remove a protected dependency')


def application_root(path):
    p = PurePosixPath(path)
    if '..' in p.parts or p.is_absolute() or p.parts[0] not in ('system', 'product', 'vendor'):
        raise ValueError('Unsafe source path')
    for folder in ('app', 'priv-app'):
        if folder in p.parts:
            index = p.parts.index(folder)
            if len(p.parts) <= index + 2:
                raise ValueError('Unexpected app layout')
            return PurePosixPath(*p.parts[:index + 2]).as_posix()
    if 'overlay' in p.parts:
        return p.as_posix() if p.parent.name == 'overlay' else p.parent.as_posix()
    raise ValueError('No reviewed app root')


selected = []
for row in rows:
    if row['package'] in remove:
        selected.append(dict(row, reason=remove[row['package']], category='OEM/fábrica' if row['package'] in oem else 'uso geral', root=application_root(row['path'])))
roots = sorted({r['root'] for r in selected})
for row in rows:
    omitted = any(row['path'] == p or row['path'].startswith(p + '/') for p in roots)
    if omitted != (row['package'] in remove):
        raise ValueError('Selected directory contains another package: ' + row['path'])
source = root / 'analise-firmware/stock-URBR2024101701/erofs-extracted'
sidecar_bytes = 0
for relative in roots:
    path = source / relative
    sidecar_bytes += sum(p.stat().st_size for p in path.rglob('*') if p.is_file() and not p.is_symlink()) if path.is_dir() else path.stat().st_size
report = {
    'source_apk_files': len(rows), 'source_packages': len({r['package'] for r in rows}),
    'removed_apk_files': len(selected), 'removed_packages': len({r['package'] for r in selected}),
    'retained_apk_files': len(rows) - len(selected),
    'removed_bytes_with_sidecars': sidecar_bytes, 'removed_apk_bytes': sum(r['bytes'] for r in selected),
    'excluded_roots': roots, 'removed': selected, 'protected_packages': sorted(protected),
    'absent_oem_from_backup': [p for p in ('com.apkpure.aegon',) if p not in {r['package'] for r in rows}],
    'manufacturer_retained': [r for r in rows if r['package'].startswith('com.softwinner.') and r['package'] not in remove],
    'kiosk_apk_in_stock': any(r['package'] == 'br.homelab.central' for r in rows),
    'kiosk_apk_backup_available': (root / 'backup/apks/br.homelab.central/base.apk').is_file(),
    'installer_ready': False,
}
(out / 'plano-limpeza.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps({k: report[k] for k in ('source_packages', 'removed_packages', 'removed_apk_files', 'removed_bytes_with_sidecars', 'retained_apk_files', 'kiosk_apk_in_stock', 'kiosk_apk_backup_available')}, ensure_ascii=False, indent=2))
