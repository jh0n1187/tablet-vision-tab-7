"""Atomically update final bundle after the guarded FAT-only visual update."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'analise-firmware/central-inteligente'
FINAL = BASE / 'FINAL'
OUT = BASE / 'aviso-boot'


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main(charging_fallback=False, black_charge=False):
    OUT = BASE / ('carga-preta' if black_charge else 'carga-fallback' if charging_fallback else 'aviso-boot')
    revision = 4 if black_charge else 3 if charging_fallback else 2
    install = json.loads((OUT / 'installation.json').read_text())
    health = json.loads((OUT / 'normal-boot.json').read_text())
    assert install['readback_verified'] and install['prefix_gpt_uboot_unchanged']
    assert health['boot_completed'] and health['display_id'] == 'Central Inteligente T307F v3'
    image = OUT / 'bootloader_a.img'
    assert sha(image) == install['actual_sha256']
    bundle = FINAL / 'T307F-Central-Inteligente-v3-particoes.zip'
    old_report = json.loads((FINAL / 'PACKAGE-VERIFIED.json').read_text())
    assert sha(bundle) == old_report['sha256']
    manifest = json.loads((FINAL / 'MANIFESTO.json').read_text(encoding='utf-8'))
    assert manifest.get('resource_revision', 1) == revision - 1
    for entry in manifest['files']:
        if entry['target'] == 'bootloader_a':
            assert entry['sha256'] == install['old_sha256']
            entry['sha256'] = install['actual_sha256']
            entry['role'] += '; initial charging frame black' if black_charge else '; static charging fallback graphics updated' if charging_fallback else '; unlocked-state graphic replaced with Central splash'
    manifest['resource_revision'] = revision
    manifest['security']['bootloader'] = 'unlocked; orange state retained; warning BMP replaced by Central splash'
    if not charging_fallback and not black_charge:
        manifest['boot_visual_update'] = {
        'only_file_changed': 'orange_warning.bmp pixel content',
        'delay_seconds_approximately': 5, 'delay_removed': False,
        'real_uboot_modified': False, 'charging_path_uses_same_graphic': True,
        'physical_early_screen_observed_by_agent': False,
        'charging_with_power_off_physically_tested': False,
        'full_resource_readback_verified': True,
            'normal_android_boot_verified': True}
    elif charging_fallback:
        manifest['boot_visual_update']['physical_screen_confirmed_by_user'] = True
        manifest['boot_visual_update']['charging_with_power_off_physically_tested'] = True
        manifest['charging_fallback_update'] = {
            'replaced': ['bat/battery_charge.bmp', 'bat/battery.bmp', 'bat/bempty.bmp', 'bat/bootlogo.bmp'],
            'connection_frame': 'Approved charger frame 0, rotated 270 degrees to native panel orientation',
            'all_32_fat_files_verified': True, 'full_resource_readback_verified': True,
            'gpt_uboot_and_inactive_resource_unchanged': True,
            'charging_control_or_temperature_warnings_changed': False,
            'physical_charging_validation_after_this_update': False}
    else:
        manifest['charging_fallback_update']['physical_charging_validation_after_this_update'] = True
        manifest['initial_charging_frame_update'] = {
            'file': 'bat/battery_charge.bmp', 'pixels': 'all black, header preserved',
            'reason': 'User prefers black before Central splash and measured charging percentage',
            'all_other_31_fat_files_unchanged': True,
            'full_resource_readback_verified': True,
            'gpt_uboot_and_inactive_resource_unchanged': True,
            'charging_logic_and_delays_changed': False,
            'physical_charging_validation_after_this_update': False}
    readme = (FINAL / 'LEIA-ME.md').read_text(encoding='utf-8')
    old = 'O aviso anterior ao splash é o estado ORANGE de bootloader desbloqueado. Ele permanece por projeto; não bloquear o bootloader com esta ROM sem comprovar suporte à chave e recuperação.'
    new = ('Revisão 2 dos recursos: os pixels de `orange_warning.bmp` foram substituídos pelo splash Central Inteligente. '
           'O estado ORANGE/desbloqueado e a pausa de cerca de 5 segundos continuam; a mudança é visual e também se aplica ao caminho de carga desligada. '
           'Código U-Boot/TOC, verificações e recursos de erro vermelho/amarelo não foram alterados. '
           'A FAT inteira foi lida de volta com SHA256 idêntico, prefixo GPT/U-Boot e FAT inativa ficaram idênticos, e o Android v3 reiniciou. '
           'A tela física anterior ao Android e a carga desligada ainda dependem de observação na unidade. '
           'Não bloquear o bootloader com esta ROM sem comprovar suporte à chave e recuperação.')
    if black_charge:
        readme = readme.replace('A confirmação física da carga após esta revisão ainda está pendente; o vídeo é anterior à correção.',
                                'O usuário confirmou a sequência da revisão 3: bateria inicial, splash Central e carga com percentual real.')
        readme += ('\n## Recursos revisão 4 — etapa inicial preta\n\n'
                   'A pedido do usuário, somente os pixels de `bat/battery_charge.bmp` foram zerados para preto, '
                   'preservando todo o cabeçalho BMP e a estrutura FAT. A sequência agora deve ser preto, '
                   'splash Central e animação Android com percentual real. Nenhum outro recurso, código ou tempo de boot mudou. '
                   'Gravação integral conferida por SHA256, GPT/U-Boot e FAT inativa idênticos, novo boot Android normal validado. '
                   'A observação física da carga após esta revisão ainda está pendente.\n')
    elif charging_fallback:
        readme = readme.replace('A tela física anterior ao Android e a carga desligada ainda dependem de observação na unidade.',
                                'O usuário confirmou o splash no reinício e enviou vídeo da carga desligada; o aviso em inglês não apareceu.')
        readme += ('\n## Recursos revisão 3 — quadros auxiliares de carga\n\n'
                   'O vídeo revelou um ícone branco antigo por cerca de 0,4 segundo antes do splash. '
                   '`bat/battery_charge.bmp` agora reutiliza o primeiro quadro da carga aprovada, com rotação nativa correta. '
                   'Também foram atualizados os recursos estáticos battery.bmp, bempty.bmp e o logo A31 antigo de bat/bootlogo.bmp. '
                   'Os demais 28 arquivos da FAT, incluindo animações, avisos de temperatura e Verified Boot, ficaram intactos. '
                   'A FAT foi gravada com hash integral conferido, sem alterar GPT/U-Boot/FAT inativa, e Android normal reiniciou. '
                   'A confirmação física da carga após esta revisão ainda está pendente; o vídeo é anterior à correção.\n')
    else:
        assert old in readme
        readme = readme.replace(old, new)
    additions = {
        'LEIA-ME.md': readme.encode('utf-8'),
        'MANIFESTO.json': json.dumps(manifest, indent=2, ensure_ascii=False).encode('utf-8'),
        f'validation/boot-resource-revision{revision}-installation.json': (OUT / 'installation.json').read_bytes(),
        f'validation/boot-resource-revision{revision}-normal-boot.json': (OUT / 'normal-boot.json').read_bytes(),
        f'validation/boot-resource-revision{revision}-offline.json': (OUT / 'bootloader_a.validation.json').read_bytes()}
    temporary = bundle.with_suffix('.updated.tmp')
    assert not temporary.exists()
    with zipfile.ZipFile(bundle) as previous, zipfile.ZipFile(temporary, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as updated:
        for info in previous.infolist():
            if info.filename in additions:
                continue
            if info.filename == 'resources/bootloader_a.img':
                updated.write(image, info.filename)
            else:
                with previous.open(info) as source, updated.open(info.filename, 'w', force_zip64=True) as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)
            print('Packed', info.filename, flush=True)
        for name, data in additions.items():
            updated.writestr(name, data)
    with zipfile.ZipFile(temporary) as z:
        for entry in manifest['files']:
            with z.open(entry['archive']) as f:
                assert hashlib.file_digest(f, 'sha256').hexdigest() == entry['sha256'], entry['archive']
        assert not any('private' in n.lower() or n.endswith(('.p12', '.pem', '.dpapi')) for n in z.namelist())
    digest = sha(temporary)
    (OUT / 'previous-package-verification.json').write_text(json.dumps(old_report, indent=2), encoding='utf-8')
    os.replace(temporary, bundle)
    (FINAL / 'LEIA-ME.md').write_text(readme, encoding='utf-8')
    (FINAL / 'MANIFESTO.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    (FINAL / (bundle.name + '.sha256')).write_text(digest + '  ' + bundle.name + '\n')
    report = dict(bundle=bundle.name, size=bundle.stat().st_size, sha256=digest,
                  resource_revision=revision, all_13_payloads_roundtrip_hash_verified=True,
                  previous_bundle_sha256=old_report['sha256'], private_keys_excluded=True)
    (FINAL / 'PACKAGE-VERIFIED.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    assert sys.argv[1:] in ([], ['--charging-fallback'], ['--black-charge'])
    main(charging_fallback=sys.argv[1:] == ['--charging-fallback'], black_charge=sys.argv[1:] == ['--black-charge'])
