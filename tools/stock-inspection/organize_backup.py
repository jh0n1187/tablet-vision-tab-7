"""Organize verified images locally without duplicating large files on the same volume."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import shutil

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / 'PARA-BACKUP'
BASE = ROOT / 'analise-firmware/central-inteligente'
DSU = ROOT / 'analise-firmware/desbloqueio-T307F/dsu'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    assert not DEST.exists(), 'Inspect existing backup export before repeating'
    final = BASE / 'FINAL'
    package = json.loads((final / 'PACKAGE-VERIFIED.json').read_text())
    assert package['resource_revision'] == 4 and package['all_13_payloads_roundtrip_hash_verified']
    original = ROOT / 'backup/firmware-2025-dsu-20261111T012532Z'
    manifest = json.loads((original / 'manifest.json').read_text())
    files = [(final / package['bundle'], '01-CUSTOMIZADA/' + package['bundle'], package['sha256'])]
    for name in ['MANIFESTO.json', 'LEIA-ME.md', 'PACKAGE-VERIFIED.json', package['bundle'] + '.sha256']:
        files.append((final / name, '01-CUSTOMIZADA/' + name, None))
    for entry in manifest['entries']:
        assert entry['two_reads_match']
        files.append((original / entry['file'], '02-ORIGINAL-2025/' + entry['file'], entry['sha256']))
    files.append((original / 'manifest.json', '02-ORIGINAL-2025/manifest.json', None))
    dsu = json.loads((DSU / 'authenticated-v2-image-manifest.json').read_text())
    files.append((DSU / 'dsu-authenticated-v2-system.img.gz', '03-DSU-AUTENTICADA/dsu-authenticated-v2-system.img.gz', dsu['gzip_sha256']))
    for name in ['authenticated-v2-image-manifest.json', 'v2-runtime-validation.json',
                 'restore-identical-test.json', 'bootloader-restore-identical-test.json']:
        files.append((DSU / name, '03-DSU-AUTENTICADA/' + name, None))
    files.append((BASE / 'carga-preta/bootloader_a.img', '01-CUSTOMIZADA/bootloader_a-recursos-rev4.img',
                  '284fc6f6c87b292d671367ae1af98683b95b1b4e6e872e490651b2916f5c15d9'))
    # Validate every source before creating the export.
    verified = []
    for source, relative, expected in files:
        digest = sha(source)
        assert expected is None or digest == expected, relative
        verified.append((source, relative, digest))
    DEST.mkdir()
    entries = []
    for source, relative, digest in verified:
        target = DEST / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(source, target)
            assert os.path.samefile(source, target)
            method = 'hardlink; copy this folder to another drive for an independent backup'
        except OSError:
            shutil.copyfile(source, target)
            assert sha(target) == digest
            method = 'copy'
        entries.append(dict(file=relative, size=target.stat().st_size, sha256=digest, organization=method))
    report = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  independent_backup=False, all_sources_full_sha256_verified=True,
                  total_bytes=sum(e['size'] for e in entries), files=entries)
    (DEST / 'MANIFESTO-BACKUP.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    (DEST / 'SHA256SUMS.txt').write_text(''.join(e['sha256'] + '  ' + e['file'] + '\n' for e in entries), encoding='utf-8')
    (DEST / 'LEIA-ME.txt').write_text('''COPIE ESTA PASTA INTEIRA PARA OUTRO DISCO OU ARMAZENAMENTO PRIVADO.

01-CUSTOMIZADA: imagem final Central Inteligente v3, recursos revisão 4. Prioridade máxima.
O ZIP contém 13 partições nativas, NÃO um instalador OTA/TWRP/PhoenixSuit. Não executar como atualização comum.
O recurso FAT atual está também separado; não é o U-Boot executável.

02-ORIGINAL-2025: backup original adquirido desta unidade, 29 arquivos e manifesto.
PRIVADO: contém partições específicas da unidade. Não publicar no GitHub.
Não é clone integral de userdata/FBE/RPMB e não garante recuperação de U-Boot danificado.

03-DSU-AUTENTICADA: imagem temporária autenticada de diagnóstico/extração e recibos de recuperação.
Nunca gravar essa GSI nas partições físicas. A chave pública autorizada é a deste PC;
para outro PC pode ser necessário reconstruí-la com a nova chave pública ADB.

Os arquivos grandes foram organizados com links locais para economizar espaço.
Esta pasta no mesmo disco NÃO é uma cópia independente. Ao copiá-la normalmente para outro disco,
os arquivos devem ser copiados de verdade. Confirme os hashes da cópia com SHA256SUMS.txt.
Não editar os arquivos nesta pasta: links locais compartilham o conteúdo com os originais.
Nenhuma chave privada de assinatura ou ADB foi incluída aqui. Preserve seu perfil Windows
e backup/private-signing separadamente se precisar manter a assinatura dos overlays.
''', encoding='utf-8')
    print(json.dumps(dict(folder=str(DEST), file_count=len(entries), total_bytes=report['total_bytes'],
                          all_hashes_verified=True, independent_backup=False), indent=2))


if __name__ == '__main__':
    main()
