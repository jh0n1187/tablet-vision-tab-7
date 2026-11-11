"""Seal the consolidated private backup after portable key export and source commit."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
from restore_private_backup import verify

ROOT = Path(__file__).resolve().parents[2]
BACKUP = ROOT / 'PARA-BACKUP'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    key_bundle = BACKUP / '04-CHAVES/central-private-keys.encrypted.json'
    envelope = json.loads(key_bundle.read_text(encoding='utf-8'))
    assert envelope['format'] == 'CentralPrivateKeys-v1' and envelope['cipher'] == 'AES-256-GCM'
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip(), 'Commit public source changes before sealing backup'
    index_path = BACKUP / 'MANIFESTO-COMPLETO.json'
    index = json.loads(index_path.read_text(encoding='utf-8'))
    assert not index.get('complete'), 'Inspect sealed backup before repeating'
    folder = BACKUP / '05-REPRODUCAO'
    bundle = folder / 'projeto-fontes.bundle'
    if not bundle.exists():
        subprocess.run(['git', 'bundle', 'create', str(bundle), 'main'], check=True, cwd=ROOT)
    else:
        refs = subprocess.check_output(['git', 'bundle', 'list-heads', str(bundle)], cwd=ROOT, text=True)
        current = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        assert current + ' refs/heads/main' in refs, 'Offline bundle is stale; inspect before replacing'
    subprocess.run(['git', 'bundle', 'verify', str(bundle)], check=True, cwd=ROOT, capture_output=True)
    for source, name in [(ROOT / 'tools/stock-inspection/restore_private_backup.py', 'restaurar.py'),
                         (ROOT / 'tools/stock-inspection/portable_private_keys.ps1', 'chaves-portateis.ps1'),
                         (ROOT / 'docs/BACKUP-PRIVADO.md', 'GUIA-RESTAURACAO.md')]:
        shutil.copyfile(source, folder / name)
    index['git_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    index['extras'] = [dict(stored=p.relative_to(BACKUP).as_posix(), size=p.stat().st_size, sha256=sha(p))
                       for p in [key_bundle, bundle, folder / 'restaurar.py', folder / 'chaves-portateis.ps1', folder / 'GUIA-RESTAURACAO.md']]
    count = verify(BACKUP, index)
    index.update(complete=True, pending=[], unique_payloads_verified=count,
                 portable_keys_encrypted=True, private_plaintext_keys_in_export=False)
    index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding='utf-8')
    checksums = {e['stored']: e['sha256'] for e in index['entries']}
    checksums.update({e['stored']: e['sha256'] for e in index['extras']})
    (BACKUP / 'SHA256SUMS-COMPLETO.txt').write_text(''.join(digest + '  ' + name + '\n' for name, digest in sorted(checksums.items())), encoding='utf-8')
    (BACKUP / 'LEIA-ME.txt').write_text('''BACKUP PRIVADO COMPLETO — COPIE SOMENTE ESTA PASTA INTEIRA PARA O HD EXTERNO.

01-CUSTOMIZADA: imagem final e FAT atual, referências e hashes.
02-ORIGINAL-2025: firmware original desta unidade; dados privados.
03-DSU-AUTENTICADA: GSI temporária de aquisição/recuperação, nunca gravar em partição física.
04-CHAVES: chaves de assinatura e ADB protegidas por AES-256-GCM e pela senha escolhida na janela local.
05-REPRODUCAO: fontes Git offline, restaurador, guia e conteúdos privados deduplicados.

Este conjunto contém os arquivos locais necessários; não é preciso copiar backup/ e analise-firmware/
separadamente para reproduzir o projeto. Windows/SDK/JDK/Docker/WSL são reinstaláveis e não foram clonados.
Guarde a senha das chaves no gerenciador de senhas, separada desta pasta. Não publique este backup.

Confira a cópia no HD:
python E:\\PARA-BACKUP\\05-REPRODUCAO\\restaurar.py --backup E:\\PARA-BACKUP

Restaurar em pasta nova (Git e Python instalados):
python E:\\PARA-BACKUP\\05-REPRODUCAO\\restaurar.py --backup E:\\PARA-BACKUP --destination C:\\projetos\\tablet-positivo --execute

Depois restaure o pacote de chaves pela ferramenta PowerShell 7 e sua senha; veja GUIA-RESTAURACAO.md.
O restaurador não grava no tablet nem sobrescreve arquivos existentes diferentes.

Arquivos grandes locais usam links para economizar espaço. Esta pasta no mesmo disco ainda NÃO é
um backup independente. Copie normalmente para outro disco e confira os hashes antes de apagar a
pasta PARA-BACKUP local. Apagar apenas esses links locais não apaga os originais do projeto.
Não editar imagens através dos links. O mapa completo é MANIFESTO-COMPLETO.json;
o manifesto antigo de 41 arquivos refere-se apenas à seleção inicial de imagens.
''', encoding='utf-8')
    size = sum(p.stat().st_size for p in BACKUP.rglob('*') if p.is_file())
    print(json.dumps(dict(complete=True, mapped_files=len(index['entries']), unique_payloads=count,
                          folder_bytes=size, portable_keys_encrypted=True, git_commit=index['git_commit']), indent=2))


if __name__ == '__main__':
    main()
