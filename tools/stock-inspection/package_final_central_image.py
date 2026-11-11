"""Create and fully verify a local final partition-image bundle. No USB writes."""
from pathlib import Path
import datetime
import hashlib
import json
import zipfile

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'analise-firmware/central-inteligente'
OUT=BASE/'candidato-2025-v3'


def read(path):return json.loads(path.read_text(encoding='utf-8'))
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    health=read(OUT/'second-boot-health-validation.json')
    assert health['second_normal_boot_completed'] and health['wifi_connected']
    assert read(OUT/'post-flash-verification.json')['all_match']
    assert read(OUT/'final-theme-runtime-validation.json')['reboot_persistence_verified']
    assets=read(OUT/'theme-assets-manifest.json')
    destination=BASE/'FINAL';destination.mkdir(exist_ok=True)
    bundle=destination/'T307F-Central-Inteligente-v3-particoes.zip'
    files=[]
    modified={'system','product','vendor','vbmeta','vbmeta_system','vbmeta_vendor'}
    for name in ['system','product','vendor','vbmeta','vbmeta_system','vbmeta_vendor',
                 'boot','init_boot','vendor_boot','dtbo','system_dlkm','vendor_dlkm']:
        source=OUT/'signed'/(name+'.img')
        files.append({'archive':'images/'+name+'.img','target':name+'_a',
                      'source':source,'size':source.stat().st_size,'sha256':sha(source),
                      'modified':name in modified,
                      'role':'Final custom payload' if name in modified else 'Preserved OEM boot/recovery/module reference; no default flash'})
    source=OUT/'bootloader_a.img'
    files.append({'archive':'resources/bootloader_a.img','target':'bootloader_a','source':source,
                  'size':source.stat().st_size,'sha256':sha(source),'modified':True,
                  'role':'Only FAT graphics resources, not executable U-Boot/TOC; separate DSU writer'})
    manifest={'name':'Central Inteligente T307F v3','base':'T307TSF.BR.OPEN.2025092701',
              'android':'14','security_patch':'2025-08-05','hardware':'This acquired T307F A523 / AIC8800 unit',
              'format':'Native active-slot partition images; NOT an OTA or PhoenixSuit IMAGEWTY container',
              'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'theme':{'dark_default':True,'palette':assets['palette'],'font':assets['font'],
                       'stock_audio_files':31,'bloat_packages_removed':49,'new_executable_services':0},
              'security':{'avb_flags':0,'verity':'enforcing','selinux':'Enforcing','adb_auth':True,
                          'normal_user_build':True,'bootloader':'unlocked; expected orange warning retained'},
              'physical_validation':{'all_seven_changed_partitions_full_sha256_match':True,
                                      'two_normal_boots':True,'wifi_reconnected':True,
                                      'speaker_and_microphone_routes_configured':True,
                                      'physical_audio_recording_test':False},
              'excluded':'No userdata, credentials, signing private keys, individual storage, GPT, TOC/U-Boot, eFuses or RPMB',
              'files':[{k:v for k,v in f.items() if k!='source'} for f in files]}
    readme='''# Central Inteligente T307F v3 — imagem final

Imagem instalada e conferida na unidade de origem. Base Android 14 de setembro de 2025, A523/AIC8800.

- 49 pacotes de bloat removidos; drivers, áudio, WebView, serviços essenciais e controles térmicos/carga preservados.
- Identidade Central Inteligente: fundos/animações aprovados, paleta do layout da central, Roboto e modo escuro padrão.
- Sons da stock 2024: todos os 31 OGGs conferidos. Overlay de fundo Toy Story substituído sem alterar os valores compilados de hardware.
- Nome do dispositivo padrão Central Inteligente; compilação Central Inteligente T307F v3. Fingerprint, modelo e SPL originais preservados.
- Sete partições modificadas com SHA256 integral conferido por DSU; dois boots normais e persistência do tema validados.

## Conteúdo e uso

Este ZIP contém partições nativas, NÃO um instalador OTA/TWRP nem imagem PhoenixSuit. É específico da base/hardware verificados; não presumir compatibilidade com outras revisões T307F.

`images/` inclui as seis partições OS/AVB modificadas e seis referências OEM preservadas de boot/recovery/módulos. As referências permitem verificar a cadeia AVB offline, mas não foram regravadas nesta instalação. `resources/bootloader_a.img` é apenas FAT de imagens de splash/carga; não é o U-Boot executável.

A instalação testada utiliza fastbootd para OS/AVB e DSU autenticada com endereço GPT e hashes verificados para a FAT, que fastbootd não abre. Use os scripts controlados e os recibos do projeto; nunca gravar esta FAT como TOC/U-Boot. Não há comando de erase, troca de slot ou factory reset nesta instalação.

Os backups OEM de recuperação ficam separados em `backup/firmware-2025-dsu-20261111T012532Z/`, com manifesto e dupla leitura. Eles não fazem parte deste ZIP e devem ser preservados. A restauração foi ensaiada de forma idempotente pelo bootloader, fastbootd e escritor FAT; não foi realizado um teste destrutivo integral nem clonagem de userdata/FBE/RPMB.

O aviso anterior ao splash é o estado ORANGE de bootloader desbloqueado. Ele permanece por projeto; não bloquear o bootloader com esta ROM sem comprovar suporte à chave e recuperação. Referência: https://source.android.com/docs/security/features/verifiedboot/boot-flow

App da central e kiosk não são incluídos nem configurados por este pacote: pertencem ao instalador do aplicativo.

Chaves privadas e dados pessoais não foram incluídos.
'''
    (destination/'LEIA-ME.md').write_text(readme,encoding='utf-8')
    (destination/'MANIFESTO.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False),encoding='utf-8')
    with zipfile.ZipFile(bundle,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True) as z:
        for file in files:
            z.write(file['source'],file['archive'])
            print('Packed',file['archive'],flush=True)
        z.writestr('LEIA-ME.md',readme)
        z.writestr('MANIFESTO.json',json.dumps(manifest,indent=2,ensure_ascii=False))
        z.write(OUT/'central-2025.avbpubkey','certificates/central-2025.avbpubkey')
        for name in ['post-flash-verification.json','final-theme-runtime-validation.json',
                     'second-boot-health-validation.json','palette-contrast.json']:
            z.write(OUT/name,'validation/'+name)
    with zipfile.ZipFile(bundle) as z:
        for file in files:
            with z.open(file['archive']) as f:
                actual=hashlib.file_digest(f,'sha256').hexdigest()
            assert actual==file['sha256'],file['archive']
        assert not any('private' in n.lower() or n.endswith(('.p12','.pem','.dpapi')) for n in z.namelist())
    digest=sha(bundle)
    (destination/(bundle.name+'.sha256')).write_text(digest+'  '+bundle.name+'\n')
    (destination/'PACKAGE-VERIFIED.json').write_text(json.dumps({'bundle':bundle.name,
        'size':bundle.stat().st_size,'sha256':digest,'all_13_payloads_roundtrip_hash_verified':True,
        'private_keys_and_userdata_excluded':True},indent=2))
    print('Final ZIP verified:',bundle.stat().st_size,'bytes;',digest,flush=True)


if __name__=='__main__':main()
