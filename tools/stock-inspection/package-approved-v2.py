"""Validate and package approved visual resources. No firmware/device writes."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

project = Path(__file__).resolve().parents[2]
base = project / 'analise-firmware/central-inteligente'
approved = base / 'aprovado-v2'
resources = approved / 'recursos-nativos'
stock = project / 'analise-firmware/stock-URBR2024101701/boot-resource-complete'
profiles = []
for path in sorted((resources / 'boot-resource').rglob('*.bmp')):
    relative = path.relative_to(resources / 'boot-resource')
    source = (stock / relative).read_bytes()
    result = path.read_bytes()
    offset = struct.unpack_from('<I', source, 10)[0]
    if len(source) != len(result) or source[:offset] != result[:offset]:
        raise ValueError('BMP native profile changed: ' + str(relative))
    profiles.append({'file': str(relative), 'bytes': len(result),
                     'width': struct.unpack_from('<i', result, 18)[0],
                     'height': struct.unpack_from('<i', result, 22)[0],
                     'bpp': struct.unpack_from('<H', result, 28)[0],
                     'original_header_preserved': True})
if len(profiles) != 14:
    raise ValueError('Expected two boot logos, eleven levels and one low-power BMP')
for path in (resources / 'system/media').glob('*.zip'):
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None or archive.read('desc.txt') != b'600 1024 14\np 0 0 part0\n':
            raise ValueError('Invalid boot animation ZIP')
        if len([n for n in archive.namelist() if n.endswith('.png')]) != 167:
            raise ValueError('Expected 167 approved frames')
        if any(i.compress_type != zipfile.ZIP_STORED for i in archive.infolist()):
            raise ValueError('Boot animation requires stored entries')
png = (resources / 'vendor/etc/res/images/charger/battery_scale.png').read_bytes()
if struct.unpack('>II', png[16:24]) != (120, 1116):
    raise ValueError('Wrong charger dimensions')
position, frame_tags = 8, []
while position < len(png):
    length = struct.unpack_from('>I', png, position)[0]
    kind = png[position + 4:position + 8]
    payload = png[position + 8:position + 8 + length]
    crc = struct.unpack_from('>I', png, position + 8 + length)[0]
    if zlib.crc32(kind + payload) != crc:
        raise ValueError('PNG CRC mismatch')
    if kind == b'tEXt' and payload.startswith(b'Frames\0'):
        frame_tags.append(payload)
    position += 12 + length
if frame_tags != [b'Frames\x006']:
    raise ValueError('Wrong charger frame metadata')
(approved / 'PERFIS-VALIDADOS.json').write_text(json.dumps({
    'bmp_profiles': profiles, 'boot_frames': 167, 'boot_fps': 14,
    'charger_frames': 6, 'bootloader_levels': 11,
    'flash_ready': False, 'device_accessed': False}, indent=2), encoding='utf-8')
readme = '''# Central Inteligente — recursos visuais aprovados, revisão 02

Este pacote contém recursos gráficos e uma prévia. NÃO é uma imagem de firmware e não deve ser aberto para gravação no PhoenixSuit. Não contém instalador, payload, vbmeta alterada ou nova assinatura.

- boot-resource/: splash 32/24 bits e bateria do bootloader em BMP, com cabeçalhos, dimensões e tamanhos preservados da stock. O aviso low_pwr foi adaptado proporcionalmente a 480×800.
- system/media/: animações clara/escura idênticas, com 167 quadros, 600×1024, 14 fps, ZIP_STORED, sem pontinhos.
- vendor/etc/res/: animação de carga com seis quadros intercalados e configuração do percentual em branco. A fonte battery_percent.png existente deve ser preservada; não foi incluída uma nova fonte.
- fundos/: papel de parede e fundo de bloqueio, para futura definição por API Android. Não há APK de overlay alterado.

Os arquivos de formato nativo foram validados no PC. Isso não valida sua instalação ou execução no tablet. Os índices de antirollback e a aceitação de uma ROM modificada continuam sem prova. Nenhum aviso de temperatura/Verified Boot ou limite de carga foi desativado.
'''
(resources / 'LEIA-ME.md').write_text(readme, encoding='utf-8')
package = base / 'CENTRAL-INTELIGENTE-v2-RECURSOS-NAO-FIRMWARE.zip'
with zipfile.ZipFile(package, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
    archive.write(approved / 'APROVACAO-VISUAL.json', 'APROVACAO-VISUAL.json')
    archive.write(approved / 'PERFIS-VALIDADOS.json', 'PERFIS-VALIDADOS.json')
    for path in sorted(resources.rglob('*')):
        if path.is_file():
            archive.write(path, 'recursos/' + path.relative_to(resources).as_posix())
with zipfile.ZipFile(package) as archive:
    if archive.testzip() is not None:
        raise ValueError('Resource package CRC failure')
source_manifest = approved / 'manifest.json'
source_manifest.rename(approved / 'manifest-proposta-aprovada.json')
files = [{'file': p.relative_to(approved).as_posix(), 'bytes': p.stat().st_size,
          'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
         for p in sorted(approved.rglob('*')) if p.is_file() and p.name != 'manifest.json']
(approved / 'manifest.json').write_text(json.dumps({'visual_approved': True, 'applied': False,
                                                  'files': files}, indent=2), encoding='utf-8')
receipt = {'visual': 'Central Inteligente — revisão 02', 'approved': True,
           'approved_snapshot': str(approved), 'flash_ready': False,
           'package': str(package), 'bytes': package.stat().st_size,
           'sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
           'validated_native_bmps': len(profiles), 'device_write_performed': False}
(base / 'VISUAL-APROVADO.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
print(json.dumps(receipt, indent=2))
