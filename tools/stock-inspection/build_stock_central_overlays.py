"""Build data-only overlays for stock Android + Central identity, offline.

Keeps every compiled hardware value in the vendor table byte-for-byte. Only
its package header is renamed, its cartoon PNGs replaced, and its manifest
recreated for a new package. Platform APKs/certificates remain untouched.
"""
from pathlib import Path
import hashlib
import json
import re
import shutil
import struct
import subprocess
import zipfile
from xml.sax.saxutils import escape

from android_resource_signing import TOOLS, sign_apk

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'analise-firmware/central-inteligente'
OUT = BASE / 'candidato-2025-v3'
AUDIT = BASE / 'candidato-2025-v2/theme-audit'
SDK = Path.home() / 'AppData/Local/Android/Sdk'
ANDROID = SDK / 'platforms/android-34/android.jar'
if not ANDROID.exists():
    ANDROID = SDK / 'platforms/android-36/android.jar'


def run(*args):
    r = subprocess.run(list(map(str, args)), capture_output=True, timeout=90)
    if r.returncode:
        raise RuntimeError((r.stdout + r.stderr).decode(errors='replace'))
    return r.stdout


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def manifest(package, target, priority):
    return f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}" android:versionCode="3" android:versionName="2025.3">
<uses-sdk android:minSdkVersion="33" android:targetSdkVersion="34"/>
<application android:hasCode="false" android:label="Central Inteligente"/>
<overlay android:targetPackage="{target}" android:isStatic="true" android:priority="{priority}"/>
</manifest>'''


def compile_apk(folder, package, target, priority, output, resources=True):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / 'AndroidManifest.xml'
    path.write_text(manifest(package, target, priority), encoding='utf-8')
    args = [TOOLS / 'aapt2.exe', 'link', '-I', ANDROID, '--manifest', path,
            '--no-resource-deduping', '--no-resource-removal', '-o', output]
    if resources:
        compiled = folder / 'compiled.zip'
        run(TOOLS / 'aapt2.exe', 'compile', '--dir', folder / 'res', '-o', compiled)
        args.append(compiled)
    run(*args)


def table_resources(path):
    text = run(TOOLS / 'aapt2.exe', 'dump', 'resources', path).decode(errors='replace')
    return text, set(re.findall(r'^\s{4}resource 0x[0-9a-f]+ (\w+/\w+)', text, re.M))


def clone_vendor(assets, report):
    source = AUDIT / 'framework-vendor-overlay.apk'
    package = 'br.homelab.central.overlay.vendor'
    work = OUT / 'overlay-build/vendor'
    shell = work / 'manifest-only.apk'
    compile_apk(work, package, 'android', 0, shell, resources=False)
    with zipfile.ZipFile(source) as z:
        original = z.read('resources.arsc')
        modified = bytearray(original)
        kind, header, size = struct.unpack_from('<HHI', modified)
        assert kind == 2 and size == len(modified)
        pos, changed = header, []
        while pos < size:
            typ, hsize, chunk_size = struct.unpack_from('<HHI', modified, pos)
            assert hsize >= 8 and chunk_size >= hsize and pos + chunk_size <= size
            if typ == 0x200:
                assert hsize >= 284 and struct.unpack_from('<I', modified, pos + 8)[0] == 0x7f
                name_offset = pos + 12
                old_name = bytes(modified[name_offset:name_offset+256]).decode('utf-16le').rstrip('\0')
                assert old_name == 'android.auto_generated_rro_vendor__'
                encoded = package.encode('utf-16le')
                assert len(encoded) < 256
                modified[name_offset:name_offset+256] = encoded + bytes(256-len(encoded))
                changed.append((name_offset, name_offset+256))
            pos += chunk_size
        assert len(changed) == 1 and pos == size
        a, b = changed[0]
        assert modified[:a] == original[:a] and modified[b:] == original[b:]
        with zipfile.ZipFile(shell) as mz:
            new_manifest = mz.read('AndroidManifest.xml')
        unsigned = work / 'vendor-unsigned.apk'
        replaced = []
        with zipfile.ZipFile(unsigned, 'w', compression=zipfile.ZIP_STORED) as dest:
            for name in z.namelist():
                if name.startswith('META-INF/') or name.endswith('/'):
                    continue
                payload = z.read(name)
                if name == 'AndroidManifest.xml': payload = new_manifest
                elif name == 'resources.arsc': payload = modified
                elif name.endswith('/default_wallpaper.png'):
                    payload = (BASE / 'aprovado-v2/recursos-nativos/fundos/wallpaper.png').read_bytes()
                    replaced.append(name)
                dest.writestr(name, payload)
        assert len(replaced) == 3
    output = assets / 'CentralVendorDefaults.apk'
    sign_apk(unsigned, output)
    old_text, old_names = table_resources(source)
    new_text, new_names = table_resources(output)
    normalize = lambda t: [x.strip() for x in t.splitlines() if x.strip() and not x.strip().startswith('Package name=')]
    assert old_names == new_names and normalize(old_text) == normalize(new_text)
    report['vendor'] = {'package': package, 'source_sha256': sha(source),
                        'output_sha256': sha(output), 'resources': len(old_names),
                        'compiled_hardware_values_unchanged': True,
                        'only_table_package_header_renamed': True,
                        'replaced_wallpapers': replaced}


def create_values(assets, name, package, target, values, report):
    work = OUT / ('overlay-build/' + name)
    res = work / 'res/values'
    res.mkdir(parents=True)
    xml = ['<resources>']
    for typ, key, value in values:
        xml.append(f'<{typ} name="{key}">{escape(value)}</{typ}>')
    xml.append('</resources>')
    (res / 'central.xml').write_text('\n'.join(xml), encoding='utf-8')
    unsigned = work / 'unsigned.apk'
    compile_apk(work, package, target, 9999, unsigned)
    output = assets / (name + '.apk')
    sign_apk(unsigned, output)
    report[name] = {'package': package, 'target': target, 'sha256': sha(output),
                    'resource_count': len(values), 'no_code_or_permissions': True}


def about_overlay(assets, report):
    text = (AUDIT / 'settingsprovider-resources.txt').read_text(encoding='utf-8')
    configs = set()
    for block in re.split(r'(?=^\s{4}resource )', text, flags=re.M):
        if not re.match(r'\s*resource 0x[0-9a-f]+ string/def_device_name(?:_simple)?\s*$', block.splitlines()[0] if block.splitlines() else ''):
            continue
        configs.update(re.findall(r'^\s+\(([^)]*)\) "', block, re.M))
    assert '' in configs and len(configs) > 40
    work = OUT / 'overlay-build/about'
    for config in configs:
        assert re.fullmatch(r'[A-Za-z0-9+_-]*', config)
        folder = work / ('res/values' + ('-' + config if config else ''))
        folder.mkdir(parents=True)
        (folder / 'brand.xml').write_text('<resources>\n<string name="def_device_name" translatable="false">Central Inteligente</string>\n<string name="def_device_name_simple" translatable="false">Central Inteligente</string>\n</resources>', encoding='utf-8')
    unsigned = work / 'unsigned.apk'
    package = 'br.homelab.central.overlay.about'
    compile_apk(work, package, 'com.android.providers.settings', 9999, unsigned)
    output = assets / 'CentralAboutDefaults.apk'
    sign_apk(unsigned, output)
    generated, _ = table_resources(output)
    assert generated.count('"Central Inteligente"') == len(configs) * 2
    report['about'] = {'package': package, 'sha256': sha(output),
                       'all_existing_language_configurations': len(configs)}


def main():
    OUT.mkdir(exist_ok=True)
    assets = OUT / 'assets'
    assets.mkdir()
    assert ANDROID.exists()
    css = Path('C:/Users/Jonathan/projetos/home-lab/modules/central/app/web/estilo.css').read_text(encoding='utf-8')
    css = css[css.index(':root{'):css.index('}', css.index(':root{'))]
    palette = dict(re.findall(r'--([\w-]+):\s*(#[0-9a-fA-F]{6})', css))
    assert palette['bg'] == '#0b1620' and palette['acc2'] == '#60a5fa'
    report = {'identity_source': 'home-lab/modules/central/app/web/estilo.css (read only)',
              'palette': palette, 'font': 'Native Android Roboto; Noto/emoji/fallbacks preserved',
              'dark_by_default': True, 'new_background_services': 0}
    clone_vendor(assets, report)
    _, available = table_resources(AUDIT / 'framework-res.apk')
    colors = {
        'background_dark': palette['bg'], 'background_device_default_dark': palette['bg'],
        'background_material_dark': palette['bg'], 'background_floating_device_default_dark': palette['card'],
        'background_floating_material_dark': palette['card'], 'surface_dark': palette['card'],
        'surface_header_dark': palette['card2'], 'surface_variant_dark': palette['card2'],
        'accent_device_default_dark': palette['acc2'], 'accent_device_default_light': '#235d9f',
        'primary_text_default_material_dark': palette['ink'], 'secondary_text_default_material_dark': palette['mut'],
        'system_background_dark': palette['bg'], 'system_on_background_dark': palette['ink'],
        'system_surface_dark': palette['card'], 'system_on_surface_dark': palette['ink'],
        'system_on_surface_variant_dark': palette['mut'], 'system_primary_dark': palette['acc2'],
        'system_secondary_dark': palette['acc'], 'system_tertiary_dark': palette['ciano']}
    neutral = {0:'#ffffff',10:'#fafcff',50:'#f3f7fb',100:palette['ink'],200:'#ccd7e1',300:'#b0bfce',
               400:palette['mut'],500:'#6c7f91',600:'#506477',700:'#234158',800:palette['card2'],
               900:palette['card'],1000:palette['bg']}
    for family in ['system_neutral1', 'system_neutral2']:
        colors.update({family+'_'+str(t):v for t,v in neutral.items()})
    def blend(a, b, ratio):
        x=bytes.fromhex(a.lstrip('#'));y=bytes.fromhex(b.lstrip('#'))
        return '#'+bytes(round(i*(1-ratio)+j*ratio) for i,j in zip(x,y)).hex()
    for family, color in [('system_accent1',palette['acc2']),('system_accent2',palette['acc']),('system_accent3',palette['ciano'])]:
        for tone in neutral:
            value=blend('#ffffff',color,tone/200) if tone<=200 else blend(color,palette['bg'],(tone-200)/800)
            colors[family+'_'+str(tone)] = value
    values=[('color',key,value) for key,value in colors.items() if 'color/'+key in available]
    assert 'integer/config_defaultNightMode' in available
    values.append(('integer','config_defaultNightMode','2'))
    create_values(assets,'CentralVisualDefaults','br.homelab.central.overlay.visual','android',values,report)
    _, systemui_resources = table_resources(AUDIT / 'SystemUI.apk')
    assert 'bool/flag_monet' in systemui_resources
    create_values(assets,'CentralSystemUIDefaults','br.homelab.central.overlay.systemui','com.android.systemui',
                  [('bool','flag_monet','false')],report)
    about_overlay(assets, report)
    stock_audio = BASE / 'aprovado-v2/stock-audio'
    report['stock_audio'] = []
    for rel in ['alarms/Oxygen.ogg','notifications/Talitha.ogg','ui/Lock.ogg','ui/Unlock.ogg']:
        source=stock_audio/rel;dest=assets/'stock-audio'/rel;dest.parent.mkdir(parents=True,exist_ok=True)
        assert source.read_bytes().startswith(b'OggS')
        shutil.copyfile(source,dest);report['stock_audio'].append({'path':rel,'sha256':sha(dest)})
    report['build_display_name']='Central Inteligente T307F v3'
    (OUT/'theme-assets-manifest.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print('Resource overlays built and signed; original compiled hardware table verified unchanged')
    print('Stock audio files:',len(report['stock_audio']),'Visual resource overrides:',len(values))
    print('Font: native Roboto; default night mode: 2; no new executable services')


if __name__=='__main__':
    main()
