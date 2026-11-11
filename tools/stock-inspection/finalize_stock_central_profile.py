"""Align existing userdata with defaults baked into the v3 image and validate.

Only appearance/name/ringtone selections and ringtone caches are migrated.
No app/kiosk provisioning, factory reset, bootloader or security changes.
"""
import os
from pathlib import Path
import datetime
import hashlib
import json
import re
import shlex
import subprocess

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analise-firmware/central-inteligente/candidato-2025-v3'
ADB=['adb','-s',os.environ.get('T307F_SERIAL', 'SET_T307F_SERIAL_BEFORE_DEVICE_ACCESS')]


def shell(command, timeout=30):
    r=subprocess.run(ADB+['shell',command],capture_output=True,timeout=timeout)
    text=(r.stdout+r.stderr).decode(errors='replace').replace('\r','').strip()
    if r.returncode or '[ERROR]' in text or 'Exception' in text:
        raise RuntimeError(text)
    return text


def main():
    assert json.loads((OUT/'post-flash-verification.json').read_text())['all_match']
    assert shell('getprop ro.build.display.id')=='Central Inteligente T307F v3'
    assert shell('getprop sys.boot_completed')=='1'
    assert shell('getprop ro.adb.secure')=='1' and shell('getprop ro.debuggable')=='0'
    assert shell('getprop ro.boot.veritymode')=='enforcing' and shell('getenforce')=='Enforcing'
    before={key:shell('settings get '+namespace+' '+key) for namespace,key in [
        ('global','device_name'),('secure','ui_night_mode'),
        ('secure','theme_customization_overlay_packages'),('system','notification_sound'),
        ('system','ringtone'),('system','alarm_alert')]}
    if not (OUT/'pre-profile-migration.json').exists():
        (OUT/'pre-profile-migration.json').write_text(json.dumps(before,indent=2))
    shell('settings put global device_name '+shlex.quote('Central Inteligente'))
    shell('cmd uimode night yes')
    shell('settings put secure theme_customization_overlay_packages '+shlex.quote('{}'))
    overlays=shell('cmd overlay list')
    for name in ['neutral','accent','dynamic']:
        identifier='com.android.systemui:'+name
        if '[x] '+identifier in overlays:
            shell('cmd overlay disable --user 0 '+shlex.quote(identifier))
    listing=shell('content query --uri content://media/internal/audio/media --projection _id:_data:title')
    rows={m[2]:{'id':m[1],'title':m[3]} for m in re.finditer(r'Row: \d+ _id=(\d+), _data=([^\r\n,]+), title=([^\r\n]+)',listing)}
    sounds={}
    for key,relative,cache in [
        ('notification_sound','notifications/Talitha.ogg','notification_sound_cache'),
        ('alarm_alert','alarms/Oxygen.ogg','alarm_alert_cache'),
        ('ringtone','ringtones/Ring_Synth_04.ogg','ringtone_cache')]:
        path='/product/media/audio/'+relative
        row=rows[path]
        uri='content://media/internal/audio/media/'+row['id']
        shell('settings put system '+key+' '+shlex.quote(uri))
        cache_uri='content://settings/system/'+cache
        shell('content write --uri '+shlex.quote(cache_uri)+' < '+shlex.quote(path))
        blob=subprocess.check_output(ADB+['exec-out','content read --uri '+shlex.quote(cache_uri)+' 2>/dev/null'],timeout=20)
        assert blob.startswith(b'OggS')
        expected=shell('sha256sum '+shlex.quote(path)).split()[0]
        assert hashlib.sha256(blob).hexdigest()==expected
        sounds[key]={'path':path,'uri':uri,'title':row['title'],'cache_matches_file':True,'sha256':expected}
    assert shell('settings get global device_name')=='Central Inteligente'
    # This BSP can lock day/night selection to its resource default. In that
    # mode UiModeManager deliberately doesn't persist a per-user DB value.
    assert shell('cmd uimode night')=='Night mode: yes'
    assert 'mNightMode=2 (yes)' in shell('dumpsys uimode')
    lookups={
        'night_default':('android','android:integer/config_defaultNightMode','2'),
        'accent_dark':('android','android:color/accent_device_default_dark','#ff60a5fa'),
        'background':('android','android:color/background_dark','#ff0b1620'),
        'cards':('android','android:color/system_neutral1_900','#ff102233'),
        'dynamic_wallpaper_palette':('com.android.systemui','com.android.systemui:bool/flag_monet','false'),
        'brand_default':('com.android.providers.settings','com.android.providers.settings:string/def_device_name_simple','Central Inteligente')}
    actual={}
    for name,(target,resource,expected) in lookups.items():
        actual[name]=shell('cmd overlay lookup '+target+' '+resource)
        assert actual[name]==expected,(name,actual[name],expected)
    installed={x.removeprefix('package:') for x in shell('pm list packages').splitlines()}
    plan=json.loads((OUT/'plano-limpeza-2025.json').read_text(encoding='utf-8'))
    assert not {e['package'] for e in plan['removed']} & installed
    assert 'android.auto_generated_rro_vendor__' not in installed
    for pkg in ['vendor','visual','systemui','about']:
        assert 'br.homelab.central.overlay.'+pkg in installed
    stock=ROOT/'analise-firmware/stock-URBR2024101701/erofs-extracted/product/media/audio'
    hashes=shell('sha256sum /product/media/audio/*/*.ogg')
    current={line.split(None,1)[1]:line.split()[0] for line in hashes.splitlines()}
    count=0
    for f in stock.rglob('*.ogg'):
        node='/product/media/audio/'+f.relative_to(stock).as_posix()
        with f.open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==current[node]
        count+=1
    assert count==31
    report={'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'baked_resource_defaults_verified':actual,'effective_dark_mode':'Night mode: yes',
            'night_mode_user_setting':shell('settings get secure ui_night_mode'),
            'device_name':'Central Inteligente','sounds':sounds,'all_31_audio_files_match_stock_2024':True,
            'planned_49_removed':True,'cartoon_vendor_overlay_absent':True,
            'all_four_data_only_overlays_installed':True,'security':'user build, ADB auth, SELinux/verity enforcing',
            'reboot_persistence_pending':True}
    (OUT/'final-theme-runtime-validation.json').write_text(json.dumps(report,indent=2))
    print('Current userdata aligned with baked defaults; all 31 audio files match stock; ringtone caches updated')
    print('Dark mode, Central brand/palette, removed cartoon overlay and all 49 removals verified')


if __name__=='__main__':main()
