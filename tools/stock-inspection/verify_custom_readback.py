"""Verify full physical firmware hashes from the authenticated temporary DSU."""
import os
from pathlib import Path
import argparse
import json
import subprocess
import time
import datetime

ROOT=Path(__file__).resolve().parents[2]
ADB=['adb','-s',os.environ.get('T307F_SERIAL', 'SET_T307F_SERIAL_BEFORE_DEVICE_ACCESS')]


def shell(*args, timeout=30):
    return subprocess.check_output(ADB+['shell',*args],timeout=timeout).decode().strip()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--revision',choices=['v2','v3'],required=True)
    p.add_argument('--boot-normal',action='store_true')
    args=p.parse_args()
    out=ROOT/('analise-firmware/central-inteligente/candidato-2025-'+args.revision)
    receipt=json.loads((out/'custom-installation-receipt.json').read_text())
    assert receipt['complete']
    for _ in range(40):
        if '\tdevice' in subprocess.check_output(['adb','devices'],timeout=5).decode():
            try:
                if shell('getprop','ro.build.display.id',timeout=5).startswith('lineage_gsi_arm64-userdebug'):
                    subprocess.run(ADB+['root'],check=True,capture_output=True,timeout=15)
                    time.sleep(1)
                    if shell('gsi_tool','status',timeout=20).startswith('running'):break
            except subprocess.TimeoutExpired:pass
        time.sleep(3)
    else:raise RuntimeError('Authenticated DSU not detected; preserve recovery state')
    assert shell('getprop','ro.adb.secure')=='1' and shell('id','-u')=='0'
    assert shell('getenforce')=='Enforcing'
    report={'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source':'Authenticated root DSU after actual write','entries':[],'all_match':False}
    entries=receipt['entries']+[{'target':'bootloader_a','sha256':json.loads((out/'resource-fat-installation.json').read_text())['expected_custom_sha256']}]
    for entry in entries:
        name=entry['target']
        node=('/dev/block/mapper/' if name in ['system_a','product_a','vendor_a'] else '/dev/block/by-name/')+name
        actual=shell('sha256sum',node,timeout=300).split()[0]
        result={'target':name,'node':node,'expected_sha256':entry['sha256'],
                'actual_sha256':actual,'matches':actual==entry['sha256']}
        report['entries'].append(result)
        (out/'post-flash-verification.json').write_text(json.dumps(report,indent=2))
        print(name, 'FULL SHA256 MATCH' if result['matches'] else 'MISMATCH',flush=True)
    report['all_match']=all(e['matches'] for e in report['entries'])
    (out/'post-flash-verification.json').write_text(json.dumps(report,indent=2))
    assert report['all_match'], 'Do not boot final Android; resolve read-back differences first'
    if args.boot_normal:
        assert '\ndisabled' in shell('gsi_tool','status').replace('\r','')
        subprocess.run(ADB+['reboot'],check=True,timeout=20)
        print('All seven complete images verified; normal final boot requested',flush=True)


if __name__=='__main__':main()
