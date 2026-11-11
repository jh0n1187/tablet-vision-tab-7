"""Inspect/load only usbmon and vhci_hcd in the authorized WSL host.

No USBFS access, capture, bind/attach, reboot, forced unload or automatic rollback.
Receipts describe the new modules; removal requires a separate reviewed action.
"""
import datetime
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

REQUESTED = ('usbmon', 'vhci_hcd')
TRACKED = ('usbmon', 'vhci_hcd', 'usbip_core', 'usbcore', 'usb_common')


def snapshot():
    modules = {}
    for line in Path('/proc/modules').read_text().splitlines():
        parts = line.split()
        if parts[0] in TRACKED:
            modules[parts[0]] = {'references': int(parts[2]), 'dependents': parts[3], 'state': parts[4]}
    nodes = []
    for path in sorted(Path('/dev').glob('usbmon*')):
        info = path.stat()
        nodes.append({'path':str(path),'character_device':stat.S_ISCHR(info.st_mode),
                      'major':os.major(info.st_rdev),'minor':os.minor(info.st_rdev),
                      'uid':info.st_uid,'gid':info.st_gid,'mode':oct(stat.S_IMODE(info.st_mode))})
    hubs = []
    for path in sorted(Path('/sys/bus/usb/devices').glob('usb*')):
        if not re.fullmatch(r'usb[0-9]+',path.name): continue
        resolved = str(path.resolve())
        if '/vhci_hcd.' not in resolved: continue
        def read(name):return (path/name).read_text().strip()
        hubs.append({'name':path.name,'sysfs':resolved,'busnum':read('busnum'),
                     'speed':read('speed'),'version':read('version')})
    return {'kernel':platform.release(),'modules':modules,'usbmon_nodes':nodes,'vhci_root_hubs':hubs}


def main():
    mode = sys.argv[1] if len(sys.argv)==2 else None
    if mode not in ('inspect','load'):raise ValueError('Only inspect/load modes supported')
    if sys.platform!='linux' or 'microsoft' not in platform.release().lower():
        raise ValueError('Expected the reviewed WSL host')
    result={'mode':mode,'utc_started':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'before':snapshot(),'steps':[],'device_commands_sent':False,'physical_capture_started':False}
    code=0
    try:
        if mode=='load':
            if os.geteuid()!=0:raise PermissionError('WSL root is required only for module activation')
            for module in REQUESTED:
                if module in result['before']['modules']:
                    result['steps'].append({'module':module,'state':'PREEXISTING_NOT_OWNED'});continue
                version=subprocess.run(['/usr/sbin/modinfo','-F','vermagic',module],capture_output=True,text=True,timeout=5)
                if version.returncode!=0 or not version.stdout.startswith(platform.release()+' '):
                    raise ValueError('Module vermagic mismatch: '+module)
                command=['/usr/sbin/modprobe','--first-time',module]
                run=subprocess.run(command,capture_output=True,text=True,timeout=10)
                result['steps'].append({'module':module,'argv':command,'exit_code':run.returncode,
                                        'stdout':run.stdout,'stderr':run.stderr})
                if run.returncode!=0:raise RuntimeError('Module activation failed; no automatic retry: '+module)
                if module not in snapshot()['modules']:raise RuntimeError('Activated module not visible: '+module)
        result['state']='INSPECTED' if mode=='inspect' else 'LOADED'
    except Exception as error:
        result['state']='FAILED';result['error']={'type':type(error).__name__,'message':str(error)};code=1
    finally:
        result['after']=snapshot()
        result['new_tracked_modules']=sorted(set(result['after']['modules'])-set(result['before']['modules']))
        result['utc_finished']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(json.dumps(result,indent=2))
    return code


if __name__=='__main__':raise SystemExit(main())
