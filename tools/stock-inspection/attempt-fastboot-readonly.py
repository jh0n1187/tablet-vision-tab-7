"""One authorized bootloader visit: fixed read queries, return, Android/kiosk checks.
No flash, erase, unlock, download, FEL or driver operations exist in this script.
"""
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analise-firmware/central-inteligente/candidato-v2/fastboot-identificacao-20261110'
SDK=Path(os.environ['LOCALAPPDATA'])/'Android/Sdk/platform-tools'
VARS=('product','unlocked','secure','version-bootloader')
PROPS=('ro.product.model','ro.build.version.incremental','ro.boot.flash.locked','ro.boot.vbmeta.device_state','ro.boot.verifiedbootstate')
state={'authorized_scope':'one adb reboot bootloader; identification/lock getvars; one return reboot; ADB/kiosk checks',
       'reboot_to_bootloader_attempts':0,'fastboot_return_attempts':0,'events':[],'queries':{},'outcome':'PREPARING'}
ids=[]

def clean(text):
 for value in ids:
  if value:text=text.replace(value,'<device>')
 return text
def save():
 (OUT/'RESULTADO.json').write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf8')
def event(message,**data):
 item={'utc':datetime.now(timezone.utc).isoformat(),'message':message,**data}
 state['events'].append(item);save();print(json.dumps(item,ensure_ascii=False),flush=True)
def command(tool,args,timeout=8):
 if tool not in ('adb','fastboot'):raise ValueError('Tool outside allowlist')
 if args==['devices']:pass
 elif len(args)>=3 and args[0]=='-s':
  tail=args[2:]
  valid=(tool=='adb' and (tail==['reboot','bootloader'] or tail[:2]==['shell','getprop'] and len(tail)==3 and tail[2] in PROPS or tail in (['shell','pidof','br.homelab.central'],['shell','dumpsys','activity','activities'],['shell','dpm','list-owners'])))
  valid|=(tool=='fastboot' and (tail==['reboot'] or len(tail)==2 and tail[0]=='getvar' and tail[1] in VARS))
  if not valid:raise ValueError('Command outside allowlist')
 else:raise ValueError('Arguments outside allowlist')
 try:
  p=subprocess.run([str(SDK/(tool+'.exe')),*args],capture_output=True,timeout=timeout)
  return p.returncode,p.stdout.decode('utf8',errors='replace'),p.stderr.decode('utf8',errors='replace')
 except subprocess.TimeoutExpired:return -999,'','command timeout; process terminated on PC'
def adb_devices():
 code,out,err=command('adb',['devices'])
 if code:return []
 return [r.split()[0] for r in out.splitlines()[1:] if len(r.split())>=2 and r.split()[1]=='device']
def pnp():
 ps="$d=Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object {$_.InstanceId -like 'USB*VID_1F3A*'}; @($d | Where-Object {$_} | ForEach-Object {[pscustomobject]@{status=$_.Status;name=$_.FriendlyName;class=$_.Class;vidpid=([regex]::Match($_.InstanceId,'VID_[0-9A-F]{4}&PID_[0-9A-F]{4}')).Value}}) | ConvertTo-Json -Compress"
 p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',ps],capture_output=True,timeout=12)
 if p.returncode:return []
 text=p.stdout.decode('utf8',errors='replace').strip()
 if not text:return []
 parsed=json.loads(text);return parsed if isinstance(parsed,list) else [parsed]
def properties(serial):
 values={}
 for prop in PROPS:
  c,o,e=command('adb',['-s',serial,'shell','getprop',prop])
  if c:raise RuntimeError('Android property read failed')
  values[prop]=o.strip()
 return values
def kiosk(serial):
 result={}
 c,o,e=command('adb',['-s',serial,'shell','pidof','br.homelab.central'])
 result['app_process_running']=c==0 and bool(o.strip())
 c,o,e=command('adb',['-s',serial,'shell','dumpsys','activity','activities'],15)
 lines=[clean(s.strip()) for s in o.splitlines() if re.search(r'mResumedActivity|topResumedActivity|mLockTaskModeState|mLockTaskModeTasks|LockTaskModeState',s)]
 result['activity_read_ok']=c==0;result['activity_evidence']=lines[:15]
 result['central_resumed']=any('br.homelab.central' in s and ('ResumedActivity' in s) for s in lines)
 result['lock_task_active']=any('LOCKED' in s or 'PINNED' in s for s in lines if 'LockTaskModeState' in s)
 c,o,e=command('adb',['-s',serial,'shell','dpm','list-owners'])
 result['central_device_owner']=c==0 and 'br.homelab.central/.Dono' in o and 'DeviceOwner' in o
 return result

def main():
 OUT.mkdir(exist_ok=False)
 devices=adb_devices()
 if len(devices)!=1:raise RuntimeError('Exactly one authorized Android target required')
 serial=devices[0];ids.append(serial)
 before=properties(serial)
 if before['ro.product.model']!='T307F':raise RuntimeError('Wrong model; no reboot sent')
 state['before']=before;state['kiosk_before']=kiosk(serial);state['pnp_before']=pnp()
 if not any('PID_4EE7' in n['vidpid'] and n['status']=='OK' for n in state['pnp_before']):raise RuntimeError('Expected healthy 4EE7 binding before reboot')
 code,o,e=command('fastboot',['devices'])
 if code or o.strip():raise RuntimeError('Pre-existing/failed fastboot inventory; no reboot sent')
 event('Baseline checked',model=before['ro.product.model'],build=before['ro.build.version.incremental'],kiosk=state['kiosk_before'])
 state['reboot_to_bootloader_attempts']=1;save()
 code,o,e=command('adb',['-s',serial,'reboot','bootloader'])
 event('Single adb reboot bootloader sent',exit_code=code,stderr=clean(e.strip()))
 fast=None;last=None
 deadline=time.monotonic()+35
 while time.monotonic()<deadline:
  nodes=pnp()
  if nodes!=last:event('Windows USB state',devices=nodes);last=nodes
  if any('PID_EFE8' in n['vidpid'] for n in nodes):
   state['outcome']='UNEXPECTED_FEL_NO_ENDPOINT_ACCESS';event('Unexpected FEL observed; no FEL commands');break
  c,o,e=command('fastboot',['devices'],4)
  f=[r.split()[0] for r in o.splitlines() if len(r.split())>=2 and r.split()[1]=='fastboot']
  if len(f)>1:state['outcome']='AMBIGUOUS_FASTBOOT';break
  if len(f)==1 and any('PID_4EE7' not in n['vidpid'] for n in nodes):fast=f[0];ids.append(fast);break
  # If Android came straight back, don't repeat reboot.
  if time.monotonic()>deadline-27 and serial in adb_devices():
   state['outcome']='ANDROID_RETURNED_WITHOUT_FASTBOOT';break
  time.sleep(.5)
 if fast:
  event('Single fastboot target recognized')
  try:
   for var in VARS:
    c,o,e=command('fastboot',['-s',fast,'getvar',var],6)
    state['queries'][var]={'exit_code':c,'stdout':clean(o.strip()),'stderr':clean(e.strip())};save()
    event('Read fastboot variable',variable=var,**state['queries'][var])
    if c==-999:break
  finally:
   state['fastboot_return_attempts']=1;save()
   c,o,e=command('fastboot',['-s',fast,'reboot'],8)
   event('Single fastboot return reboot sent',exit_code=c,stdout=clean(o.strip()),stderr=clean(e.strip()))
 else:event('No query-capable fastboot target; no alternate reboot sent')
 deadline=time.monotonic()+100
 event('Waiting for normal Android return')
 while time.monotonic()<deadline:
  if serial in adb_devices():
   try:after=properties(serial)
   except RuntimeError:time.sleep(2);continue
   state['after']=after;state['same_build']=after==before
   # Allow launcher and Device Owner to resume after adbd becomes ready.
   for i in range(12):
    k=kiosk(serial);state['kiosk_after']=k;save()
    if k['app_process_running'] and k['central_resumed'] and k['lock_task_active']:break
    time.sleep(2)
   state['pnp_after']=pnp()
   state['outcome']='ANDROID_RETURNED';event('Android return checked',same_properties=state['same_build'],kiosk=state['kiosk_after'],devices=state['pnp_after']);return
  time.sleep(2)
 state['outcome']='MANUAL_RETURN_REQUIRED';event('Android unavailable; manual power-button return needed',devices=pnp())

if __name__=='__main__':
 try:main()
 except Exception as exc:
  if OUT.is_dir():state['error']=clean(str(exc));event('Stopped on error',error=state['error'])
  else:print('Attempt directory already exists or unavailable; no retry',flush=True)
  sys.exit(1)
