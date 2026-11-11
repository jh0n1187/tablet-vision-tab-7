"""Read a fixed property allowlist via normal ADB. No reboot/settings/write/FEL commands."""
from pathlib import Path
import json
import os
import subprocess

PROPS=('ro.product.model','ro.product.device','ro.build.display.id','ro.build.version.incremental',
       'ro.build.version.release','ro.build.version.security_patch','ro.boot.flash.locked',
       'ro.boot.vbmeta.device_state','ro.boot.verifiedbootstate','ro.boot.veritymode',
       'ro.boot.slot_suffix','ro.oem_unlock_supported','sys.oem_unlock_allowed',
       'ro.boot.avb_version','ro.fastbootd.available')

def main():
 root=Path(__file__).resolve().parents[2]
 out=root/'analise-firmware/central-inteligente/candidato-v2/estado-android-leitura.json'
 if out.exists():raise FileExistsError(out)
 adb=Path(os.environ['LOCALAPPDATA'])/'Android/Sdk/platform-tools/adb.exe'
 def run(args):
  p=subprocess.run([str(adb),*args],capture_output=True,timeout=15)
  if p.returncode:raise RuntimeError('ADB read failed; stderr not printed to avoid device identifier disclosure')
  return p.stdout.decode('utf8',errors='replace').strip()
 devices=[line.split() for line in run(['devices']).splitlines()[1:] if line.strip()]
 ready=[r[0] for r in devices if len(r)>1 and r[1]=='device']
 if len(ready)!=1:raise RuntimeError('Exactly one authorized Android device required')
 serial=ready[0]
 model=run(['-s',serial,'shell','getprop','ro.product.model'])
 if model!='T307F':raise RuntimeError('Expected T307F; no further commands sent')
 values={key:run(['-s',serial,'shell','getprop',key]) for key in PROPS}
 record=dict(read_only=True,commands='ADB devices + shell getprop for fixed property allowlist',
             rebooted=False,storage_write_commands=False,fel_query=False,properties=values)
 out.write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf8')
 print(json.dumps(record,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
