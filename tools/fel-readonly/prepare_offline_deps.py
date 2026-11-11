"""Fetch pinned PC-only analysis dependencies. No installation or device access."""
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parent
NAME='unicorn-2.1.4-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'
URL='https://files.pythonhosted.org/packages/e7/df/ded5e3684c2d7600b30cc8a7530277b8cb36644a1a9d34cade7ebb45604c/'+NAME
SHA='9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239'

def main():
    folder=ROOT/'build'/'offline-deps';folder.mkdir(parents=True,exist_ok=True)
    wheel=folder/NAME
    if not wheel.exists():
        data=urllib.request.urlopen(URL,timeout=60).read()
        if hashlib.sha256(data).hexdigest()!=SHA:raise RuntimeError('download hash mismatch')
        wheel.write_bytes(data)
    if hashlib.sha256(wheel.read_bytes()).hexdigest()!=SHA:raise RuntimeError('wheel hash mismatch')
    target=folder/'unicorn-linux'
    with zipfile.ZipFile(wheel) as archive:
        for item in archive.infolist():
            destination=(target/item.filename).resolve()
            if not destination.is_relative_to(target.resolve()):raise RuntimeError('unsafe wheel path')
        archive.extractall(target)
    manifest={'name':'unicorn','version':'2.1.4','url':URL,'sha256':SHA,
              'use':'Linux WSL PC-only ARM instruction emulation; no USB; not a BROM or cache model',
              'license':'GPLv2 engine / BSD Python bindings; analysis dependency only',
              'global_installation':False}
    (folder/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(manifest,indent=2))

if __name__=='__main__':main()
