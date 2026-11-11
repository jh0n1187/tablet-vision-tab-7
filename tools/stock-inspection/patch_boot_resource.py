"""Replace equal-size approved BMP contents in a new FAT16 copy; retain all other bytes."""
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from extract_boot_fat import extract


def patch(source, assets, output, expected_count=14):
    source, assets, output=map(Path,(source,assets,output))
    if output.exists():raise FileExistsError(output)
    original=source.read_bytes();data=bytearray(original)
    u16=lambda off:struct.unpack_from('<H',original,off)[0]
    sector=u16(11);cluster_size=sector*original[13];fat=sector*u16(14)
    root=(u16(14)+original[16]*u16(22))*sector;rootlen=u16(17)*32
    start=root+((rootlen+sector-1)//sector)*sector
    if sector!=512 or original[54:62]!=b'FAT16   ':raise ValueError('Unexpected FAT profile')
    files={}
    def chain(first):
        result=[];seen=set()
        while 2<=first<0xfff8:
            if first in seen or fat+first*2+2>root:raise ValueError('Invalid chain')
            seen.add(first);off=start+(first-2)*cluster_size
            if off>=len(data):raise ValueError('Cluster out of bounds')
            result.append(off);first=u16(fat+first*2)
        if first<0xfff8:raise ValueError('Unexpected chain end')
        return result
    def walk(raw,parent='',depth=0):
        if depth>8:raise ValueError('Directory depth')
        long={}
        for pos in range(0,len(raw),32):
            e=raw[pos:pos+32]
            if len(e)!=32 or e[0]==0:break
            if e[0]==0xe5:long={};continue
            if e[11]==15:long[e[0]&31]=e[1:11]+e[14:26]+e[28:32];continue
            short=e[:8].decode('ascii').rstrip()+('.'+e[8:11].decode('ascii').rstrip() if e[8:11].strip() else '')
            n=b''.join(long[i] for i in sorted(long)).decode('utf-16-le').split('\0',1)[0] if long else short
            long={}
            if n in ('.','..') or e[11]&8:continue
            path=parent+n;offsets=chain(struct.unpack_from('<H',e,26)[0])
            if e[11]&16:walk(b''.join(original[o:o+cluster_size] for o in offsets),path+'/',depth+1)
            else:files[path]=(struct.unpack_from('<I',e,28)[0],offsets)
    walk(original[root:root+rootlen])
    changes=[];allowed=bytearray(len(data))
    for f in sorted(assets.rglob('*.bmp')):
        path=f.relative_to(assets).as_posix();size,offsets=files[path];new=f.read_bytes()
        old=b''.join(original[o:o+cluster_size] for o in offsets)[:size]
        if len(new)!=size or old[:2]!=b'BM' or new[:54]!=old[:54]:raise ValueError('BMP native profile differs')
        left=size;pos=0
        for off in offsets:
            count=min(left,cluster_size)
            data[off:off+count]=new[pos:pos+count];allowed[off:off+count]=b'\1'*count
            left-=count;pos+=count
        if left:raise ValueError('Short file chain')
        changes.append(dict(path=path,size=size,old_sha256=hashlib.sha256(old).hexdigest(),new_sha256=hashlib.sha256(new).hexdigest()))
    if len(changes)!=expected_count:raise ValueError(f'Expected exactly {expected_count} approved BMP files')
    if any(a!=b and not mask for a,b,mask in zip(original,data,allowed)):raise ValueError('Change outside approved file content')
    with output.open('xb') as f:f.write(data)
    extracted=output.parent/'boot-resource-verificacao'
    extract(output,extracted)
    for path,(size,offsets) in files.items():
        expected=(assets/path).read_bytes() if (assets/path).is_file() else b''.join(original[o:o+cluster_size] for o in offsets)[:size]
        if (extracted/path).read_bytes()!=expected:raise ValueError('Re-extracted file differs')
    report=dict(passed=True,changed_files=changes,all_files_checked=len(files),
                bytes_outside_replacement_files_unchanged=True,fat_and_directories_unchanged=True,
                source_sha256=hashlib.sha256(original).hexdigest(),sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),flashable=False,container_and_bootloader_verification='UNPROVEN')
    output.with_suffix('.validation.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in report.items() if k!='changed_files'},indent=2))


if __name__=='__main__':patch(*sys.argv[1:])
