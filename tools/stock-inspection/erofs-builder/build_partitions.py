"""Offline build and semantic round-trip audit. No device access, mounts or flash commands."""
import base64
import copy
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile


def dump(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def name(value):
    value = value.removeprefix('./').rstrip('/')
    if value.startswith('/') or '..' in value.split('/'):
        raise ValueError('Unsafe archive pathname')
    return value or '.'


def attributes(t):
    attrs = {}
    for k, v in t.pax_headers.items():
        if k.startswith('LIBARCHIVE.xattr.'):
            attrs[k[17:]] = base64.b64decode(v + '=' * (-len(v) % 4)).hex()
        elif k.startswith('SCHILY.xattr.'):
            attrs[k[13:]] = v.encode('utf-8', 'surrogateescape').hex()
    result = dict(mode=t.mode, uid=t.uid, gid=t.gid,
                  mtime=str(Decimal(t.pax_headers.get('mtime', str(t.mtime))).normalize()),
                  xattrs=attrs, type=t.type.decode('ascii'))
    if t.issym() or t.islnk():
        result['link'] = name(t.linkname) if t.islnk() else t.linkname
    if t.ischr() or t.isblk():
        result.update(major=t.devmajor, minor=t.devminor)
    if t.isfile():
        result['size'] = t.size
    return result


class DigestReader:
    def __init__(self, f):
        self.f, self.hash = f, hashlib.sha256()
    def read(self, size=-1):
        block = self.f.read(size)
        self.hash.update(block)
        return block


def scan(image):
    p = subprocess.Popen(['erofs-export', str(image)], stdout=subprocess.PIPE)
    records = {}
    with tarfile.open(fileobj=p.stdout, mode='r|') as tar:
        for t in tar:
            key = name(t.name)
            if key in records:
                raise ValueError('Duplicate entry')
            rec = attributes(t)
            if t.isfile():
                f = DigestReader(tar.extractfile(t))
                while f.read(1024 * 1024):
                    pass
                rec['sha256'] = f.hash.hexdigest()
            records[key] = rec
    p.stdout.close()
    if p.wait():
        raise RuntimeError('EROFS export failed')
    return records


def compare(expected, actual):
    errors = []
    if expected.keys() != actual.keys():
        errors.append({'missing': sorted(expected.keys()-actual.keys()),
                       'unexpected': sorted(actual.keys()-expected.keys())})
    for key in expected.keys() & actual.keys():
        if expected[key] != actual[key]:
            errors.append({'path': key, 'expected': expected[key], 'actual': actual[key]})
    return errors


def mkfs(target, source):
    # Baseline 4K LZ4, no new xattr-name-filter kernel requirement.
    subprocess.run(['mkfs.erofs', '-z', 'lz4hc,9', '-E', '^xattr-name-filter',
                    '--tar=f', str(target), str(source)], check=True,
                   stdout=open(str(target)+'.mkfs.log', 'w'), stderr=subprocess.STDOUT)
    subprocess.run(['fsck.erofs', '--extract', str(target)], check=True,
                   stdout=open(str(target)+'.fsck.log', 'w'), stderr=subprocess.STDOUT)


def fixture(out):
    target = out/'metadata-test.img'
    if target.exists():
        raise FileExistsError(target)
    records = {}
    with tarfile.open(out/'metadata-test.tar', 'w', format=tarfile.PAX_FORMAT) as tar:
        for key, typ, content, link in [('.', tarfile.DIRTYPE, b'', ''),
                ('dir', tarfile.DIRTYPE, b'', ''), ('dir/file', tarfile.REGTYPE, b'offline\0data\xff'*8000, ''),
                ('dir/link', tarfile.SYMTYPE, b'', 'file'), ('hard', tarfile.LNKTYPE, b'', 'dir/file')]:
            t=tarfile.TarInfo(key);t.type=typ;t.uid=1000;t.gid=2000;t.mode=0o750;t.mtime=1234567890
            t.linkname=link;t.size=len(content)
            t.pax_headers={'mtime':'1234567890.123456789',
                           'SCHILY.xattr.security.selinux':'u:object_r:system_file:s0\0'}
            if typ == tarfile.REGTYPE:
                t.pax_headers['SCHILY.xattr.security.capability']=(b'\x01\x00\x00\x02'+b'\0'*16).decode('utf8')
            if typ == tarfile.LNKTYPE:
                # Hardlinks share the inode, including its capabilities.
                t.pax_headers['SCHILY.xattr.security.capability']=(b'\x01\x00\x00\x02'+b'\0'*16).decode('utf8')
            tar.addfile(t,io.BytesIO(content));records[key]=attributes(t)
            if typ == tarfile.REGTYPE:records[key]['sha256']=hashlib.sha256(content).hexdigest()
    mkfs(target,out/'metadata-test.tar')
    actual=scan(target);errors=compare(records,actual)
    dump(out/'metadata-test-result.json',dict(passed=not errors,errors=errors,expected=records,actual=actual))
    if errors:raise RuntimeError('Metadata round trip failed')
    print('Metadata fixture: PASS',flush=True)


def build(partition, root, out, image_dir=None, plan_path=None, customization_path=None):
    image_dir = image_dir or root/'analise-firmware/stock-URBR2024101701/logical'
    plan_path = plan_path or root/'analise-firmware/central-inteligente/limpeza/plano-limpeza.json'
    image=Path(image_dir)/f'{partition}_a.img'
    plan=json.loads(Path(plan_path).read_text())
    excluded=[p.split('/',1)[1] for p in plan['excluded_roots'] if p.startswith(partition+'/')]
    custom=json.loads(Path(customization_path).read_text()).get(partition,{}) if customization_path else {}
    excluded += custom.get('exclude',[])
    additions=custom.get('additions',[])
    templates={}
    assets=root/'analise-firmware/central-inteligente/aprovado-v2/recursos-nativos'
    replacements={}
    if partition=='system':
        replacements={f'system/media/{p}':assets/'system/media'/p for p in ['bootanimation.zip','bootanimation_dark.zip']}
    if partition=='vendor':
        replacements={str(p.relative_to(assets/'vendor')):p for p in (assets/'vendor').rglob('*') if p.is_file()}
    for key, relative in custom.get('replacements',{}).items():
        assert name(key)==key and not Path(relative).is_absolute()
        replacements[key]=root/relative
        assert replacements[key].is_file()
    target=out/f'{partition}_a.img'
    tarpath=out/f'{partition}.tar'
    if target.exists() or tarpath.exists():raise FileExistsError(target)
    original,expected,changes={},{},[]
    found=set(); media_template=None; removed=set(); buildprop=False
    p=subprocess.Popen(['erofs-export',str(image)],stdout=subprocess.PIPE)
    with tarfile.open(fileobj=p.stdout,mode='r|') as source, tarfile.open(tarpath,'w',format=tarfile.PAX_FORMAT) as dest:
        for t in source:
            key=name(t.name);rec=attributes(t)
            if any(a['template']==key for a in additions):
                templates[key]=copy.deepcopy(t)
            data=source.extractfile(t) if t.isfile() else None
            oldhash=DigestReader(data) if data else None
            drop=any(key==r or key.startswith(r+'/') for r in excluded)
            if drop:
                removed.add(next(r for r in excluded if key==r or key.startswith(r+'/')))
                if oldhash:
                    while oldhash.read(1024*1024):pass
            else:
                t=copy.deepcopy(t)
                # Explicit nine-digit PAX fraction works around the old parser's
                # unscaled short fraction and uninitialised integer nanoseconds.
                sec=Decimal(t.pax_headers.get('mtime',str(t.mtime)))
                t.pax_headers['mtime']=format(sec,'.9f')
                if key in replacements:
                    raw=oldhash.read();rec['sha256']=oldhash.hash.hexdigest()
                    payload=replacements[key].read_bytes();t.size=len(payload);found.add(key)
                    changes.append(dict(path=key,kind='approved_visual',old_sha256=rec['sha256'],new_sha256=hashlib.sha256(payload).hexdigest()))
                    data=io.BytesIO(payload)
                elif (partition=='system' and key=='system/build.prop') or key==custom.get('property_file'):
                    raw=oldhash.read();rec['sha256']=oldhash.hash.hexdigest()
                    text=raw.decode('utf8')
                    if partition=='system':
                        for prop in ('ro.config.wallpaper','ro.config.lock_wallpaper'):
                            if any(line.startswith(prop+'=') for line in text.splitlines()):raise ValueError('Wallpaper property already set')
                        text+='\n# Central Inteligente: approved default resources.\nro.config.wallpaper=/system/media/central-wallpaper.png\nro.config.lock_wallpaper=/system/media/central-lockscreen.png\n'
                        buildprop=True
                    for prop,value in custom.get('properties',{}).items():
                        assert '\n' not in value and '=' not in prop
                        lines=text.splitlines();indexes=[i for i,line in enumerate(lines) if line.startswith(prop+'=')]
                        assert len(indexes)<=1
                        if indexes:lines[indexes[0]]=prop+'='+value
                        else:lines.append(prop+'='+value)
                        text='\n'.join(lines)+'\n'
                    payload=text.encode();t.size=len(payload);data=io.BytesIO(payload)
                    changes.append(dict(path=key,kind='wallpaper_properties',old_sha256=rec['sha256'],new_sha256=hashlib.sha256(payload).hexdigest()))
                else:data=oldhash
                if key=='system/media/bootanimation.zip':media_template=copy.deepcopy(t)
                newrec=attributes(t)
                if t.isfile():
                    newhash=DigestReader(data);dest.addfile(t,newhash);newrec['sha256']=newhash.hash.hexdigest()
                else:dest.addfile(t)
                expected[key]=newrec
            if oldhash and 'sha256' not in rec:rec['sha256']=oldhash.hash.hexdigest()
            original[key]=rec
        if partition=='system':
            if not media_template or not buildprop:raise ValueError('Missing wallpaper metadata template/build.prop')
            for filename,asset in [('central-wallpaper.png','wallpaper.png'),('central-lockscreen.png','lockscreen.png')]:
                t=copy.deepcopy(media_template);t.name='system/media/'+filename
                t.pax_headers={k:v for k,v in t.pax_headers.items() if k not in ('path','size','linkpath')}
                raw=(assets/'fundos'/asset).read_bytes();t.size=len(raw);dest.addfile(t,io.BytesIO(raw))
                expected[t.name]=attributes(t);expected[t.name]['sha256']=hashlib.sha256(raw).hexdigest()
                changes.append(dict(path=t.name,kind='approved_default_wallpaper',new_sha256=expected[t.name]['sha256']))
        for addition in additions:
            key=name(addition['path']);assert key==addition['path'] and key not in original and key not in expected
            parent=str(Path(key).parent);assert parent in expected and expected[parent]['type']=='5'
            t=copy.deepcopy(templates[addition['template']]);assert t.isfile()
            t.name=key;t.pax_headers={k:v for k,v in t.pax_headers.items() if k not in ('path','size','linkpath')}
            sec=Decimal(t.pax_headers.get('mtime',str(t.mtime)));t.pax_headers['mtime']=format(sec,'.9f')
            payload=(root/addition['source']).read_bytes();t.size=len(payload);dest.addfile(t,io.BytesIO(payload))
            expected[key]=attributes(t);expected[key]['sha256']=hashlib.sha256(payload).hexdigest()
            changes.append(dict(path=key,kind='audited_resource_overlay',metadata_template=addition['template'],new_sha256=expected[key]['sha256']))
    p.stdout.close()
    if p.wait():raise RuntimeError('Source export failed')
    if found!=replacements.keys() or removed!=set(excluded):raise ValueError('Missing replacement/exclusion path')
    dump(out/f'{partition}-original.json',original);dump(out/f'{partition}-expected.json',expected)
    dump(out/f'{partition}-changes.json',dict(excluded_roots=excluded,changes=changes))
    print(f'{partition}: exported {len(original)}, retained/added {len(expected)} entries',flush=True)
    mkfs(target,tarpath)
    actual=scan(target);dump(out/f'{partition}-actual.json',actual)
    errors=compare(expected,actual)
    report=dict(passed=not errors,errors=errors,entries=len(actual),xattr_entries=sum(bool(r['xattrs']) for r in actual.values()),
                source_bytes=image.stat().st_size,candidate_bytes=target.stat().st_size,
                sha256=hashlib.file_digest(target.open('rb'),'sha256').hexdigest(),flashable=False,
                avb='NOT_SIGNED_NOT_AUTHORIZED_BY_OEM_CHAIN')
    dump(out/f'{partition}-validation.json',report)
    if errors:raise RuntimeError(f'{partition}: semantic validation failed ({len(errors)} differences)')
    if target.stat().st_size>image.stat().st_size:raise RuntimeError('Candidate exceeds original partition')
    print(f'{partition}: PASS metadata and all retained content',flush=True)


if __name__=='__main__':
    out=Path(sys.argv[2]);out.mkdir(exist_ok=True)
    if sys.argv[1]=='test':fixture(out)
    else:build(sys.argv[1],Path('/source'),out,
               Path(sys.argv[3]) if len(sys.argv)>3 else None,
               Path(sys.argv[4]) if len(sys.argv)>4 else None,
               Path(sys.argv[5]) if len(sys.argv)>5 else None)
