"""Consolidate audited development artifacts; deliberately emits no flash command/package."""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'analise-firmware/central-inteligente'
OUT=BASE/'candidato-v2'
STOCK=ROOT/'analise-firmware/stock-URBR2024101701'
sys.path.insert(0,str(ROOT/'tools/stock-inspection/vendor'))
import avbtool


def read(p):return json.loads(p.read_text(encoding='utf8'))
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def features(p):
    with p.open('rb') as f:f.seek(1024);b=f.read(128)
    return dict(magic=hex(struct.unpack_from('<I',b)[0]),compat=struct.unpack_from('<I',b,8)[0],
                block_bits=b[12],incompat=struct.unpack_from('<I',b,80)[0],
                compression=struct.unpack_from('<H',b,84)[0],extra_devices=struct.unpack_from('<H',b,86)[0])


def main():
    if (OUT/'MANIFESTO.json').exists():raise FileExistsError('Already consolidated')
    approved=BASE/'aprovado-v2'
    files=read(approved/'manifest.json')['files']
    for e in files:
        p=approved/e['file']
        if p.stat().st_size!=e['bytes'] or sha(p)!=e['sha256']:raise ValueError('Approved snapshot differs')
    validations={p:read(OUT/f'{p}-validation.json') for p in ('system','product','vendor')}
    for p,r in validations.items():
        if not r['passed'] or r['errors'] or sha(OUT/f'{p}_a.img')!=r['sha256']:raise ValueError('Partition validation/hash failed')
    if not read(OUT/'test-2/metadata-test-result.json')['passed']:raise ValueError('Fixture failed')
    if not read(OUT/'boot-resource.validation.json')['passed']:raise ValueError('FAT validation failed')
    actual={p:read(OUT/f'{p}-actual.json') for p in validations}
    retained=read(BASE/'limpeza/resultado-copia.json')['retained']
    for a in retained:
        part,path=a['path'].split('/',1)
        if actual[part][path]['sha256']!=a['sha256']:raise ValueError('Retained APK mismatch')
    plan=read(BASE/'limpeza/plano-limpeza.json')
    for r in plan['excluded_roots']:
        part,path=r.split('/',1)
        if any(p==path or p.startswith(path+'/') for p in actual[part]):raise ValueError('Excluded path remains')
    feature_reports={}
    for p in validations:
        src=features(STOCK/'logical'/f'{p}_a.img');new=features(OUT/f'{p}_a.img')
        if src!=new:raise ValueError(f'EROFS feature profile differs: {p}: {src} vs {new}')
        feature_reports[p]=dict(source=src,candidate=new,equal=True)
    print('Approved assets, APKs, exclusions and feature profiles: PASS',flush=True)
    sources={}
    for p in read(STOCK/'logical-extraction.json')['partitions']:
        if 'sha256' in p:
            f=STOCK/'logical'/(p['name']+'.img')
            if sha(f)!=p['sha256']:raise ValueError('Original logical partition changed')
            sources[p['name']]=p['sha256']
    firmware=STOCK/'T307F.URBR2024101701U.pro1.u_pk_s_v0_20241017_USER.img'
    firmware_hash=sha(firmware)
    if firmware_hash!='c56a33d150b644eef96696409ebfa0bda8877f739252640313d3332c310c22f1':raise ValueError('Original firmware changed')
    print('Original firmware and extracted partitions: hashes unchanged',flush=True)
    # Calculate engineering roots with the original salts/algorithms. No footer,
    # signature, verification-disable flags or rollback changes are written.
    descriptors={}
    avb=avbtool.Avb()
    for part in ('vbmeta','vbmeta_system','vbmeta_vendor'):
        _,_,ds,_=avb._parse_image(avbtool.ImageHandler(str(STOCK/'avb/image-set'/(part+'.img')),read_only=True))
        for d in ds:
            if isinstance(d,avbtool.AvbHashtreeDescriptor):descriptors[d.partition_name]=d
    avb_report={}
    for p in validations:
        d=descriptors[p];f=OUT/f'{p}_a.img';size=f.stat().st_size
        digest_size=len(avbtool.create_avb_hashtree_hasher(d.hash_algorithm,b'').digest())
        pad=avbtool.round_to_pow2(digest_size)-digest_size
        offsets,tree_size=avbtool.calc_hash_level_offsets(size,d.data_block_size,digest_size+pad)
        image=avbtool.ImageHandler(str(f),read_only=True)
        digest,_=avbtool.generate_hash_tree(image,size,d.data_block_size,d.hash_algorithm,d.salt,pad,offsets,tree_size)
        matches=(size==d.image_size and digest==d.root_digest)
        if matches:raise ValueError('Modified image unexpectedly matches old AVB descriptor')
        avb_report[p]=dict(original_signed_data_size=d.image_size,candidate_data_size=size,
                           original_signed_root=d.root_digest.hex(),candidate_root=digest.hex(),
                           original_chain_accepts_candidate=matches,tree_bytes=tree_size,
                           hash_algorithm=d.hash_algorithm,original_fec_roots=d.fec_num_roots,
                           hashtree_or_footer_written=False,new_signature_created=False)
    (OUT/'avb-candidate-comparison.json').write_text(json.dumps(avb_report,indent=2))
    total=sum(r['candidate_bytes'] for r in validations.values())
    original_total=sum(r['source_bytes'] for r in validations.values())
    manifest=dict(state='OFFLINE_PARTITIONS_VALIDATED_INSTALLATION_BLOCKED',flashable=False,
        device_accessed=False,tablet_written=False,base='T307F URBR2024101701 / Android 14 / patch 2024-10-05',
        installed_from_backup='T307TSF URTSF2025092701 / Android 14 / patch 2025-08-05',
        candidate_is_android_upgrade=False,approved_files_checked=len(files),retained_apks_checked=len(retained),
        removed_packages=plan['removed_packages'],removed_roots=len(plan['excluded_roots']),
        entries_checked=sum(r['entries'] for r in validations.values()),
        candidate_partition_bytes=total,original_partition_bytes=original_total,
        difference_bytes=original_total-total,
        size_note='EROFS-only candidates versus original partitions with AVB/padding; not user-data or RAM savings.',
        partitions=validations,erofs_features=feature_reports,original_firmware_sha256=firmware_hash,
        original_logical_hashes=sources,boot_resource=read(OUT/'boot-resource.validation.json'),
        app_included=False,device_owner_reprovisioned=False,
        blockers=['OEM AVB signing / supported bootloader unlock route not demonstrated',
                  'Stock older than installed build; rollback counters unknown',
                  'No full validated current firmware backup or proven recovery route',
                  'No signed AVB/FEC, super or Allwinner flash container generated'])
    (OUT/'MANIFESTO.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({k:manifest[k] for k in ('state','entries_checked','retained_apks_checked','removed_packages','candidate_partition_bytes','difference_bytes')},indent=2),flush=True)


if __name__=='__main__':main()
