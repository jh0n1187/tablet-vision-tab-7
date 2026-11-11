"""Offline consistency audit. No probe, memory test or approval for hardware."""
import hashlib
import itertools
import json
from pathlib import Path
import re
import struct

ROOT=Path(__file__).resolve().parent
REF=ROOT.parents[1]/'analise-firmware/revisao-fel/referencias'


def main():
    manifest=json.loads((REF/'manifest.json').read_text(encoding='utf-8-sig'))
    for item in manifest:
        path=REF/item['File']
        if hashlib.sha256(path.read_bytes()).hexdigest().lower()!=item['SHA256'].lower():
            raise RuntimeError('reference hash mismatch: '+item['File'])
    soc=(REF/'sunxi-tools-34dfa20f8284273085666436e4cac09af19646c8/soc_info.c').read_text()
    profile=soc.split('.soc_id       = 0x1890,',1)[1].split('},{',1)[0].split('\n\t},',1)[0]
    def value(field):
        return int(re.search(r'\.'+field+r'\s*=\s*(0x[0-9a-fA-F]+)',profile).group(1),16)
    scratch,thunk,spl=value('scratch_addr'),value('thunk_addr'),value('spl_addr')
    swap_text=soc.split('sram_swap_buffers a523_sram_swap_buffers[] = {',1)[1].split('};',1)[0]
    swap=re.search(r'\.buf1\s*=\s*(0x\w+).*?\.buf2\s*=\s*(0x\w+).*?\.size\s*=\s*(0x\w+)',swap_text)
    original,backup,size=(int(x,16) for x in swap.groups())
    banks=[('MCU0 boot mapping',0x20000,0x40000),('SRAM A2',0x40000,0x64000)]
    proposed=[('code window',0x20000,0x28000),('request',0x2ff00,0x2ff20),
              ('response',0x2ff40,0x2ff90),('data',0x30000,0x40000),
              ('stack reservation',0x57000,0x58000)]
    reference=[('upstream thunk reservation',thunk,thunk+value('thunk_size')),
               ('upstream saved region',original,original+size),
               ('upstream swap destination',backup,backup+size)]
    def intersects(left,right):return max(left[1],right[1])<min(left[2],right[2])
    collisions=[(a[0],b[0]) for a,b in itertools.combinations(proposed,2) if intersects(a,b)]
    if collisions:raise RuntimeError('proposed memory overlaps: '+repr(collisions))
    if not all(any(lo<=start and end<=hi for _,lo,hi in banks) for _,start,end in proposed):
        raise RuntimeError('proposed region outside documentary banks')
    with_reference=[(a[0],b[0]) for a in proposed for b in reference if intersects(a,b)]
    if with_reference:raise RuntimeError('overlap with upstream preservation areas')
    # Verify consistency with the actual linked entry and protocol definitions.
    import felro
    import usb_transport
    assert (felro.CODE,felro.REQUEST_ADDR,felro.DATA)==(0x20000,0x2ff00,0x30000)
    assert usb_transport.RESPONSE_ADDR==0x2ff40
    assert (felro.REQUEST.size,felro.RESPONSE.size)==(32,80)
    entry=(ROOT/'build/locked.bin').read_bytes()[:32]
    assert struct.unpack_from('<I',entry,28)[0]==0x58000
    for name in ('locked','candidate-NOT-FOR-DEVICE'):
        code=(ROOT/'build'/(name+'.bin')).read_bytes()
        assert 0<len(code)<=0x8000
    def ranges(items):return [{'name':name,'start':hex(start),'end_exclusive':hex(end),
                              'bytes':end-start} for name,start,end in items]
    report={'scope':'PC-only static analysis; documentary address ranges are NOT live availability',
            'reference_hashes_checked':len(manifest),
            'banks':ranges(banks),'proposed':ranges(proposed),'reference_preservation':ranges(reference),
            'proposed_overlaps':collisions,'overlaps_with_upstream_preservation':with_reference,
            'upstream_scratch':hex(scratch),'upstream_spl':hex(spl),
            'upstream_spl_nominal_envelope':['0x44000','0x5c000'],
            'warning':'Nominal SPL envelope intersects proposed stack; do not combine with SPL loading',
            'physical_execution_approved':False,
            'unknowns':['MCU0 mapping/arbitration in actual FEL','BROM build and security state',
                        'Live BROM stacks, exception vectors, data and translation tables',
                        'Actual SCTLR/MMU/cache state and instruction coherency',
                        'Available scratch bootstrap and safe return contract'],
            'tablet_accessed':False}
    (ROOT/'build/brom-sram-audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
