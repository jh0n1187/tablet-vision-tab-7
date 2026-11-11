"""Execute ARM instructions ONLY inside a Linux PC emulator, never USB/BROM.

Unicorn does not model A523 caches, TrustZone, memory arbitration or BROM.
MMIO is deliberately unmapped; any access is a stop, not simulated hardware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zlib

ROOT=Path(__file__).resolve().parent


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deps',type=Path,required=True)
    args=parser.parse_args()
    sys.path.insert(0,str(args.deps.resolve()))
    import unicorn as u
    from unicorn import arm_const as a

    results=[]
    def check(condition,message):
        if not condition:raise AssertionError(message)

    def machine(code,address,cpsr):
        emu=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_ARM|u.UC_MODE_LITTLE_ENDIAN)
        emu.ctl_set_cpu_model(a.UC_CPU_ARM_CORTEX_A15)
        emu.mem_map(0x20000,0x44000) # documented SRAM banks; synthetic availability
        emu.mem_map(0x100000,0x1000) # synthetic caller; NOT a BROM mapping
        emu.mem_write(address,code)
        emu.reg_write(a.UC_ARM_REG_CPSR,cpsr)
        emu.reg_write(a.UC_ARM_REG_SP,0x53000)
        emu.reg_write(a.UC_ARM_REG_LR,0x100000)
        for i in range(4,12):emu.reg_write(getattr(a,f'UC_ARM_REG_R{i}'),0x12300000+i)
        return emu

    def request(op=1,lba=0,count=0,magic=0x314f5246,seq=7,reserved=0,corrupt=False):
        data=struct.pack('<8I',magic,1,op,seq,lba,count,reserved,0)
        crc=zlib.crc32(data)^(1 if corrupt else 0)
        return data[:-4]+struct.pack('<I',crc)

    cases=[('info',request(),6),('read',request(2,0,1),6),
           ('bad-crc',request(corrupt=True),1),('forbidden',request(24),2),
           ('bad-magic',request(magic=0),1),('zero-sequence',request(seq=0),1),
           ('reserved',request(reserved=1),1),('info-range',request(lba=1),3),
           ('zero-count',request(2,0,0),3),('too-many',request(2,0,129),3),
           ('lba-overflow',request(2,0xffffffff,2),3)]
    contexts=[0x13,0xd3,0x1f,0xdf,0x12,0xd2] # SVC, SYS, IRQ; IRQ/FIQ masks on/off
    for name in ('locked','candidate-NOT-FOR-DEVICE'):
        code=(ROOT/'build'/(name+'.bin')).read_bytes()
        for cpsr in contexts:
            for case,req,status in cases:
                if name!='locked' and status==6:continue # valid candidate reaches MMIO
                emu=machine(code,0x20000,cpsr)
                emu.mem_write(0x2ff00,req)
                emu.mem_write(0x30000,b'\xa5'*65536)
                writes=[]
                def write_hook(uc,access,address,size,value,user):
                    check((0x57000<=address and address+size<=0x58000) or
                          (0x2ff40<=address and address+size<=0x2ff90),
                          f'write outside response/stack: {address:#x}')
                    writes.append((address,size,value))
                emu.hook_add(u.UC_HOOK_MEM_WRITE,write_hook)
                emu.emu_start(0x20000,0x100000,count=200000)
                check(emu.reg_read(a.UC_ARM_REG_PC)==0x100000,'did not return to synthetic caller')
                check(emu.reg_read(a.UC_ARM_REG_SP)==0x53000,'SP not restored')
                for i in range(4,12):
                    check(emu.reg_read(getattr(a,f'UC_ARM_REG_R{i}'))==0x12300000+i,'callee register changed')
                check(emu.reg_read(a.UC_ARM_REG_LR)==0x100000,'LR not restored')
                check(emu.reg_read(a.UC_ARM_REG_CPSR)&0xff==cpsr,'CPSR control changed')
                check(bytes(emu.mem_read(0x20000,len(code)))==code,'code changed')
                check(bytes(emu.mem_read(0x2ff00,32))==req,'request changed')
                check(bytes(emu.mem_read(0x30000,65536))==b'\xa5'*65536,'data touched on rejected request')
                reply=bytes(emu.mem_read(0x2ff40,80));fields=struct.unpack('<20I',reply)
                check(fields[3]==status,'unexpected response status')
                check(fields[2]==struct.unpack('<8I',req)[3],'sequence mismatch')
                check(zlib.crc32(reply[:64]+bytes(4)+reply[68:])==fields[16],'response CRC')
                response_writes=[w for w in writes if 0x2ff40<=w[0]<0x2ff90]
                check(response_writes[-1]==(0x2ff40,4,0x314f5246),'magic not published last')
                results.append({'binary':name,'case':case,'cpsr':hex(cpsr),
                                'writes':len(writes),'status':status,
                                'lowest_stack_write':hex(min(w[0] for w in writes if w[0]>=0x57000))})

    # A valid candidate must encounter unmapped MMIO: the emulator never models
    # the board or permits access to a physical device.
    candidate=(ROOT/'build/candidate-NOT-FOR-DEVICE.bin').read_bytes()
    emu=machine(candidate,0x20000,0xd3);emu.mem_write(0x2ff00,request())
    blocked=[]
    def invalid_hook(uc,access,address,size,value,user):
        blocked.append({'access':access,'address':hex(address),'bytes':size});return False
    emu.hook_add(u.UC_HOOK_MEM_INVALID,invalid_hook)
    try:emu.emu_start(0x20000,0x100000,count=200000)
    except u.UcError:pass
    check(blocked and blocked[0]['address']=='0x2000060','candidate MMIO boundary changed')

    # Extract the upstream I-cache thunk; execute only in synthetic CPU state.
    source=ROOT.parents[1]/'analise-firmware/revisao-fel/referencias/sunxi-tools-34dfa20f8284273085666436e4cac09af19646c8/fel_lib.c'
    text=source.read_text()
    body=text.split('static void aw_disable_icache',1)[1].split('};',1)[0]
    words=[int(x,16) for x in re.findall(r'htole32\((0x[0-9a-f]+)\)',body)]
    check(words==[0xee110f10,0xe3c00a01,0xee010f10,0xee070f15,0xf57ff06f,0xe12fff1e],
          'upstream cache sequence changed; review required')
    cache_code=struct.pack('<6I',*words)
    cache_results=[]
    for bits in (0,4,0x800,0x1000,0x1004,0x1804):
        emu=machine(cache_code,0x45000,0xd3)
        base=emu.cpr_read(15,0,1,0,0,0,False)&~0x1805
        initial=base|bits
        emu.cpr_write(15,0,1,0,0,0,False,initial)
        observed_initial=emu.cpr_read(15,0,1,0,0,0,False)
        emu.emu_start(0x45000,0x100000,count=100)
        final=emu.cpr_read(15,0,1,0,0,0,False)
        check(final==observed_initial&~0x1000,'cache thunk changed other SCTLR bits')
        check(emu.reg_read(a.UC_ARM_REG_PC)==0x100000,'cache thunk did not return')
        check(emu.reg_read(a.UC_ARM_REG_SP)==0x53000,'cache thunk changed SP')
        cache_results.append({'sctlr_before':hex(observed_initial),'sctlr_after':hex(final)})

    report={'emulator':'Unicorn '+u.__version__,'cpu_model':'Cortex-A15 AArch32, NOT A523 hardware',
            'input_binary_sha256':{name:hashlib.sha256((ROOT/'build'/name).read_bytes()).hexdigest()
                                   for name in ('locked.bin','candidate-NOT-FOR-DEVICE.bin')},
            'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'arm_payload_scenarios_passed':len(results),'cache_register_scenarios_passed':len(cache_results),
            'valid_candidate_stops_at_unmapped_mmio':blocked,
            'cache_reference_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'cache_opcode_words':[hex(w) for w in words],
            'scenarios':results,'cache_scenarios':cache_results,
            'limitations':['No cache/coherency/TrustZone/BROM model','SRAM availability assumed',
                           'No IRQ/FIQ delivery modeled','No ARM execution on tablet'],
            'usb_opened':False,'tablet_accessed':False}
    (ROOT/'build/arm-offline-results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('scenarios','cache_scenarios')},indent=2))

if __name__=='__main__':main()
