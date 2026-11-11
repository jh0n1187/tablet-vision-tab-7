"""Offline execution of real 2024 bootm entry bytes up to state dispatch.
Device/storage/display calls are mocked. This is not hardware validation.
"""
from pathlib import Path
import json
import re
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/fel-readonly/build/offline-deps/unicorn-linux'))
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_INVALID
from unicorn.arm_const import *

BASE=0x4a000000
OUT=ROOT/'analise-firmware/desbloqueio-T307F/legacy-adapter'

def main():
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    raw=(ROOT/'analise-firmware/desbloqueio-T307F/u-boot.fex').read_bytes()
    for addr,size in [(BASE,0x200000),(0x47000000,0x10000),(0x49000000,0x10000),
                      (0x4b000000,0x10000),(0x60000000,0x100000),(0x68000000,0x10000)]:
        uc.mem_map(addr,size)
    uc.mem_write(BASE,raw)
    wrapper=(OUT/'probe-fastboot.img').read_bytes()
    uc.mem_write(0x47000000,wrapper)
    uc.mem_write(0x49000000,b'R'*1024)
    vendor=(ROOT/'analise-firmware/stock-URBR2024101701/parts/vendor_boot.fex').read_bytes()[:4096]
    uc.mem_write(0x4b000000,vendor)
    uc.mem_write(0x68000100,b'bootm\0')
    uc.mem_write(0x68000120,b'47000800\0')
    uc.mem_write(0x68000080,struct.pack('<II',0x68000100,0x68000120))
    uc.reg_write(UC_ARM_REG_R0,0)
    uc.reg_write(UC_ARM_REG_R1,0)
    uc.reg_write(UC_ARM_REG_R2,2)
    uc.reg_write(UC_ARM_REG_R3,0x68000080)
    uc.reg_write(UC_ARM_REG_R9,0x68001000)
    uc.reg_write(UC_ARM_REG_SP,0x6800ff00)
    uc.reg_write(UC_ARM_REG_LR,0x68000001)
    calls=[];copies=[];reached=False
    dis=(ROOT/'analise-firmware/desbloqueio-T307F/u-boot-thumb-disassembly.txt').read_text()
    targets=set()
    for line in dis.splitlines():
        if line.startswith('4a009') and '\tbl\t' in line:
            address=int(line[:8],16)
            if 0x4a0093d4<=address<0x4a009758:
                targets.add(int(re.search(r'\tbl\t0x([0-9a-f]+)',line)[1],16))
    def string(addr):
        out=bytearray()
        for i in range(2048):
            b=bytes(uc.mem_read(addr+i,1))
            if b==b'\0':return out.decode(errors='replace')
            out.extend(b)
        raise ValueError('Unbounded string')
    def ret(v):
        uc.reg_write(UC_ARM_REG_R0,v&0xffffffff)
        uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    def hook(cpu,address,size,unused):
        nonlocal reached
        if address not in targets:
            if not BASE+0x93d4<=address<BASE+0x9758:
                raise RuntimeError('Unmodeled branch dependency '+hex(address))
            return
        regs=[cpu.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
        calls.append({'callee':hex(address),'arguments':[hex(x) for x in regs]})
        a,b,n,d=regs
        if address==BASE+0x7d44c:
            value=string(a)
            if b:cpu.mem_write(b,struct.pack('<I',a+len(value)))
            ret(int(value,n));return
        if address==BASE+0x10318:ret(0);return # no fake_go or boot_from_partition
        if address==BASE+0x7c04:ret(0);return # unlocked verification succeeds
        if address==BASE+0x2391c:ret(1);return # LCD operation complete
        if address==BASE+0x10368:ret(b);return # env_get_hex returns default
        if address==BASE+0x152ac:
            cpu.mem_write(b,struct.pack('<I',0x49000000))
            cpu.mem_write(n,struct.pack('<I',1024));ret(0);return
        if address==BASE+0x7c568:
            x,y=bytes(cpu.mem_read(a,n)),bytes(cpu.mem_read(b,n));ret((x>y)-(x<y));return
        if address==BASE+0x14ab4:ret(0x4b000000);return
        if address==BASE+0x146c0:
            if n>4096:raise ValueError('Unexpected copy size')
            cpu.mem_write(a,bytes(cpu.mem_read(b,n)));copies.append({'destination':hex(a),'source':hex(b),'bytes':n});ret(a);return
        if address==BASE+0x9000:ret(0);return # RAM checksum mock
        if address==BASE+0x2d6c:ret(0);return # memory diagnostic log
        if address==BASE+0x10094:ret(0);return # RAM environment set_hex
        if address==BASE+0x11ce0:ret(0);return # bootargs update helper
        if address==BASE+0x2bd4:ret(1);return # secure monitor present
        if address==BASE+0x2a3c:ret(0);return # force_32bit flag remains off
        if address in (BASE+0x61f4,BASE+0x686c):ret(0);return # bootargs / vendor bootconfig updates
        if address in (BASE+0x7c6fa,BASE+0x7c6e0):
            haystack=string(a)
            needle=string(b) if address==BASE+0x7c6fa else chr(b&255)
            index=haystack.find(needle);ret(0 if index<0 else a+index);return
        if address in (BASE+0x13180,BASE+0x7d350,BASE+0x7c758):ret(0);return
        if address==BASE+0x1136c:
            reached=True;cpu.emu_stop();return
        raise RuntimeError('Unmodeled bootm dependency '+hex(address)+' '+repr(regs))
    def invalid(cpu,access,address,size,value,unused):
        raise RuntimeError('Unmapped/MMIO bootm access '+hex(address))
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.hook_add(UC_HOOK_MEM_INVALID,invalid)
    try:
        uc.emu_start(BASE+0x93d5,0x68000000,timeout=2000000,count=100000)
        result={'reached_state_dispatch':reached,'copies':copies,'calls':calls,
                'mocked_dependencies':True,'physical_validation':False}
        assert reached
        assert copies==[{'destination':'0x60006060','source':'0x49000000','bytes':1024}]
        print(json.dumps({'reached_state_dispatch':True,'copy_target_verified':True,'physical_validation':False}))
    finally:
        (OUT/'bootm-entry-emulation.json').write_text(json.dumps({'reached_state_dispatch':reached,'copies':copies,'calls':calls},indent=2))

if __name__=='__main__':main()
