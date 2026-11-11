"""Execute exact 2024 stock gate bytes on a synthetic ARM CPU, never hardware.
Storage/libc/log/environment dependencies are explicit host-side stubs.
This proves only the isolated branch semantics of this pinned stock binary.
"""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,'/source/tools/fel-readonly/build/offline-deps/unicorn-linux')
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_INVALID,UC_PROT_ALL,UC_PROT_READ,UC_PROT_EXEC
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R9,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC

BASE=0x4a000000
STACK=0x60000000
GLOBAL=0x61000000
RETURN=0x62000000
GATE=BASE+0x6d4b8
PIN='ae69037c35ffaf45345074a116ba904e232a40899d5624c604ebbbc2e5119143'

def run(raw,secure,flags,init_failure=False):
    uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    uc.mem_map(BASE,(len(raw)+4095)&~4095,UC_PROT_ALL);uc.mem_write(BASE,raw)
    uc.mem_protect(BASE,(len(raw)+4095)&~4095,UC_PROT_READ|UC_PROT_EXEC)
    for addr in (STACK,GLOBAL,RETURN):uc.mem_map(addr,65536,UC_PROT_ALL)
    uc.mem_write(GLOBAL+0xd0,secure.to_bytes(4,'little'))
    uc.reg_write(UC_ARM_REG_SP,STACK+0xff00);uc.reg_write(UC_ARM_REG_R9,GLOBAL);uc.reg_write(UC_ARM_REG_LR,RETURN|1)
    calls=[];env={};done=False
    def string(addr):
        b=bytearray()
        for i in range(512):
            v=bytes(uc.mem_read(addr+i,1))
            if v==b'\0':return bytes(b)
            b.extend(v)
        raise ValueError('Unbounded synthetic string read')
    def ret(value):
        uc.reg_write(UC_ARM_REG_R0,value&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    def hook(cpu,addr,size,user):
        nonlocal done
        if addr==RETURN:done=True;cpu.emu_stop();return
        if addr==BASE+0x81e54:calls.append('secure_storage_init');ret(-1 if init_failure else 0)
        elif addr==BASE+0x824fc:
            key=string(cpu.reg_read(UC_ARM_REG_R0)).decode();calls.append('read_object:'+key)
            if key not in flags:ret(-1);return
            value=flags[key];dest=cpu.reg_read(UC_ARM_REG_R1);cap=cpu.reg_read(UC_ARM_REG_R2);length=cpu.reg_read(UC_ARM_REG_R3)
            if len(value)>cap:raise ValueError('Synthetic read exceeds requested capacity')
            if not STACK<=dest<STACK+65536 or not STACK<=length<STACK+65536:raise RuntimeError(f'Unexpected synthetic output pointers for {key}: 0x{dest:x}, 0x{length:x}')
            cpu.mem_write(dest,value);cpu.mem_write(length,len(value).to_bytes(4,'little'));ret(0)
        elif addr==BASE+0x1000:
            dest=cpu.reg_read(UC_ARM_REG_R0);value=cpu.reg_read(UC_ARM_REG_R1)&255;n=cpu.reg_read(UC_ARM_REG_R2)
            if n>4096:raise ValueError('Unexpected memset length')
            cpu.mem_write(dest,bytes([value])*n);ret(dest)
        elif addr==BASE+0x7c552:
            a=string(cpu.reg_read(UC_ARM_REG_R0));b=string(cpu.reg_read(UC_ARM_REG_R1));ret((a>b)-(a<b))
        elif addr in (BASE+0x7d350,BASE+0x7d2e4,BASE+0x13180):ret(0)
        elif addr==BASE+0x10040:
            env[string(cpu.reg_read(UC_ARM_REG_R0)).decode()]=string(cpu.reg_read(UC_ARM_REG_R1)).decode();ret(0)
    def invalid(cpu,access,addr,size,value,user):raise RuntimeError(f'Unmapped access 0x{addr:x}; no hardware/MMIO model supplied')
    uc.hook_add(UC_HOOK_CODE,hook);uc.hook_add(UC_HOOK_MEM_INVALID,invalid)
    uc.emu_start(GATE|1,RETURN,timeout=1000000,count=100000)
    done=done or uc.reg_read(UC_ARM_REG_PC) in (RETURN,RETURN|1)
    if not done or uc.reg_read(UC_ARM_REG_SP)!=STACK+0xff00:raise RuntimeError('Synthetic gate did not return with preserved stack')
    return dict(return_u32=uc.reg_read(UC_ARM_REG_R0),state_u32=int.from_bytes(uc.mem_read(GLOBAL+0xdc,4),'little'),stub_calls=calls,synthetic_env=env)

def main():
    source=Path('/source/analise-firmware/desbloqueio-T307F/u-boot.fex');raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:raise ValueError('Pinned stock binary mismatch')
    scenarios=[('normal_mode',0,{},False,0xffffffff,0),
      ('secure1_no_flags',1,{},False,0,0xaa),
      ('secure1_locked',1,{'fastboot_status_flag':b'locked'},False,0,0xaa),
      ('secure1_unlocked',1,{'fastboot_status_flag':b'unlocked','device_unlock':b'unlock'},False,0xffffffff,0xa5),
      ('secure2_locked',2,{'fastboot_status_flag':b'locked'},False,0,0xaa),
      ('secure2_unlocked',2,{'fastboot_status_flag':b'unlocked','device_unlock':b'unlock'},False,0xffffffff,0xa5),
      ('init_failure',1,{},True,0,0),
      ('locked_with_device_unlock',1,{'fastboot_status_flag':b'locked','device_unlock':b'unlock'},False,0,0xaa)]
    results=[]
    for name,secure,flags,fail,expected_return,expected_state in scenarios:
        try:result=run(raw,secure,flags,fail)
        except Exception as exc:raise RuntimeError(f'{name}: {exc}') from exc
        result['scenario']=name
        result['passed']=result['return_u32']==expected_return and result['state_u32']==expected_state
        if not result['passed']:raise RuntimeError(f'{name}: unexpected gate result {result}')
        results.append(result)
    report=dict(passed=True,scenarios=results,binary_sha256=PIN,source_build='URBR2024101701 (2024), NOT current 2025 bootloader',
                code_under_test='Thumb function at stock file offset 0x6d4b8 and called stock branch logic',
                dependencies_stubbed=True,mmio_or_hardware_model=False,current_device_compatibility_proven=False,
                tablet_accessed=False,payload_loaded_to_tablet=False,storage_writes=False)
    out=Path('/out/unlock-gate-emulation.json')
    if out.exists():raise FileExistsError(out)
    out.write_text(json.dumps(report,indent=2),encoding='utf8')
    print('PASS: 8 stock Thumb gate scenarios, synthetic CPU/storage dependencies only')

if __name__=='__main__':main()
