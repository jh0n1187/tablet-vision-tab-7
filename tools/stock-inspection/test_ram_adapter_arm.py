"""ARM emulation of compiled diagnostic plus actual 2024 command registry.
No USB/hardware. Calls to firmware are intercepted; MMIO is never mapped.
"""
from pathlib import Path
import json
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/fel-readonly/build/offline-deps/unicorn-linux'))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_WRITE
from unicorn.arm_const import *

OUT = ROOT / 'analise-firmware/desbloqueio-T307F/legacy-adapter'
BASE, APP, STACK, RETURN, HEADER = 0x4a000000, 0x60600000, 0x68000000, 0x4a009000, 0x4b000000

def check(mode):
    raw = bytearray((ROOT / 'analise-firmware/desbloqueio-T307F/u-boot.fex').read_bytes())
    if mode == 'missing_registry':
        struct.pack_into('<I', raw, 0x110ba8, 0)
    if mode == 'ambiguous_registry':
        raw[0x120000:0x120014] = raw[0x110a74:0x110a88]
    if mode == 'cache_signature_changed':
        raw[0x15244] ^= 1
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(BASE - 0x100000, 0x300000)
    uc.mem_write(BASE, bytes(raw))
    for address, size in [(APP, 0x10000), (STACK, 0x10000), (HEADER, 0x10000), (0x70000000, 0x10000)]:
        uc.mem_map(address, size)
    uc.mem_write(APP, (OUT / 'probe.bin').read_bytes())
    header = bytearray(4096)
    header[:8] = b'ANDROID!'
    struct.pack_into('<I', header, 12, 2000000)
    struct.pack_into('<I', header, 40, 4)
    uc.mem_write(HEADER, bytes(header))
    uc.mem_write(BASE + 0x118780, struct.pack('<I', HEADER))
    uc.reg_write(UC_ARM_REG_SP, STACK + 0xff00)
    uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
    preserved = {}
    for number in range(4, 12):
        reg = globals()['UC_ARM_REG_R' + str(number)]
        value = 0x11223000 + number
        uc.reg_write(reg, value)
        preserved[reg] = value
    targets = {BASE + 0xdb48: 'sunxi_flash', BASE + 0x93d4: 'bootm',
               BASE + 0xfc18: 'env', BASE + 0x1002c: 'setenv'}
    commands = []
    markers = []
    writes = []
    done = False
    def string(address):
        data = bytearray()
        for i in range(8192):
            byte = bytes(uc.mem_read(address + i, 1))
            if byte == b'\0': return data.decode()
            data.extend(byte)
        raise ValueError('Unbounded string')
    def ret(value):
        uc.reg_write(UC_ARM_REG_R0, value)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    def code(cpu, address, size, unused):
        nonlocal done
        if address == RETURN:
            done = True
            cpu.emu_stop()
            return
        if address not in targets: return
        name = targets[address]
        argc = cpu.reg_read(UC_ARM_REG_R2)
        argv = cpu.reg_read(UC_ARM_REG_R3)
        args = [string(struct.unpack('<I', cpu.mem_read(argv + 4*i, 4))[0]) for i in range(argc)]
        commands.append(args)
        if name == 'sunxi_flash':
            assert args == ['sunxi_flash', 'read', '70000000', 'boot_a', '4000000']
            if mode == 'read_failure': ret(1); return
            data = bytearray(4096)
            data[:8] = b'BADMAGIC' if mode == 'bad_boot_header' else b'ANDROID!'
            struct.pack_into('<I', data, 8, 47000000)
            struct.pack_into('<I', data, 40, 4)
            cpu.mem_write(0x70000000, bytes(data))
        elif name == 'env':
            assert args[:5] == ['env','export','-t','-s','1000'] and args[6] == 'bootargs'
            dest = int(args[5],16)
            cpu.mem_write(dest, b'bootargs=console=ttyAS0 androidboot.verifiedbootstate=orange\n\0')
        elif name == 'setenv':
            assert args[0:2] == ['setenv', 'bootargs']
            markers.append(args[2].split('androidboot.t307_ram_adapter=')[1])
        elif name == 'bootm':
            assert args == ['bootm', '70000000']
        ret(0)
    def bad_memory(cpu, access, address, size, value, unused):
        raise RuntimeError(f'Unmapped/MMIO access: {address:#x}')
    def write(cpu, access, address, size, value, unused):
        # Firmware callbacks are mocked, so every actual ARM store must be
        # confined to this application's RAM or its stack.
        if not (APP <= address and address+size <= APP+0x10000 or STACK <= address and address+size <= STACK+0x10000):
            raise RuntimeError(f'Unexpected ARM write: {address:#x}')
        writes.append(address)
    # Intercept only firmware entry points, not millions of scan instructions.
    # The latter would test Python callback throughput rather than the ARM code.
    for address in [RETURN, *targets]:
        uc.hook_add(UC_HOOK_CODE, code, begin=address, end=address)
    uc.hook_add(UC_HOOK_MEM_INVALID, bad_memory)
    uc.hook_add(UC_HOOK_MEM_WRITE, write)
    uc.emu_start(APP + 0x60, RETURN, timeout=20000000, count=150000000)
    done = done or uc.reg_read(UC_ARM_REG_PC) in (RETURN, RETURN | 1)
    assert done, (mode, 'did not return', hex(uc.reg_read(UC_ARM_REG_PC)), commands)
    assert uc.reg_read(UC_ARM_REG_SP) == STACK + 0xff00
    assert all(uc.reg_read(reg) == value for reg,value in preserved.items())
    result = uc.reg_read(UC_ARM_REG_R0)
    expected = {'normal':0,'missing_registry':12,'ambiguous_registry':12,
                'read_failure':13,'bad_boot_header':14,'cache_signature_changed':0}[mode]
    assert result == expected, (mode, result, expected)
    if mode in ('missing_registry','ambiguous_registry'): assert commands == []
    if mode == 'normal': assert markers == ['probe_cache_ok']
    if mode == 'cache_signature_changed': assert markers == ['probe_cache_miss']
    return {'case':mode,'return':result,'commands':commands,'stack_preserved':True,
            'callee_saved_preserved':True,'stores_outside_application':0,'mocked_firmware':True}

def main():
    results = [check(case) for case in ['normal','missing_registry','ambiguous_registry',
                                      'read_failure','bad_boot_header','cache_signature_changed']]
    (OUT / 'arm-emulation.json').write_text(json.dumps(results,indent=2))
    print(json.dumps({'passed':len(results),'hardware_access':False,'cases':[r['case'] for r in results]}))

if __name__ == '__main__': main()
