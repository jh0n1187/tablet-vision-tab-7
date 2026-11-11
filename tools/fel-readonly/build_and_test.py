"""Build and test on the PC. This script has NO device/USB commands."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parent


def run(argv):
    result=subprocess.run([str(x) for x in argv],cwd=ROOT,capture_output=True)
    if result.returncode:
        raise RuntimeError(f'PC command failed: {argv}\nstdout hex={result.stdout.hex()}\n{result.stderr.decode(errors="replace")}')
    return result.stdout


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm-bin',type=Path,required=True)
    parser.add_argument('--offline-arm',action='store_true',
                        help='also run ARM instruction emulation in WSL with prepared local dependencies')
    args=parser.parse_args(); llvm=args.llvm_bin
    out=ROOT/'build'; out.mkdir(exist_ok=True)
    compiler=llvm/'clang.exe'
    version=run([compiler,'--version']).decode().strip()
    common=['-ffreestanding','-fno-builtin','-nostdlib','-fno-stack-protector',
            '-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror','-O2',
            '-fuse-ld=lld','-Wl,--gc-sections','-Ipayload']
    sources=['payload/core.c','payload/hardware.c','payload/entry.S']
    artifacts=[]
    for name,defines in [('locked',[]),('candidate-NOT-FOR-DEVICE',['-DRO_BOARD_APPROVED=1'])]:
        elf=out/(name+'.elf'); binary=out/(name+'.bin')
        objects=[]
        for source in sources:
            obj=out/(name+'-'+Path(source).stem+'.o');objects.append(obj)
            flags=['--target=armv7a-none-eabi','-marm','-mfloat-abi=soft','-mfpu=none',
                   '-ffreestanding','-fno-builtin','-fno-stack-protector',
                   '-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror','-O2',
                   '-Ipayload',*defines]
            if source.endswith('.c'):
                flags+=['-fno-vectorize','-fno-slp-vectorize','-fstack-usage']
            run([compiler,*flags,'-c',source,'-o',obj])
        run([compiler,'--target=armv7a-none-eabi','-nostdlib','-fuse-ld=lld',
             '-Wl,--gc-sections','-Wl,-T,payload/link.ld','-Wl,-Map,'+str(out/(name+'.map')),*objects,'-o',elf])
        run([llvm/'llvm-objcopy.exe','-O','binary',elf,binary])
        for tool,suffix,opts in [('llvm-objdump.exe','.disassembly.txt',['-d']),
                                 ('llvm-readelf.exe','.headers.txt',['-h','-S','-l']),
                                 ('llvm-nm.exe','.symbols.txt',['-n'])]:
            text=run([llvm/tool,*opts,elf]); (out/(name+suffix)).write_bytes(text)
        headers=(out/(name+'.headers.txt')).read_text()
        symbols=(out/(name+'.symbols.txt')).read_text()
        if '0x20000' not in headers or '00020000 T _start' not in symbols:
            raise RuntimeError('entry point mismatch')
        if run([llvm/'llvm-nm.exe','--undefined-only',elf]).strip():
            raise RuntimeError('unresolved binary symbols')
        assembly=(out/(name+'.disassembly.txt')).read_text()
        if re.search(r'^\s*[0-9a-f]+:\s+[0-9a-f]+\s+v[a-z0-9]+\b',assembly,re.M):
            raise RuntimeError('VFP/NEON instructions require unverified processor state')
        if len(binary.read_bytes())>0x8000: raise RuntimeError('code window overflow')
        artifacts.append({'file':binary.name,'bytes':binary.stat().st_size,
                          'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
        # Sum every static frame plus assembly entry's 40 bytes: conservative
        # bound for this non-recursive candidate (call graph also reviewed).
        stack_frames=[]
        for source in ('core','hardware'):
            for line in (out/(name+'-'+source+'.su')).read_text().splitlines():
                fields=line.split('\t')
                if fields[-1]!='static': raise RuntimeError('dynamic/unbounded stack')
                stack_frames.append(int(fields[-2]))
        stack_bound=40+sum(stack_frames)
        if stack_bound>4096: raise RuntimeError('review stack budget exceeded')
        artifacts[-1]['conservative_stack_bound_bytes']=stack_bound
    # Compile the identical core for a PC Linux process using a mock card HAL.
    native=out/'payload-core-tests-linux'
    run([compiler,'--target=x86_64-unknown-linux-gnu',*common,'-DRO_SIMULATION=1',
         '-Wl,-e,_start','-static','payload/core.c','tests/payload_test.c','-o',native])
    wsl_path='/mnt/'+native.drive[0].lower()+str(native)[2:].replace('\\','/')
    c_output=run(['wsl.exe','-d','Ubuntu','--exec',wsl_path])
    if len(c_output)!=8: raise RuntimeError('invalid native test result')
    c_checks,c_failures=struct.unpack('<2I',c_output)
    if c_failures: raise RuntimeError('C payload assertions failed')
    native_locked=out/'locked-core-tests-linux'
    run([compiler,'--target=x86_64-unknown-linux-gnu',*common,'-DRO_TEST_LOCKED=1',
         '-Wl,-e,_start','-static','payload/core.c','tests/payload_test.c','-o',native_locked])
    locked_path='/mnt/'+native_locked.drive[0].lower()+str(native_locked)[2:].replace('\\','/')
    locked_checks,locked_failures=struct.unpack('<2I',run(['wsl.exe','-d','Ubuntu','--exec',locked_path]))
    if locked_failures: raise RuntimeError('default safety lock failed')
    native_hw=out/'hardware-tests-linux'
    run([compiler,'--target=x86_64-unknown-linux-gnu',*common,'-DRO_SIMULATION=1','-DRO_MMIO_TEST=1',
         '-Wl,-e,_start','-static','payload/core.c','payload/hardware.c','tests/hardware_test.c','-o',native_hw])
    hw_path='/mnt/'+native_hw.drive[0].lower()+str(native_hw)[2:].replace('\\','/')
    hardware_checks,hardware_failures=struct.unpack('<2I',run(['wsl.exe','-d','Ubuntu','--exec',hw_path]))
    if hardware_failures: raise RuntimeError('hardware model assertions failed')
    sram_audit=json.loads(run([sys.executable,ROOT/'brom_sram_audit.py']))
    arm_report=None
    if args.offline_arm:
        deps=out/'offline-deps/unicorn-linux'
        if not deps.is_dir():raise RuntimeError('run prepare_offline_deps.py first')
        def linux_path(path):return '/mnt/'+path.drive[0].lower()+str(path)[2:].replace('\\','/')
        arm_report=json.loads(run(['wsl.exe','-d','Ubuntu','--exec','python3',
                            linux_path(ROOT/'arm_offline_validation.py'),'--deps',linux_path(deps)]))
    # The native ABI fixture has no imports or entry point: only synthetic buffers.
    fixture=out/'winusb-memory-fixture.dll'
    fixture_obj=out/'winusb-memory-fixture.obj'
    run([compiler,'--target=x86_64-pc-windows-msvc','-ffreestanding','-fno-builtin',
         '-fno-stack-protector','-Wall','-Wextra','-Werror','-O2','-c',
         'tests/winusb_fixture.c','-o',fixture_obj])
    run([llvm/'ld.lld.exe','-flavor','link','/dll','/noentry','/nodefaultlib',
         '/machine:x64','/out:'+str(fixture),fixture_obj])
    imports=run([llvm/'llvm-readobj.exe','--coff-imports',fixture]).decode()
    (out/'winusb-fixture-imports.txt').write_text(imports,encoding='utf-8')
    if 'Import {' in imports: raise RuntimeError('fixture must not import OS APIs')
    old_fixture=os.environ.get('FEL_RO_NATIVE_FIXTURE')
    os.environ['FEL_RO_NATIVE_FIXTURE']=str(fixture)
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    with (out/'python-tests.txt').open('w',encoding='utf-8') as log:
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    if old_fixture is None: os.environ.pop('FEL_RO_NATIVE_FIXTURE',None)
    else: os.environ['FEL_RO_NATIVE_FIXTURE']=old_fixture
    manifest={'compiler':version,'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),
              'python':sys.version,'platform':platform.platform(),'artifacts':artifacts,
              'c_assertions':c_checks,'c_failures':c_failures,'python_tests':result.testsRun,
              'hardware_model_assertions':hardware_checks,'hardware_model_failures':hardware_failures,
              'locked_build_assertions':locked_checks,'locked_build_failures':locked_failures,
              'python_failures':len(result.failures),'python_errors':len(result.errors),
              'python_skipped':len(result.skipped),
              'native_ctypes_fixture_executed':result.testsRun>=55 and not result.skipped,
              'validation_limitations':[reason for _,reason in result.skipped],
              'native_fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),
              'brom_sram_audit':{'reference_hashes_checked':sram_audit['reference_hashes_checked'],
                                 'physical_execution_approved':False},
              'arm_emulation':None if arm_report is None else {
                  'payload_scenarios':arm_report['arm_payload_scenarios_passed'],
                  'cache_register_scenarios':arm_report['cache_register_scenarios_passed'],
                  'physical_cache_coherency_validated':False},
              'physical_usb_backend':True,'physical_usb_enabled':False,
              'native_usb_api_executed':False,'usb_enumerated':False,'tablet_commands_executed':False}
    manifest['upstream_revisions']={
        'A523-root':'6bd71e4c6181f3c6556e671794448efaa5e8a5f3',
        'xfel_reviewed_not_executed':'445e8aefe6914c85817cc9bd1d201629364b0ec6'}
    manifest['source_sha256']={str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(ROOT.rglob('*')) if p.is_file() and 'build' not in p.relative_to(ROOT).parts
        and p.suffix in ('.py','.c','.h','.S','.ld')}
    (out/'results.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(manifest,indent=2))
    if not result.wasSuccessful():
        print((out/'python-tests.txt').read_text(),file=sys.stderr); return 1
    return 0


if __name__=='__main__': sys.exit(main())
