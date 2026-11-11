"""Offline INF policy audit and Windows INF parser: never installs a driver.

Only SetupOpenInfFileW/GetLineCountW/GetLineTextW/CloseInfFile are bound.
"""
import argparse
import configparser
import ctypes as c
import hashlib
import io
import json
import os
from pathlib import Path

ROOT=Path(__file__).resolve().parent
HWID=r'USB\VID_1F3A&PID_EFE8'
GUID='{431CD5B9-DF93-4B87-B9EB-DA404040F0C4}'


def audit(text):
    ini=configparser.ConfigParser(interpolation=None,strict=True,allow_no_value=True,
                                  inline_comment_prefixes=(';',))
    ini.read_file(io.StringIO(text))
    sections={'Version','Manufacturer','Models.NTamd64.10.0','USB_Install',
              'USB_Install.HW','USB_Install.Services','DeviceInterface_AddReg','Strings'}
    if set(ini.sections())!=sections:raise ValueError('unexpected/missing INF section')
    expected={
        'Version':{'signature':'"$Windows NT$"','class':'USBDevice',
                   'classguid':'{88BAE032-5A81-49F0-BC3D-A4FF138216D6}',
                   'provider':'%ProviderName%','catalogfile':'homelab-fel-efe8.cat',
                   'driverver':'11/09/2026,1.0.0.0','pnplockdown':'1'},
        'Manufacturer':{'%providername%':'Models,NTamd64.10.0'},
        'Models.NTamd64.10.0':{'%devicename%':'USB_Install,'+HWID},
        'USB_Install':{'include':'winusb.inf','needs':'WINUSB.NT'},
        'USB_Install.HW':{'include':'winusb.inf','needs':'WINUSB.NT.HW','addreg':'DeviceInterface_AddReg'},
        'USB_Install.Services':{'include':'winusb.inf','needs':'WINUSB.NT.Services'},
        'DeviceInterface_AddReg':{('HKR,,DeviceInterfaceGUIDs,0x00010008,"'+GUID+'"').lower():None},
        'Strings':{'providername':'"Homelab local preparation"','devicename':'"Allwinner FEL 1F3A EFE8 - WinUSB"'}
    }
    for section,values in expected.items():
        if dict(ini[section])!=values:raise ValueError('INF policy mismatch: '+section)
    if '4EE7' in text.upper():raise ValueError('ADB PID must not occur in INF')
    return {'hardware_ids':[HWID],'architectures':['Windows 10/11 x64'],
            'interface_guid':GUID,'uses_inbox_driver':'winusb.inf',
            'only_registry_value':'HKR DeviceInterfaceGUIDs (REG_MULTI_SZ append)',
            'filter_driver':False}


def native_parse(path):
    if os.name!='nt':raise RuntimeError('Windows parser requires Windows')
    api=c.WinDLL(str(Path(os.environ['SystemRoot'])/'System32/setupapi.dll'),use_last_error=True)
    u32=c.c_uint32
    open_inf=api.SetupOpenInfFileW;open_inf.argtypes=[c.c_wchar_p,c.c_wchar_p,u32,c.POINTER(u32)];open_inf.restype=c.c_void_p
    close_inf=api.SetupCloseInfFile;close_inf.argtypes=[c.c_void_p];close_inf.restype=None
    count=api.SetupGetLineCountW;count.argtypes=[c.c_void_p,c.c_wchar_p];count.restype=c.c_int32
    line=api.SetupGetLineTextW;line.argtypes=[c.c_void_p,c.c_void_p,c.c_wchar_p,c.c_wchar_p,c.POINTER(c.c_wchar),u32,c.POINTER(u32)];line.restype=c.c_int32
    error_line=u32();handle=open_inf(str(path.resolve()),'USBDevice',2,c.byref(error_line))
    if handle==c.c_void_p(-1).value:raise OSError(c.get_last_error(),f'INF parser error at line {error_line.value}')
    try:
        models=count(handle,'Models.NTamd64.10.0')
        if models!=1:raise ValueError('native model count must be one')
        values={}
        for key in ('Class','ClassGuid','CatalogFile','DriverVer'):
            needed=u32()
            if not line(None,handle,'Version',key,None,0,c.byref(needed)):raise c.WinError(c.get_last_error())
            if not 1<=needed.value<=4096:raise ValueError('native INF field size')
            buf=c.create_unicode_buffer(needed.value)
            if not line(None,handle,'Version',key,buf,len(buf),c.byref(needed)):raise c.WinError(c.get_last_error())
            values[key]=buf.value
        return {'SetupAPI_opened_and_parsed':True,'model_lines':models,'version_fields':values,
                'installation_functions_bound':False,'signature_or_WDK_validation':False}
    finally:close_inf(handle)


def mutation_tests(text):
    mutations=[text.replace(HWID,r'USB\VID_1F3A&PID_4EE7'),
               text.replace(HWID,r'USB\Class_FF'),
               text.replace(HWID,r'USB\VID_1F3A*'),
               text.replace('[Strings]','[USB_Install.CoInstallers]\nCopyFiles=evil\n\n[Strings]'),
               text.replace('Needs=WINUSB.NT.Services','Needs=SomethingElse'),
               text.replace('HKR,,DeviceInterfaceGUIDs','HKLM,Software\\Global,DeviceInterfaceGUIDs'),
               text.replace('[USB_Install.HW]','[USB_Install.HW]\nUpperFilters=filter'),
               text.replace('%ProviderName%=Models,NTamd64.10.0','%ProviderName%=Models,NTamd64.10.0,NTarm64')]
    for candidate in mutations:
        try:audit(candidate)
        except (ValueError,configparser.Error):continue
        raise AssertionError('unsafe INF mutation accepted')
    return len(mutations)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',action='store_true')
    args=parser.parse_args()
    path=ROOT/'package/homelab-fel-efe8.inf';text=path.read_text(encoding='ascii')
    wdk_path=ROOT/'validation/wdk-results.json'
    wdk=json.loads(wdk_path.read_text(encoding='utf-8')) if wdk_path.exists() else None
    trust_path=ROOT/'validation/trust-import-results.json'
    trust=json.loads(trust_path.read_text(encoding='utf-8')) if trust_path.exists() else None
    stage_path=ROOT/'validation/driver-install-results.json'
    stage=json.loads(stage_path.read_text(encoding='utf-8')) if stage_path.exists() else None
    report={'policy':audit(text),'unsafe_mutations_rejected':mutation_tests(text),
            'inf_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'native_parser':native_parse(path) if args.native else None,
            'catalog_exists':(ROOT/'package/homelab-fel-efe8.cat').exists(),
            'wdk_validation':wdk,
            'installable':False,'pending':(['Inf2Cat/WDK package validation'] if wdk is None else [])+(['Authorized FEL enumeration and active PnP association validation'] if stage and stage.get('status')=='PASS' else ['Driver staging/installation authorization and PnP validation'] if trust and trust.get('status')=='PASS' else ['Catalog signing accepted by Windows policy']),
            'local_trust_verification':trust,'driver_staging_verification':stage,
            'mutation_flags_scope':'This read-only verifier invocation only',
            'driver_store_changed':False,'certificate_store_changed':False,'tablet_rebooted':False}
    (ROOT/'validation/results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
