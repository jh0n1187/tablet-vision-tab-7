"""Fast Windows device-tree polling ONLY: no USB handles, ADB or reboot.

Uses cfgmgr32 read APIs. Does not query a physical USB endpoint, install a
driver, request reenumeration, change device state or load tablet code.
"""
import argparse
import ctypes as c
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import time

U32=c.c_uint32
FLAGS=0x101  # CM_GETIDLIST_FILTER_ENUMERATOR | CM_GETIDLIST_FILTER_PRESENT


def device_record(instance,status,problem,configret=0,*,canonical_key=False):
    match=re.match(r'^USB\\VID_1F3A&PID_([0-9A-F]{4})(?:&|\\)',instance,re.I)
    if not match:return None
    return {'key':hashlib.sha256((instance.upper() if canonical_key else instance).encode('utf-8')).hexdigest()[:16],
            'vid':'1F3A','pid':match[1].upper(),'configret':configret,
            'devnode_status':status if configret==0 else None,
            'has_problem':bool(status&0x400) if configret==0 else None,
            'problem_code':problem if configret==0 and status&0x400 else None}


class DeviceTree:
    def __init__(self,*,canonical_keys=False):
        if os.name!='nt':raise RuntimeError('Windows-only device-tree reader')
        self.canonical_keys=canonical_keys
        self.library=c.WinDLL(str(Path(os.environ['SystemRoot'])/'System32/cfgmgr32.dll'))
        def bind(name,args):
            fn=getattr(self.library,name);fn.argtypes=args;fn.restype=U32;return fn
        p=c.POINTER(U32)
        self.size=bind('CM_Get_Device_ID_List_SizeW',[p,c.c_wchar_p,U32])
        self.list=bind('CM_Get_Device_ID_ListW',[c.c_wchar_p,c.POINTER(c.c_wchar),U32,U32])
        self.locate=bind('CM_Locate_DevNodeW',[p,c.c_wchar_p,U32])
        self.status=bind('CM_Get_DevNode_Status',[p,p,U32,U32])

    def snapshot(self):
        # Handle size races, but never loop indefinitely during USB churn.
        for attempt in range(3):
            size=U32()
            result=self.size(c.byref(size),'USB',FLAGS)
            if result:raise RuntimeError(f'CM list size: CONFIGRET {result:#x}')
            if not 1<=size.value<=1048576:raise RuntimeError('invalid ID list size')
            buffer=c.create_unicode_buffer(size.value)
            result=self.list('USB',buffer,size,FLAGS)
            if result==0x1a:continue # CR_BUFFER_SMALL
            if result:raise RuntimeError(f'CM list: CONFIGRET {result:#x}')
            raw=''.join(buffer)
            if not raw.endswith('\0\0') and raw!='\0':raise RuntimeError('unterminated MULTI_SZ')
            break
        else:raise RuntimeError('device tree changed repeatedly; no snapshot')
        records=[]
        for instance in raw.split('\0'):
            if not re.match(r'^USB\\VID_1F3A&PID_',instance,re.I):continue
            node=U32();status=U32();problem=U32()
            result=self.locate(c.byref(node),instance,0) # NORMAL: no phantom/restart/reenumeration
            if result==0:result=self.status(c.byref(status),c.byref(problem),node,0)
            record=device_record(instance,status.value,problem.value,result,canonical_key=self.canonical_keys)
            if record:records.append(record)
        return sorted(records,key=lambda item:item['key'])


def self_test():
    assert device_record(r'USB\VID_1234&PID_EFE8\TEST',0,28) is None
    record=device_record(r'USB\VID_1F3A&PID_EFE8\PRIVATE_INSTANCE',0x400,28)
    assert record['problem_code']==28 and record['has_problem']
    assert 'PRIVATE_INSTANCE' not in json.dumps(record)
    assert device_record(r'USB\VID_1F3A&PID_4EE7\TEST',8,28)['problem_code'] is None
    assert device_record(r'USB\VID_1F3A&PID_EFE8\TEST',0x400,28,0xd)['problem_code'] is None
    assert device_record(r'USB\VID_1F3A&PID_EFE8\TEST',0,0)['pid']=='EFE8'
    print('6 synthetic checks passed; no DLL/device-tree access')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--seconds',type=float,default=90)
    parser.add_argument('--interval-ms',type=float,default=10)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.self_test:self_test();return
    if not args.output or not 1<=args.seconds<=180 or not 5<=args.interval_ms<=1000:
        parser.error('output required; seconds 1..180; interval-ms 5..1000')
    # Exclusive file creation precedes any native API call; never overwrite evidence.
    with args.output.open('x',encoding='utf-8') as stream:
        tree=DeviceTree();start=time.perf_counter();previous=None;gaps=[];last=None;count=0;changes=0
        while time.perf_counter()-start<args.seconds:
            tick=time.perf_counter()
            if last is not None:gaps.append(tick-last)
            last=tick
            devices=tree.snapshot()
            state=json.dumps(devices,sort_keys=True)
            sample={'utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':tick-start,
                    'completed_seconds':time.perf_counter()-start,'devices':devices}
            stream.write(json.dumps(sample)+'\n');stream.flush();count+=1
            if state!=previous:
                print(json.dumps(sample),flush=True);changes+=1;previous=state
            time.sleep(args.interval_ms/1000)
    ordered=sorted(gaps)
    report={'samples':count,'changes':changes,'requested_interval_ms':args.interval_ms,
            'median_gap_ms':statistics.median(gaps)*1000 if gaps else None,
            'p95_gap_ms':ordered[int(.95*(len(ordered)-1))]*1000 if gaps else None,
            'max_gap_ms':max(gaps)*1000 if gaps else None,
            'device_tree_only':True,'usb_endpoints_opened':False,'reboot_sent':False}
    args.output.with_suffix('.summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report),flush=True)

if __name__=='__main__':main()
