import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import felro as ro
import usb_transport as usb
import winusb_backend as win
from test_felro import SimulatedUSB, HASH

PAYLOAD=b'test-only-payload'
PATH='\\\\?\\usb#vid_1f3a&pid_efe8#synthetic-only'


class WireDevice:
    """AWUC/FEL wire state machine in PC memory; never opens a handle."""
    identity=usb.USBIdentity(usb.VID,usb.PID,0,0x81,1,'synthetic')
    def __init__(self):
        self.pending=None;self.queue=[];self.current=None;self.data_write=False
        self.ram={};self.writes=[];self.commands=[];self.closed=False
        self.soc=usb.SOC_RAW;self.protocol=1;self.version_magic=b'AWUSBFEX'
        self.ack=b'AWUS'+bytes(9);self.status=bytes(8)
        self.short_write=False;self.short_read=False;self.disconnect=False;self.timeout=False
        self.bad_readback=False;self.reader_fault=None
        self.reader=SimulatedUSB()

    def write(self,data):
        if self.disconnect: raise OSError('synthetic disconnect')
        self.writes.append(bytes(data))
        if self.short_write:return len(data)-1
        if data[:8]==b'AWUC'+bytes(4):
            magic,n,constant,op,n2,pad=struct.unpack('<8sIIHI10s',data)
            assert constant==0x0C000000 and n==n2 and pad==bytes(10)
            if op==0x12:self.pending=n
            else:
                assert op==0x11
                if self.current[0]==1:
                    reply=struct.pack('<8sIIHBBI8s',self.version_magic,self.soc,1,self.protocol,0,8,0x45000,bytes(8))
                    self.current=(0,0,0,0)
                elif self.current[0]==0x103:
                    reply=self.ram[self.current[1]][:n]
                    if self.bad_readback and self.current[1]==ro.CODE:reply=bytes(n)
                    self.current=(0,0,0,0)
                else: reply=self.status
                assert len(reply)==n
                self.queue.extend([reply,self.ack])
        else:
            assert self.pending==len(data);self.pending=None
            if self.data_write:
                self.ram[self.current[1]]=data;self.data_write=False;self.current=(0,0,0,0)
            else:
                self.current=struct.unpack('<4I',data);self.commands.append(self.current)
                op,address,n,reserved=self.current
                assert reserved==0
                if op==0x101:self.data_write=True
                if op==0x102:
                    assert address==ro.CODE
                    self.reader.fault=None if self.reader_fault=='valid_error' else self.reader_fault
                    header,payload=self.reader.exchange(self.ram[ro.REQUEST_ADDR])
                    if self.reader_fault=='valid_error':
                        fields=list(ro.RESPONSE.unpack(header));fields[3]=4;fields[7]=fields[15]=fields[16]=0
                        fields[16]=ro.crc(ro.RESPONSE.pack(*fields));header=ro.RESPONSE.pack(*fields)
                    self.ram[usb.RESPONSE_ADDR]=header;self.ram[ro.DATA]=payload
            self.queue.append(self.ack)
        return len(data)

    def read(self,n):
        if self.timeout:raise TimeoutError('synthetic timeout')
        if self.disconnect:raise OSError('synthetic disconnect')
        data=self.queue.pop(0);assert len(data)==n
        return data[:-1] if self.short_read else data

    def close(self): self.closed=True


class WireTests(unittest.TestCase):
    def ready(self):
        device=WireDevice();link=usb.FelReadonly([device],HASH)
        link.identify();link.prepare_payload(PAYLOAD,usb.MemoryReview(True,'synthetic-test-fixture'))
        return device,link

    def test_version_has_no_memory_or_exec_commands(self):
        device=WireDevice();link=usb.FelReadonly([device],HASH);version=link.identify()
        self.assertEqual(version['soc_normalized'],0x1890)
        self.assertEqual(device.commands,[(1,0,0,0)])
        self.assertEqual(link.audit,[{'fel_request':1,'address':0,'length':0}])
        self.assertEqual(device.writes[0].hex(),'4157554300000000100000000000000c12001000000000000000000000000000')
        self.assertEqual(device.writes[1],b'\x01'+bytes(15))
        self.assertEqual(device.ram,{})

    def test_wrong_usb_identity_before_io(self):
        for pid in (0x1010,0xFFFF):
            d=WireDevice();d.identity=usb.USBIdentity(usb.VID,pid,0,0x81,1,'synthetic')
            with self.assertRaises(ro.Rejected):usb.FelReadonly([d],HASH)
            self.assertFalse(d.writes)

    def test_ambiguous_selection(self):
        for pipes in ([],[WireDevice(),WireDevice()]):
            with self.assertRaises(ro.Rejected):usb.FelReadonly(pipes,HASH)

    def test_unknown_soc_protocol_signature_poison(self):
        for field,value in (('soc',0x00185900),('protocol',0),('version_magic',b'INVALID!')):
            with self.subTest(field=field):
                d=WireDevice();setattr(d,field,value);link=usb.FelReadonly([d],HASH)
                with self.assertRaises(ro.Rejected):link.identify()
                before=len(d.writes)
                with self.assertRaises(ro.Rejected):link.identify()
                self.assertEqual(len(d.writes),before)

    def test_payload_gate_and_hash_before_io(self):
        d=WireDevice();link=usb.FelReadonly([d],HASH);link.identify();before=len(d.writes)
        for payload,review in ((PAYLOAD,usb.MemoryReview()),(b'wrong',usb.MemoryReview(True,'test'))):
            with self.assertRaises(ro.Rejected):link.prepare_payload(payload,review)
            self.assertEqual(len(d.writes),before)

    def test_readback_verified_before_exec(self):
        d=WireDevice();d.bad_readback=True;link=usb.FelReadonly([d],HASH);link.identify()
        with self.assertRaises(ro.Rejected):link.prepare_payload(PAYLOAD,usb.MemoryReview(True,'test'))
        self.assertFalse(any(c[0]==0x102 for c in d.commands))
        with self.assertRaises(ro.Rejected):link.exchange(ro.request(ro.INFO,1))

    def test_complete_client_protocol_pipeline(self):
        d,link=self.ready();client=ro.Client([link],HASH);identity=client.identify()
        self.assertEqual(identity[0],4096)
        self.assertEqual(client.read(100,128),d.reader.disk.read(100,128))
        self.assertTrue(all(c[0] in (1,0x101,0x102,0x103) for c in d.commands))
        writes=[(a,n) for op,a,n,_ in d.commands if op==0x101]
        self.assertTrue(all(a==ro.CODE or a==ro.REQUEST_ADDR and n==32 for a,n in writes))
        self.assertEqual(sum(op==0x102 for op,*_ in d.commands),2)

    def test_forbidden_addresses_and_operations_before_io(self):
        d,link=self.ready();before=len(d.writes)
        for op,a,n in ((0x101,0x4022018,4),(0x103,0x45000,4),(0x102,0x45000,0),
                       (0x101,ro.CODE,0x8001),(0x103,ro.DATA,65537),(0x999,0,0)):
            with self.assertRaises(ro.Rejected):link._fel(op,a,n)
        self.assertEqual(len(d.writes),before)

    def test_invalid_or_replayed_reader_request_before_io(self):
        d,link=self.ready();link.exchange(ro.request(ro.INFO,1));before=len(d.writes)
        for raw in (ro.request(ro.INFO,1),bytes(32),bytes(16)):
            with self.assertRaises(ro.Rejected):link.exchange(raw)
        self.assertEqual(len(d.writes),before)

    def test_bad_reply_does_not_read_data(self):
        for fault in ('header_crc','nonce','lba','reserved','area','bus','capacity'):
            with self.subTest(fault=fault):
                d,link=self.ready()
                d.reader_fault=fault
                with self.assertRaises(ro.Rejected):link.exchange(ro.request(ro.INFO,1))
                self.assertFalse(any(op==0x103 and a==ro.DATA for op,a,*_ in d.commands))

    def test_error_reply_does_not_read_data(self):
        d,link=self.ready();d.reader_fault='status'
        # A failed payload must publish zero data length (the simulator's
        # deliberately inconsistent error reply is rejected as malformed).
        with self.assertRaises(ro.Rejected):link.exchange(ro.request(ro.INFO,1))
        self.assertFalse(any(op==0x103 and a==ro.DATA for op,a,*_ in d.commands))

    def test_valid_payload_error_poison(self):
        d,link=self.ready();d.reader_fault='valid_error'
        header,data=link.exchange(ro.request(ro.INFO,1))
        self.assertEqual(data,b'');self.assertEqual(ro.RESPONSE.unpack(header)[3],4)
        before=len(d.commands)
        with self.assertRaises(ro.Rejected):link.exchange(ro.request(ro.INFO,2))
        self.assertEqual(len(d.commands),before)

    def test_short_transfers_timeout_disconnect_poison(self):
        for field,value in (('short_read',True),('short_write',True),('disconnect',True),('timeout',True),
                            ('ack',b'FAIL'+bytes(9)),('status',b'\x01'+bytes(7))):
            with self.subTest(field=field):
                d=WireDevice();setattr(d,field,value);link=usb.FelReadonly([d],HASH)
                with self.assertRaises((ro.Rejected,OSError)):link.identify()
                before=len(d.writes)
                with self.assertRaises(ro.Rejected):link.identify()
                self.assertEqual(len(d.writes),before)

    def test_changed_identity_and_close(self):
        d,link=self.ready();d.identity=usb.USBIdentity(usb.VID,usb.PID,0,0x81,1,'another')
        with self.assertRaises(ro.Rejected):link.exchange(ro.request(ro.INFO,1))
        link.close();self.assertTrue(d.closed)


class FakeNative:
    def __init__(self):
        self.calls=[];self.bad_descriptor=False;self.bad_pipes=False;self.fail_init=False
    def open(self,path):self.calls.append('open');return 11
    def initialize(self,file):
        self.calls.append('initialize')
        if self.fail_init:raise OSError('synthetic initialize error')
        return 22
    def descriptor(self,h):
        data=bytearray(18);data[:2]=b'\x12\x01'
        struct.pack_into('<2H',data,8,usb.VID,0x1010 if self.bad_descriptor else usb.PID)
        return bytes(data)
    def pipes(self,h):
        return 0,0,[win.PipeInfo(0x81,2,512),win.PipeInfo(1,3 if self.bad_pipes else 2,512)]
    def configure(self,h,pipe):self.calls.append(('configure',pipe))
    def write(self,h,pipe,data):self.calls.append(('write',pipe,data));return len(data)
    def read(self,h,pipe,n):self.calls.append(('read',pipe,n));return bytes(n)
    def free(self,h):self.calls.append('free')
    def close(self,h):self.calls.append('close')


class NativeBoundaryTests(unittest.TestCase):
    def test_live_gate_precedes_native_api_loading(self):
        with patch.object(win,'_NativeAPI',side_effect=AssertionError('must not load DLL')):
            with self.assertRaisesRegex(ro.Rejected,'physical USB disabled'):win.WinUSBPipe(PATH)

    def test_explicit_path_only(self):
        api=FakeNative()
        for path in ('',r'\\.\PhysicalDrive0','auto','\\\\?\\usb#vid_1f3a&pid_1010#synthetic'):
            with self.assertRaises(ro.Rejected):win.WinUSBPipe(path,_test_api=api)
        self.assertEqual(api.calls,[])

    def test_native_wrapper_with_injected_api_only(self):
        api=FakeNative();pipe=win.WinUSBPipe(PATH,_test_api=api)
        self.assertEqual(pipe.write(b'x'),1);self.assertEqual(pipe.read(3),bytes(3))
        self.assertIn(('configure',0x81),api.calls);self.assertIn(('configure',1),api.calls)
        pipe.close();pipe.close();self.assertEqual(api.calls.count('close'),1)
        with self.assertRaises(ro.Rejected):pipe.read(1)

    def test_failed_open_releases_handles(self):
        for failure in ('bad_descriptor','bad_pipes','fail_init'):
            api=FakeNative();setattr(api,failure,True)
            with self.assertRaises((ro.Rejected,OSError)):win.WinUSBPipe(PATH,_test_api=api)
            self.assertIn('close',api.calls)
            self.assertEqual('free' in api.calls,failure!='fail_init')


if __name__=='__main__':unittest.main(verbosity=2)
