"""Explicit-path WinUSB pipe. No enumeration, driver installation or auto-open.

The live factory is locked in this revision. Tests inject a fake native API.
No DLL is loaded on import or when the safety gate rejects an open attempt.
"""
from dataclasses import dataclass

from felro import Rejected
from usb_transport import USBIdentity, VID, PID

LIVE_USB_ENABLED = False


@dataclass(frozen=True)
class PipeInfo:
    pipe_id: int
    pipe_type: int  # USBD_PIPE_TYPE: bulk == 2
    max_packet: int


class WinUSBPipe:
    def __init__(self, path: str, *, _test_api=None):
        if _test_api is None and not LIVE_USB_ENABLED:
            raise Rejected('physical USB disabled pending T307F review')
        if not isinstance(path,str) or not path.casefold().startswith('\\\\?\\usb#vid_1f3a&pid_efe8#'):
            raise Rejected('explicit FEL BootROM device path required')
        self._api = _test_api if _test_api is not None else _NativeAPI()
        self._file = self._handle = None
        self._closed = False
        try:
            self._file = self._api.open(path)
            self._handle = self._api.initialize(self._file)
            descriptor = self._api.descriptor(self._handle)
            if len(descriptor)!=18 or descriptor[:2]!=b'\x12\x01':
                raise Rejected('USB device descriptor')
            if (int.from_bytes(descriptor[8:10],'little'),int.from_bytes(descriptor[10:12],'little'))!=(VID,PID):
                raise Rejected('USB descriptor identity mismatch')
            interface,alt,pipes=self._api.pipes(self._handle)
            incoming=[p for p in pipes if p.pipe_type==2 and p.pipe_id&0x80]
            outgoing=[p for p in pipes if p.pipe_type==2 and not p.pipe_id&0x80]
            if interface!=0 or alt!=0 or len(pipes)!=2 or len(incoming)!=1 or len(outgoing)!=1:
                raise Rejected('ambiguous/non-bulk interface')
            if any(not 1<=p.max_packet<=1024 for p in pipes):
                raise Rejected('invalid endpoint packet size')
            self.identity=USBIdentity(VID,PID,interface,incoming[0].pipe_id,outgoing[0].pipe_id,path)
            self.identity.validate()
            self._api.configure(self._handle,self.identity.endpoint_in)
            self._api.configure(self._handle,self.identity.endpoint_out)
        except Exception:
            self.close()
            raise

    def _check(self):
        if self._closed or self._handle is None:
            raise Rejected('closed USB pipe')

    def write(self,data: bytes) -> int:
        self._check()
        if type(data) is not bytes or not 0<len(data)<=65536:
            raise Rejected('invalid bulk payload')
        return self._api.write(self._handle,self.identity.endpoint_out,data)

    def read(self,length: int) -> bytes:
        self._check()
        if type(length) is not int or not 0<length<=65536:
            raise Rejected('invalid bulk read length')
        return self._api.read(self._handle,self.identity.endpoint_in,length)

    def close(self):
        if self._closed: return
        self._closed=True
        try:
            if self._handle is not None: self._api.free(self._handle)
        finally:
            self._handle=None
            if self._file is not None:
                self._api.close(self._file); self._file=None


class _NativeAPI:
    """Small ctypes binding; constructor reached only after explicit live gate.

    No SetupDi enumeration, registry edits, reset, abort, pipe flush, descriptor
    writes, device-control request, auto-detach, permission or driver changes.
    """
    def __init__(self):
        import ctypes as c
        from ctypes import wintypes as w
        self.c,self.w=c,w
        self.kernel=c.WinDLL('kernel32',use_last_error=True)
        self.usb=c.WinDLL('winusb',use_last_error=True)
        class Interface(c.Structure):
            _pack_=1
            _fields_=[('length',c.c_ubyte),('type',c.c_ubyte),('number',c.c_ubyte),
                      ('alternate',c.c_ubyte),('count',c.c_ubyte),('cls',c.c_ubyte),
                      ('subclass',c.c_ubyte),('protocol',c.c_ubyte),('index',c.c_ubyte)]
        class Pipe(c.Structure):
            _fields_=[('pipe_type',c.c_int),('pipe_id',c.c_ubyte),
                      ('max_packet',c.c_ushort),('interval',c.c_ubyte)]
        self.Interface,self.Pipe=Interface,Pipe
        def bind(dll,name,args,result=w.BOOL):
            fn=getattr(dll,name);fn.argtypes=args;fn.restype=result;return fn
        self.create=bind(self.kernel,'CreateFileW',[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE],w.HANDLE)
        self.close_file=bind(self.kernel,'CloseHandle',[w.HANDLE])
        self.init=bind(self.usb,'WinUsb_Initialize',[w.HANDLE,c.POINTER(c.c_void_p)])
        self.release=bind(self.usb,'WinUsb_Free',[c.c_void_p])
        self.desc=bind(self.usb,'WinUsb_GetDescriptor',[c.c_void_p,c.c_ubyte,c.c_ubyte,c.c_ushort,c.c_void_p,w.ULONG,c.POINTER(w.ULONG)])
        self.query=bind(self.usb,'WinUsb_QueryInterfaceSettings',[c.c_void_p,c.c_ubyte,c.POINTER(Interface)])
        self.query_pipe=bind(self.usb,'WinUsb_QueryPipe',[c.c_void_p,c.c_ubyte,c.c_ubyte,c.POINTER(Pipe)])
        self.policy=bind(self.usb,'WinUsb_SetPipePolicy',[c.c_void_p,c.c_ubyte,w.ULONG,w.ULONG,c.c_void_p])
        signature=[c.c_void_p,c.c_ubyte,c.c_void_p,w.ULONG,c.POINTER(w.ULONG),c.c_void_p]
        self.read_pipe=bind(self.usb,'WinUsb_ReadPipe',signature)
        self.write_pipe=bind(self.usb,'WinUsb_WritePipe',signature)

    def _ok(self,result):
        if not result: raise self.c.WinError(self.c.get_last_error())

    def open(self,path):
        # OPEN_EXISTING, overlapped-capable handle as required by WinUSB.
        h=self.create(path,0xC0000000,0,None,3,0x40000000,None)
        if h==self.c.c_void_p(-1).value: raise self.c.WinError(self.c.get_last_error())
        return h

    def initialize(self,file):
        handle=self.c.c_void_p();self._ok(self.init(file,self.c.byref(handle)));return handle

    def descriptor(self,handle):
        data=self.c.create_string_buffer(18);actual=self.w.ULONG()
        self._ok(self.desc(handle,1,0,0,data,18,self.c.byref(actual)))
        if actual.value!=18:raise Rejected('native descriptor length mismatch')
        return data.raw[:actual.value]

    def pipes(self,handle):
        desc=self.Interface();self._ok(self.query(handle,0,self.c.byref(desc)))
        result=[]
        for i in range(desc.count):
            p=self.Pipe();self._ok(self.query_pipe(handle,0,i,self.c.byref(p)))
            result.append(PipeInfo(p.pipe_id,p.pipe_type,p.max_packet))
        return desc.number,desc.alternate,result

    def set_timeout(self,handle,pipe,ms):
        value=self.w.ULONG(ms)
        self._ok(self.policy(handle,pipe,3,self.c.sizeof(value),self.c.byref(value)))

    def configure(self,handle,pipe):
        self.set_timeout(handle,pipe,5000)
        # Host-side policies only. Do not clear/reset stalls or retain excess
        # packets silently. No device-control request is issued here.
        for policy in (2,5,6,7):
            value=self.c.c_ubyte(0)
            self._ok(self.policy(handle,pipe,policy,1,self.c.byref(value)))

    def write(self,handle,pipe,data):
        import time
        buffer=self.c.create_string_buffer(data);actual=self.w.ULONG(0xFFFFFFFF)
        start=time.perf_counter();result=None
        try:
            result=self.write_pipe(handle,pipe,buffer,len(data),self.c.byref(actual),None)
            error=self.c.get_last_error() if not result else None
            if not result:raise self.c.WinError(error)
            if actual.value>len(data):raise Rejected('native write count exceeds buffer')
            return actual.value
        finally:
            if getattr(self,'diagnostics_enabled',False):
                self.io_trace.append({'api':'WinUsb_WritePipe','endpoint':pipe,
                    'requested':len(data),'actual':actual.value,'api_return':result,
                    'elapsed_ms':(time.perf_counter()-start)*1000,
                    'data_prefix_hex':data[:64].hex(),'count_written':actual.value!=0xFFFFFFFF,
                    'winerror':locals().get('error')})

    def read(self,handle,pipe,length):
        import time
        # An untouched output buffer must not masquerade as a zero ACK.
        # The trailing guard is host memory only; BufferLength stays unchanged.
        initial=b'\xA5'*length;guard=b'\xD3'*16
        buffer=self.c.create_string_buffer(initial+guard,length+len(guard))
        actual=self.w.ULONG(0xFFFFFFFF);start=time.perf_counter();result=None
        try:
            result=self.read_pipe(handle,pipe,buffer,length,self.c.byref(actual),None)
            error=self.c.get_last_error() if not result else None
            if not result:raise self.c.WinError(error)
            if actual.value>length:raise Rejected('native read count exceeds buffer')
            if buffer.raw[length:]!=guard:raise Rejected('native read modified buffer guard')
            return buffer.raw[:actual.value]
        finally:
            if getattr(self,'diagnostics_enabled',False):
                self.io_trace.append({'api':'WinUsb_ReadPipe','endpoint':pipe,
                    'requested':length,'actual':actual.value,'api_return':result,
                    'elapsed_ms':(time.perf_counter()-start)*1000,
                    'data_prefix_hex':buffer.raw[:min(actual.value,length,64)].hex(),
                    'initial_fill_hex':'a5','buffer_unchanged':buffer.raw[:length]==initial,
                    'guard_intact':buffer.raw[length:]==guard,
                    'count_written':actual.value!=0xFFFFFFFF,'winerror':locals().get('error')})

    def free(self,handle): self._ok(self.release(handle))
    def close(self,file): self._ok(self.close_file(file))
