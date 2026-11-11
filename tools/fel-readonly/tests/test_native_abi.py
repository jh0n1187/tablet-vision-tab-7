"""ctypes calls a locally built memory-only DLL, not kernel32 or WinUSB."""
import ctypes as c
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import winusb_backend as win
from felro import Rejected


class NativeCountGuardTests(unittest.TestCase):
    """Exercise Python guards with ctypes buffers, without loading any DLL."""
    def api(self):
        from ctypes import wintypes
        api=win._NativeAPI.__new__(win._NativeAPI)
        api.c=c;api.w=wintypes
        return api

    def test_descriptor_count_rejected(self):
        api=self.api()
        def reply(handle,kind,index,language,buffer,length,actual):
            c.cast(actual,c.POINTER(api.w.ULONG))[0]=19
            return 1
        api.desc=reply
        with self.assertRaises(Rejected):api.descriptor(None)

    def test_read_count_rejected(self):
        api=self.api()
        def reply(handle,pipe,buffer,length,actual,overlapped):
            c.cast(actual,c.POINTER(api.w.ULONG))[0]=length+1
            return 1
        api.read_pipe=reply
        with self.assertRaises(Rejected):api.read(None,0x81,4)

    def test_write_count_rejected(self):
        api=self.api()
        def reply(handle,pipe,buffer,length,actual,overlapped):
            c.cast(actual,c.POINTER(api.w.ULONG))[0]=length+1
            return 1
        api.write_pipe=reply
        with self.assertRaises(Rejected):api.write(None,1,b'abc')


@unittest.skipUnless(os.name=='nt' and os.environ.get('FEL_RO_NATIVE_FIXTURE'),
                     'run build_and_test.py to build the memory-only DLL')
class NativeABITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.fixture=c.WinDLL(os.environ['FEL_RO_NATIVE_FIXTURE'],use_last_error=True)
        except OSError as error:
            if getattr(error,'winerror',None)==4551:
                raise unittest.SkipTest('Windows Application Control blocked local fixture DLL (4551)') from error
            raise
        cls.fixture.TestGet.argtypes=[c.c_uint32];cls.fixture.TestGet.restype=c.c_uint64
        cls.fixture.TestFault.argtypes=[c.c_uint32];cls.fixture.TestFault.restype=None
        cls.fixture.TestReset.argtypes=[];cls.fixture.TestReset.restype=None

    def setUp(self):
        self.fixture.TestReset()
        def fake_library(name,**kwargs):
            if name not in ('kernel32','winusb'):raise AssertionError(name)
            return self.fixture
        # DLL loading for OS APIs is intercepted before _NativeAPI construction.
        with patch.object(c,'WinDLL',side_effect=fake_library): self.api=win._NativeAPI()

    def test_windows_scalar_and_struct_layouts(self):
        self.assertEqual(c.sizeof(self.api.w.ULONG),4)
        self.assertEqual(c.sizeof(self.api.w.HANDLE),8)
        self.assertEqual(c.sizeof(self.api.Interface),9)
        self.assertEqual(c.sizeof(self.api.Pipe),12)
        self.assertEqual(self.api.Pipe.pipe_id.offset,4)
        self.assertEqual(self.api.Pipe.max_packet.offset,6)
        self.assertEqual(self.api.Pipe.interval.offset,8)

    def test_64bit_handles_and_open_flags(self):
        f=self.api.open('synthetic-path');h=self.api.initialize(f)
        self.assertEqual(f,0x1234567800000011)
        self.assertEqual(h.value,0x8765432100000022)
        self.assertEqual(self.fixture.TestGet(8),f)
        self.assertEqual([self.fixture.TestGet(i) for i in (1,2,3,4,5)],
                         [0xc0000000,0,3,0x40000000,1])
        self.api.free(h);self.api.close(f)
        self.assertEqual(self.fixture.TestGet(9),h.value)
        self.assertEqual(self.fixture.TestGet(6),f)

    def test_descriptor_and_endpoint_structs(self):
        h=self.api.initialize(self.api.open('synthetic'))
        self.assertEqual(self.api.descriptor(h)[8:12],b'\x3a\x1f\xe8\xef')
        number,alt,pipes=self.api.pipes(h)
        self.assertEqual((number,alt),(0,0))
        self.assertEqual([(p.pipe_id,p.pipe_type,p.max_packet) for p in pipes],[(0x81,2,512),(1,2,512)])

    def test_policy_buffer_widths(self):
        self.api.configure(c.c_void_p(22),0x81)
        self.assertEqual(self.fixture.TestGet(16),5)
        self.assertEqual(self.fixture.TestGet(17),5000)
        self.assertEqual(self.fixture.TestGet(18),sum(1<<p for p in (2,5,6,7)))

    def test_transfer_buffers_counts_and_null_overlapped(self):
        h=c.c_void_p(0x8765432100000022)
        self.assertEqual(self.api.write(h,1,b'abc'),3)
        self.assertEqual(self.api.read(h,0x81,1024),bytes(range(256))*4)
        self.assertEqual(self.fixture.TestGet(19),h.value)
        self.assertEqual(self.fixture.TestGet(24),h.value)
        self.assertEqual(self.fixture.TestGet(22),1)
        self.assertEqual(self.fixture.TestGet(27),1)

    def test_native_error_propagation(self):
        self.fixture.TestFault(1)
        with self.assertRaises(OSError):self.api.open('synthetic')
        self.fixture.TestFault(2)
        with self.assertRaises(OSError):self.api.initialize(11)
        self.fixture.TestFault(4)
        with self.assertRaises(OSError):self.api.configure(c.c_void_p(22),1)
        self.fixture.TestFault(7)
        with self.assertRaises(OSError):self.api.read(c.c_void_p(22),0x81,4)
        with self.assertRaises(OSError):self.api.write(c.c_void_p(22),1,b'abc')

    def test_overreported_native_lengths_rejected(self):
        for fault,call in ((3,lambda:self.api.descriptor(c.c_void_p(22))),
                           (5,lambda:self.api.write(c.c_void_p(22),1,b'abc')),
                           (6,lambda:self.api.read(c.c_void_p(22),0x81,4))):
            with self.subTest(fault=fault):
                self.fixture.TestFault(fault)
                with self.assertRaises(Rejected):call()
