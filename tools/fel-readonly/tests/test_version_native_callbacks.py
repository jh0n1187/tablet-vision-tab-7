"""Windows FFI loopback in process memory. No DLL file or physical handle.

Exports use SDK signatures, WINFUNCTYPE trampolines and synthetic handles;
the actual _NativeAPI -> _NativeVersionPipe -> VersionOnce code is exercised.
"""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import version_only as v
import winusb_backend as win
from test_version_only import MemoryPipe, PATH


class MemoryDLL:
    FILE = 0x1234567800000011
    USB = 0x8765432100000022

    def __init__(self, mode='normal'):
        self.mode = mode
        self.wire = MemoryPipe()
        self.calls = []
        self.callback_errors = []
        self.keepalive = []

        def export(name, result, args, function):
            prototype = c.WINFUNCTYPE(result, *args, use_last_error=True)
            def safe(*values):
                self.calls.append((name, values[0] if values else None))
                try:
                    return function(*values)
                except BaseException as error:
                    self.callback_errors.append(repr(error)); c.set_last_error(5); return 0
            callback = prototype(safe)
            self.keepalive.append(callback)
            # A fresh call-through function crosses the real native trampoline.
            setattr(self, name, prototype(c.cast(callback, c.c_void_p).value))

        export('CreateFileW', w.HANDLE,
               [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE], self.open)
        export('CloseHandle', w.BOOL, [w.HANDLE], lambda h: int(h == self.FILE))
        export('WinUsb_Initialize', w.BOOL, [c.c_void_p, c.POINTER(c.c_void_p)], self.initialize)
        export('WinUsb_Free', w.BOOL, [c.c_void_p], lambda h: int(h == self.USB))
        export('WinUsb_GetDescriptor', w.BOOL,
               [c.c_void_p, c.c_ubyte, c.c_ubyte, c.c_ushort, c.c_void_p, w.ULONG, c.POINTER(w.ULONG)], self.descriptor)
        export('WinUsb_QueryInterfaceSettings', w.BOOL, [c.c_void_p, c.c_ubyte, c.c_void_p], self.interface)
        export('WinUsb_QueryPipe', w.BOOL, [c.c_void_p, c.c_ubyte, c.c_ubyte, c.c_void_p], self.pipe)
        export('WinUsb_SetPipePolicy', w.BOOL, [c.c_void_p, c.c_ubyte, w.ULONG, w.ULONG, c.c_void_p], self.policy)
        signature = [c.c_void_p, c.c_ubyte, c.c_void_p, w.ULONG, c.POINTER(w.ULONG), c.c_void_p]
        export('WinUsb_WritePipe', w.BOOL, signature, self.write)
        export('WinUsb_ReadPipe', w.BOOL, signature, self.read)

    def open(self, path, access, share, security, disposition, flags, template):
        assert path == PATH and access == 0xC0000000 and share == 0
        assert not security and disposition == 3 and flags == 0x40000000 and not template
        return self.FILE

    def initialize(self, file, out):
        assert file == self.FILE
        out[0] = self.USB
        return 1

    def descriptor(self, handle, kind, index, language, buffer, length, actual):
        assert handle == self.USB and (kind, index, language, length) == (1, 0, 0, 18)
        raw = bytes.fromhex('12010002000000403a1fe8efffff00000001')
        c.memmove(buffer, raw, 18); actual[0] = 18; return 1

    def interface(self, handle, alternate, out):
        assert handle == self.USB and alternate == 0
        c.memmove(out, bytes((9, 4, 0, 0, 2, 255, 255, 255, 0)), 9); return 1

    def pipe(self, handle, alternate, index, out):
        assert handle == self.USB and alternate == 0 and index in (0, 1)
        # WINUSB_PIPE_INFORMATION: type@0, id@4, max packet@6, interval@8, size12.
        raw = bytearray(12); struct.pack_into('<I', raw, 0, 2)
        raw[4] = 0x81 if index == 0 else 2; struct.pack_into('<H', raw, 6, 512)
        c.memmove(out, bytes(raw), 12); return 1

    def policy(self, handle, endpoint, policy, size, value):
        assert handle == self.USB and endpoint in (2, 0x81)
        if policy == 3:
            assert size == 4 and c.cast(value, c.POINTER(w.ULONG))[0] in (100, 5000)
        else:
            assert policy in (2, 5, 6, 7) and size == 1 and c.string_at(value, 1) == b'\0'
        return 1

    def write(self, handle, endpoint, buffer, length, actual, overlapped):
        assert handle == self.USB and endpoint == 2 and not overlapped
        actual[0] = self.wire.write(c.string_at(buffer, length)); return 1

    def read(self, handle, endpoint, buffer, length, actual, overlapped):
        assert handle == self.USB and endpoint == 0x81 and not overlapped
        if self.mode == 'timeout':
            c.set_last_error(121); return 0
        data = self.wire.read(length)
        if self.mode == 'zero': data = bytes(length)
        if self.mode != 'untouched': c.memmove(buffer, data, length)
        if self.mode != 'missing_count': actual[0] = length - 1 if self.mode == 'short' else length
        if self.mode == 'overflow': c.memmove(buffer + length, b'X', 1)
        return 1

    def api(self):
        def library(name, **kwargs):
            assert name in ('kernel32', 'winusb')
            return self
        with patch.object(c, 'WinDLL', side_effect=library): api = win._NativeAPI()
        api.diagnostics_enabled = True; api.io_trace = []
        return api


@unittest.skipUnless(os.name == 'nt', 'Windows ABI callbacks only')
class NativeCallbackTests(unittest.TestCase):
    def query(self, mode='normal'):
        dll = MemoryDLL(mode); api = dll.api()
        query = v.VersionOnce(v._NativeVersionPipe(PATH, _test_api=api))
        return dll, api, query

    def test_full_version_via_native_buffers(self):
        dll, api, query = self.query()
        result = query.query()
        self.assertTrue(result['compatible_a523']); self.assertFalse(dll.callback_errors)
        self.assertEqual(len(api.io_trace), 9)
        self.assertEqual([e['endpoint'] for e in api.io_trace], [2, 2, 0x81, 2, 0x81, 0x81, 2, 0x81, 0x81])
        self.assertEqual(api.io_trace[2]['data_prefix_hex'], v.ACK.hex())
        self.assertFalse(api.io_trace[2]['buffer_unchanged'])
        self.assertTrue(all(e.get('guard_intact', True) and e['count_written'] for e in api.io_trace))
        self.assertEqual([n for n, _ in dll.calls[-2:]], ['WinUsb_Free', 'CloseHandle'])
        self.assertEqual(api.io_trace[0]['data_prefix_hex'], v.STEPS[0][1].hex())

    def test_actual_zero_data_rejected_and_marked_modified(self):
        dll, api, query = self.query('zero')
        with self.assertRaisesRegex(v.Rejected, 'AWUS'): query.query()
        self.assertEqual(api.io_trace[-1]['data_prefix_hex'], '00' * 13)
        self.assertFalse(api.io_trace[-1]['buffer_unchanged'])
        count = len(dll.calls)
        with self.assertRaises(v.Rejected): query.query()
        self.assertEqual(len(dll.calls), count)

    def test_untouched_output_now_distinct_from_zero_response(self):
        dll, api, query = self.query('untouched')
        with self.assertRaises(v.Rejected): query.query()
        self.assertEqual(api.io_trace[-1]['data_prefix_hex'], 'a5' * 13)
        self.assertTrue(api.io_trace[-1]['buffer_unchanged'])
        self.assertFalse(dll.callback_errors)

    def test_old_zero_initialized_buffer_reproduces_false_zero_observation(self):
        dll = MemoryDLL('untouched'); api = dll.api()
        api.write(c.c_void_p(dll.USB), 2, v.STEPS[0][1])
        api.write(c.c_void_p(dll.USB), 2, v.REQUEST)
        buffer = c.create_string_buffer(13); actual = w.ULONG()
        ok = api.read_pipe(c.c_void_p(dll.USB), 0x81, buffer, 13, c.byref(actual), None)
        self.assertEqual(ok, 1); self.assertEqual(actual.value, 13)
        self.assertEqual(buffer.raw[:actual.value], bytes(13))
        self.assertFalse(dll.callback_errors)

    def test_short_count_missing_count_and_guard_overwrite(self):
        for mode in ('short', 'missing_count', 'overflow'):
            with self.subTest(mode=mode):
                dll, api, query = self.query(mode)
                with self.assertRaises((v.Rejected, win.Rejected)): query.query()
                self.assertEqual(len(api.io_trace), 3)
                self.assertFalse(dll.callback_errors)
                self.assertEqual([n for n, _ in dll.calls[-2:]], ['WinUsb_Free', 'CloseHandle'])

    def test_native_error_captured_without_retry(self):
        dll, api, query = self.query('timeout')
        with self.assertRaises(OSError): query.query()
        self.assertEqual(api.io_trace[-1]['api_return'], 0)
        self.assertEqual(api.io_trace[-1]['winerror'], 121)
        self.assertFalse(api.io_trace[-1]['count_written'])
        self.assertFalse(dll.callback_errors)

    def test_header_offsets_against_independent_packed_structure(self):
        class Reference(c.LittleEndianStructure):
            _pack_ = 1
            _fields_ = [('magic', c.c_char * 8), ('length', c.c_uint32),
                        ('constant', c.c_uint32), ('operation', c.c_uint16),
                        ('length2', c.c_uint32), ('pad', c.c_char * 10)]
        h = Reference(b'AWUC', 16, 0x0C000000, 0x12, 16, bytes(10))
        self.assertEqual(c.sizeof(h), 32); self.assertEqual(Reference.length2.offset, 18)
        self.assertEqual(bytes(h), v.STEPS[0][1])


if __name__ == '__main__': unittest.main()
