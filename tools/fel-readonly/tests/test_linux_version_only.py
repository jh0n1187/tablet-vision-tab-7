import ctypes
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import linux_version_only as l
import version_only as v

PATH = '/dev/bus/usb/001/007'
SYSFS = '/sys/bus/usb/devices/1-2.3'
DESC = bytes.fromhex('12010002000000403a1fe8efffff00000001')
CONFIG = bytes.fromhex('0902200001010080320904000002ffffff000705020200020007058102000200')
REPLY = v.REPLY.pack(b'AWUSBFEX', v.SOC, 1, 1, 0, 8, 0x45000, bytes(8))


class Fake:
    def __init__(self):
        self.calls = []
        self.meta = (1, 7, '1f3a', 'efe8', '1', '480', '1')
        self.desc = DESC + CONFIG
        self.fault = None
        self.ack = v.ACK
        self.reply = REPLY
        self.count = 0

    def metadata(self, path):
        self.calls.append('metadata')
        return self.meta

    def open(self, path, bus, device):
        self.calls.append('open')
        if self.fault == 'open': raise OSError('not present')
        return 42

    def descriptors(self, fd): self.calls.append('descriptors'); return self.desc
    def claim(self, fd):
        self.calls.append('claim')
        if self.fault == 'claim': raise OSError('busy')
    def release(self, fd): self.calls.append('release')
    def close(self, fd): self.calls.append('close')
    def bulk(self, fd, ep, value, timeout):
        index = self.count
        self.count += 1
        self.calls.append((ep, value, timeout))
        if self.fault == index: raise OSError('timeout/disconnect')
        if self.fault == ('short', index): return len(value) - 1 if ep == 2 else b''
        if ep == 2: return len(value)
        kind = v.STEPS[index][0]
        return self.reply if kind == 'version' else bytes(8) if kind == 'status' else self.ack


class LinuxTests(unittest.TestCase):
    def pipe(self, fake=None, **kwargs):
        fake = fake or Fake()
        return l._LinuxVersionPipe(PATH, SYSFS, _test_api=fake, **kwargs)

    def test_physical_gate_precedes_all_native_preparation(self):
        with patch.object(l, '_UsbfsAPI', side_effect=AssertionError('native API constructed')):
            with self.assertRaisesRegex(v.Rejected, 'disabled'): l.prepare_linux(PATH, SYSFS)
        self.assertFalse(l.LIVE_LINUX_VERSION_ENABLED)

    def test_exact_success_and_close(self):
        api = Fake(); pipe = self.pipe(api); once = v.VersionOnce(pipe)
        self.assertTrue(once.query()['compatible_a523'])
        self.assertEqual(api.count, 9)
        self.assertEqual(api.calls[-2:], ['release', 'close'])
        self.assertTrue(all(1 <= x[2] <= 100 for x in api.calls if isinstance(x, tuple)))
        with self.assertRaises(v.Rejected): once.query()
        self.assertEqual(api.count, 9)

    def test_zero_ack_stops_after_three_transfers(self):
        api = Fake(); api.ack = bytes(13); pipe = self.pipe(api)
        with self.assertRaises(v.Rejected): v.VersionOnce(pipe).query()
        self.assertEqual(api.count, 3)
        self.assertEqual(pipe.native_io_snapshot()[-1]['result'], '00' * 13)
        with self.assertRaises(v.Rejected): pipe.read(13)

    def test_all_disconnects_short_reads_writes_close_without_retry(self):
        for index in range(9):
            for fault in (index, ('short', index)):
                with self.subTest(fault=fault):
                    api = Fake(); api.fault = fault; pipe = self.pipe(api)
                    with self.assertRaises((OSError, v.Rejected)): v.VersionOnce(pipe).query()
                    self.assertEqual(api.count, index + 1)
                    self.assertEqual(api.calls[-2:], ['release', 'close'])

    def test_arbitrary_data_read_order_and_closed_pipe_rejected(self):
        for write, data in [(True, b'payload'), (False, 13), (True, bytearray(v.STEPS[0][1]))]:
            api = Fake(); pipe = self.pipe(api)
            with self.assertRaises(v.Rejected): (pipe.write if write else pipe.read)(data)
            self.assertEqual(api.count, 0)
            self.assertTrue(pipe.closed)

    def test_wrong_identity_speed_config_before_open(self):
        for index, value in [(1, 8), (2, 'ffff'), (3, '4ee7'), (4, '0'), (5, '12'), (6, '2')]:
            api = Fake(); meta = list(api.meta); meta[index] = value; api.meta = tuple(meta)
            with self.assertRaises(v.Rejected): self.pipe(api)
            self.assertNotIn('open', api.calls)

    def test_changed_identity_after_claim_releases(self):
        api = Fake()
        original = api.metadata
        api.metadata = lambda path: original(path) if api.count == 0 and 'claim' not in api.calls else (0,)*7
        with self.assertRaises(v.Rejected): self.pipe(api)
        self.assertEqual(api.calls[-2:], ['release', 'close'])

    def test_claim_busy_does_not_detach(self):
        api = Fake(); api.fault = 'claim'
        with self.assertRaises(OSError): self.pipe(api)
        self.assertEqual(api.calls[-1], 'close')
        self.assertNotIn('release', api.calls)

    def test_bad_descriptor_and_endpoints_close_before_claim(self):
        for raw in [DESC, DESC[:-1] + b'\x02' + CONFIG, DESC + CONFIG[:-1],
                    DESC + CONFIG.replace(b'\x07\x05\x02', b'\x07\x05\x01')]:
            api = Fake(); api.desc = raw
            with self.assertRaises(v.Rejected): self.pipe(api)
            self.assertNotIn('claim', api.calls)
            self.assertEqual(api.calls[-1], 'close')

    def test_target_paths_are_explicit_and_matched(self):
        for path, sysfs in [('/dev/sda', SYSFS), (PATH, '/sys/bus/usb/devices/2-1'),
                            ('/dev/bus/usb/001/000', SYSFS), (PATH, SYSFS + '/../x')]:
            with self.assertRaises(v.Rejected): l.validate_target(path, sysfs)

    def test_deadline_prevents_transfer(self):
        ticks = iter([0, 2]); api = Fake(); pipe = self.pipe(api, clock=lambda: next(ticks))
        with self.assertRaises(v.Rejected): pipe.write(v.STEPS[0][1])
        self.assertEqual(api.count, 0)

    def test_unknown_soc_retained_but_not_accepted(self):
        api = Fake(); api.reply = v.REPLY.pack(b'AWUSBFEX', 0, 1, 1, 0, 0, 0, bytes(8))
        with self.assertRaises(v.Rejected) as error: v.VersionOnce(self.pipe(api)).query()
        self.assertFalse(error.exception.result['compatible_a523'])

    def test_arrival_consumes_even_when_open_fails(self):
        calls = []
        def factory(path, sysfs): calls.append(path); raise OSError('gone')
        armed = l.ArmedLinuxVersion(PATH, SYSFS, factory=factory)
        self.assertIsNone(armed.arrival('/dev/bus/usb/001/008', SYSFS))
        with self.assertRaises(OSError): armed.arrival(PATH, SYSFS)
        with self.assertRaises(v.Rejected): armed.arrival(PATH, SYSFS)
        self.assertEqual(len(calls), 1)

    def test_abi_offsets_and_ioctl_numbers(self):
        self.assertEqual(ctypes.sizeof(l.Bulk), 24)
        self.assertEqual(l.Bulk.timeout.offset, 8)
        self.assertEqual(l.abi_profile()['bulk_ioctl'], 0xc0185502)

    def test_native_bulk_marshalling_with_memory_only_ioctl(self):
        api = l._UsbfsAPI.__new__(l._UsbfsAPI)
        api.abi = l.abi_profile()
        calls = []
        def ioctl(fd, code, raw):
            request = l.Bulk.from_buffer_copy(raw)
            self.assertEqual((fd, code, request.timeout), (42, 0xc0185502, 100))
            calls.append(request.ep)
            if request.ep == 2:
                self.assertEqual(ctypes.string_at(request.data, request.length), v.STEPS[0][1])
            else:
                self.assertEqual(ctypes.string_at(request.data, request.length), b'\xa5' * 13)
                ctypes.memmove(request.data, v.ACK, 13)
            return request.length
        api.ioctl = ioctl
        self.assertEqual(api.bulk(42, 2, v.STEPS[0][1], 100), 32)
        self.assertEqual(api.bulk(42, 0x81, 13, 100), v.ACK)
        self.assertEqual(calls, [2, 0x81])

    def test_native_short_data_not_padded_and_guard_detected(self):
        api = l._UsbfsAPI.__new__(l._UsbfsAPI); api.abi = l.abi_profile()
        def short(fd, code, raw):
            request = l.Bulk.from_buffer_copy(raw)
            ctypes.memmove(request.data, b'abc', 3)
            return 3
        api.ioctl = short
        self.assertEqual(api.bulk(42, 0x81, 13, 100), b'abc')
        def corrupt(fd, code, raw):
            request = l.Bulk.from_buffer_copy(raw)
            ctypes.memset(request.data + request.length, 0, 1)
            return request.length
        api.ioctl = corrupt
        with self.assertRaisesRegex(v.Rejected, 'guard'): api.bulk(42, 0x81, 13, 100)

    def test_native_claim_release_use_only_interface_zero(self):
        api = l._UsbfsAPI.__new__(l._UsbfsAPI); api.abi = l.abi_profile()
        calls = []
        api.ioctl = lambda *args: calls.append(args)
        api.claim(42); api.release(42)
        self.assertEqual(calls, [(42, 0x8004550f, bytes(4)), (42, 0x80045510, bytes(4))])

    def test_libc_ioctl_signed_count_and_eintr_are_not_retried(self):
        import errno
        api = l._UsbfsAPI.__new__(l._UsbfsAPI)
        calls = []
        def success(fd, code, pointer):
            calls.append(code)
            self.assertEqual(ctypes.string_at(pointer, 4), bytes(4))
            return 32
        api._sys_ioctl = success
        self.assertEqual(api.ioctl(42, 99, bytes(4)), 32)
        def interrupted(*args):
            calls.append('EINTR'); ctypes.set_errno(errno.EINTR); return -1
        api._sys_ioctl = interrupted
        with self.assertRaises(OSError) as error: api.ioctl(42, 99, bytes(4))
        self.assertEqual(error.exception.errno, errno.EINTR)
        self.assertEqual(calls, [99, 'EINTR'])


if __name__ == '__main__': unittest.main()
