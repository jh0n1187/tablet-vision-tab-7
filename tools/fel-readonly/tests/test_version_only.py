import ast
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import version_only as v
import version_arrival as arrival
from winusb_backend import PipeInfo

PATH = r'\\?\usb#vid_1f3a&pid_efe8#synthetic-instance#{431cd5b9-df93-4b87-b9eb-da404040f0c4}'


class MemoryPipe:
    def __init__(self, fault=None, version=None):
        self.steps = []
        self.closed = False
        self.fault = fault
        self.version = version or v.REPLY.pack(b'AWUSBFEX', v.SOC, 1, 1, 0, 8, 0x45000, bytes(8))

    def step(self, kind, value):
        index = len(self.steps)
        expected_kind, expected = v.STEPS[index]
        assert (kind == 'write') == (expected_kind == 'write')
        assert value == expected
        self.steps.append((kind, value))
        if self.fault == index:
            raise OSError('Injected disconnect/timeout')
        return expected_kind

    def write(self, data):
        self.step('write', data)
        return len(data)

    def read(self, count):
        kind = self.step('read', count)
        return self.version if kind == 'version' else bytes(8) if kind == 'status' else v.ACK

    def close(self):
        self.closed = True


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.desc = bytearray(18)
        self.desc[:2] = b'\x12\x01'
        self.desc[8:12] = b'\x3a\x1f\xe8\xef'
        self.shape = (0, 0, [PipeInfo(0x81, 2, 512), PipeInfo(2, 2, 512)])
        self.wire = MemoryPipe()

    def open(self, path): self.calls.append(('open', path)); return 0x1234567800000011
    def initialize(self, handle): self.calls.append(('initialize', handle)); return 0x8765432100000022
    def descriptor(self, handle): return bytes(self.desc)
    def pipes(self, handle): return self.shape
    def configure(self, handle, endpoint): self.calls.append(('configure', endpoint))
    def set_timeout(self, handle, endpoint, ms): self.calls.append(('timeout', endpoint, ms))
    def free(self, handle): self.calls.append(('free', handle))
    def close(self, handle): self.calls.append(('close', handle))
    def write(self, handle, endpoint, data):
        assert endpoint == 2
        return self.wire.write(data)
    def read(self, handle, endpoint, count):
        assert endpoint == 0x81
        return self.wire.read(count)


class VersionOnlyTests(unittest.TestCase):
    def test_exact_transcript_and_no_memory_request(self):
        p = MemoryPipe(); q = v.VersionOnce(p); result = q.query()
        self.assertTrue(result['compatible_a523']); self.assertTrue(p.closed)
        self.assertEqual(len(p.steps), 9)
        self.assertEqual([x for k, x in p.steps if k == 'write'],
                         [bytes.fromhex('4157554300000000100000000000000c12001000000000000000000000000000'),
                          struct.pack('<4I', 1, 0, 0, 0),
                          bytes.fromhex('4157554300000000200000000000000c11002000000000000000000000000000'),
                          bytes.fromhex('4157554300000000080000000000000c11000800000000000000000000000000')])
        with self.assertRaises(v.Rejected): q.query()
        self.assertEqual(len(p.steps), 9)

    def test_fault_at_each_transfer_is_terminal_and_closes(self):
        for index in range(9):
            with self.subTest(index=index):
                p = MemoryPipe(fault=index); q = v.VersionOnce(p)
                with self.assertRaises(OSError): q.query()
                self.assertTrue(p.closed); count = len(p.steps)
                with self.assertRaises(v.Rejected): q.query()
                self.assertEqual(len(p.steps), count)

    def test_short_reads_and_nonzero_status_ack(self):
        for target in (2, 4, 5, 7, 8):
            for short in (True, False):
                with self.subTest(target=target, short=short):
                    p = MemoryPipe(); original = p.read
                    def read(count):
                        data = original(count)
                        if len(p.steps) - 1 == target:
                            return data[:-1] if short else b'X' * count
                        return data
                    p.read = read; q = v.VersionOnce(p)
                    with self.assertRaises(v.Rejected): q.query()
                    self.assertTrue(p.closed)

    def test_short_writes_stop(self):
        for target in (0, 1, 3, 6):
            p = MemoryPipe(); original = p.write
            def write(data):
                n = original(data)
                return n - 1 if len(p.steps) - 1 == target else n
            p.write = write
            with self.assertRaises(v.Rejected): v.VersionOnce(p).query()
            self.assertTrue(p.closed); self.assertEqual(len(p.steps), target + 1)

    def test_unknown_identity_preserves_raw_and_stops(self):
        for magic, soc, protocol in ((b'NOTFEL!!', v.SOC, 1), (b'AWUSBFEX', 0x00185900, 1), (b'AWUSBFEX', v.SOC, 2)):
            raw = v.REPLY.pack(magic, soc, 1, protocol, 0, 8, 0x45000, bytes(8))
            p = MemoryPipe(version=raw)
            with self.assertRaises(v.Rejected) as ctx: v.VersionOnce(p).query()
            self.assertEqual(ctx.exception.result['raw_hex'], raw.hex()); self.assertTrue(p.closed)

    def test_deadline_stops_before_io(self):
        ticks = iter((0.0, 1.1)); p = MemoryPipe()
        with self.assertRaises(v.Rejected): v.VersionOnce(p, clock=lambda: next(ticks)).query()
        self.assertFalse(p.steps); self.assertTrue(p.closed)

    def test_live_gate_and_wrong_paths_before_api_calls(self):
        with self.assertRaises(v.Rejected): v.prepare_native(PATH)
        for path in (PATH.replace('efe8', '4ee7'), PATH.replace(v.GUID, 'a5dcbf10-6530-11d2-901f-00c04fb951ed'), '', 'file.img', PATH + '\\extra'):
            api = FakeAPI()
            with self.assertRaises(v.Rejected): v._NativeVersionPipe(path, _test_api=api)
            self.assertFalse(api.calls)

    def test_native_adapter_fake_preserves_handles_and_only_version(self):
        api = FakeAPI(); result = v.VersionOnce(v._NativeVersionPipe(PATH, _test_api=api)).query()
        self.assertTrue(result['compatible_a523'])
        self.assertEqual([x for x in api.calls if x[0] == 'timeout'], [('timeout', 2, 100), ('timeout', 0x81, 100)])
        self.assertEqual(api.calls[-2:], [('free', 0x8765432100000022), ('close', 0x1234567800000011)])

    def test_bad_native_identity_closes_without_bulk(self):
        for fault in ('descriptor', 'endpoint', 'interface'):
            api = FakeAPI()
            if fault == 'descriptor': api.desc[10:12] = b'\xe7\x4e'
            elif fault == 'endpoint': api.shape = (0, 0, [PipeInfo(0x82, 2, 512), PipeInfo(1, 2, 512)])
            else: api.shape = (1, 0, api.shape[2])
            with self.assertRaises(v.Rejected): v._NativeVersionPipe(PATH, _test_api=api)
            self.assertFalse(api.wire.steps); self.assertEqual([x[0] for x in api.calls[-2:]], ['free', 'close'])

    def test_old_incorrect_out01_profile_rejected(self):
        api = FakeAPI()
        api.shape = (0, 0, [PipeInfo(0x81, 2, 512), PipeInfo(1, 2, 512)])
        with self.assertRaises(v.Rejected) as ctx: v._NativeVersionPipe(PATH, _test_api=api)
        self.assertEqual(ctx.exception.profile['pipes'], [(1, 2, 512), (0x81, 2, 512)])
        self.assertFalse(api.wire.steps)

    def test_native_profile_matches_frozen_etw_descriptor(self):
        # USBHUB3/43, next-20261109T175710Z-160fa8ab: entire 32-byte configuration.
        raw = bytes.fromhex('0902200001010080fa0904000002ffffff000705810200020007050202000200')
        pipes = []; offset = 0
        while offset < len(raw):
            if raw[offset + 1] == 5:
                pipes.append(PipeInfo(raw[offset + 2], raw[offset + 3] & 3,
                                      int.from_bytes(raw[offset + 4:offset + 6], 'little')))
            offset += raw[offset]
        api = FakeAPI(); api.shape = (raw[11], raw[12], pipes)
        result = v.VersionOnce(v._NativeVersionPipe(PATH, _test_api=api)).query()
        self.assertTrue(result['compatible_a523'])

    def test_api_has_no_generic_fel_methods(self):
        methods = {n.name for n in ast.walk(ast.parse(Path(v.__file__).read_text(encoding='utf-8'))) if isinstance(n, ast.FunctionDef)}
        self.assertFalse(methods & {'exec', 'reset', 'load_payload', 'prepare_payload', 'read_memory', 'write_memory', 'reboot', 'flash'})

    def test_arrival_selects_only_exact_path_and_runs_once(self):
        calls = []; pipe = MemoryPipe()
        def factory(path): calls.append(path); return v.VersionOnce(pipe)
        arm = v.ArmedVersion(PATH, factory=factory)
        self.assertIsNone(arm.arrival(PATH.replace('efe8', '4ee7')))
        self.assertIsNone(arm.arrival(PATH.replace('synthetic-instance', 'other-instance')))
        self.assertFalse(calls)
        self.assertTrue(arm.arrival(PATH.upper())['compatible_a523'])
        with self.assertRaises(v.Rejected): arm.arrival(PATH)
        self.assertEqual(len(calls), 1)

    def test_failed_open_consumes_arrival_before_second_pulse(self):
        calls = []
        def fail(path): calls.append(path); raise OSError('open failed')
        arm = v.ArmedVersion(PATH, factory=fail)
        with self.assertRaises(OSError): arm.arrival(PATH)
        with self.assertRaises(v.Rejected): arm.arrival(PATH)
        self.assertEqual(len(calls), 1)

    def test_watcher_single_appearance_and_ready_before_query(self):
        events = []; snapshots = iter(([], [], [PATH]))
        class Metadata:
            def paths(self, **kwargs): return next(snapshots)
        def factory(path): events.append('query'); return v.VersionOnce(MemoryPipe())
        result = arrival.watch_once(Metadata(), PATH, factory=factory, sleep=lambda _: None,
                                    ready=lambda: events.append('ready'))
        self.assertTrue(result['compatible_a523']); self.assertEqual(events, ['ready', 'query'])

    def test_watcher_failure_does_not_wait_for_second_pulse(self):
        snapshots = iter(([], [PATH], [], [PATH])); calls = []
        class Metadata:
            def paths(self, **kwargs): return next(snapshots)
        def factory(path): calls.append(path); raise OSError('not openable')
        with self.assertRaises(OSError): arrival.watch_once(Metadata(), PATH, factory=factory)
        self.assertEqual(calls, [PATH])

    def test_watcher_gate_and_preexisting_device(self):
        class Metadata:
            calls = 0
            def paths(self, **kwargs): self.calls += 1; return [PATH]
        m = Metadata()
        with self.assertRaises(v.Rejected): arrival.watch_once(m, PATH)
        self.assertEqual(m.calls, 0)
        with self.assertRaises(v.Rejected): arrival.watch_once(m, PATH, factory=lambda _: None)
        self.assertEqual(m.calls, 1)

    def test_watcher_timeout_without_command(self):
        class Metadata:
            def paths(self, **kwargs): return []
        ticks = iter((0, 0, 2)); calls = []
        with self.assertRaises(TimeoutError):
            arrival.watch_once(Metadata(), PATH, seconds=1, clock=lambda: next(ticks),
                               sleep=lambda _: None, factory=lambda p: calls.append(p))
        self.assertFalse(calls)


if __name__ == '__main__':
    unittest.main()
