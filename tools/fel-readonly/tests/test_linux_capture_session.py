import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import linux_capture_session as s
import linux_version_only as linux
from version_only import VersionOnce, Rejected
from test_linux_version_only import Fake as FakeUSB
from test_inspect_usbmon import frames, pcap

PORT = '/sys/bus/usb/devices/1-2.3'
ANDROID = s.Arrival(1, 5, 1, '1f3a', '4ee7', True)
EFE8 = s.Arrival(1, 7, 2, '1f3a', 'efe8', True)
PENDING = s.Arrival(1, 7, 2, '1f3a', 'efe8', False)
SECOND = s.Arrival(1, 8, 3, '1f3a', 'efe8', True)
HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 4096, 220)
STATS = "Packets received/dropped on interface 'usbmon1': 20/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n"


class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now
    def sleep(self, n): self.now += n


class Monitor:
    def __init__(self, events=None):
        self.events = list([ANDROID, ANDROID, None, EFE8] if events is None else events)
        self.last = None
    def snapshot(self):
        if self.events:
            self.last = self.events.pop(0)
        if isinstance(self.last, Exception): raise self.last
        return self.last


class Capture:
    def __init__(self):
        self.calls = []
        self.readiness = [True]
        self.running = False
        self.failstart = False
        self.failstop = False
        self.result = {'clean': True, 'drops': {'known': True, 'zero_reported_drops': True}}
    def start(self):
        self.calls.append('start'); self.running = True
        if self.failstart: raise OSError('start failed halfway')
    def alive(self): return self.running
    def ready(self):
        self.calls.append('ready')
        return self.readiness.pop(0) if len(self.readiness) > 1 else self.readiness[0]
    def stop(self):
        self.calls.append('stop'); self.running = False
        if self.failstop: raise OSError('cleanup failed')
        return self.result


class Query:
    def __init__(self, calls, error=None): self.calls, self.error = calls, error
    def query(self):
        self.calls.append('query')
        if self.error: raise self.error
        return {'compatible_a523': True, 'synthetic': True}


class SessionTests(unittest.TestCase):
    def build(self, events=None, capture=None, error=None, factory=None):
        self.calls = []
        self.clock = Clock()
        self.capture = capture or Capture()
        def make(path, sysfs):
            self.calls.append(('open', path, sysfs))
            return Query(self.calls, error)
        self.session = s.Session(PORT, Monitor(events), self.capture, factory=factory or make,
                                 clock=self.clock, sleep=self.clock.sleep)
        return self.session

    def test_native_gate_precedes_resources_and_query_gate_stays_false(self):
        with patch.object(s, '_SysfsPort', side_effect=AssertionError('resource opened')):
            with self.assertRaisesRegex(Rejected, 'disabled'):
                s.prepare_native_session(PORT, '/usr/bin/dumpcap', '/tmp/unused')
        with self.assertRaises(Rejected): s._Dumpcap('/usr/bin/dumpcap', 1, '/tmp/unused')
        self.assertFalse(linux.LIVE_LINUX_VERSION_ENABLED)

    def test_success_order_ready_and_single_attempt(self):
        session = self.build()
        def ready():
            self.assertEqual(self.calls, [])
            self.assertTrue(self.capture.running)
            self.assertEqual(session.audit[-1], 'CAPTURE_READY_MONITOR_ARMED')
        report = session.run(ready=ready)
        self.assertEqual(report['query_attempts'], 1)
        self.assertEqual(report['status'], 'VERSION_RETURNED_PENDING_CAPTURE_REVIEW')
        self.assertEqual(self.calls[0], ('open', EFE8.path, PORT))
        self.assertEqual(self.capture.calls[-1], 'stop')
        with self.assertRaises(Rejected): session.run()

    def test_no_arrival_times_out_and_stops(self):
        report = self.build([ANDROID]).run(seconds=1)
        self.assertEqual(report['query_attempts'], 0)
        self.assertEqual(report['error']['type'], 'TimeoutError')
        self.assertFalse(self.capture.running)

    def test_existing_efe8_and_arrival_during_start_are_not_queried(self):
        for events in ([EFE8], [ANDROID, EFE8]):
            report = self.build(events).run()
            self.assertEqual(report['query_attempts'], 0)
            self.assertEqual(self.calls, [])

    def test_pending_metadata_becomes_ready_without_multiple_opens(self):
        report = self.build([ANDROID, ANDROID, PENDING, PENDING, EFE8]).run()
        self.assertEqual(report['query_attempts'], 1)
        self.assertEqual(len([c for c in self.calls if isinstance(c, tuple)]), 1)

    def test_first_pulse_disappearing_or_generation_changed_stops(self):
        for replacement in (None, SECOND, ANDROID):
            report = self.build([ANDROID, ANDROID, PENDING, replacement, EFE8]).run()
            self.assertEqual(report['query_attempts'], 0)
            self.assertIn('disappeared/changed', report['error']['message'])

    def test_pending_deadline_no_later_open(self):
        report = self.build([ANDROID, ANDROID, PENDING]).run()
        self.assertEqual(report['query_attempts'], 0)
        self.assertLess(self.clock.now, .2)

    def test_open_failure_consumes_arrival_and_stops(self):
        calls = []
        def fail(*args): calls.append(args); raise OSError('gone')
        report = self.build(factory=fail).run()
        self.assertEqual(report['query_attempts'], 1)
        self.assertEqual(len(calls), 1)
        self.assertFalse(self.capture.running)

    def test_query_failure_still_stops_collector(self):
        report = self.build(error=Rejected('zero ACK')).run()
        self.assertEqual(report['status'], 'INCONCLUSIVE')
        self.assertEqual(report['query_attempts'], 1)
        self.assertEqual(self.capture.calls[-1], 'stop')

    def test_real_protocol_with_fake_usb_stops_at_zero_ack(self):
        usb = FakeUSB(); usb.ack = bytes(13)
        def factory(path, sysfs):
            return VersionOnce(linux._LinuxVersionPipe(path, sysfs, _test_api=usb))
        report = self.build(factory=factory).run()
        self.assertEqual(usb.count, 3)
        self.assertEqual(report['client_io'][-1]['result'], '00' * 13)
        self.assertEqual(report['client_io'][-1]['error_type'], 'Rejected')
        self.assertFalse(linux.LIVE_LINUX_VERSION_ENABLED)
        self.assertFalse(self.capture.running)

    def test_capture_start_and_ready_timeout_cleanup(self):
        cap = Capture(); cap.failstart = True
        report = self.build(capture=cap).run()
        self.assertEqual(cap.calls, ['start', 'stop'])
        self.assertEqual(report['query_attempts'], 0)
        cap = Capture(); cap.readiness = [False]
        report = self.build(capture=cap).run()
        self.assertEqual(report['error']['type'], 'TimeoutError')
        self.assertEqual(report['query_attempts'], 0)

    def test_collector_death_prevents_query(self):
        cap = Capture()
        original = cap.ready
        def dies():
            original(); cap.running = False; return True
        cap.ready = dies
        report = self.build(capture=cap).run()
        self.assertEqual(report['query_attempts'], 0)
        self.assertIn('Collector stopped', report['error']['message'])

    def test_metadata_exception_unknown_identity_and_wrong_port(self):
        for event in (OSError('sysfs denied'), s.Arrival(1, 7, 2, 'ffff', 'ffff', True),
                      s.Arrival(2, 7, 2, '1f3a', 'efe8', True)):
            report = self.build([ANDROID, ANDROID, event]).run()
            self.assertEqual(report['query_attempts'], 0)
            self.assertFalse(self.capture.running)

    def test_drops_unknown_nonzero_unclean_and_cleanup_failure(self):
        for result in ({'clean': False, 'drops': {'zero_reported_drops': True}},
                       {'clean': True, 'drops': {'known': False}},
                       {'clean': True, 'drops': {'zero_reported_drops': False}}):
            cap = Capture(); cap.result = result
            report = self.build(capture=cap).run()
            self.assertTrue(report['status'].startswith('INCONCLUSIVE_CAPTURE'))
        cap = Capture(); cap.failstop = True
        report = self.build(capture=cap).run()
        self.assertEqual(report['status'], 'CLEANUP_FAILED')

    def test_notification_failure_and_interrupt_cleanup(self):
        session = self.build()
        def broken(): raise OSError('notification error')
        self.assertEqual(session.run(ready=broken)['query_attempts'], 0)
        session = self.build()
        def interrupt(): raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): session.run(ready=interrupt)
        self.assertFalse(self.capture.running)


class CollectorTests(unittest.TestCase):
    def test_argv_no_shell_no_global_bus_and_explicit_pcap(self):
        args = s.capture_argv('/usr/bin/dumpcap', 3, '/tmp/test')
        self.assertEqual(args[1:5], ['-i', 'usbmon3', '-F', 'pcap'])
        self.assertNotIn('usbmon0', args)
        for exe, bus in [('/tmp/dumpcap', 1), ('dumpcap; reboot', 1), ('/usr/bin/dumpcap', 0)]:
            with self.assertRaises(Rejected): s.capture_argv(exe, bus, '/tmp/test')

    def test_header_validation(self):
        self.assertTrue(s.inspect_header(HEADER))
        self.assertFalse(s.inspect_header(HEADER[:20]))
        for header in [b'\x0a\x0d\x0d\x0a' + bytes(20), HEADER[:-4] + struct.pack('<I', 249),
                       HEADER[:16] + struct.pack('<II', 64, 220)]:
            with self.assertRaises(Rejected): s.inspect_header(header)

    def test_drops_not_inferred_from_empty_log(self):
        self.assertTrue(s.drop_counters(STATS, 1)['zero_reported_drops'])
        self.assertFalse(s.drop_counters(STATS, 2)['known'])
        self.assertFalse(s.drop_counters('', 1)['zero_reported_drops'])
        self.assertFalse(s.drop_counters(STATS + STATS, 1)['known'])
        self.assertFalse(s.drop_counters(STATS.replace('20/0', '20/1').replace('pcap:0', 'pcap:1'), 1)['zero_reported_drops'])
        self.assertFalse(s.drop_counters(STATS.replace('ps_ifdrop:0', 'ps_ifdrop:1'), 1)['zero_reported_drops'])

    def collector(self, directory, process=None):
        obj = s._Dumpcap.__new__(s._Dumpcap)
        obj.argv = s.capture_argv('/usr/bin/dumpcap', 1, directory)
        obj.directory, obj.bus = Path(directory), 1
        obj.process, obj.log, obj.stopped = process, None, None
        return obj

    def test_start_with_fake_process_no_real_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'new'
            collector = self.collector(directory)
            process = Process()
            with patch('subprocess.Popen', return_value=process) as popen:
                collector.start()
                self.assertIs(popen.call_args.kwargs['shell'], False)
                self.assertEqual(popen.call_args.kwargs['env']['LC_ALL'], 'C')
            (directory / 'usbmon.pcap').write_bytes(HEADER)
            self.assertTrue(collector.ready())
            collector.log.write(STATS.encode()); collector.log.flush()
            result = collector.stop()
            self.assertTrue(result['clean'])
            self.assertTrue(result['drops']['zero_reported_drops'])
            self.assertIs(collector.stop(), result)
            self.assertEqual(process.calls, ['SIGINT', 'wait'])

    def test_preexisting_output_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = self.collector(tmp)
            with patch('subprocess.Popen', side_effect=AssertionError('spawned')):
                with self.assertRaises(FileExistsError): collector.start()

    def test_force_termination_and_kill_are_not_clean(self):
        for timeouts, expected in [(1, ['SIGINT', 'wait', 'terminate', 'wait']),
                                   (2, ['SIGINT', 'wait', 'terminate', 'wait', 'kill', 'wait'])]:
            with tempfile.TemporaryDirectory() as tmp:
                process = Process(timeouts)
                result = self.collector(tmp, process).stop()
                self.assertTrue(result['forced'])
                self.assertFalse(result['clean'])
                self.assertTrue(result['process_reaped'])
                self.assertEqual(process.calls, expected)

    def test_sysfs_reader_uses_only_temporary_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fields = dict(busnum='1', devnum='7', idVendor='1f3a', idProduct='efe8',
                          bConfigurationValue='1', speed='480', bNumConfigurations='1')
            for name, value in fields.items(): (base / name).write_text(value)
            monitor = s._SysfsPort.__new__(s._SysfsPort); monitor.path = base; monitor.bus = 1
            event = monitor.snapshot()
            self.assertTrue(event.ready)
            self.assertEqual(event.path, EFE8.path)
            (base / 'bConfigurationValue').unlink()
            self.assertFalse(monitor.snapshot().ready)
            (base / 'devnum').unlink()
            self.assertIsNone(monitor.snapshot())

    def test_offline_review_of_synthetic_closed_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / 'usbmon.pcap').write_bytes(pcap(frames(bytes(13))))
            (base / 'dumpcap.stderr').write_text(STATS)
            report = {'capture': {'clean': True, 'process_reaped': True},
                      'target': {'path': EFE8.path, 'sysfs': PORT}}
            review = s.review_files(report, base)
            self.assertTrue(review['capture_integrity_accepted'])
            self.assertFalse(review['valid_version_established'])
            self.assertEqual(review['capture_analysis']['ack_hex'], '00' * 13)
            self.assertEqual(len(review['files']['usbmon.pcap']['sha256']), 64)
            (base / 'dumpcap.stderr').write_text('no counters')
            self.assertFalse(s.review_files(report, base)['capture_integrity_accepted'])

    def test_offline_review_refuses_running_writer_or_missing_target(self):
        for report in ({'capture': {'process_reaped': False}},
                       {'capture': {'process_reaped': True}}):
            with self.assertRaises(Rejected): s.review_files(report, 'unused')


class Process:
    def __init__(self, timeouts=0): self.calls = []; self.timeouts = timeouts; self.done = False
    def poll(self): return 0 if self.done else None
    def send_signal(self, sig): self.calls.append('SIGINT')
    def terminate(self): self.calls.append('terminate')
    def kill(self): self.calls.append('kill')
    def wait(self, timeout):
        self.calls.append('wait')
        if self.timeouts:
            self.timeouts -= 1
            raise subprocess.TimeoutExpired('fake', timeout)
        self.done = True
        return 0


if __name__ == '__main__': unittest.main()
