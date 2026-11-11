import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import session as s
import arrival_bridge as bridge


PROFILE = {'busid': '1-2', 'hardware_id': '1f3a:efe8', 'gateway': '172.26.160.1',
           'guest_ip': '172.26.161.170', 'usbip_sha256': 'a' * 64,
           'nonce': 'b' * 32, 'efe8_key': 'c' * 16, 'normal_key': 'd' * 16}


def ports(state=4, local='0-0'):
    rows = ['hub port sta spd dev sockfd local_busid']
    for i in range(16):
        active = i == 0 and state != 4
        rows.append(f'{"hs" if i < 8 else "ss"} {i:04d} {state if active else 4:03d} '
                    f'{3 if active else 0:03d} 00010002 000000 {local if active else "0-0"}')
    return s.parse_ports('\n'.join(rows))


class SafetyTests(unittest.TestCase):
    def test_windows_instance_case_is_canonicalized_without_accepting_other_ports(self):
        from pnp_fast_capture import device_record
        upper = r'USB\VID_1F3A&PID_EFE8\5&551BC54&0&2'
        lower = r'USB\VID_1F3A&PID_EFE8\5&551bc54&0&2'
        a = device_record(upper, 0, 0, canonical_key=True)
        b = device_record(lower, 0, 0, canonical_key=True)
        self.assertEqual(a['key'], b['key'])
        self.assertEqual(a['key'], '8315dd560054876e')
        self.assertNotEqual(device_record(lower, 0, 0)['key'], a['key'])
        other = device_record(upper[:-1] + '3', 0, 0, canonical_key=True)
        self.assertNotEqual(other['key'], a['key'])

    def test_preview_never_calls_subprocess_or_usb(self):
        with patch.object(s.subprocess, 'run', side_effect=AssertionError('subprocess')), \
                patch.object(s.version, 'prepare_linux', side_effect=AssertionError('USB')):
            result = s.plan(PROFILE)
            self.assertFalse(result['physical_enabled'])
            self.assertIn('--hardware-id', result['policy_add'])

    def test_wrong_pid_port_or_network_rejected(self):
        for field, value in [('hardware_id', '1f3a:4ee7'), ('busid', '1-8'),
                             ('gateway', '192.168.1.1'), ('guest_ip', '172.26.161.171')]:
            with self.subTest(field=field):
                p = dict(PROFILE, **{field: value})
                with self.assertRaises(s.Rejected):
                    s.plan(p)

    def test_explicit_execution_guard_precedes_environment_access(self):
        with patch.object(s.Path, 'read_text', side_effect=AssertionError('file access')):
            with self.assertRaises(s.Rejected):
                s.run_once(PROFILE, '.', execute=False)

    def test_stale_wrong_target_future_and_foreign_run_triggers_rejected(self):
        t = {'nonce': PROFILE['nonce'], 'key': PROFILE['efe8_key'], 'pid': 'EFE8', 'time': 100.0}
        s.validate_trigger(t, PROFILE, 100.1)
        for now, changes in [(101., {}), (99., {}), (100.1, {'pid': '4EE7'}),
                             (100.1, {'nonce': '0' * 32}), (100.1, {'key': '0' * 16})]:
            with self.assertRaises(s.Rejected):
                s.validate_trigger(dict(t, **changes), PROFILE, now)

    def test_empty_and_own_high_speed_port(self):
        self.assertIsNone(s.owned_port(ports(), lambda _: '', PROFILE))
        row = s.owned_port(ports(6, '1-1'), lambda _: '172.26.160.1 3240 1-2\n', PROFILE)
        self.assertEqual(row['port'], 0)

    def test_foreign_owner_or_bus_rejected(self):
        for record in ['172.26.160.1 3240 1-8', '192.168.1.1 3240 1-2']:
            with self.assertRaises(s.Rejected):
                s.owned_port(ports(6, '1-1'), lambda _: record, PROFILE)
        with self.assertRaises(s.Rejected):
            s.owned_port(ports(6, '2-1'), lambda _: '172.26.160.1 3240 1-2', PROFILE)

    def test_ambiguous_ports_rejected(self):
        rows = ports(6, '1-1')
        rows[1].update(state=6, speed=3, local='1-2')
        with self.assertRaises(s.Rejected):
            s.owned_port(rows, lambda _: '172.26.160.1 3240 1-2', PROFILE)

    def test_query_gate_restored_after_open_failure(self):
        def failed(*args):
            self.assertTrue(s.version.LIVE_LINUX_VERSION_ENABLED)
            raise OSError('simulated failure before opening')
        with patch.object(s.version, 'prepare_linux', side_effect=failed) as factory:
            result = s.query_once('/dev/bus/usb/001/002', '/sys/bus/usb/devices/1-1')
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(result['state'], 'QUERY_FAILED')
        self.assertFalse(s.version.LIVE_LINUX_VERSION_ENABLED)

    def test_query_gate_restored_after_protocol_failure_and_audit_retained(self):
        class Query:
            audit = [{'received_hex': '00' * 13}]
            def query(self):
                raise s.Rejected('simulated zero ACK')
            def native_io_snapshot(self):
                return self.audit
        with patch.object(s.version, 'prepare_linux', return_value=Query()) as factory:
            result = s.query_once('/dev/bus/usb/001/002', '/sys/bus/usb/devices/1-1')
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(result['native_io'][0]['received_hex'], '00' * 13)
        self.assertFalse(s.version.LIVE_LINUX_VERSION_ENABLED)

    def test_adb_never_triggers(self):
        self.assertIsNone(bridge.select_arrival([{'pid': '4EE7'}], PROFILE))

    def test_pnp_problem_or_wrong_instance_never_triggers(self):
        good = {'pid': 'EFE8', 'key': PROFILE['efe8_key'], 'configret': 0, 'has_problem': False}
        self.assertEqual(bridge.select_arrival([good], PROFILE), good)
        for value in [dict(good, has_problem=True), dict(good, configret=13), dict(good, key='0' * 16)]:
            with self.assertRaises(s.Rejected):
                bridge.select_arrival([value], PROFILE)
        with self.assertRaises(s.Rejected):
            bridge.select_arrival([good, good], PROFILE)

    def simulated_session(self, *, import_timeout=False, protocol_failure=False):
        """Exercise orchestration with files/fake USBIP; no native device API."""
        p = dict(PROFILE, usbip_sha256=hashlib.sha256(b'reviewed-client-fixture').hexdigest())
        original_read = Path.read_text
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            status = directory / 'status'
            def text_for(state):
                return 'hub port sta spd dev sockfd local_busid\n' + '\n'.join(
                    f'{"hs" if r["port"] < 8 else "ss"} {r["port"]} {r["state"]} {r["speed"]} '
                    f'{r["devid"]} {r["socket"]} {r["local"]}' for r in ports(state, '1-1'))
            status.write_text(text_for(4))
            def read(path, *args, **kwargs):
                if path.as_posix() == '/proc/sys/kernel/osrelease':
                    return 'test-microsoft-WSL2'
                if path.as_posix() == '/run/vhci_hcd/port0':
                    return '172.26.160.1 3240 1-2\n'
                if path.as_posix() == '/sys/bus/usb/devices/1-1/devnum':
                    return '2'
                return original_read(path, *args, **kwargs)
            def wait(_):
                trigger = {'nonce': p['nonce'], 'key': p['efe8_key'], 'pid': 'EFE8', 'time': time.time()}
                (directory / 'trigger.json').write_text(json.dumps(trigger))
            commands = []
            def command(argv, **kwargs):
                commands.append(argv)
                status.write_text(text_for(6 if argv[1] == 'attach' else 4))
                if argv[1] == 'attach' and import_timeout:
                    raise subprocess.TimeoutExpired(argv, 2)
                return subprocess.CompletedProcess(argv, 0, 'simulated', '')
            query_result = {'state': 'QUERY_FAILED' if protocol_failure else 'VERSION_RECEIVED'}
            with patch.object(s, 'STATUS', status), patch.object(s.sys, 'platform', 'linux'), \
                    patch.object(os, 'geteuid', return_value=0, create=True), \
                    patch.object(Path, 'read_text', read), \
                    patch.object(Path, 'read_bytes', return_value=b'reviewed-client-fixture'), \
                    patch.object(s.time, 'sleep', side_effect=wait), \
                    patch.object(s.subprocess, 'run', side_effect=command), \
                    patch.object(s, 'query_once', return_value=query_result) as query:
                result = s.run_once(p, directory, execute=True)
            self.assertEqual([cmd[1] for cmd in commands], ['attach', 'detach'])
            self.assertTrue(result['ports_empty_final'])
            self.assertFalse(result['physical_gate_final'])
            self.assertEqual(result['imports'], 1)
            self.assertEqual(query.call_count, 0 if import_timeout else 1)
            with self.assertRaises(s.Rejected):
                s.run_once(p, directory, execute=False)
            return result

    def test_full_simulated_session_import_query_and_owned_detach(self):
        result = self.simulated_session()
        self.assertEqual(result['state'], 'VERSION_RECEIVED')
        self.assertEqual(result['queries'], 1)

    def test_timeout_after_kernel_attach_still_detaches_without_query_or_retry(self):
        result = self.simulated_session(import_timeout=True)
        self.assertEqual(result['queries'], 0)
        self.assertEqual(result['state'], 'STOPPED')

    def test_protocol_failure_does_not_repeat_import_or_query(self):
        result = self.simulated_session(protocol_failure=True)
        self.assertEqual(result['queries'], 1)
        self.assertEqual(result['state'], 'QUERY_FAILED')


if __name__ == '__main__':
    unittest.main()
