import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_linux_validation as n
from version_only import Rejected
from test_inspect_usbmon import frames, pcap, DESC
from test_linux_capture_session import Clock, STATS

PORT = '/sys/bus/usb/devices/1-2.3'
VID, PID = '1234', '5678'
TEST_DESC = DESC[:8] + bytes.fromhex('34127856') + DESC[12:]


class NativePreparationTests(unittest.TestCase):
    def test_preview_does_not_read_metadata_or_start_anything(self):
        with patch.object(n, '_metadata', side_effect=AssertionError('metadata read')):
            result = n.plan(PORT, VID, PID)
        self.assertTrue(result['preview_only'])
        self.assertFalse(any(result['physical_gates'].values()))
        self.assertEqual(result['version_commands_to_test_device'], 0)

    def test_tablet_identity_and_ambiguous_targets_rejected(self):
        for vid, pid in [('1f3a', '5678'), ('1234', 'EFE8'), ('1234', '4ee7'),
                         ('0000', '0000'), ('123', '5678'), ('1234;', '5678')]:
            with self.assertRaises(Rejected): n.plan(PORT, vid, pid)
        with self.assertRaises(Rejected): n.plan('/sys/bus/usb/devices/usb1', VID, PID)

    def test_native_modes_reject_windows_and_wsl(self):
        for host, release in [('win32', 'Windows'), ('linux', '6.6-microsoft-standard-WSL2')]:
            with patch.object(n.sys, 'platform', host), patch.object(n.platform, 'release', return_value=release):
                with self.assertRaises(Rejected): n.native_host()
                with self.assertRaises(Rejected): n.libc_null_probe()

    def test_changed_gate_stops_validation(self):
        with patch.object(n.linux, 'LIVE_LINUX_VERSION_ENABLED', True):
            with self.assertRaises(Rejected): n.gates()

    def test_observation_timing_with_synthetic_arrival(self):
        clock = Clock(); values = iter([None, None, {'bus':1,'device':7,'vid':VID,'pid':PID}])
        result = n.observe_test(PORT, VID, PID, snapshot=lambda:next(values), clock=clock, sleep=clock.sleep)
        self.assertEqual(result['arrival']['device'], 7)
        self.assertEqual(result['version_commands_sent'], 0)
        self.assertEqual(result['max_observed_gap_ms'], 5)
        self.assertFalse(result['transient_pulse_detection_proven'])

    def test_observation_timeout_existing_device_and_invalid_duration(self):
        clock = Clock()
        result = n.observe_test(PORT, VID, PID, seconds=1, snapshot=lambda:None, clock=clock, sleep=clock.sleep)
        self.assertIsNone(result['arrival'])
        with self.assertRaises(Rejected): n.observe_test(PORT, VID, PID, snapshot=lambda:{'device':7})
        with self.assertRaises(Rejected): n.observe_test(PORT, VID, PID, seconds=100, snapshot=lambda:None)

    def test_actual_shared_metadata_reader_on_temporary_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for key, value in dict(busnum='1',devnum='7',idVendor=VID,idProduct=PID,
                                   bConfigurationValue='1',speed='480',bNumConfigurations='1').items():
                (base/key).write_text(value)
            original=n.session.port_snapshot
            with patch.object(n.session, 'port_snapshot', side_effect=lambda path,bus: original(base,bus)):
                result = n._metadata(PORT, VID, PID)
                self.assertTrue(result['reviewed_480Mbps_configuration_ready'])
                with self.assertRaises(Rejected): n._metadata(PORT,'9876',PID)

    def review(self, records, text=STATS):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); (base/'test.pcap').write_bytes(pcap(records)); (base/'stderr').write_text(text)
            return n.review_test_capture(base/'test.pcap',base/'stderr',bus=1,device=7,vid=VID,pid=PID)

    def test_known_test_descriptor_and_zero_loss(self):
        result=self.review(frames(descriptor=TEST_DESC)[:2])
        self.assertTrue(result['passive_capture_bytes_and_zero_loss'])
        self.assertFalse(result['FEL_VERSION_validated_on_hardware'])

    def test_capture_unknown_loss_or_nonzero_loss_inconclusive(self):
        result=self.review(frames(descriptor=TEST_DESC)[:2],text='')
        self.assertFalse(result['passive_capture_bytes_and_zero_loss'])
        result=self.review(frames(descriptor=TEST_DESC)[:2],text=STATS.replace('20/0','20/1').replace('pcap:0','pcap:1'))
        self.assertFalse(result['passive_capture_bytes_and_zero_loss'])

    def test_wrong_identity_missing_descriptor_failed_or_truncated_data_rejected(self):
        for records in [frames()[:2], frames(descriptor=TEST_DESC)[:1], [],
                        frames(descriptor=TEST_DESC[:8])[:2]]:
            with self.assertRaises(ValueError): self.review(records)
        records=frames(descriptor=TEST_DESC)[:2]; records[-1]['status']=-110
        with self.assertRaises(ValueError): self.review(records)

    def test_passive_capture_rejects_fel_commands(self):
        with self.assertRaisesRegex(ValueError, 'FEL traffic'):
            self.review(frames(descriptor=TEST_DESC))

    def test_passive_coordination_with_fake_collector_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)/'new'; calls=[]
            class Collector:
                def __init__(self,*args): pass
                def start(self):
                    calls.append('start'); base.mkdir()
                    (base/'usbmon.pcap').write_bytes(pcap(frames(descriptor=TEST_DESC)[:2]))
                    (base/'dumpcap.stderr').write_text(STATS)
                def ready(self): return True
                def alive(self): return True
                def stop(self):
                    calls.append('stop'); return {'clean':True,'process_reaped':True}
            item={'bus':1,'device':7,'vid':VID,'pid':PID}
            with patch.object(n,'native_host',return_value={}), patch.object(n,'_PassiveTestCollector',Collector), \
                 patch.object(n,'_metadata',side_effect=[None,None,None,item]), patch.object(n.time,'sleep'):
                result=n.capture_test(PORT,VID,PID,'/usr/bin/dumpcap',base,ready=lambda:calls.append('ready'))
            self.assertEqual(calls,['start','ready','stop'])
            self.assertTrue(result['test_capture_accepted'])
            self.assertEqual(result['VERSION_commands_sent'],0)
            self.assertTrue((base/'test-result.json').is_file())

    def test_passive_start_failure_still_calls_cleanup(self):
        calls=[]
        class Collector:
            def __init__(self,*args): pass
            def start(self): raise OSError('fake start failure')
            def stop(self): calls.append('stop'); return {'clean':False,'process_reaped':False}
        with patch.object(n,'native_host',return_value={}), patch.object(n,'_PassiveTestCollector',Collector), \
             patch.object(n,'_metadata',return_value=None):
            result=n.capture_test(PORT,VID,PID,'/usr/bin/dumpcap','not-created')
        self.assertFalse(result['test_capture_accepted'])
        self.assertEqual(calls,['stop'])


if __name__=='__main__': unittest.main()
