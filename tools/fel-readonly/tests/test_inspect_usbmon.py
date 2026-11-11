"""Synthetic usbmon records from published ABI; no USB/capture dependencies."""
import io
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import inspect_usbmon as p
import inspect_usbpcap as profile

DESC = bytes.fromhex('12010002000000403a1fe8efffff00000001')
REPLY = struct.pack('<8sIIHBBI8s', b'AWUSBFEX', 0x00189000, 1, 1, 0, 8, 0x45000, bytes(8))


def event(urb, kind, ep, data=b'', *, transfer=3, length=None, status=None,
          setup=None, df=None, bus=1, device=7):
    return dict(urb=urb, kind=kind, ep=ep, data=data, transfer=transfer,
                length=len(data) if length is None else length,
                status=(-115 if kind == 'S' else 0) if status is None else status,
                setup=setup, df=(0 if data else ord('<') if ep & 0x80 else ord('>')) if df is None else df,
                bus=bus, device=device)


def frames(ack=profile.ACK, descriptor=DESC, full=False):
    data = [event(1, 'S', 0x80, transfer=2, length=64, setup=bytes.fromhex('8006000100004000')),
            event(1, 'C', 0x80, descriptor, transfer=2)]
    transfers = [(2, profile.HEADER), (2, profile.VERSION), (0x81, ack)]
    if full:
        transfers += [(2, profile.READ_VERSION), (0x81, REPLY), (0x81, profile.ACK),
                      (2, profile.READ_STATUS), (0x81, bytes(8)), (0x81, profile.ACK)]
    for urb, (ep, payload) in enumerate(transfers, 10):
        data += [event(urb, 'S', ep, payload if ep == 2 else b'', length=len(payload)),
                 event(urb, 'C', ep, payload if ep == 0x81 else b'', length=len(payload))]
    return data


def pcap(records, link=220, endian='<', cut=None):
    raw = struct.pack(endian + 'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 4096, link)
    for i, r in enumerate(records):
        setup = r['setup'] or bytes(8)
        header = struct.pack(endian + 'QBBBBHBBqiiII8s', r['urb'], ord(r['kind']),
                             r['transfer'], r['ep'], r['device'], r['bus'],
                             0 if r['setup'] is not None else ord('-'), r['df'],
                             1000, i, r['status'], r['length'], len(r['data']), setup)
        if link == 220: header += bytes(16)
        body = header + r['data']
        saved = body[:-1] if i == cut else body
        raw += struct.pack(endian + 'IIII', 1000, i, len(saved), len(body)) + saved
    return raw


class UsbmonTests(unittest.TestCase):
    def analyze(self, records=None, **kwargs):
        return p.analyze(io.BytesIO(pcap(frames() if records is None else records, **kwargs)), bus=1, device=7)

    def test_both_linktypes_both_endians(self):
        for link in (189, 220):
            for endian in ('<', '>'):
                with self.subTest(link=link, endian=endian):
                    self.assertEqual(self.analyze(link=link, endian=endian)['outcome'], 'AWUS_ACK_AT_CAPTURE_LAYER')

    def test_zero_other_and_complete_version(self):
        self.assertEqual(self.analyze(frames(bytes(13)))['outcome'], 'ZERO_ACK_AT_CAPTURE_LAYER')
        self.assertEqual(self.analyze(frames(b'Z' * 13))['ack_hex'], '5a' * 13)
        self.assertTrue(self.analyze(frames(full=True))['valid_version_reply_established'])
        self.assertFalse(self.analyze()['valid_version_reply_established'])

    def test_missing_data_not_classified_as_zero(self):
        records = frames(); records[-1]['data'] = b''; records[-1]['df'] = ord('<')
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        for cut in (1, 2, 7):
            with self.assertRaises(p.InvalidCapture): self.analyze(cut=cut)

    def test_descriptor_requires_matching_control_request(self):
        records = frames(); records[0]['setup'] = bytes.fromhex('8006000200004000')
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        with self.assertRaises(p.InvalidCapture): self.analyze(frames()[1:])
        with self.assertRaises(p.InvalidCapture): self.analyze(frames()[2:])

    def test_wrong_identity_reuse_and_descriptor_after_bulk(self):
        wrong = DESC[:10] + bytes.fromhex('e74e') + DESC[12:]
        with self.assertRaises(p.InvalidCapture): self.analyze(frames(descriptor=wrong))
        records = frames() + frames(descriptor=wrong)[:2]
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        records = frames(); records = records[2:] + records[:2]
        with self.assertRaises(p.InvalidCapture): self.analyze(records)

    def test_failure_submission_error_and_short_transfer(self):
        for field, value in [('kind', 'E'), ('status', -110), ('length', 12)]:
            records = frames(); records[-1][field] = value
            with self.assertRaises(p.InvalidCapture): self.analyze(records)

    def test_correlation_missing_duplicate_and_endpoint_mismatch(self):
        records = frames(); records[-1]['urb'] = 99
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        records = frames(); records.insert(3, records[2].copy())
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        records = frames(); records[-1]['ep'] = 0x82
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        with self.assertRaises(p.InvalidCapture): self.analyze(frames()[:-1])

    def test_other_devices_not_used(self):
        records = frames(bytes(13))
        other = frames();
        for e in other: e['device'] = 8
        self.assertEqual(self.analyze(records + other)['ack_hex'], '00' * 13)

    def test_unexpected_out_payload_or_extra_commands_rejected(self):
        records = frames(); records[4]['data'] = struct.pack('<4I', 0x101, 0, 0, 0)
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        records = frames() + [event(50, 'S', 2, b'X'), event(50, 'C', 2, length=1)]
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        with self.assertRaises(p.InvalidCapture): self.analyze(frames(bytes(13), full=True))

    def test_no_payload_on_completion_out_or_submission_in(self):
        records = frames(); records[3]['data'] = b'X'; records[3]['df'] = 0
        with self.assertRaises(p.InvalidCapture): self.analyze(records)

    def test_bad_global_record_lengths_and_pcapng(self):
        for raw in (b'', b'\x0a\x0d\x0d\x0a' + bytes(20), pcap(frames(), link=249), pcap(frames())[:-1]):
            with self.assertRaises(p.InvalidCapture): p.analyze(io.BytesIO(raw), bus=1, device=7)
        raw = bytearray(pcap(frames())); struct.pack_into('<I', raw, 32, 0xffffffff)
        with self.assertRaises(p.InvalidCapture): p.analyze(io.BytesIO(raw), bus=1, device=7)

    def test_layout_against_abi_offsets(self):
        raw = pcap(frames())[40:]
        self.assertEqual(raw[8:12], b'S\x02\x80\x07')
        self.assertEqual(raw[12:16], b'\x01\x00\x00<')
        self.assertEqual(raw[32:40], struct.pack('<II', 64, 0))
        self.assertEqual(raw[40:48], bytes.fromhex('8006000100004000'))

    def test_bad_flags_and_mmapped_isodescs(self):
        records = frames(); records[-1]['df'] = ord('<')
        with self.assertRaises(p.InvalidCapture): self.analyze(records)
        raw = bytearray(pcap(frames())); struct.pack_into('<I', raw, 40 + 60, 1)
        with self.assertRaises(p.InvalidCapture): p.analyze(io.BytesIO(raw), bus=1, device=7)

    def test_completion_timing_and_overlapping_client_rejected(self):
        records = frames(); records[3], records[4] = records[4], records[3]
        with self.assertRaises(p.InvalidCapture): self.analyze(records)


if __name__ == '__main__': unittest.main()
