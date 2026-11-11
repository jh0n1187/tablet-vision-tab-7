"""Synthetic classic-pcap fixtures. No live USB/capture dependencies."""
import io
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import inspect_usbpcap as p

DESC = bytes.fromhex('12010002000000403a1fe8efffff00000001')


def usb(irp, endpoint, data=b'', *, info=0, status=0, device=7, bus=1,
        transfer=3, function=9, declared=None):
    extra = b'\x03' if transfer == 2 else b''
    # Published USBPcap header: 27 bytes, little-endian; control adds a stage byte.
    header = struct.pack('<HQIHBHHBBI', 27 + len(extra), irp, status, function,
                         info, bus, device, endpoint, transfer,
                         len(data) if declared is None else declared)
    return header + extra + data


def capture(ack=p.ACK, *, descriptor=DESC, command=p.VERSION):
    return [usb(1, 0x80, descriptor, info=1, transfer=2, function=11),
            usb(10, 2, p.HEADER), usb(10, 2, info=1),
            usb(11, 2, command), usb(11, 2, info=1),
            usb(12, 0x81, declared=512), usb(12, 0x81, ack, info=1)]


def pcap(frames, *, link=249, snaplen=4096, cut=None):
    raw = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, snaplen, link)
    for i, frame in enumerate(frames):
        saved = frame if cut is None or i != cut else frame[:27]
        raw += struct.pack('<IIII', 1000, i, len(saved), len(frame)) + saved
    return raw


class InspectTests(unittest.TestCase):
    def analyze(self, frames, **kwargs):
        return p.analyze(io.BytesIO(pcap(frames, **kwargs)), bus=1, device=7)

    def test_awus_and_zero_payload_are_distinguished(self):
        self.assertEqual(self.analyze(capture())['outcome'], 'AWUS_ACK_AT_CAPTURE_LAYER')
        zero = self.analyze(capture(bytes(13)))
        self.assertEqual(zero['outcome'], 'ZERO_ACK_AT_CAPTURE_LAYER')
        self.assertFalse(zero['valid_version_reply_established'])
        self.assertEqual(zero['ack_hex'], '00' * 13)

    def test_other_ack_retained_without_accepting(self):
        report = self.analyze(capture(b'Z' * 13))
        self.assertEqual(report['outcome'], 'OTHER_ACK_AT_CAPTURE_LAYER')
        self.assertEqual(report['ack_hex'], '5a' * 13)

    def test_missing_or_truncated_payload_not_interpreted_as_zero(self):
        with self.assertRaises(p.InvalidCapture): self.analyze(capture(), cut=6)
        frames = capture(); frames[-1] = usb(12, 0x81, info=1, declared=13)
        with self.assertRaises(p.InvalidCapture): self.analyze(frames)

    def test_requires_matching_captured_vid_pid(self):
        for descriptor in (b'', DESC[:10] + b'\xe7\x4e' + DESC[12:]):
            with self.assertRaises(p.InvalidCapture): self.analyze(capture(descriptor=descriptor))
        with self.assertRaises(p.InvalidCapture): self.analyze(capture()[1:])

    def test_address_reuse_with_conflicting_descriptor_rejected(self):
        frames = capture() + [usb(90, 0x80, DESC[:10] + b'\xe7\x4e' + DESC[12:], info=1, transfer=2)]
        with self.assertRaises(p.InvalidCapture): self.analyze(frames)

    def test_wrong_out_bytes_or_memory_request_rejected(self):
        for command in (struct.pack('<4I', 0x101, 0x20000, 4, 0), p.VERSION[:-1]):
            with self.assertRaises(p.InvalidCapture): self.analyze(capture(command=command))
        frames = capture(); frames[1] = usb(10, 2, b'X' * 32)
        with self.assertRaises(p.InvalidCapture): self.analyze(frames)

    def test_failed_usb_completion_rejected_even_with_awus(self):
        frames = capture(); frames[-1] = usb(12, 0x81, p.ACK, info=1, status=0xC0000001)
        with self.assertRaises(p.InvalidCapture): self.analyze(frames)

    def test_irp_mismatch_and_duplicate_rejected(self):
        frames = capture(); frames[-1] = usb(99, 0x81, p.ACK, info=1)
        with self.assertRaises(p.InvalidCapture): self.analyze(frames)
        frames = capture(); frames.insert(2, frames[1])
        with self.assertRaises(p.InvalidCapture): self.analyze(frames)

    def test_incomplete_capture_rejected(self):
        with self.assertRaises(p.InvalidCapture): self.analyze(capture()[:-1])

    def test_foreign_device_packets_not_used(self):
        frames = capture(bytes(13)) + [usb(100, 0x81, p.ACK, info=1, device=8)]
        self.assertEqual(self.analyze(frames)['ack_hex'], '00' * 13)

    def test_irp_address_reuse_after_completion_allowed(self):
        frames = capture()
        for i in (3, 4):
            blob = bytearray(frames[i]); struct.pack_into('<Q', blob, 2, 10); frames[i] = bytes(blob)
        self.assertEqual(self.analyze(frames)['outcome'], 'AWUS_ACK_AT_CAPTURE_LAYER')

    def test_global_header_and_record_bounds(self):
        for data in (b'', pcap(capture(), link=1), pcap(capture(), snaplen=1), pcap(capture())[:-1]):
            with self.assertRaises(p.InvalidCapture): p.analyze(io.BytesIO(data), bus=1, device=7)
        raw = bytearray(pcap(capture())); struct.pack_into('<I', raw, 24 + 8, 0xFFFFFFFF)
        with self.assertRaises(p.InvalidCapture): p.analyze(io.BytesIO(raw), bus=1, device=7)

    def test_header_layout_against_published_offsets(self):
        raw = usb(0x8877665544332211, 0x81, bytes(13), info=1)
        self.assertEqual(raw[:2], b'\x1b\x00')
        self.assertEqual(raw[2:10].hex(), '1122334455667788')
        self.assertEqual(raw[16], 1); self.assertEqual(raw[21:23], b'\x81\x03')
        self.assertEqual(raw[23:27], b'\x0d\x00\x00\x00')

    def test_complete_version_capture(self):
        frames = capture()
        reply = struct.pack('<8sIIHBBI8s', b'AWUSBFEX', 0x00189000, 1, 1, 0, 8, 0x45000, bytes(8))
        for irp, endpoint, payload in ((20, 2, p.READ_VERSION), (21, 0x81, reply),
                (22, 0x81, p.ACK), (23, 2, p.READ_STATUS), (24, 0x81, bytes(8)), (25, 0x81, p.ACK)):
            frames.extend([usb(irp, endpoint, payload if endpoint == 2 else b''),
                           usb(irp, endpoint, payload if endpoint == 0x81 else b'', info=1)])
        self.assertTrue(self.analyze(frames)['valid_version_reply_established'])
        frames[6] = usb(12, 0x81, bytes(13), info=1)
        with self.assertRaises(p.InvalidCapture): self.analyze(frames)

    def test_extra_unexpected_transfers_not_silently_ignored(self):
        frames = capture() + [usb(20, 2, b'x'), usb(20, 2, info=1)]
        with self.assertRaises(p.InvalidCapture): self.analyze(frames)


if __name__ == '__main__': unittest.main()
