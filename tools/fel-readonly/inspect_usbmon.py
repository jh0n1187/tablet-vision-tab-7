"""Offline Linux usbmon classic-PCAP verifier. No capture or device I/O.

Supports LINKTYPE_USB_LINUX 189 (48 bytes) and MMAPPED 220 (64 bytes),
microsecond classic PCAP in either byte order. PCAPNG is explicitly rejected.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import stat
import struct

from inspect_usbpcap import InvalidCapture, Packet, analyze_packets, MAX_PACKET, _exact


@dataclass(frozen=True)
class Event:
    index: int
    time: int
    urb: int
    kind: int
    transfer: int
    endpoint: int
    device: int
    bus: int
    setup_flag: int
    data_flag: int
    status: int
    length: int
    data: bytes
    setup: bytes
    truncated: bool


def events(stream):
    magic = _exact(stream, 4)
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(magic)
    if endian is None:
        raise InvalidCapture('Only microsecond classic PCAP supported; PCAPNG must be exported first')
    major, minor, zone, accuracy, snap, link = struct.unpack(endian + 'HHIIII', _exact(stream, 20))
    if (major, minor) != (2, 4) or link not in (189, 220):
        raise InvalidCapture('Expected Linux usbmon linktype 189 or 220')
    size = 48 if link == 189 else 64
    if not size <= snap <= MAX_PACKET:
        raise InvalidCapture('Invalid snapshot length')
    layout = struct.Struct(endian + 'QBBBBHBBqiiII8s')
    index = 0
    while True:
        raw = stream.read(16)
        if not raw:
            return
        if len(raw) != 16:
            raise InvalidCapture('Truncated record header')
        sec, usec, included, original = struct.unpack(endian + 'IIII', raw)
        if usec >= 1000000 or not size <= included <= min(snap, original):
            raise InvalidCapture('Invalid record timestamp/length')
        body = _exact(stream, included)
        urb, kind, transfer, ep, dev, bus, sf, df, ts, us, status, length, n, setup = layout.unpack_from(body)
        if kind not in b'SCE' or transfer not in (0, 1, 2, 3) or length > MAX_PACKET or n > MAX_PACKET or not 0 <= us < 1000000:
            raise InvalidCapture('Invalid usbmon fields')
        if link == 220 and transfer != 0 and struct.unpack_from(endian + 'I', body, 60)[0] != 0:
            raise InvalidCapture('Unexpected isochronous descriptors')
        data = body[size:]
        if len(data) > n or (df != 0 and (n or data)):
            raise InvalidCapture('Contradictory captured-data flag/length')
        index += 1
        if index > 200000:
            raise InvalidCapture('Record limit exceeded')
        yield Event(index, sec * 1000000 + usec, urb, kind, transfer, ep, dev, bus,
                    sf, df, status, length, data, setup,
                    included != original or len(data) != n)


def analyze(stream, *, bus, device):
    if not 1 <= bus <= 65535 or not 1 <= device <= 127:
        raise InvalidCapture('Explicit bus and device address required')
    selected = [e for e in events(stream) if (e.bus, e.device) == (bus, device)]
    pending = {}
    normalized = []
    descriptor_frames = []
    first_bulk = None
    for e in selected:
        if e.transfer not in (2, 3):
            raise InvalidCapture('Unexpected transfer type at selected address')
        if e.kind == ord('E'):
            raise InvalidCapture('usbmon reports submission error')
        key = e.urb
        if e.kind == ord('S'):
            if key in pending or e.status not in (0, -115):
                raise InvalidCapture('Duplicate submission or failed submit status')
            pending[key] = e
            continue
        if key not in pending:
            raise InvalidCapture('Completion without matching submission')
        s = pending.pop(key)
        if (s.transfer, s.endpoint) != (e.transfer, e.endpoint) or (e.time, e.index) < (s.time, s.index):
            raise InvalidCapture('URB correlation/order mismatch')
        if e.status != 0 or e.length > s.length:
            raise InvalidCapture('Failed or oversized completion')
        if e.transfer == 2:
            if s.endpoint not in (0, 0x80):
                raise InvalidCapture('Invalid control endpoint')
            if s.setup_flag == 0 and s.setup[:6] == b'\x80\x06\x00\x01\x00\x00':
                # Setup packet fields always USB little-endian, even in BE PCAP.
                requested = struct.unpack_from('<H', s.setup, 6)[0]
                if requested >= 18:
                    if e.truncated or e.data_flag != 0 or e.length != 18 or len(e.data) != 18 or e.data[:2] != b'\x12\x01':
                        raise InvalidCapture('Missing/truncated full device descriptor')
                    if e.data[8:12] != b'\x3a\x1f\xe8\xef':
                        raise InvalidCapture('Wrong identity or reused address')
                    descriptor_frames.append(e.index)
                    normalized.append(Packet(e.index, e.time, 28, e.urb, 0, 11, 1,
                                             bus, device, 0x80, 2, 18, e.data, False, 3))
            continue
        first_bulk = s.index if first_bulk is None else min(first_bulk, s.index)
        if s.endpoint not in (2, 0x81):
            raise InvalidCapture('Unexpected bulk endpoint')
        carrier = e if s.endpoint & 0x80 else s
        other = s if s.endpoint & 0x80 else e
        if s.truncated or e.truncated or carrier.data_flag != 0 or len(carrier.data) != carrier.length or other.data:
            raise InvalidCapture('Missing/truncated/ambiguous bulk payload')
        if e.length != s.length:
            raise InvalidCapture('Short USB transfer')
        for item, info in ((s, 0), (e, 1)):
            data = item.data if item is carrier else b''
            normalized.append(Packet(item.index, item.time, 27, item.urb, 0, 9, info,
                                     bus, device, item.endpoint, 3, len(data), data, False, None))
    if pending:
        raise InvalidCapture('Incomplete selected URBs')
    if not descriptor_frames or first_bulk is None or min(descriptor_frames) >= first_bulk:
        raise InvalidCapture('Captured full EFE8 descriptor required before bulk traffic')
    normalized.sort(key=lambda e: e.index)
    report = analyze_packets(normalized, bus=bus, device=device)
    report['capture_layer'] = 'Linux usbmon URB/HCD boundary; not electrical bus analyzer'
    report['source_format'] = 'Linux usbmon classic PCAP (189/220)'
    report['descriptor_completion_frames'] = descriptor_frames
    report['loss_assessment'] = 'Not encoded in classic PCAP; collector drop counters must be reviewed separately'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--bus', type=int, required=True)
    parser.add_argument('--device', type=int, required=True)
    args = parser.parse_args()
    path = args.capture
    if str(path).startswith(('\\\\.\\', '\\\\?\\')) or not path.is_file() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > 512 * 1024 * 1024:
        parser.error('Existing regular capture file, up to 512 MiB, required')
    with path.open('rb') as stream:
        report = analyze(stream, bus=args.bus, device=args.device)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
