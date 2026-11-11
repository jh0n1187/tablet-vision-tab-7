"""Offline USBPcap classic-pcap verifier for one VERSION/ACK transaction.

Reads regular files only. No capture, device APIs, ADB or live USB imports.
Requires explicit bus/address and a captured 1F3A:EFE8 device descriptor.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import stat
import struct

GLOBAL = struct.Struct('<IHHIIII')
RECORD = struct.Struct('<IIII')
USB = struct.Struct('<HQIHBHHBBI')  # USBPcap packed header, 27 bytes.
MAX_PACKET = 1024 * 1024
HEADER = bytes.fromhex('4157554300000000100000000000000c12001000000000000000000000000000')
VERSION = bytes.fromhex('01000000000000000000000000000000')
ACK = b'AWUS' + bytes(9)
READ_VERSION = bytes.fromhex('4157554300000000200000000000000c11002000000000000000000000000000')
READ_STATUS = bytes.fromhex('4157554300000000080000000000000c11000800000000000000000000000000')


class InvalidCapture(ValueError):
    pass


@dataclass(frozen=True)
class Packet:
    index: int
    timestamp_us: int
    header_length: int
    irp: int
    status: int
    function: int
    info: int
    bus: int
    device: int
    endpoint: int
    transfer: int
    declared_length: int
    payload: bytes
    truncated: bool
    stage: int | None


def _exact(stream, n):
    data = stream.read(n)
    if len(data) != n:
        raise InvalidCapture('Truncated pcap structure')
    return data


def packets(stream):
    magic, major, minor, zone, accuracy, snaplen, link = GLOBAL.unpack(_exact(stream, GLOBAL.size))
    if magic != 0xA1B2C3D4 or (major, minor) != (2, 4) or link != 249:
        raise InvalidCapture('Only little-endian classic pcap 2.4 LINKTYPE_USBPCAP=249 supported')
    if not 27 <= snaplen <= MAX_PACKET:
        raise InvalidCapture('Snapshot length outside supported bounds')
    index = 0
    while True:
        raw = stream.read(RECORD.size)
        if not raw:
            return
        if len(raw) != RECORD.size:
            raise InvalidCapture('Truncated record header')
        seconds, micros, included, original = RECORD.unpack(raw)
        if micros >= 1000000 or included > snaplen or included > original or included < USB.size:
            raise InvalidCapture('Invalid timestamp/record lengths')
        body = _exact(stream, included)
        hlen, irp, status, function, info, bus, dev, ep, transfer, n = USB.unpack_from(body)
        if not USB.size <= hlen <= included or info & ~1 or n > MAX_PACKET:
            raise InvalidCapture('Invalid USBPcap header')
        payload = body[hlen:]
        if len(payload) > n:
            raise InvalidCapture('Payload exceeds declared data length')
        index += 1
        if index > 200000:
            raise InvalidCapture('Record limit exceeded')
        stage = body[USB.size] if transfer == 2 and hlen == 28 else None
        yield Packet(index, seconds * 1000000 + micros, hlen, irp, status,
                     function, info, bus, dev, ep, transfer, n, payload,
                     included != original or len(payload) != n, stage)


def analyze(stream, *, bus, device):
    return analyze_packets(packets(stream), bus=bus, device=device)


def analyze_packets(packet_iter, *, bus, device):
    """Verify normalized records; adapters must validate their source format first."""
    if not 0 <= bus <= 65535 or not 1 <= device <= 127:
        raise InvalidCapture('Explicit USB bus and device address required')
    selected = [p for p in packet_iter if (p.bus, p.device) == (bus, device)]
    identities = set()
    for p in selected:
        if p.transfer == 2 and p.info == 1 and p.status == 0 and p.stage in (1, 3) and not p.truncated:
            if len(p.payload) == 18 and p.payload[:2] == b'\x12\x01':
                identities.add(struct.unpack_from('<HH', p.payload, 8))
    if identities != {(0x1F3A, 0xEFE8)}:
        raise InvalidCapture('Missing/wrong/ambiguous captured device descriptor for selected address')

    pending = {}; transactions = []
    for p in selected:
        if p.transfer != 3:
            continue
        if p.function != 9 or p.header_length != 27 or p.endpoint not in (2, 0x81):
            raise InvalidCapture('Unexpected selected bulk function/header/endpoint')
        key = (p.irp, p.endpoint)
        if p.info == 0:
            if key in pending:
                raise InvalidCapture('Duplicate pending IRP')
            pending[key] = p
        else:
            if key not in pending:
                raise InvalidCapture('Completion without matching submission')
            request = pending.pop(key)
            if p.timestamp_us < request.timestamp_us:
                raise InvalidCapture('Completion predates submission')
            transactions.append((request, p))
    if pending:
        raise InvalidCapture('Capture ends with incomplete selected IRPs')
    transactions.sort(key=lambda t: (t[0].timestamp_us, t[0].index))
    for previous, current in zip(transactions, transactions[1:]):
        if (current[0].timestamp_us, current[0].index) < (previous[1].timestamp_us, previous[1].index):
            raise InvalidCapture('Overlapping transfers do not match the synchronous client')
    if len(transactions) not in (3, 9):
        raise InvalidCapture('Expected initial ACK transaction or complete VERSION; isolate capture/address')
    expected_endpoints = [2, 2, 0x81] if len(transactions) == 3 else [2, 2, 0x81, 2, 0x81, 0x81, 2, 0x81, 0x81]
    if [t[0].endpoint for t in transactions] != expected_endpoints:
        raise InvalidCapture('Unexpected transaction direction/order')
    for request, complete in transactions:
        if complete.status != 0:
            raise InvalidCapture('USB completion status is not success')
    header, command, reply = transactions[0][0], transactions[1][0], transactions[2][1]
    if any(p.truncated for p in (header, command, reply)):
        raise InvalidCapture('Transfer data truncated/missing; cannot classify ACK')
    if header.payload != HEADER or command.payload != VERSION:
        raise InvalidCapture('Captured OUT bytes differ from fixed VERSION transcript')
    if len(reply.payload) != 13:
        raise InvalidCapture('ACK completion must contain exactly 13 captured bytes')
    outcome = ('AWUS_ACK_AT_CAPTURE_LAYER' if reply.payload == ACK else
               'ZERO_ACK_AT_CAPTURE_LAYER' if reply.payload == bytes(13) else
               'OTHER_ACK_AT_CAPTURE_LAYER')
    version_hex = None
    compatible = False
    if len(transactions) == 9:
        if reply.payload != ACK:
            raise InvalidCapture('Extra transactions after invalid first ACK')
        data = [(a if not a.endpoint & 0x80 else b) for a, b in transactions[3:]]
        if any(p.truncated for p in data):
            raise InvalidCapture('Extended VERSION transcript has truncated payload')
        if (data[0].payload != READ_VERSION or
            len(data[1].payload) != 32 or data[2].payload != ACK or
            data[3].payload != READ_STATUS or data[4].payload != bytes(8) or data[5].payload != ACK):
            raise InvalidCapture('Extended VERSION transcript differs from fixed profile')
        magic, soc, firmware, protocol, flags, length, scratch, reserved = struct.unpack('<8sIIHBBI8s', data[1].payload)
        version_hex = data[1].payload.hex()
        compatible = magic == b'AWUSBFEX' and soc == 0x00189000 and protocol == 1
    return {'capture_layer': 'USBPcap URB filter; not electrical bus analyzer',
            'bus': bus, 'device': device, 'captured_vid': '1F3A', 'captured_pid': 'EFE8',
            'out_header_hex': header.payload.hex(), 'out_version_hex': command.payload.hex(),
            'ack_hex': reply.payload.hex(), 'outcome': outcome,
            'irp_pairs': [{'submission_frame': a.index, 'completion_frame': b.index,
                           'endpoint': a.endpoint, 'status': b.status} for a, b in transactions],
            'version_reply_hex': version_hex, 'valid_version_reply_established': compatible}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    p.add_argument('--bus', type=int, required=True)
    p.add_argument('--device', type=int, required=True)
    args = p.parse_args()
    path = args.capture
    if str(path).startswith(('\\\\.\\', '\\\\?\\')) or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        p.error('Only an existing regular local capture file is accepted')
    if path.stat().st_size > 512 * 1024 * 1024:
        p.error('Capture exceeds offline review size limit')
    with path.open('rb') as f:
        report = analyze(f, bus=args.bus, device=args.device)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
