"""Restricted FEL framing over an injected bulk pipe. No USB discovery or CLI.

Importing this module does no I/O. WinUSB is optional and locked separately.
This is a new implementation from the documented wire format, not xfel code.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Protocol

import felro as ro

VID, PID, SOC_RAW = 0x1F3A, 0xEFE8, 0x00189000
RESPONSE_ADDR = 0x2FF40
USB_HEADER = struct.Struct('<8sIIHI10s')
FEL_REQUEST = struct.Struct('<4I')
VERSION_REPLY = struct.Struct('<8sIIHBBI8s')
MAX_TRANSFER = 65536


@dataclass(frozen=True)
class USBIdentity:
    vid: int
    pid: int
    interface: int
    endpoint_in: int
    endpoint_out: int
    key: str  # explicit path or synthetic identity; no automatic first-match

    def validate(self):
        if (self.vid, self.pid, self.interface) != (VID, PID, 0) or not self.key:
            raise ro.Rejected('not the expected FEL BootROM interface')
        if not 0x81 <= self.endpoint_in <= 0x8F or not 1 <= self.endpoint_out <= 15:
            raise ro.Rejected('invalid bulk endpoints')


class BulkPipe(Protocol):
    identity: USBIdentity
    def write(self, data: bytes) -> int: ...
    def read(self, length: int) -> bytes: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class MemoryReview:
    """Review record, not user authorization. Default intentionally unapproved."""
    approved: bool = False
    evidence_id: str = ''


class FelReadonly:
    def __init__(self, pipes: list[BulkPipe], payload_sha256: str):
        if len(pipes) != 1:
            raise ro.Rejected('exactly one explicitly selected USB pipe required')
        pipes[0].identity.validate()
        if len(payload_sha256) != 64 or any(c not in '0123456789abcdef' for c in payload_sha256):
            raise ro.Rejected('payload SHA-256 required')
        self._pipe = pipes[0]
        self._identity = self._pipe.identity
        self.payload_sha256 = payload_sha256
        self._failed = False
        self._version = None
        self._loaded = False
        self._last_sequence = 0
        self.audit: list[dict] = []

    def _check(self):
        if self._failed or self._pipe.identity != self._identity:
            self._failed = True
            raise ro.Rejected('USB session failed or device identity changed')

    def _write(self, data: bytes):
        self._check()
        try:
            if not 0 < len(data) <= MAX_TRANSFER or self._pipe.write(data) != len(data):
                raise ro.Rejected('short/invalid USB write')
        except Exception:
            self._failed = True
            raise

    def _read(self, length: int) -> bytes:
        self._check()
        try:
            if not 0 < length <= MAX_TRANSFER:
                raise ro.Rejected('invalid USB read length')
            data = self._pipe.read(length)
            if len(data) != length:
                raise ro.Rejected('short USB read; no automatic retry')
            return data
        except Exception:
            self._failed = True
            raise

    def _usb_header(self, operation: int, length: int) -> bytes:
        if operation not in (0x11, 0x12) or not 0 < length <= MAX_TRANSFER:
            raise ro.Rejected('invalid AWUC request')
        return USB_HEADER.pack(b'AWUC\0\0\0\0', length, 0x0C000000, operation, length, bytes(10))

    def _ack(self):
        # Strict initial profile: unknown fields/status cause a stop, not a guess.
        if self._read(13) != b'AWUS' + bytes(9):
            self._failed = True
            raise ro.Rejected('unexpected AWUS acknowledgement')

    def _send(self, data: bytes):
        self._write(self._usb_header(0x12, len(data)))
        self._write(data)
        self._ack()

    def _receive(self, length: int) -> bytes:
        self._write(self._usb_header(0x11, length))
        data = self._read(length)
        self._ack()
        return data

    def _status(self):
        if self._receive(8) != bytes(8):
            self._failed = True
            raise ro.Rejected('nonzero/unknown FEL status')

    def _fel(self, operation: int, address: int, length: int):
        # Called only by the finite operations below; never a public raw RPC.
        if operation == 1:
            allowed = address == length == 0
        elif operation == 0x101:
            allowed = ((address == ro.CODE and 0 < length <= 0x8000) or
                       (address == ro.REQUEST_ADDR and length == ro.REQUEST.size)) and self._version is not None
        elif operation == 0x102:
            allowed = address == ro.CODE and length == 0 and self._loaded
        elif operation == 0x103:
            allowed = ((address == RESPONSE_ADDR and length == ro.RESPONSE.size) or
                       (address == ro.CODE and 0 < length <= 0x8000) or
                       (address == ro.DATA and 0 < length <= MAX_TRANSFER)) and self._loaded
        else:
            allowed = False
        if not allowed:
            raise ro.Rejected('FEL operation/address outside finite policy')
        self.audit.append({'fel_request':operation,'address':address,'length':length})
        self._send(FEL_REQUEST.pack(operation, address, length, 0))

    def identify(self) -> dict:
        self._check()
        if self._loaded:
            raise ro.Rejected('version query only before loading the reader')
        self._fel(1, 0, 0)
        raw = self._receive(VERSION_REPLY.size)
        self._status()
        magic, soc, firmware, protocol, flags, length, scratchpad, reserved = VERSION_REPLY.unpack(raw)
        # The meaning of flags, firmware and scratchpad is recorded, not used to
        # authorize arbitrary addresses. Unknown protocol/SoC never loads code.
        if magic != b'AWUSBFEX' or soc != SOC_RAW or protocol != 1:
            self._failed = True
            raise ro.Rejected('unknown FEL magic/SoC/protocol')
        self._version = {'soc_raw': soc, 'soc_normalized': (soc >> 8) & 0xFFFF,
                         'firmware': firmware, 'protocol': protocol, 'flags': flags,
                         'length': length, 'scratchpad': scratchpad,
                         'reserved_hex': reserved.hex()}
        return dict(self._version)

    def prepare_payload(self, payload: bytes, review: MemoryReview):
        self._check()
        if not review.approved or not review.evidence_id or self._version is None or self._loaded:
            raise ro.Rejected('memory/BROM review missing or invalid session state')
        ro.RamEnvelope.upload(ro.CODE, payload, self.payload_sha256)
        self._fel(0x101, ro.CODE, len(payload))
        self._send(payload)
        self._status()
        self._loaded = True
        self._fel(0x103, ro.CODE, len(payload))
        readback = self._receive(len(payload)); self._status()
        if hashlib.sha256(readback).hexdigest() != self.payload_sha256:
            self._failed = True
            raise ro.Rejected('uploaded code readback hash mismatch')

    def exchange(self, raw: bytes) -> tuple[bytes, bytes]:
        self._check()
        if not self._loaded:
            raise ro.Rejected('reader not loaded')
        ro.RamEnvelope.upload(ro.REQUEST_ADDR, raw, self.payload_sha256)
        _, _, op, seq, lba, count, _, _ = ro.REQUEST.unpack(raw)
        if seq <= self._last_sequence:
            raise ro.Rejected('request sequence replay/wrap')
        self._last_sequence = seq
        self._fel(0x101, ro.REQUEST_ADDR, len(raw)); self._send(raw); self._status()
        self._fel(0x102, ro.CODE, 0); self._status()
        self._fel(0x103, RESPONSE_ADDR, ro.RESPONSE.size)
        header = self._receive(ro.RESPONSE.size); self._status()
        fields = list(ro.RESPONSE.unpack(header)); checksum = fields[16]; fields[16] = 0
        expected = ro.SECTOR if op == ro.INFO else count * ro.SECTOR
        if (ro.crc(ro.RESPONSE.pack(*fields)) != checksum or
            fields[:3] != [ro.MAGIC, ro.VERSION, seq] or fields[4:6] != [lba, count] or
            any(fields[17:]) or (fields[3] == 0 and (fields[7] != expected or fields[12])) or
            (fields[3] == 0 and (not 1 <= fields[6] < 0xffffffff or fields[13] & 7 or fields[14])) or
            (fields[3] != 0 and fields[7] != 0)):
            self._failed = True
            raise ro.Rejected('invalid reader response; no data read')
        if fields[3]:
            self._failed = True
            return header, b''
        self._fel(0x103, ro.DATA, expected)
        data = self._receive(expected); self._status()
        if ro.crc(data) != fields[15]:
            self._failed = True
            raise ro.Rejected('reader data CRC')
        return header, data

    def close(self):
        self._failed = True
        self._pipe.close()
