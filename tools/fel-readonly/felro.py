"""Offline acquisition core. Standard library only; no physical USB backend.

There is deliberately no subprocess, ADB, xfel, USB library or live-device CLI.
Hardware support must be implemented/reviewed separately before FEL use.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import secrets
import struct
from typing import Protocol

MAGIC, VERSION, INFO, READ = 0x314F5246, 1, 1, 2
SECTOR, MAX_SECTORS = 512, 128
REQUEST, RESPONSE = struct.Struct('<8I'), struct.Struct('<20I')
CODE, REQUEST_ADDR, DATA = 0x20000, 0x2FF00, 0x30000
APPROVED_PARTITIONS = frozenset({
    'bootloader_a', 'bootloader_b', 'boot_a', 'boot_b', 'vendor_boot_a',
    'vendor_boot_b', 'init_boot_a', 'init_boot_b', 'vbmeta_a', 'vbmeta_b',
    'vbmeta_system_a', 'vbmeta_system_b', 'vbmeta_vendor_a', 'vbmeta_vendor_b',
    'dtbo_a', 'dtbo_b', 'super', 'media_data',
})


class Rejected(ValueError):
    pass


def crc(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def integer(value: int, maximum: int = 0xFFFFFFFF) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise Rejected('integer out of range')
    return value


def request(op: int, seq: int, lba: int = 0, count: int = 0) -> bytes:
    for value in (op, seq, lba, count):
        integer(value)
    if op not in (INFO, READ) or not seq:
        raise Rejected('operation/sequence forbidden')
    if op == INFO and (lba or count):
        raise Rejected('INFO has no range')
    if op == READ and (not 1 <= count <= MAX_SECTORS or lba + count > 2**32):
        raise Rejected('READ range forbidden')
    raw = REQUEST.pack(MAGIC, VERSION, op, seq, lba, count, 0, 0)
    return raw[:-4] + struct.pack('<I', crc(raw))


class Transport(Protocol):
    payload_sha256: str
    def exchange(self, raw: bytes) -> tuple[bytes, bytes]: ...


class RamEnvelope:
    """Pure validation of a future transport's SRAM envelope; no I/O here."""
    @staticmethod
    def upload(address: int, data: bytes, expected_payload_hash: str) -> None:
        if address == CODE:
            if not 0 < len(data) <= 0x8000 or hashlib.sha256(data).hexdigest() != expected_payload_hash:
                raise Rejected('unidentified payload')
        elif address == REQUEST_ADDR:
            if len(data) != REQUEST.size:
                raise Rejected('request size')
            m, v, op, seq, lba, count, reserved, checksum = REQUEST.unpack(data)
            if m != MAGIC or v != VERSION or reserved or data != request(op, seq, lba, count):
                raise Rejected('invalid request')
        else:
            raise Rejected('address outside approved SRAM windows')

    @staticmethod
    def execute(address: int) -> None:
        if address != CODE:
            raise Rejected('arbitrary execution forbidden')


class Client:
    def __init__(self, transports: list[Transport], payload_sha256: str):
        if len(transports) != 1:
            raise Rejected('exactly one selected transport required')
        if len(payload_sha256) != 64 or any(c not in '0123456789abcdef' for c in payload_sha256):
            raise Rejected('payload hash required')
        self.transport = transports[0]
        if self.transport.payload_sha256 != payload_sha256:
            raise Rejected('payload identity mismatch')
        self.payload_hash = payload_sha256
        self.identity: tuple[int, ...] | None = None
        self.sequence = secrets.randbelow(0xFFFFFFFE) + 1

    def _exchange(self, op: int, lba: int, count: int) -> tuple[tuple[int, ...], bytes]:
        seq = self.sequence
        if seq == 0xFFFFFFFF:
            raise Rejected('sequence exhausted; start a new session')
        self.sequence += 1
        raw = request(op, seq, lba, count)
        header, data = self.transport.exchange(raw)
        if len(header) != RESPONSE.size:
            raise Rejected('short response header')
        values = list(RESPONSE.unpack(header))
        saved_crc = values[16]
        values[16] = 0
        if crc(RESPONSE.pack(*values)) != saved_crc:
            raise Rejected('response header CRC')
        if values[:3] != [MAGIC, VERSION, seq] or values[4:6] != [lba, count] or any(values[17:]):
            raise Rejected('stale/mismatched response')
        if values[3] or values[12]:
            raise Rejected(f'payload failed: status={values[3]} error={values[12]}')
        expected = SECTOR if op == INFO else count * SECTOR
        if values[7] != expected or len(data) != expected or crc(data) != values[15]:
            raise Rejected('short/corrupt payload data')
        capacity = values[6]
        if not 1 <= capacity < 0xFFFFFFFF or values[13] & 7 or values[14]:
            raise Rejected('invalid capacity/area/bus width')
        identity = (capacity, *values[8:12], values[13], values[14])
        if not any(values[8:12]) or all(v == 0xFFFFFFFF for v in values[8:12]):
            raise Rejected('invalid CID')
        if self.identity is not None and identity != self.identity:
            raise Rejected('device changed during session')
        if op == INFO:
            if struct.unpack_from('<I', data, 212)[0] != capacity or data[179] != values[13] or data[183] != values[14]:
                raise Rejected('inconsistent EXT_CSD')
            self.identity = identity
        elif self.identity is None or lba + count > capacity:
            raise Rejected('unidentified/out-of-range read')
        return tuple(values), data

    def identify(self) -> tuple[int, ...]:
        self._exchange(INFO, 0, 0)
        assert self.identity is not None
        return self.identity

    def read(self, lba: int, count: int) -> bytes:
        integer(lba); integer(count)
        if self.identity is None or not count or lba + count > self.identity[0]:
            raise Rejected('unidentified/out-of-range read')
        chunks = []
        for offset in range(0, count, MAX_SECTORS):
            chunks.append(self._exchange(READ, lba + offset, min(MAX_SECTORS, count - offset))[1])
        return b''.join(chunks)


@dataclass(frozen=True)
class Partition:
    name: str
    first: int
    last: int
    guid: bytes


@dataclass(frozen=True)
class Table:
    disk_guid: bytes
    first_usable: int
    last_usable: int
    entries_lba: int
    entry_count: int
    entry_size: int
    entries_crc: int
    partitions: tuple[Partition, ...]
    raw_header: bytes
    raw_entries: bytes

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.raw_header + self.raw_entries).hexdigest()


def exact_read(reader, lba: int, count: int, capacity: int) -> bytes:
    integer(lba, 2**64 - 1); integer(count, 2**64 - 1)
    if not count or lba + count > capacity:
        raise Rejected('metadata beyond capacity')
    raw = reader.read(lba, count)
    if len(raw) != count * SECTOR:
        raise Rejected('short metadata transfer')
    return raw


def read_gpt(reader, capacity: int, *, backup: bool = False) -> Table:
    integer(capacity, 2**64 - 1)
    if capacity < 8:
        raise Rejected('disk too small')
    mbr = exact_read(reader, 0, 1, capacity)
    mbr_entries = [mbr[446+16*i:462+16*i] for i in range(4)]
    protective = [e for e in mbr_entries if e[4] == 0xEE]
    if (mbr[510:512] != b'\x55\xaa' or len(protective) != 1 or
        any(e[4] not in (0, 0xEE) for e in mbr_entries) or
        struct.unpack_from('<2I', protective[0], 8) != (1, min(capacity-1, 0xFFFFFFFF))):
        raise Rejected('protective MBR missing')
    here = capacity - 1 if backup else 1
    header = exact_read(reader, here, 1, capacity)
    if header[:8] != b'EFI PART':
        raise Rejected('GPT signature')
    revision, size, checksum, reserved = struct.unpack_from('<4I', header, 8)
    if revision != 0x10000 or not 92 <= size <= SECTOR or reserved:
        raise Rejected('GPT header fields')
    checked = bytearray(header[:size]); checked[16:20] = bytes(4)
    if crc(checked) != checksum:
        raise Rejected('GPT header CRC')
    current, alternate, first, last = struct.unpack_from('<4Q', header, 24)
    if current != here or alternate != (1 if backup else capacity - 1) or not 2 <= first <= last < capacity - 1:
        raise Rejected('GPT LBA fields')
    disk_guid = header[56:72]
    if disk_guid == bytes(16):
        raise Rejected('zero disk GUID')
    array_lba, count, entry_size, array_crc = struct.unpack_from('<Q3I', header, 72)
    if not 1 <= count <= 4096 or entry_size < 128 or entry_size > 4096 or entry_size % 128 or (entry_size // 128) & (entry_size // 128 - 1):
        raise Rejected('GPT entry layout')
    byte_count = count * entry_size
    sectors = (byte_count + SECTOR - 1) // SECTOR
    if array_lba < 2 or array_lba + sectors > capacity:
        raise Rejected('GPT table outside disk')
    if (not backup and array_lba + sectors > first) or (backup and (array_lba <= last or array_lba + sectors > here)):
        raise Rejected('GPT table overlaps usable/header area')
    entries = exact_read(reader, array_lba, sectors, capacity)[:byte_count]
    if crc(entries) != array_crc:
        raise Rejected('GPT entries CRC')
    parts, names, guids = [], set(), set()
    for offset in range(0, byte_count, entry_size):
        entry = entries[offset:offset + entry_size]
        if entry[:16] == bytes(16):
            continue
        guid = entry[16:32]
        start, end = struct.unpack_from('<2Q', entry, 32)
        try:
            name = entry[56:128].decode('utf-16-le').split('\0', 1)[0]
        except UnicodeError as error:
            raise Rejected('partition name encoding') from error
        if not name or name.casefold() in names or guid == bytes(16) or guid in guids:
            raise Rejected('duplicate/empty partition identity')
        if not first <= start <= end <= last:
            raise Rejected('partition out of usable range')
        parts.append(Partition(name, start, end, guid))
        names.add(name.casefold()); guids.add(guid)
    ordered = sorted(parts, key=lambda p: p.first)
    if any(a.last >= b.first for a, b in zip(ordered, ordered[1:])):
        raise Rejected('overlapping partitions')
    return Table(disk_guid, first, last, array_lba, count, entry_size, array_crc, tuple(parts), header[:size], entries)


def paired_gpt(reader, capacity: int) -> Table:
    first, second = read_gpt(reader, capacity), read_gpt(reader, capacity, backup=True)
    if (first.disk_guid, first.first_usable, first.last_usable, first.entry_count,
        first.entry_size, first.raw_entries) != (second.disk_guid, second.first_usable,
        second.last_usable, second.entry_count, second.entry_size, second.raw_entries):
        raise Rejected('primary/backup GPT mismatch')
    return first


class ImageReader:
    """Local regular file only; refuse Windows device paths and symlinks."""
    def __init__(self, path: Path):
        path = Path(path)
        if path.is_symlink() or not path.is_file() or str(path).startswith(('\\\\', '/dev/')):
            raise Rejected('regular local image required')
        self.file = path.open('rb')
        self.capacity = path.stat().st_size // SECTOR
        if path.stat().st_size % SECTOR:
            self.file.close(); raise Rejected('unaligned image')

    def read(self, lba: int, count: int) -> bytes:
        self.file.seek(lba * SECTOR)
        return self.file.read(count * SECTOR)

    def close(self):
        self.file.close()


def acquire_partition(client: Client, table: Table, name: str, destination: Path) -> dict:
    """No raw-range acquisition or resume. Two independent reads per chunk."""
    if client.identity is None or name not in APPROVED_PARTITIONS:
        raise Rejected('partition not approved')
    # Never trust a supplied/cached GPT alone: bind it to this identified session.
    current = paired_gpt(client, client.identity[0])
    if current.fingerprint != table.fingerprint:
        raise Rejected('GPT changed')
    matches = [p for p in current.partitions if p.name == name]
    if len(matches) != 1:
        raise Rejected('partition not found')
    part = matches[0]
    destination = Path(destination)
    partial = destination.with_name(destination.name + '.partial')
    journal = destination.with_name(destination.name + '.jsonl')
    if destination.exists() or partial.exists() or journal.exists():
        raise Rejected('output already exists; resume is forbidden')
    record = {'partition': name, 'first_lba': part.first, 'last_lba': part.last,
              'identity': client.identity, 'gpt_sha256': table.fingerprint,
              'payload_sha256': client.payload_hash}
    digest = hashlib.sha256()
    # Exclusive .partial creation prevents concurrent acquisition of this name.
    # The final name is published atomically by hard link, with no overwrite.
    with partial.open('xb') as output, journal.open('x', encoding='utf-8') as log:
        log.write(json.dumps({'event': 'start', **record}) + '\n'); log.flush()
        try:
            for lba in range(part.first, part.last + 1, MAX_SECTORS):
                count = min(MAX_SECTORS, part.last - lba + 1)
                a, b = client.read(lba, count), client.read(lba, count)
                if a != b:
                    raise Rejected('independent reads differ')
                output.write(a); digest.update(a)
                log.write(json.dumps({'event': 'block', 'lba': lba, 'count': count,
                                      'sha256': hashlib.sha256(a).hexdigest()}) + '\n')
                log.flush()
            record.update(bytes=(part.last-part.first+1)*SECTOR, sha256=digest.hexdigest())
            output.flush(); os.fsync(output.fileno())
            os.link(partial, destination)
            log.write(json.dumps({'event': 'complete', **record}) + '\n')
        except Exception as error:
            log.write(json.dumps({'event': 'failed', 'reason': str(error)}) + '\n')
            raise
    # Retain .partial as evidence; the successful final name references the same
    # verified PC file. A failed acquisition never publishes a final image.
    return record


def main():
    parser = argparse.ArgumentParser(description='Offline GPT inspection only. No tablet/USB support.')
    parser.add_argument('image', type=Path)
    args = parser.parse_args()
    image = ImageReader(args.image)
    try:
        table = paired_gpt(image, image.capacity)
        print(json.dumps({'gpt_sha256': table.fingerprint, 'partitions': [
            {'name': p.name, 'first': p.first, 'last': p.last} for p in table.partitions]}, indent=2))
    finally:
        image.close()


if __name__ == '__main__':
    main()
