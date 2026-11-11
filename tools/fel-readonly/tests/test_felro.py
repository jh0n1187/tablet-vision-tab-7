import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import felro as ro

HASH = hashlib.sha256(b'test-only-payload').hexdigest()


class Disk:
    """Sparse PC memory disk; deliberately supports LBAs above 32 bits."""
    def __init__(self, capacity=4096, array_lba=4, entry_size=128, parts=None):
        self.capacity, self.sectors, self.calls = capacity, {}, []
        self.array_lba, self.entry_size = array_lba, entry_size
        self.first, self.last = 64, capacity - 64
        if parts is None:
            parts = [('bootloader_a', 128, 260), ('userdata', 300, 350)]
        self.entries = bytearray(4 * entry_size)
        for i, (name, first, last) in enumerate(parts):
            start = i * entry_size
            self.entries[start:start+16] = uuid.UUID(int=1).bytes_le
            self.entries[start+16:start+32] = uuid.UUID(int=i+2).bytes_le
            struct.pack_into('<2Q', self.entries, start+32, first, last)
            encoded = name.encode('utf-16-le')
            self.entries[start+56:start+56+len(encoded)] = encoded
        mbr = bytearray(512); mbr[450] = 0xEE; mbr[510:] = b'\x55\xaa'
        struct.pack_into('<2I',mbr,454,1,min(capacity-1,0xFFFFFFFF))
        self.sectors[0] = bytes(mbr)
        self.rebuild()

    def put(self, lba, raw):
        raw += bytes((-len(raw)) % 512)
        for i in range(0, len(raw), 512): self.sectors[lba+i//512] = raw[i:i+512]

    def rebuild(self):
        backup_lba = self.capacity - 1 - (len(self.entries)+511)//512
        self.put(self.array_lba, bytes(self.entries)); self.put(backup_lba, bytes(self.entries))
        for backup in (False, True):
            current = self.capacity-1 if backup else 1
            header = bytearray(512); header[:8] = b'EFI PART'
            struct.pack_into('<4I', header, 8, 0x10000, 92, 0, 0)
            struct.pack_into('<4Q', header, 24, current, 1 if backup else self.capacity-1, self.first, self.last)
            header[56:72] = uuid.UUID(int=77).bytes_le
            struct.pack_into('<Q3I', header, 72, backup_lba if backup else self.array_lba,
                             4, self.entry_size, ro.crc(self.entries))
            struct.pack_into('<I', header, 16, ro.crc(header[:92]))
            self.sectors[current] = bytes(header)

    def header_change(self, offset, fmt, value, backup=False):
        lba = self.capacity-1 if backup else 1
        h = bytearray(self.sectors[lba]); struct.pack_into(fmt, h, offset, value)
        h[16:20] = bytes(4); struct.pack_into('<I', h, 16, ro.crc(h[:92]))
        self.sectors[lba] = bytes(h)

    def read(self, lba, count):
        self.calls.append((lba, count))
        return b''.join(self.sectors.get(n, struct.pack('<Q', n)*64) for n in range(lba, lba+count))


class SimulatedUSB:
    """Protocol simulator, not a USB stack, device or physical eMMC emulator."""
    payload_sha256 = HASH
    def __init__(self, disk=None):
        self.disk = disk or Disk()
        self.calls, self.fault, self.previous = [], None, None
        self.cid = [1, 2, 3, 4]

    def exchange(self, raw):
        m, v, op, seq, lba, count, reserved, checksum = ro.REQUEST.unpack(raw)
        assert raw == ro.request(op, seq, lba, count)
        self.calls.append((op, seq, lba, count))
        if op == ro.INFO:
            data = bytearray(512); struct.pack_into('<I', data, 212, self.disk.capacity)
            data = bytes(data)
        else:
            data = self.disk.read(lba, count)
        fields = [m, v, seq, 0, lba, count, self.disk.capacity, len(data),
                  *self.cid, 0, 0, 0, ro.crc(data), 0, 0, 0, 0]
        if self.fault == 'status': fields[3] = 4
        if self.fault == 'crc_error': fields[12] = 1 << 7
        if self.fault == 'nonce': fields[2] -= 1
        if self.fault == 'lba': fields[4] += 1
        if self.fault == 'capacity': fields[6] = 0
        if self.fault == 'area': fields[13] = 1
        if self.fault == 'bus': fields[14] = 1
        if self.fault == 'cid': fields[8] += 1
        if self.fault == 'reserved': fields[19] = 1
        fields[16] = ro.crc(ro.RESPONSE.pack(*fields))
        header = ro.RESPONSE.pack(*fields)
        if self.fault == 'header_crc': header = header[:-1] + bytes([header[-1]^1])
        if self.fault == 'short_header': header = header[:-1]
        if self.fault == 'short_data': data = data[:-1]
        if self.fault == 'data_crc': data = bytes([data[0]^1]) + data[1:]
        if self.fault == 'ext': data = data[:212] + bytes(4) + data[216:]
        if self.fault == 'old' and self.previous is not None: return self.previous
        self.previous = header, data
        return header, data


class ProtocolTests(unittest.TestCase):
    def setup_client(self):
        usb = SimulatedUSB(); client = ro.Client([usb], HASH); client.identify()
        return usb, client

    def test_forbidden_commands_before_transport(self):
        for op in (0, 3, 4, 5, 6, 24, 25, 38, 0xFFFFFFFF):
            with self.subTest(op=op), self.assertRaises(ro.Rejected): ro.request(op, 1)

    def test_bad_arguments(self):
        for lba, count in ((-1,1),(0,0),(0,129),(2**32-1,2),(True,1),(0,'1')):
            with self.subTest(lba=lba,count=count), self.assertRaises(ro.Rejected): ro.request(ro.READ,1,lba,count)

    def test_info_arguments(self):
        for seq,lba,count in ((0,0,0),(1,1,0),(1,0,1)):
            with self.assertRaises(ro.Rejected): ro.request(ro.INFO,seq,lba,count)

    def test_ambiguous_target_and_hash(self):
        for transports in ([],[SimulatedUSB(),SimulatedUSB()]):
            with self.assertRaises(ro.Rejected): ro.Client(transports,HASH)
        with self.assertRaises(ro.Rejected): ro.Client([SimulatedUSB()],'0'*64)

    def test_ram_envelope(self):
        payload = b'test-only-payload'
        ro.RamEnvelope.upload(ro.CODE,payload,HASH)
        ro.RamEnvelope.upload(ro.REQUEST_ADDR,ro.request(ro.INFO,1),HASH)
        ro.RamEnvelope.execute(ro.CODE)
        for address in (0,0x04022018,0x07090100,ro.DATA,ro.CODE+4):
            with self.assertRaises(ro.Rejected): ro.RamEnvelope.upload(address,payload,HASH)
            with self.assertRaises(ro.Rejected): ro.RamEnvelope.execute(address)
        with self.assertRaises(ro.Rejected): ro.RamEnvelope.upload(ro.CODE,b'wrong',HASH)
        with self.assertRaises(ro.Rejected): ro.RamEnvelope.upload(ro.REQUEST_ADDR,bytes(32),HASH)

    def test_chunked_read(self):
        usb,client=self.setup_client()
        self.assertEqual(client.read(100,130),usb.disk.read(100,130))
        self.assertEqual([(x[2],x[3]) for x in usb.calls[1:]],[(100,128),(228,2)])

    def test_bounds_before_io(self):
        usb,client=self.setup_client(); before=len(usb.calls)
        for args in ((4096,1),(4095,2),(-1,1),(0,0)):
            with self.assertRaises(ro.Rejected): client.read(*args)
        self.assertEqual(len(usb.calls),before)
        fresh=ro.Client([usb],HASH)
        with self.assertRaises(ro.Rejected): fresh.read(0,1)

    def test_transfer_failures(self):
        for fault in ('status','crc_error','nonce','lba','capacity','area','bus','cid',
                      'reserved','header_crc','short_header','short_data','data_crc','old'):
            with self.subTest(fault=fault):
                usb,client=self.setup_client(); usb.fault=fault
                with self.assertRaises(ro.Rejected): client.read(100,1)

    def test_invalid_identification(self):
        usb=SimulatedUSB(); usb.cid=[0,0,0,0]
        with self.assertRaises(ro.Rejected): ro.Client([usb],HASH).identify()
        usb=SimulatedUSB(); usb.fault='ext'
        with self.assertRaises(ro.Rejected): ro.Client([usb],HASH).identify()

    def test_sequence_does_not_wrap(self):
        usb,client=self.setup_client(); client.sequence=0xFFFFFFFF
        with self.assertRaises(ro.Rejected): client.read(1,1)


class GPTTests(unittest.TestCase):
    def test_valid_primary_backup(self):
        disk=Disk(); table=ro.paired_gpt(disk,disk.capacity)
        self.assertEqual(table.partitions[0].name,'bootloader_a')

    def test_dynamic_array_and_entry_size(self):
        disk=Disk(array_lba=8,entry_size=256)
        self.assertEqual(ro.paired_gpt(disk,disk.capacity).entry_size,256)
        self.assertIn((8,2),disk.calls)

    def test_64bit_lba(self):
        lba=2**32+128
        disk=Disk(capacity=2**32+4096,parts=[('bootloader_a',lba,lba+10)])
        self.assertEqual(ro.paired_gpt(disk,disk.capacity).partitions[0].first,lba)

    def test_header_crc_before_array_read(self):
        disk=Disk(); h=bytearray(disk.sectors[1]); h[24]^=1; disk.sectors[1]=bytes(h)
        with self.assertRaises(ro.Rejected): ro.read_gpt(disk,disk.capacity)
        self.assertEqual(disk.calls,[(0,1),(1,1)])

    def test_table_crc(self):
        disk=Disk(); disk.sectors[disk.array_lba]=bytes(512)
        with self.assertRaises(ro.Rejected): ro.read_gpt(disk,disk.capacity)

    def test_signature_and_mbr(self):
        for lba,offset in ((0,510),(1,0)):
            disk=Disk(); data=bytearray(disk.sectors[lba]); data[offset]=0; disk.sectors[lba]=bytes(data)
            with self.assertRaises(ro.Rejected): ro.read_gpt(disk,disk.capacity)

    def test_hybrid_and_wrong_protective_mbr(self):
        for offset,value in ((466,0x83),(454,2),(458,0)):
            disk=Disk(); mbr=bytearray(disk.sectors[0]);mbr[offset]=value;disk.sectors[0]=bytes(mbr)
            with self.assertRaises(ro.Rejected): ro.read_gpt(disk,disk.capacity)

    def test_header_bounds(self):
        for offset,fmt,value in ((12,'I',513),(20,'I',1),(24,'Q',2),(32,'Q',8),
                                 (72,'Q',0),(72,'Q',4095),(72,'Q',63),(80,'I',0),
                                 (80,'I',4097),(84,'I',129),(84,'I',384)):
            with self.subTest(offset=offset,value=value):
                disk=Disk(); disk.header_change(offset,'<'+fmt,value)
                with self.assertRaises(ro.Rejected): ro.read_gpt(disk,disk.capacity)

    def test_duplicate_and_overlap(self):
        for parts in ([('bootloader_a',128,150),('BOOTLOADER_A',160,180)],
                      [('a',128,180),('b',170,200)], [('a',10,20)], [('a',180,170)]):
            disk=Disk(parts=parts)
            with self.assertRaises(ro.Rejected): ro.read_gpt(disk,disk.capacity)

    def test_duplicate_guid_and_zero_identity(self):
        for zero in (True,False):
            disk=Disk(); disk.entries[144:160]=bytes(16) if zero else disk.entries[16:32]; disk.rebuild()
            with self.assertRaises(ro.Rejected): ro.read_gpt(disk,disk.capacity)

    def test_invalid_name(self):
        disk=Disk(); disk.entries[56:58]=b'\x00\xd8'; disk.rebuild()
        with self.assertRaises(ro.Rejected): ro.read_gpt(disk,disk.capacity)

    def test_backup_mismatch(self):
        disk=Disk(); disk.header_change(56,'<I',999,backup=True)
        with self.assertRaises(ro.Rejected): ro.paired_gpt(disk,disk.capacity)

    def test_short_metadata(self):
        class Short:
            def read(self,*args): return b'0'*511
        with self.assertRaises(ro.Rejected): ro.read_gpt(Short(),4096)


class AcquisitionTests(unittest.TestCase):
    def setup_acquisition(self):
        usb=SimulatedUSB(); client=ro.Client([usb],HASH); client.identify()
        return usb,client,ro.paired_gpt(client,usb.disk.capacity)

    def test_verified_acquisition_and_journal(self):
        usb,client,table=self.setup_acquisition()
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'logo.img'; result=ro.acquire_partition(client,table,'bootloader_a',path)
            self.assertEqual(path.read_bytes(),usb.disk.read(128,133))
            self.assertEqual(result['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            events=[json.loads(s) for s in path.with_name('logo.img.jsonl').read_text().splitlines()]
            self.assertEqual([x['event'] for x in events],['start','block','block','complete'])

    def test_existing_files_never_overwritten(self):
        for suffix in ('','.partial','.jsonl'):
            usb,client,table=self.setup_acquisition()
            with tempfile.TemporaryDirectory() as d:
                path=Path(d)/'logo.img'; existing=Path(str(path)+suffix); existing.write_bytes(b'preserve')
                with self.assertRaises(ro.Rejected): ro.acquire_partition(client,table,'bootloader_a',path)
                self.assertEqual(existing.read_bytes(),b'preserve')

    def test_sensitive_partition_refused_before_io(self):
        usb,client,table=self.setup_acquisition(); before=len(usb.calls)
        for name in ('userdata','frp','private','metadata','env_a','../bootloader_a'):
            with self.assertRaises(ro.Rejected): ro.acquire_partition(client,table,name,Path('unused'))
        self.assertEqual(len(usb.calls),before)

    def test_changed_gpt_refused(self):
        usb,client,table=self.setup_acquisition(); usb.disk.header_change(56,'<I',999)
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ro.Rejected):
            ro.acquire_partition(client,table,'bootloader_a',Path(d)/'x')

    def test_failed_double_read_stays_partial(self):
        usb,client,table=self.setup_acquisition()
        original=usb.exchange; seen=0
        def different(raw):
            nonlocal seen
            values=ro.REQUEST.unpack(raw)
            if values[2]==ro.READ and values[4]==128:
                seen+=1
                if seen==2: usb.fault='data_crc'
            return original(raw)
        usb.exchange=different
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'x'
            with self.assertRaises(ro.Rejected): ro.acquire_partition(client,table,'bootloader_a',path)
            self.assertFalse(path.exists()); self.assertTrue(Path(str(path)+'.partial').exists())
            self.assertIn('failed',Path(str(path)+'.jsonl').read_text())

    def test_valid_crc_but_inconsistent_double_read(self):
        usb,client,table=self.setup_acquisition(); original=usb.exchange; seen=0
        def different(raw):
            nonlocal seen
            header,data=original(raw); fields=list(ro.RESPONSE.unpack(header))
            if fields[4]==128:
                seen+=1
                if seen==2:
                    data=bytes([data[0]^1])+data[1:];fields[15]=ro.crc(data);fields[16]=0
                    fields[16]=ro.crc(ro.RESPONSE.pack(*fields));header=ro.RESPONSE.pack(*fields)
            return header,data
        usb.exchange=different
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'x'
            with self.assertRaisesRegex(ro.Rejected,'independent reads differ'):
                ro.acquire_partition(client,table,'bootloader_a',path)
            self.assertFalse(path.exists())

    def test_cli_has_no_device_transport(self):
        import subprocess
        result=subprocess.run([sys.executable,str(Path(ro.__file__)),'--help'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0); self.assertIn('No tablet/USB support',result.stdout)


if __name__=='__main__': unittest.main(verbosity=2)
