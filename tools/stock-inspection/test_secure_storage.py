"""Synthetic local bytes only. The reference patcher is not executed."""
import struct
import unittest
from inspect_secure_storage import inspect,crc,MAGIC,BLOCK,TOTAL,CRC_OFFSET

def fixture(entries):
    data=bytearray(TOTAL);m=bytearray(BLOCK);pos=0
    for index,(name,payload,encrypted) in enumerate(entries):
        encoded=(name+':3996\0').encode();m[pos:pos+len(encoded)]=encoded;pos+=len(encoded)
        item=bytearray(BLOCK);struct.pack_into('<I',item,0,MAGIC)
        item[8:8+len(name)]=name.encode();struct.pack_into('<I',item,72,0x86734716 if encrypted else 0)
        struct.pack_into('<I',item,76,1);struct.pack_into('<I',item,96,len(payload));item[100:100+len(payload)]=payload
        struct.pack_into('<I',item,CRC_OFFSET,crc(item[:CRC_OFFSET]))
        offset=2*BLOCK+index*2*BLOCK;data[offset:offset+BLOCK]=item;data[offset+BLOCK:offset+2*BLOCK]=item
    struct.pack_into('<I',m,4088,MAGIC);struct.pack_into('<I',m,4092,crc(m[:4092]))
    data[:BLOCK]=m;data[BLOCK:2*BLOCK]=m;return data

def remap(data,blob):
    m=bytearray(BLOCK);m[:len(blob)]=blob;struct.pack_into('<I',m,4088,MAGIC);struct.pack_into('<I',m,4092,crc(m[:4092]))
    data[:BLOCK]=m;data[BLOCK:2*BLOCK]=m;return data

class Validation(unittest.TestCase):
    def setUp(self):self.data=fixture([('fastboot_status_flag',b'unlocked',False),('device_unlock',b'unlock',False)])
    def test_valid_fixture_is_not_device_unlock_proof(self):
        r=inspect(self.data);self.assertTrue(r['both_expected_plain_flags']);self.assertFalse(r['device_unlock_confirmed']);self.assertFalse(r['safe_to_patch_or_flash'])
    def test_absent_flags(self):self.assertFalse(inspect(fixture([]))['both_expected_plain_flags'])
    def test_names_alone_not_enough(self):self.assertFalse(inspect(fixture([('fastboot_status_flag',b'locked',False),('device_unlock',b'unlock',False)]))['both_expected_plain_flags'])
    def test_encrypted_flags_not_interpreted(self):self.assertFalse(inspect(fixture([('fastboot_status_flag',b'unlocked',True),('device_unlock',b'unlock',False)]))['both_expected_plain_flags'])
    def test_payloads_not_disclosed(self):self.assertNotIn('SECRET_PAYLOAD',str(inspect(fixture([('private',b'SECRET_PAYLOAD',False)]))))
    def test_wrong_sizes(self):
        for n in (0,4096,TOTAL-1,TOTAL+1):
            with self.subTest(n=n),self.assertRaises(ValueError):inspect(bytes(n))
    def test_corrupt_map(self):
        self.data[30]^=1
        with self.assertRaises(ValueError):inspect(self.data)
    def test_map_backup(self):
        self.data[BLOCK]^=1
        with self.assertRaises(ValueError):inspect(self.data)
    def test_corrupt_item_both_copies(self):
        self.data[2*BLOCK+100]^=1;self.data[3*BLOCK+100]^=1
        with self.assertRaises(ValueError):inspect(self.data)
    def test_item_backup(self):
        self.data[3*BLOCK+100]^=1
        with self.assertRaises(ValueError):inspect(self.data)
    def test_duplicate_names(self):
        with self.assertRaises(ValueError):inspect(fixture([('same',b'a',False),('same',b'b',False)]))
    def test_more_entries_than_pairs(self):
        blob=b''.join(f'n{i}:3996\0'.encode() for i in range(16))
        with self.assertRaises(ValueError):inspect(remap(bytearray(TOTAL),blob))
    def test_map_item_name_mismatch(self):
        with self.assertRaises(ValueError):inspect(remap(self.data,b'other:3996\0device_unlock:3996\0'))
    def test_unterminated_map(self):
        self.data[:4088]=b'A'*4088;struct.pack_into('<I',self.data,4092,crc(self.data[:4092]));self.data[BLOCK:2*BLOCK]=self.data[:BLOCK]
        with self.assertRaises(ValueError):inspect(self.data)
    def test_bad_declared_size(self):
        for value in ('0','4097','-1','many'):
            with self.subTest(value=value),self.assertRaises(ValueError):inspect(remap(self.data,('a:'+value+'\0').encode()))
    def test_oversize_payload(self):
        for off in (2*BLOCK,3*BLOCK):
            struct.pack_into('<I',self.data,off+96,3073);struct.pack_into('<I',self.data,off+CRC_OFFSET,crc(self.data[off:off+CRC_OFFSET]))
        with self.assertRaises(ValueError):inspect(self.data)

if __name__=='__main__':unittest.main()
