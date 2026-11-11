"""Offline, read-only validator for the *reference* A523 Secure Storage format.
No patch generation, raw-device I/O, transport imports or unlock operation.
Matching this format does not establish the T307F address or unlock compatibility.
"""
import binascii
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import sys

MAGIC=0x17253948
BLOCK=4096
TOTAL=131072
PAYLOAD=3072
CRC_OFFSET=3172
FLAGS={'fastboot_status_flag':b'unlocked','device_unlock':b'unlock'}

def crc(data):return binascii.crc32(data)&0xffffffff
def u32(data,offset):return struct.unpack_from('<I',data,offset)[0]

def inspect(data):
    if len(data)!=TOTAL:raise ValueError('Expected exact 128 KiB reference-format capture')
    primary,backup=data[:BLOCK],data[BLOCK:2*BLOCK]
    if primary!=backup:raise ValueError('Map backup mismatch')
    if u32(primary,4088)!=MAGIC or u32(primary,4092)!=crc(primary[:4092]):raise ValueError('Map magic/CRC mismatch')
    entries=[];names=set();pos=0
    while pos<4088 and primary[pos]:
        end=primary.find(b'\0',pos,4088)
        if end<0:raise ValueError('Map entry has no bounded terminator')
        try:entry=primary[pos:end].decode('ascii')
        except UnicodeDecodeError:raise ValueError('Non-ASCII map entry') from None
        match=re.fullmatch(r'([A-Za-z0-9_.-]{1,63}):([0-9]{1,5})',entry)
        if not match:raise ValueError('Malformed map entry')
        name,size=match[1],int(match[2])
        if name in names or not 1<=size<=BLOCK:raise ValueError('Duplicate name or invalid declared size')
        entries.append((name,size));names.add(name);pos=end+1
        if 2*BLOCK+len(entries)*2*BLOCK>TOTAL:raise ValueError('Item pairs exceed capture; reference supports at most 15')
    if pos>=4088 or any(primary[pos:4088]):raise ValueError('Map termination/padding invalid')
    flag_states={n:'absent' for n in FLAGS}
    encrypted=0
    for index,(name,size) in enumerate(entries):
        offset=2*BLOCK+index*2*BLOCK
        item=data[offset:offset+BLOCK];copy=data[offset+BLOCK:offset+2*BLOCK]
        if item!=copy:raise ValueError('Item backup mismatch')
        if u32(item,0)!=MAGIC or u32(item,CRC_OFFSET)!=crc(item[:CRC_OFFSET]):raise ValueError('Item magic/CRC mismatch')
        encoded=item[8:72]
        null=encoded.find(b'\0')
        if null<0 or any(encoded[null:]):raise ValueError('Invalid bounded item name')
        if encoded[:null].decode('ascii',errors='strict')!=name:raise ValueError('Item/map name mismatch')
        length=u32(item,96)
        if length>PAYLOAD:raise ValueError('Payload length exceeds CRC-covered payload area')
        encryption=u32(item,72)
        if encryption not in (0,0x86734716):raise ValueError('Unknown encryption marker; review required')
        encrypted+=encryption!=0
        if name in FLAGS:
            payload=item[100:100+length]
            # Do not infer unlocked state from a name alone or from ciphertext.
            flag_states[name]=('encrypted_uninterpreted' if encryption else
                               'expected_plain_value' if payload==FLAGS[name] else
                               'other_plain_value')
    used=2*BLOCK+len(entries)*2*BLOCK
    return dict(matches_reference_format=True,item_count=len(entries),encrypted_item_count=encrypted,
                map_and_item_backups_match=True,crc_checks_passed=True,flag_states=flag_states,
                both_expected_plain_flags=all(v=='expected_plain_value' for v in flag_states.values()),
                trailing_bytes_nonzero=any(data[used:]),sha256=hashlib.sha256(data).hexdigest(),
                payloads_disclosed=False,t307f_location_confirmed=False,device_unlock_confirmed=False,
                safe_to_patch_or_flash=False)

def inspect_file(path):
    text=str(path)
    if text.startswith(('\\\\','/dev/')):raise ValueError('Device/UNC path prohibited')
    p=Path(path)
    if p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode):raise ValueError('Regular local file required')
    if p.stat().st_size!=TOTAL:raise ValueError('Reference capture size mismatch')
    with p.open('rb') as f:return inspect(f.read(TOTAL+1))

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: inspect_secure_storage.py LOCAL_CAPTURE_FILE')
    print(json.dumps(inspect_file(sys.argv[1]),ensure_ascii=False,indent=2))
