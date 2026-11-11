"""One-shot, read-only fastbootd fetch for this T307F; default is preview.

No flash/download/erase/unlock/reboot or arbitrary protocol commands are exposed.
This tests the device fetch handler even when SDK max-fetch-size preflight fails.
"""
import os
import argparse
import ctypes as c
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
SERIAL = os.environ.get('T307F_SERIAL', 'SET_T307F_SERIAL_BEFORE_DEVICE_ACCESS')
GUID = 'f72fe0d4-cbcb-407d-8814-9ed673d0dd6b'
INSTANCE = 'USB\\VID_18D1&PID_4EE0\\' + SERIAL
FETCH = b'fetch:vendor_boot_a:0:33554432'
SIZE = 33554432


def response(pipe, audit):
    for _ in range(32):
        data = pipe.read(256)
        if not 4 <= len(data) <= 256 or data[:4] not in (b'INFO', b'FAIL', b'OKAY', b'DATA'):
            raise ValueError('Invalid fastboot response')
        audit.append({'response': data.decode('ascii', errors='replace')})
        if data[:4] != b'INFO':
            return data[:4], data[4:]
    raise ValueError('INFO response budget exhausted')


def acquire(pipe, stream, audit):
    for command, expected in ((b'getvar:is-userspace', b'yes'),
                              (b'getvar:product', b'T307F'),
                              (b'getvar:unlocked', b'yes')):
        pipe.write(command)
        audit.append({'command': command.decode()})
        status, message = response(pipe, audit)
        if status != b'OKAY' or message.strip() != expected:
            raise ValueError('Fastbootd identity/state check failed')
    pipe.write(FETCH)
    audit.append({'command': FETCH.decode()})
    status, message = response(pipe, audit)
    if status == b'FAIL':
        return {'acquired': False, 'device_refusal': message.decode(errors='replace')}
    if status != b'DATA' or len(message) != 8 or int(message, 16) != SIZE:
        raise ValueError('Unexpected fetch size/status')
    digest = hashlib.sha256()
    remaining = SIZE
    while remaining:
        block = pipe.read(min(1048576, remaining))
        if not block or len(block) > remaining:
            raise ValueError('Invalid or truncated partition transfer')
        stream.write(block)
        digest.update(block)
        remaining -= len(block)
    status, message = response(pipe, audit)
    if status != b'OKAY':
        raise ValueError('Fetch completion failed')
    return {'acquired': True, 'bytes': SIZE, 'sha256': digest.hexdigest()}


def exact_interface():
    dll = c.WinDLL('cfgmgr32', use_last_error=True)
    guid = (c.c_ubyte * 16).from_buffer_copy(uuid.UUID(GUID).bytes_le)
    size = dll.CM_Get_Device_Interface_List_SizeW
    size.argtypes = [c.POINTER(c.c_uint32), c.c_void_p, c.c_wchar_p, c.c_uint32]
    size.restype = c.c_uint32
    get = dll.CM_Get_Device_Interface_ListW
    get.argtypes = [c.c_void_p, c.c_wchar_p, c.c_void_p, c.c_uint32, c.c_uint32]
    get.restype = c.c_uint32
    count = c.c_uint32()
    if size(c.byref(count), c.byref(guid), INSTANCE, 0) or not 2 <= count.value <= 65536:
        raise ValueError('Exact connected interface unavailable')
    buffer = c.create_unicode_buffer(count.value)
    if get(c.byref(guid), INSTANCE, buffer, count.value, 0):
        raise ValueError('Interface metadata query failed')
    paths = [p for p in ''.join(buffer).split('\0') if p]
    prefix = '\\\\?\\usb#vid_18d1&pid_4ee0#' + SERIAL.lower() + '#'
    if len(paths) != 1 or not paths[0].lower().startswith(prefix):
        raise ValueError('Ambiguous/wrong interface')
    return paths[0]


class NativePipe:
    def __init__(self):
        sys.path.insert(0, str(ROOT / 'tools/fel-readonly'))
        import winusb_backend as binding
        if binding.LIVE_USB_ENABLED:
            raise ValueError('Unexpected generic FEL gate')
        self.api = binding._NativeAPI()
        self.file = self.handle = None
        try:
            self.file = self.api.open(exact_interface())
            self.handle = self.api.initialize(self.file)
            descriptor = self.api.descriptor(self.handle)
            if descriptor[8:12] != bytes.fromhex('d118e04e'):
                raise ValueError('Descriptor identity differs')
            number, alternate, pipes = self.api.pipes(self.handle)
            shape = sorted((p.pipe_id, p.pipe_type, p.max_packet) for p in pipes)
            if number != 0 or alternate != 0 or shape != [(1, 2, 512), (129, 2, 512)]:
                raise ValueError('Unexpected fastbootd endpoint profile: ' + repr(shape))
            for endpoint in (1, 129):
                self.api.configure(self.handle, endpoint)
        except BaseException:
            self.close()
            raise

    def write(self, command):
        allowed = (b'getvar:is-userspace', b'getvar:product', b'getvar:unlocked', FETCH)
        if command not in allowed:
            raise ValueError('Command outside read-only allowlist')
        if self.api.write(self.handle, 1, command) != len(command):
            raise ValueError('Short command transfer')

    def read(self, length):
        return self.api.read(self.handle, 129, length)

    def close(self):
        try:
            if self.handle is not None:
                self.api.free(self.handle)
        finally:
            self.handle = None
            if self.file is not None:
                self.api.close(self.file)
                self.file = None


def self_test():
    import io
    class Fake:
        def __init__(self, values):
            self.values = iter(values)
            self.writes = []
        def read(self, length):
            return next(self.values)
        def write(self, command):
            self.writes.append(command)
    checks = 0
    fake = Fake([b'OKAYyes', b'OKAYT307F', b'OKAYyes', b'FAILfetch not allowed'])
    assert acquire(fake, io.BytesIO(), []) == {'acquired': False, 'device_refusal': 'fetch not allowed'}
    assert fake.writes[-1] == FETCH
    checks += 1
    for bad in (b'', b'BOGUS', b'DATAFFFFFFFF'):
        fake = Fake([b'OKAYyes', b'OKAYT307F', b'OKAYyes', bad])
        try:
            acquire(fake, io.BytesIO(), [])
        except ValueError:
            checks += 1
        else:
            raise AssertionError('Malformed response accepted')
    fake = Fake([b'OKAYno'])
    try:
        acquire(fake, io.BytesIO(), [])
    except ValueError:
        assert fake.writes == [b'getvar:is-userspace']
        checks += 1
    else:
        raise AssertionError('Bootloader accepted as userspace')
    print(json.dumps({'offline_checks_passed': checks, 'physical_io': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--acquire-reviewed-vendor-boot', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.acquire_reviewed_vendor_boot:
        print(json.dumps({'preview_only': True, 'command': FETCH.decode(),
                          'partition_writes': False, 'serial': SERIAL}))
        return
    out = ROOT / 'analise-firmware/desbloqueio-T307F' / ('direct-fetch-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir()
    result = {'partition_writes': False, 'audit': []}
    pipe = None
    try:
        pipe = NativePipe()
        with (out / 'vendor_boot_a.img.partial').open('xb') as stream:
            result.update(acquire(pipe, stream, result['audit']))
        if result['acquired']:
            (out / 'vendor_boot_a.img.partial').rename(out / 'vendor_boot_a.img')
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
    finally:
        if pipe is not None:
            pipe.close()
        (out / 'result.json').write_text(json.dumps(result, indent=2))
    print(str(out))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
