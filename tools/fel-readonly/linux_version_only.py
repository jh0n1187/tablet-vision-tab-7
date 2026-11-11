"""Linux USBFS one-shot FEL VERSION. CLI is preview-only; physical I/O locked.

stdlib only. No discovery, payload, reset, detach, set-configuration or reboot.
The native API is constructed only behind the disabled physical gate.
"""
import ctypes
import json
import re
import struct
import sys
import time

from version_only import VersionOnce, Rejected, STEPS

LIVE_LINUX_VERSION_ENABLED = False


class Bulk(ctypes.Structure):
    _fields_ = [('ep', ctypes.c_uint), ('length', ctypes.c_uint),
                ('timeout', ctypes.c_uint), ('data', ctypes.c_void_p)]


def abi_profile():
    if ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(Bulk) != 24 or Bulk.data.offset != 16:
        raise Rejected('Only reviewed Linux 64-bit USBFS ABI supported')
    return {'bulk_size': 24, 'data_offset': 16, 'bulk_ioctl': 0xC0185502,
            'claim_ioctl': 0x8004550F, 'release_ioctl': 0x80045510}


def validate_target(path, sysfs):
    match = re.fullmatch(r'/dev/bus/usb/([0-9]{3})/([0-9]{3})', path)
    node = re.fullmatch(r'/sys/bus/usb/devices/([1-9][0-9]*)-([1-9][0-9]*(?:\.[1-9][0-9]*)*)', sysfs)
    if not match or not node:
        raise Rejected('Explicit USBFS node and physical sysfs port required')
    bus, device = map(int, match.groups())
    if not 1 <= bus <= 999 or not 1 <= device <= 127 or int(node[1]) != bus:
        raise Rejected('Bus/address mismatch or out of range')
    return bus, device


def validate_descriptors(raw):
    if len(raw) < 18 or raw[:2] != b'\x12\x01' or raw[8:12] != b'\x3a\x1f\xe8\xef' or raw[17] != 1:
        raise Rejected('Unexpected cached device descriptor')
    pos = 18
    config = interface = None
    endpoints = []
    while pos < len(raw):
        if pos + 2 > len(raw) or raw[pos] < 2 or pos + raw[pos] > len(raw):
            raise Rejected('Malformed cached descriptors')
        n, kind = raw[pos:pos + 2]
        data = raw[pos:pos + n]
        if kind == 2:
            if config is not None or n != 9 or data[4] != 1 or data[5] != 1:
                raise Rejected('Unexpected configuration')
            config = struct.unpack_from('<H', data, 2)[0]
            if config != len(raw) - 18:
                raise Rejected('Configuration total length mismatch')
        elif kind == 4:
            if config is None or interface is not None or n != 9 or tuple(data[2:5]) != (0, 0, 2):
                raise Rejected('Unexpected interface/alternate')
            interface = 0
        elif kind == 5:
            if interface is None or n != 7:
                raise Rejected('Unexpected endpoint descriptor')
            endpoints.append((data[2], data[3], struct.unpack_from('<H', data, 4)[0]))
        else:
            raise Rejected('Unreviewed descriptor type')
        pos += n
    if config is None or interface != 0 or sorted(endpoints) != [(2, 2, 512), (0x81, 2, 512)]:
        raise Rejected('Expected exactly OUT02/IN81 bulk512')


class _UsbfsAPI:
    def __init__(self):
        import platform
        if sys.platform != 'linux' or platform.machine().lower() not in ('x86_64', 'aarch64') or sys.byteorder != 'little':
            raise Rejected('Reviewed native platform: little-endian Linux x86_64/aarch64')
        self.abi = abi_profile()
        import os
        self.os = os
        # Python 3.14+ fcntl.ioctl retries EINTR automatically. Call libc once
        # instead: an interrupted bulk transfer must never be resubmitted.
        self.libc = ctypes.CDLL(None, use_errno=True)
        self._sys_ioctl = self.libc.ioctl
        self._sys_ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
        self._sys_ioctl.restype = ctypes.c_int

    def ioctl(self, fd, code, raw):
        argument = ctypes.create_string_buffer(raw)
        result = self._sys_ioctl(fd, code, ctypes.addressof(argument))
        if result < 0:
            number = ctypes.get_errno()
            raise OSError(number, 'USBFS ioctl failed; no retry')
        return result

    def metadata(self, sysfs):
        from pathlib import Path
        base = Path(sysfs)
        def value(name):
            with (base / name).open('r', encoding='ascii') as stream:
                text = stream.read(128)
            if len(text) >= 128:
                raise Rejected('Oversized sysfs metadata')
            return text.strip()
        return (int(value('busnum')), int(value('devnum')), value('idVendor'),
                value('idProduct'), value('bConfigurationValue'),
                value('speed'), value('bNumConfigurations'))

    def open(self, path, bus, device):
        import stat
        fd = self.os.open(path, self.os.O_RDWR | self.os.O_CLOEXEC | self.os.O_NOFOLLOW)
        try:
            info = self.os.fstat(fd)
            if not stat.S_ISCHR(info.st_mode) or self.os.major(info.st_rdev) != 189 or self.os.minor(info.st_rdev) != (bus - 1) * 128 + device - 1:
                raise Rejected('Unexpected USBFS device number/type')
            return fd
        except BaseException:
            self.os.close(fd)
            raise

    def descriptors(self, fd):
        # USBFS read returns cached descriptors; no CONTROL ioctl is exposed.
        return self.os.read(fd, 4096)

    def claim(self, fd):
        self.ioctl(fd, self.abi['claim_ioctl'], struct.pack('=I', 0))

    def release(self, fd):
        self.ioctl(fd, self.abi['release_ioctl'], struct.pack('=I', 0))

    def bulk(self, fd, endpoint, data_or_count, timeout):
        count = data_or_count if isinstance(data_or_count, int) else len(data_or_count)
        data = ctypes.create_string_buffer(count + 16)
        ctypes.memset(ctypes.addressof(data) + count, 0xD3, 16)
        if endpoint == 2:
            ctypes.memmove(data, data_or_count, count)
        else:
            ctypes.memset(data, 0xA5, count)
        request = Bulk(endpoint, count, timeout, ctypes.addressof(data))
        packed = bytes(request)
        actual = self.ioctl(fd, self.abi['bulk_ioctl'], packed)
        if data.raw[count:] != b'\xd3' * 16:
            raise Rejected('USBFS buffer guard changed')
        if not 0 <= actual <= count:
            raise Rejected('Invalid USBFS transfer count')
        return actual if endpoint == 2 else data.raw[:actual]

    def close(self, fd):
        self.os.close(fd)


class _LinuxVersionPipe:
    def __init__(self, path, sysfs, *, _test_api=None, clock=time.monotonic):
        # No sysfs reads, libc bindings or device opens before the physical gate.
        if _test_api is None and not LIVE_LINUX_VERSION_ENABLED:
            raise Rejected('Physical Linux VERSION disabled')
        bus, device = validate_target(path, sysfs)
        self.api = _test_api if _test_api is not None else _UsbfsAPI()
        self.fd = None
        self.claimed = False
        self.closed = False
        self.step = 0
        self.clock = clock
        self.start = clock()
        self.trace = []
        expected = (bus, device, '1f3a', 'efe8', '1', '480', '1')
        try:
            if self.api.metadata(sysfs) != expected:
                raise Rejected('Wrong target identity/configuration/speed')
            self.fd = self.api.open(path, bus, device)
            validate_descriptors(self.api.descriptors(self.fd))
            self.api.claim(self.fd)  # Refuse busy interface; never detach a driver.
            self.claimed = True
            if self.api.metadata(sysfs) != expected:
                raise Rejected('Target changed during open')
        except BaseException:
            self.close()
            raise

    def _transfer(self, write, value):
        if self.closed or self.step >= len(STEPS):
            raise Rejected('Closed/consumed Linux VERSION pipe')
        kind, expected = STEPS[self.step]
        if (kind == 'write') != write or value != expected or (write and type(value) is not bytes):
            self.close()
            raise Rejected('Only fixed VERSION transcript allowed')
        self.step += 1  # Consume before I/O; an error cannot be retried.
        remaining = 1.0 - (self.clock() - self.start)
        if remaining <= 0:
            self.close()
            raise Rejected('Linux VERSION deadline exceeded')
        entry = {'endpoint': 2 if write else 0x81, 'requested': len(value) if write else value}
        self.trace.append(entry)
        try:
            result = self.api.bulk(self.fd, entry['endpoint'], value, max(1, min(100, int(remaining * 1000))))
            if (write and result != len(value)) or (not write and (type(result) is not bytes or len(result) != value)):
                raise Rejected('Short/invalid USBFS transfer; no retry')
            entry['result'] = result if write else result.hex()
            if not write and kind in ('ack', 'status') and result != (b'AWUS' + bytes(9) if kind == 'ack' else bytes(8)):
                raise Rejected('Invalid ACK/status; no further USB transfers')
            return result
        except BaseException as error:
            entry['error_type'] = type(error).__name__
            self.close()
            raise

    def write(self, data):
        return self._transfer(True, data)

    def read(self, count):
        return self._transfer(False, count)

    def native_io_snapshot(self):
        return [dict(item) for item in self.trace]

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.claimed:
                self.claimed = False
                self.api.release(self.fd)
        finally:
            if self.fd is not None:
                fd, self.fd = self.fd, None
                self.api.close(fd)


def prepare_linux(path, sysfs):
    return VersionOnce(_LinuxVersionPipe(path, sysfs))


class ArmedLinuxVersion:
    """Explicit arrival target only; consumes before opening, never retries."""
    def __init__(self, path, sysfs, *, factory=prepare_linux):
        validate_target(path, sysfs)
        self.target = (path, sysfs)
        self.factory = factory
        self.consumed = False

    def arrival(self, path, sysfs):
        if (path, sysfs) != self.target:
            return None
        if self.consumed:
            raise Rejected('Linux arrival attempt already consumed')
        self.consumed = True
        return self.factory(path, sysfs).query()


def main():
    import argparse
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps({'preview_only': True, 'physical_enabled': LIVE_LINUX_VERSION_ENABLED,
                      'maximum_queries': 1, 'abi': abi_profile(),
                      'operations': [{'kind': k, 'hex': v.hex()} if k == 'write' else {'kind': k, 'length': v} for k, v in STEPS]}, indent=2))


if __name__ == '__main__':
    main()
