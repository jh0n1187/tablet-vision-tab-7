"""One-shot FEL VERSION preparation. CLI is preview-only; physical I/O locked.

No payload, arbitrary command/address, reboot, reset or storage operations.
The wire transaction is a fixed transcript, not a general FEL transport.
"""
import json
import re
import struct
import time

LIVE_VERSION_ENABLED = False
_SYSTEM_API = None
GUID = '431cd5b9-df93-4b87-b9eb-da404040f0c4'
SOC = 0x00189000
ACK = b'AWUS' + bytes(9)
REQUEST = struct.pack('<4I', 1, 0, 0, 0)
REPLY = struct.Struct('<8sIIHBBI8s')


class Rejected(RuntimeError):
    pass


def _header(operation, length):
    return struct.pack('<8sIIHI10s', b'AWUC' + bytes(4), length,
                       0x0C000000, operation, length, bytes(10))


# Immutable, exact byte sequence. No caller-supplied bytes can reach the pipe.
STEPS = (('write', _header(0x12, 16)), ('write', REQUEST),
         ('ack', 13), ('write', _header(0x11, 32)), ('version', 32),
         ('ack', 13), ('write', _header(0x11, 8)), ('status', 8), ('ack', 13))


def validate_path(path):
    if not isinstance(path, str) or not re.fullmatch(
            r'\\\\\?\\usb#vid_1f3a&pid_efe8#[^#\s/\\]+#\{' + GUID + r'\}',
            path, re.IGNORECASE):
        raise Rejected('Explicit EFE8 path with reviewed interface GUID required')


class VersionOnce:
    """Pipe must already belong to the explicitly selected/verified EFE8 node."""
    def __init__(self, pipe, *, clock=time.monotonic):
        self.__pipe = pipe
        self.__clock = clock
        self.__used = False
        self.audit = []

    def query(self):
        if self.__used:
            raise Rejected('One attempt consumed; no retry, including after failure')
        self.__used = True
        start = self.__clock()
        raw = None
        try:
            for kind, value in STEPS:
                if self.__clock() - start > 1.0:
                    raise Rejected('Transaction deadline exceeded')
                self.audit.append({'operation': kind, 'length': len(value) if kind == 'write' else value})
                if kind == 'write':
                    if self.__pipe.write(value) != len(value):
                        raise Rejected('Short write; no retry')
                    continue
                data = self.__pipe.read(value)
                if type(data) is bytes:
                    self.audit[-1]['received_hex'] = data.hex()
                if type(data) is not bytes or len(data) != value:
                    raise Rejected('Short/invalid read; no retry')
                if kind == 'ack' and data != ACK:
                    raise Rejected('Unexpected AWUS acknowledgement')
                if kind == 'status' and data != bytes(8):
                    raise Rejected('Nonzero/unknown FEL status')
                if kind == 'version':
                    raw = data
            if self.__clock() - start > 1.0:
                raise Rejected('Transaction deadline exceeded after final read')
            magic, soc, firmware, protocol, flags, length, scratch, reserved = REPLY.unpack(raw)
            result = {'magic_hex': magic.hex(), 'soc_raw': soc, 'firmware': firmware,
                      'protocol': protocol, 'flags': flags, 'length': length,
                      'scratchpad': scratch, 'reserved_hex': reserved.hex(),
                      'raw_hex': raw.hex(), 'compatible_a523': magic == b'AWUSBFEX' and soc == SOC and protocol == 1,
                      'elapsed_ms': (self.__clock() - start) * 1000}
            if not result['compatible_a523']:
                error = Rejected('Unknown FEL identity/protocol; raw response retained')
                error.result = result
                raise error
            return result
        finally:
            self.__pipe.close()

    def native_io_snapshot(self):
        getter=getattr(self.__pipe,'native_io_snapshot',None)
        return getter() if getter else []


class _NativeVersionPipe:
    """Only the one-shot object receives this low-level pipe; no live CLI."""
    def __init__(self, path, *, _test_api=None):
        validate_path(path)
        if _test_api is None and not LIVE_VERSION_ENABLED:
            raise Rejected('Physical VERSION disabled pending review and execution authorization')
        if _test_api is None:
            if _SYSTEM_API is None:
                raise Rejected('Preload system bindings before arming; no DLL load during arrival')
            _test_api = _SYSTEM_API
        self.__api = _test_api
        self.__file = self.__handle = None
        self.__closed = False
        try:
            self.__file = self.__api.open(path)
            self.__handle = self.__api.initialize(self.__file)
            desc = self.__api.descriptor(self.__handle)
            if len(desc) != 18 or desc[:2] != b'\x12\x01' or desc[8:12] != b'\x3a\x1f\xe8\xef':
                raise Rejected('Unexpected USB descriptor')
            interface, alt, pipes = self.__api.pipes(self.__handle)
            shape = sorted((p.pipe_id, p.pipe_type, p.max_packet) for p in pipes)
            if (interface, alt) != (0, 0) or shape != [(2, 2, 512), (0x81, 2, 512)]:
                error = Rejected('Unexpected EFE8 endpoint configuration')
                error.profile = {'interface': interface, 'alternate': alt, 'pipes': shape}
                raise error
            # Host-side policies; no clear/reset/abort/flush or power-policy calls.
            for endpoint in (2, 0x81):
                self.__api.configure(self.__handle, endpoint)
                self.__api.set_timeout(self.__handle, endpoint, 100)
        except BaseException:
            self.close()
            raise

    def write(self, data):
        return self.__api.write(self.__handle, 2, data)

    def read(self, length):
        return self.__api.read(self.__handle, 0x81, length)

    def native_io_snapshot(self):
        return [dict(entry) for entry in getattr(self.__api,'io_trace',[])]

    def close(self):
        if self.__closed:
            return
        self.__closed = True
        try:
            if self.__handle is not None:
                self.__api.free(self.__handle)
        finally:
            self.__handle = None
            if self.__file is not None:
                try:
                    self.__api.close(self.__file)
                finally:
                    self.__file = None


def prepare_native(path):
    """Not called by CLI. Gate rejects before loading DLLs/opening the device."""
    return VersionOnce(_NativeVersionPipe(path))


def preload_system_bindings():
    """PC-only symbol/layout preparation. Does not open or initialize a device."""
    global _SYSTEM_API
    import ctypes
    from winusb_backend import _NativeAPI
    api = _NativeAPI()
    sizes = tuple(ctypes.sizeof(t) for t in (api.w.ULONG, api.w.HANDLE, api.Interface, api.Pipe))
    if sizes != (4, 8, 9, 12):
        raise Rejected('Unexpected x64 Windows ABI layouts')
    _SYSTEM_API = api
    api.diagnostics_enabled = True
    api.io_trace = []
    return {'symbols_bound': True, 'layouts': sizes, 'device_handles_opened': False,
            'physical_version_enabled': LIVE_VERSION_ENABLED}


class ArmedVersion:
    """Arrival callback policy only; no discovery, thread, timer or live CLI.

    Consumes the attempt BEFORE opening: a failed first open cannot target
    the second EFE8 pulse. A future watcher must supply the reviewed exact path.
    """
    def __init__(self, expected_path, *, factory=prepare_native):
        validate_path(expected_path)
        self.__expected = expected_path.casefold()
        self.__factory = factory
        self.__consumed = False

    def arrival(self, path):
        if not isinstance(path, str) or path.casefold() != self.__expected:
            return None
        if self.__consumed:
            raise Rejected('Arrival attempt already consumed; no reopen')
        self.__consumed = True
        return self.__factory(path).query()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()  # No device, live, payload or reboot switches accepted.
    print(json.dumps({'preview_only': True, 'physical_enabled': LIVE_VERSION_ENABLED,
                      'fel_request_hex': REQUEST.hex(), 'maximum_version_queries': 1,
                      'transcript': [{'operation': k, 'hex': v.hex()} if k == 'write'
                                     else {'operation': k, 'length': v} for k, v in STEPS]}, indent=2))
