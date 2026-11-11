"""Windows interface metadata reader and one-shot watcher, no reboot commands.

No work on import. Physical VERSION remains locked by version_only's gate.
"""
import re
import time
import uuid
import version_only as v


class InterfaceMetadata:
    def __init__(self, instance):
        if not isinstance(instance, str) or not re.fullmatch(r'USB\\VID_1F3A&PID_EFE8\\[^\\]+', instance, re.IGNORECASE):
            raise v.Rejected('Explicit reviewed EFE8 instance required')
        import ctypes as c
        import os
        from pathlib import Path
        self.c = c
        self.instance = instance
        self.guid = (c.c_ubyte * 16).from_buffer_copy(uuid.UUID(v.GUID).bytes_le)
        dll = c.WinDLL(str(Path(os.environ['SystemRoot']) / 'System32/cfgmgr32.dll'))
        self.size = dll.CM_Get_Device_Interface_List_SizeW
        self.size.argtypes = [c.POINTER(c.c_uint32), c.c_void_p, c.c_wchar_p, c.c_uint32]
        self.size.restype = c.c_uint32
        self.list = dll.CM_Get_Device_Interface_ListW
        self.list.argtypes = [c.c_void_p, c.c_wchar_p, c.POINTER(c.c_wchar), c.c_uint32, c.c_uint32]
        self.list.restype = c.c_uint32

    def paths(self, *, present=True):
        c = self.c
        flags = 0 if present else 1
        for _ in range(3):  # Metadata-buffer race only, never a USB-command retry.
            count = c.c_uint32()
            rc = self.size(c.byref(count), c.byref(self.guid), self.instance, flags)
            if rc or not 1 <= count.value <= 65536:
                raise v.Rejected('Interface metadata size failed')
            buffer = c.create_unicode_buffer(count.value)
            rc = self.list(c.byref(self.guid), self.instance, buffer, count.value, flags)
            if rc == 0x1A:
                continue
            if rc:
                raise v.Rejected('Interface metadata list failed')
            raw = ''.join(buffer)
            if not raw.endswith('\0\0') and raw != '\0':
                raise v.Rejected('Malformed interface MULTI_SZ')
            paths = [p for p in raw.split('\0') if p]
            for path in paths:
                v.validate_path(path)
            if len(paths) > 1:
                raise v.Rejected('Ambiguous interface set; no first-match selection')
            return paths
        raise v.Rejected('Interface metadata changed repeatedly')


def watch_once(metadata, expected_path, *, factory=v.prepare_native,
               seconds=90, interval=0.005, clock=time.monotonic, sleep=time.sleep, ready=None):
    if factory is v.prepare_native and not v.LIVE_VERSION_ENABLED:
        raise v.Rejected('Physical VERSION disabled; watcher not armed')
    if not 1 <= seconds <= 120 or not 0.005 <= interval <= 0.1:
        raise v.Rejected('Watcher duration/interval outside policy')
    v.validate_path(expected_path)
    if metadata.paths(present=True):
        raise v.Rejected('Expected disconnected starting state; do not probe existing device')
    arm = v.ArmedVersion(expected_path, factory=factory)
    start = clock()
    if ready:
        ready()
    while clock() - start < seconds:
        paths = metadata.paths(present=True)
        if paths:
            if len(paths) != 1 or paths[0].casefold() != expected_path.casefold():
                raise v.Rejected('Arrival differs from reviewed interface')
            return arm.arrival(paths[0])  # Failure propagates, no reopen/retry.
        sleep(interval)
    raise TimeoutError('No matching arrival before deadline; no command sent')
