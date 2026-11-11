"""Linux EFE8 port monitor and usbmon coordination. CLI preview only.

No installation, reboot, payload, driver changes or work on import.
Native metadata monitoring/capture and the VERSION transport have separate gates.
"""
from dataclasses import dataclass
import json
from pathlib import Path
import re
import struct
import time

import linux_version_only as version
from version_only import Rejected

LIVE_LINUX_MONITOR_CAPTURE_ENABLED = False


@dataclass(frozen=True)
class Arrival:
    bus: int
    device: int
    generation: int
    vid: str
    pid: str
    ready: bool

    @property
    def token(self):
        return self.bus, self.device, self.generation

    @property
    def path(self):
        return f'/dev/bus/usb/{self.bus:03d}/{self.device:03d}'


def port_bus(sysfs):
    if not isinstance(sysfs, str):
        raise Rejected('Explicit physical sysfs port required')
    match = re.fullmatch(r'/sys/bus/usb/devices/([1-9][0-9]*)-([1-9][0-9]*(?:\.[1-9][0-9]*)*)', sysfs)
    if not match or not 1 <= int(match[1]) <= 999:
        raise Rejected('Explicit non-root USB port required')
    return int(match[1])


def capture_argv(executable, bus, directory):
    if not isinstance(executable, str) or not re.fullmatch(r'/(?:usr/)?(?:s?bin)/dumpcap', executable):
        raise Rejected('Explicit system dumpcap executable required')
    if type(bus) is not int or not 1 <= bus <= 999:
        raise Rejected('One explicit USB bus required; usbmon0 forbidden')
    return [executable, '-i', f'usbmon{bus}', '-F', 'pcap', '-s', '4096',
            '-B', '8', '-a', 'duration:105', '-a', 'filesize:32768',
            '-w', str(Path(directory) / 'usbmon.pcap')]


def inspect_header(raw):
    if len(raw) < 24:
        return False
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(raw[:4])
    if endian is None:
        raise Rejected('Collector did not create microsecond classic PCAP')
    major, minor, zone, accuracy, snap, link = struct.unpack(endian + 'HHIIII', raw[4:24])
    if (major, minor) != (2, 4) or snap != 4096 or link not in (189, 220):
        raise Rejected('Unexpected collector PCAP snapshot/linktype')
    return True


def drop_counters(text, bus):
    pattern = (r"Packets received/dropped on interface 'usbmon" + str(bus) +
               r"': (\d+)/(\d+) \(pcap:(\d+)/dumpcap:(\d+)/flushed:(\d+)/ps_ifdrop:(\d+)\)")
    matches = re.findall(pattern, text)
    if len(matches) != 1:
        return {'known': False, 'zero_reported_drops': False}
    received, total, pcap, dumpcap, flushed, interface = map(int, matches[0])
    return {'known': total == pcap + dumpcap + flushed, 'received': received,
            'total': total, 'pcap': pcap, 'dumpcap': dumpcap, 'flushed': flushed,
            'interface': interface,
            'zero_reported_drops': total == pcap == dumpcap == flushed == interface == 0}


class _SysfsPort:
    """Read one configured port only; never scan or open /dev/bus/usb."""
    def __init__(self, sysfs):
        if not LIVE_LINUX_MONITOR_CAPTURE_ENABLED:
            raise Rejected('Physical Linux monitor/capture disabled')
        self.bus = port_bus(sysfs)
        self.path = Path(sysfs)

    def snapshot(self):
        return port_snapshot(self.path, self.bus)


def port_snapshot(path, expected_bus):
    """Shared metadata reader; caller chooses/gates the explicit port."""
    def read(name):
        with (path / name).open('r', encoding='ascii') as stream:
            data = stream.read(128)
        if len(data) >= 128:
            raise Rejected('Oversized sysfs field')
        return data.strip()
    try:
        before = path.stat().st_ino
        bus, device = int(read('busnum')), int(read('devnum'))
        vid, pid = read('idVendor'), read('idProduct')
    except FileNotFoundError:
        return None
    if bus != expected_bus or not 1 <= device <= 127 or not re.fullmatch(r'[0-9a-f]{4}', vid) or not re.fullmatch(r'[0-9a-f]{4}', pid):
        raise Rejected('Invalid port metadata')
    try:
        ready = (read('bConfigurationValue'), read('speed'), read('bNumConfigurations')) == ('1', '480', '1')
        after = path.stat().st_ino
        # Re-read identity to reject metadata mixed across a re-enumeration.
        unchanged = (before == after and int(read('devnum')) == device and
                     read('idVendor') == vid and read('idProduct') == pid)
    except FileNotFoundError:
        return Arrival(bus, device, before, vid, pid, False)
    if not unchanged:
        raise Rejected('Port changed during metadata snapshot')
    return Arrival(bus, device, before, vid, pid, ready)


class _Dumpcap:
    def __init__(self, executable, bus, directory):
        if not LIVE_LINUX_MONITOR_CAPTURE_ENABLED:
            raise Rejected('Physical Linux monitor/capture disabled')
        self._initialize(executable, bus, directory)

    def _initialize(self, executable, bus, directory):
        """Shared process setup; native callers must enforce their own policy."""
        self.argv = capture_argv(executable, bus, directory)
        self.bus, self.directory = bus, Path(directory)
        if not self.directory.is_absolute() or '..' in self.directory.parts:
            raise Rejected('New absolute output directory required')
        self.process = self.log = None
        self.stopped = None

    def start(self):
        import os
        import subprocess
        if self.process is not None or self.stopped is not None:
            raise Rejected('Collector already started/consumed')
        # A new private directory prevents overwriting old captures or following
        # pre-existing output symlinks. No chmod or global permission changes.
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        if self.directory.resolve() != self.directory:
            raise Rejected('Output path contains symlink components')
        self.log = (self.directory / 'dumpcap.stderr').open('xb')
        try:
            env = dict(os.environ, LC_ALL='C', LANG='C')
            self.process = subprocess.Popen(self.argv, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, stderr=self.log,
                                            shell=False, close_fds=True, env=env)
        except BaseException:
            self.log.close()
            raise

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def ready(self):
        if not self.alive():
            raise Rejected('Collector exited before readiness')
        try:
            with (self.directory / 'usbmon.pcap').open('rb') as stream:
                return inspect_header(stream.read(24))
        except FileNotFoundError:
            return False

    def stop(self):
        import signal
        import subprocess
        if self.stopped is not None:
            return self.stopped
        result = {'process_reaped': False, 'forced': False, 'exit_code': None}
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    try:
                        self.process.send_signal(signal.SIGINT)
                    except ProcessLookupError:
                        pass
                try:
                    result['exit_code'] = self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    result['forced'] = True
                    self.process.terminate()
                    try:
                        result['exit_code'] = self.process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        result['exit_code'] = self.process.wait(timeout=1)
                result['process_reaped'] = True
        finally:
            if self.log is not None:
                self.log.close()
        if self.directory.exists():
            log = self.directory / 'dumpcap.stderr'
            text = ''
            if log.is_file():
                with log.open('rb') as stream:
                    raw = stream.read(1024 * 1024 + 1)
                if len(raw) <= 1024 * 1024:
                    text = raw.decode('utf-8', errors='replace')
            result['drops'] = drop_counters(text, self.bus)
        result['clean'] = result['process_reaped'] and not result['forced'] and result['exit_code'] == 0
        self.stopped = result
        return result


class Session:
    """Injectable coordinator. Native adapters stay gated, including on Linux.

    ready() is notification only; there is no reboot/cable/power action here.
    Polling metadata is not an assurance that every transient pulse is observed.
    """
    def __init__(self, sysfs, monitor, capture, *, factory=version.prepare_linux,
                 clock=time.monotonic, sleep=time.sleep):
        self.bus = port_bus(sysfs)
        self.sysfs, self.monitor, self.capture = sysfs, monitor, capture
        self.factory, self.clock, self.sleep = factory, clock, sleep
        self.used = False
        self.audit = []

    def _snapshot(self):
        item = self.monitor.snapshot()
        if item is not None:
            version.validate_target(item.path, self.sysfs)
            if item.bus != self.bus or (item.vid, item.pid) not in [('1f3a', '4ee7'), ('1f3a', 'efe8')]:
                raise Rejected('Unexpected identity at selected physical port')
        return item

    def _healthy(self):
        if not self.capture.alive():
            raise Rejected('Collector stopped; no query may start')

    def run(self, *, seconds=90, interval=0.005, ready=None):
        if self.used:
            raise Rejected('Session already consumed')
        self.used = True
        if not 1 <= seconds <= 90 or not 0.005 <= interval <= 0.02:
            raise Rejected('Watch bounds exceeded')
        report = {'query_attempts': 0, 'status': 'INCONCLUSIVE', 'audit': self.audit}
        started = False
        try:
            initial = self._snapshot()
            if initial is not None and initial.pid == 'efe8':
                raise Rejected('EFE8 already present before capture; do not probe')
            self.capture.start()
            started = True
            self.audit.append('CAPTURE_STARTED')
            deadline = self.clock() + 3
            while not self.capture.ready():
                self._healthy()
                if self.clock() >= deadline:
                    raise TimeoutError('Collector readiness deadline')
                self.sleep(interval)
            self._healthy()
            initial = self._snapshot()
            if initial is not None and initial.pid == 'efe8':
                raise Rejected('EFE8 arrived before monitor armed; no query')
            self.audit.append('CAPTURE_READY_MONITOR_ARMED')
            if ready is not None:
                ready()
            deadline = self.clock() + seconds
            while True:
                self._healthy()
                if self.clock() >= deadline:
                    raise TimeoutError('No EFE8 arrival observed; no command sent')
                item = self._snapshot()
                if item is not None and item.pid == 'efe8':
                    break
                self.sleep(interval)
            self.audit.append('FIRST_EFE8_OBSERVED')
            token = item.token
            configured_deadline = min(deadline, self.clock() + 0.100)
            while not item.ready:
                self._healthy()
                if self.clock() >= configured_deadline:
                    raise TimeoutError('First EFE8 not ready in metadata window')
                self.sleep(interval)
                item = self._snapshot()
                if item is None or item.pid != 'efe8' or item.token != token:
                    raise Rejected('First EFE8 disappeared/changed; no later pulse queried')
            self._healthy()
            report['query_attempts'] = 1  # Consume before factory/open.
            report['target'] = {'path': item.path, 'sysfs': self.sysfs, 'generation': item.generation}
            self.audit.append('ONE_VERSION_ATTEMPT')
            query = self.factory(item.path, self.sysfs)
            try:
                report['version'] = query.query()
                self._healthy()
                report['status'] = 'VERSION_RETURNED_PENDING_CAPTURE_REVIEW'
            finally:
                getter = getattr(query, 'native_io_snapshot', None)
                if getter is not None:
                    report['client_io'] = getter()
        except Exception as error:
            report['error'] = {'type': type(error).__name__, 'message': str(error)}
        finally:
            # Even start() failing halfway must be cleaned up.
            try:
                report['capture'] = self.capture.stop()
            except Exception as error:
                report['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
                report['status'] = 'CLEANUP_FAILED'
            self.audit.append('CAPTURE_STOP_REQUESTED')
        if report.get('capture', {}).get('clean') is not True and 'cleanup_error' not in report:
            report['status'] = 'INCONCLUSIVE_CAPTURE_NOT_CLEAN'
        if not report.get('capture', {}).get('drops', {}).get('zero_reported_drops') and 'cleanup_error' not in report:
            report['status'] = 'INCONCLUSIVE_CAPTURE_LOSS_UNKNOWN_OR_NONZERO'
        report['capture_started'] = started
        return report


def review_files(report, directory):
    """Offline only: hash closed files and correlate with the consumed target.

    Does not start/stop processes or change any gate. No file writes performed.
    """
    import hashlib
    import stat
    from inspect_usbmon import analyze
    base = Path(directory)
    capture = report.get('capture', {})
    if capture.get('process_reaped') is not True:
        raise Rejected('Do not read capture until its writer is reaped')
    target = report.get('target')
    if not isinstance(target, dict):
        raise Rejected('No consumed VERSION target available for offline correlation')
    bus, device = version.validate_target(target['path'], target['sysfs'])
    files = {}
    for name in ('usbmon.pcap', 'dumpcap.stderr'):
        path = base / name
        info = path.lstat()
        limit = 40 * 1024 * 1024 if name.endswith('.pcap') else 1024 * 1024
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise Rejected('Offline review requires bounded regular files, no symlinks')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(65536), b''):
                digest.update(chunk)
        files[name] = {'bytes': info.st_size, 'sha256': digest.hexdigest()}
    with (base / 'usbmon.pcap').open('rb') as stream:
        result = analyze(stream, bus=bus, device=device)
    with (base / 'dumpcap.stderr').open('r', encoding='utf-8', errors='replace') as stream:
        drops = drop_counters(stream.read(1024 * 1024), bus)
    clean = capture.get('clean') is True and drops.get('known') is True and drops.get('zero_reported_drops') is True
    return {'offline_only': True, 'files': files, 'capture_analysis': result, 'drops_from_log': drops,
            'capture_integrity_accepted': clean,
            'valid_version_established': clean and result['valid_version_reply_established'],
            'scope': 'URB capture layer, not electrical proof'}


def prepare_native_session(sysfs, executable, directory):
    if not LIVE_LINUX_MONITOR_CAPTURE_ENABLED:
        raise Rejected('Physical Linux monitor/capture disabled')
    import sys
    if sys.platform != 'linux':
        raise Rejected('Native Linux required')
    if not version.LIVE_LINUX_VERSION_ENABLED:
        raise Rejected('Linux VERSION remains disabled; do not start a physical session')
    bus = port_bus(sysfs)
    return Session(sysfs, _SysfsPort(sysfs), _Dumpcap(executable, bus, directory))


def main():
    import argparse
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps({'preview_only': True,
                      'physical_monitor_capture_enabled': LIVE_LINUX_MONITOR_CAPTURE_ENABLED,
                      'physical_version_enabled': version.LIVE_LINUX_VERSION_ENABLED,
                      'capture_command_example_only': capture_argv('/usr/bin/dumpcap', 1, '/tmp/REVIEW-NEW-DIRECTORY'),
                      'order': ['baseline', 'capture_start', 'pcap_header_and_process_ready',
                                'monitor_arm', 'external_action_not_implemented',
                                'first_EFE8_only', 'one_VERSION', 'stop_reap', 'offline_review'],
                      'reboot_implemented': False}, indent=2))


if __name__ == '__main__':
    main()
