"""Native Linux validation kit: no installs, reboot, VERSION or USBFS opens.

Default CLI prints a plan. Test observation reads only explicit sysfs metadata.
Capture command is returned as data; this module never launches dumpcap.
"""
import argparse
import ctypes
import errno
import json
from pathlib import Path
import platform
import re
import shutil
import struct
import sys
import time

import linux_capture_session as session
import linux_version_only as linux
import version_only
from version_only import Rejected


def gates():
    # Inspect the Windows gate as data; do not import its general USB transport.
    import ast
    tree = ast.parse(Path(__file__).with_name('winusb_backend.py').read_text(encoding='utf-8-sig'))
    flags = [ast.literal_eval(node.value) for node in ast.walk(tree)
             if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'LIVE_USB_ENABLED' for t in node.targets)]
    if len(flags) != 1 or type(flags[0]) is not bool:
        raise Rejected('Unknown Windows gate declaration')
    values = {'LIVE_VERSION_ENABLED': version_only.LIVE_VERSION_ENABLED,
              'LIVE_USB_ENABLED': flags[0],
              'LIVE_LINUX_VERSION_ENABLED': linux.LIVE_LINUX_VERSION_ENABLED,
              'LIVE_LINUX_MONITOR_CAPTURE_ENABLED': session.LIVE_LINUX_MONITOR_CAPTURE_ENABLED}
    if any(values.values()):
        raise Rejected('Validation requires all physical gates disabled')
    return values


def native_host():
    gates()
    if sys.platform != 'linux' or 'microsoft' in platform.release().lower() or 'microsoft' in platform.version().lower():
        raise Rejected('Native Linux required; Windows/WSL rejected')
    if platform.machine().lower() not in ('x86_64', 'aarch64') or sys.byteorder != 'little':
        raise Rejected('Reviewed native ABI requires little-endian Linux x86_64/aarch64')
    return {'system': platform.system(), 'release': platform.release(),
            'machine': platform.machine(), 'python': platform.python_version(),
            'abi': linux.abi_profile(), 'dumpcap_path': shutil.which('dumpcap'),
            'compiler_path': shutil.which('cc'), 'physical_gates': gates(),
            'hardware_host_confirmed': False,
            'note': 'Operator must confirm native hardware and disconnected tablet; no host discovery performed'}


def test_identity(vid, pid):
    if not isinstance(vid, str) or not isinstance(pid, str) or not re.fullmatch('[0-9a-fA-F]{4}', vid) or not re.fullmatch('[0-9a-fA-F]{4}', pid):
        raise Rejected('Explicit four-digit test VID/PID required')
    vid, pid = vid.lower(), pid.lower()
    if vid in ('0000', '1f3a') or pid in ('0000', 'efe8', '4ee7'):
        raise Rejected('Tablet/Allwinner identities forbidden in passive test validation')
    return vid, pid


def plan(sysfs, vid, pid):
    gates()
    bus = session.port_bus(sysfs)
    vid, pid = test_identity(vid, pid)
    return {'preview_only': True, 'test_port': sysfs, 'test_vid': vid, 'test_pid': pid,
            'tablet_must_be_physically_disconnected': True,
            'physical_gates': gates(), 'version_commands_to_test_device': 0,
            'capture_argv_data_only': session.capture_argv('/usr/bin/dumpcap', bus, '/tmp/NEW-PRIVATE-TEST-DIRECTORY'),
            'steps': ['native_host_check', 'ABI_C_probe_if_compiler_exists', 'unit_tests_with_fake_USB',
                      'libc_null_device_probe', 'capture_before_test_device_plug',
                      'observe_only_test_port', 'stop_and_reap_collector', 'offline_descriptor_and_loss_review']}


def libc_null_probe():
    """One Linux ioctl on /dev/null, never on a USB node; expect ENOTTY."""
    native_host()
    import os
    import stat
    fd = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISCHR(info.st_mode) or (os.major(info.st_rdev), os.minor(info.st_rdev)) != (1, 3):
            raise Rejected('Unexpected /dev/null device')
        api = linux._UsbfsAPI()  # Bind libc only, no USB discovery/open.
        try:
            api.bulk(fd, 0x81, 13, 100)
        except OSError as error:
            if error.errno != errno.ENOTTY:
                raise
            return {'libc_ioctl_bound': True, 'expected_errno': 'ENOTTY',
                    'target': '/dev/null', 'usb_device_opened': False,
                    'native_USBFS_bulk_validated': False}
        raise Rejected('Unexpected successful USB ioctl on /dev/null')
    finally:
        os.close(fd)


def _metadata(sysfs, vid, pid):
    """Read the named test port only; no USB enumeration or device handles."""
    item = session.port_snapshot(Path(sysfs), session.port_bus(sysfs))
    if item is None:
        return None
    if (item.vid, item.pid) != (vid, pid):
        raise Rejected('Selected port has another identity; stop without opening it')
    return {'bus': item.bus, 'device': item.device, 'generation': item.generation,
            'vid': vid, 'pid': pid, 'reviewed_480Mbps_configuration_ready': item.ready}


def observe_test(sysfs, vid, pid, *, seconds=20, snapshot=None, clock=time.monotonic, sleep=time.sleep):
    """Measure scheduling + observe first test insertion. No VERSION callback."""
    gates()
    session.port_bus(sysfs)
    vid, pid = test_identity(vid, pid)
    if snapshot is None:
        native_host()
        snapshot = lambda: _metadata(sysfs, vid, pid)
    if type(seconds) not in (int, float) or not 1 <= seconds <= 30:
        raise Rejected('Observation duration must be 1..30 seconds')
    if snapshot() is not None:
        raise Rejected('Start observation with test device unplugged')
    start = previous = clock()
    gaps = []
    first = None
    samples = 0
    while clock() - start < seconds:
        before = clock()
        item = snapshot()
        after = clock()
        gaps.append(after - previous)
        previous = after
        samples += 1
        if item is not None:
            first = dict(item, elapsed_seconds=after - start, read_seconds=after - before)
            break
        sleep(0.005)
    ordered = sorted(gaps)
    return {'observation_only': True, 'test_sysfs': sysfs, 'test_vid': vid, 'test_pid': pid,
            'arrival': first, 'samples': samples, 'requested_interval_ms': 5,
            'max_observed_gap_ms': max(gaps, default=0) * 1000,
            'p95_observed_gap_ms': ordered[min(len(ordered)-1, int(len(ordered)*0.95))] * 1000 if ordered else None,
            'usb_handles_opened': 0, 'version_commands_sent': 0,
            'transient_pulse_detection_proven': False}


def review_test_capture(capture, stderr, *, bus, device, vid, pid):
    """Verify passive test descriptor bytes, not a FEL transcript."""
    from inspect_usbmon import events, InvalidCapture
    gates()
    vid, pid = test_identity(vid, pid)
    if type(bus) is not int or not 1 <= bus <= 999 or type(device) is not int or not 1 <= device <= 127:
        raise Rejected('Explicit test bus/address required')
    def regular(path, limit):
        import stat
        path = Path(path)
        if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > limit:
            raise Rejected('Bounded regular local file required')
        return path
    capture = regular(capture, 40*1024*1024)
    stderr = regular(stderr, 1024*1024)
    pairs = []; pending = {}
    with capture.open('rb') as stream:
        for item in events(stream):
            if (item.bus, item.device) != (bus, device):
                continue
            if item.endpoint == 2 and item.data.startswith(b'AWUC'):
                raise InvalidCapture('FEL traffic found in passive test capture')
            if item.transfer != 2:
                continue
            if item.kind == ord('S'):
                if item.urb in pending:
                    raise InvalidCapture('Duplicate control submission')
                pending[item.urb] = item
            elif item.kind == ord('E'):
                raise InvalidCapture('Control submission failed')
            else:
                request = pending.pop(item.urb, None)
                if request is None:
                    raise InvalidCapture('Incomplete control correlation')
                if request.setup_flag != 0 or request.setup[:6] != bytes.fromhex('800600010000'):
                    continue
                if struct.unpack_from('<H', request.setup, 6)[0] < 18:
                    continue
                if (item.status != 0 or item.endpoint != request.endpoint or item.endpoint not in (0, 0x80) or
                    item.truncated or request.truncated or item.data_flag != 0 or
                    len(item.data) != item.length or item.length != 18 or item.data[:2] != b'\x12\x01' or
                    request.length < item.length or request.status not in (0, -115) or
                    (item.time, item.index) < (request.time, request.index)):
                    raise InvalidCapture('Missing/truncated/failed device descriptor')
                found = struct.unpack_from('<HH', item.data, 8)
                if found != (int(vid, 16), int(pid, 16)):
                    raise InvalidCapture('Wrong identity/address reuse in capture')
                pairs.append({'submission_frame': request.index, 'completion_frame': item.index,
                              'descriptor_hex': item.data.hex()})
    if not pairs or pending:
        raise InvalidCapture('Complete test descriptor/correlation missing')
    counters = session.drop_counters(stderr.read_text(encoding='utf-8', errors='replace'), bus)
    return {'offline_only': True, 'test_descriptor_pairs': pairs,
            'byte_identity_verified': True, 'loss_counters': counters,
            'passive_capture_bytes_and_zero_loss': counters.get('known') is True and counters.get('zero_reported_drops') is True,
            'clean_collector_exit_must_be_checked_separately': True,
            'FEL_VERSION_validated_on_hardware': False}


class _PassiveTestCollector(session._Dumpcap):
    """Only capture URBs for the test run; never constructs a VERSION client."""
    def __init__(self, sysfs, vid, pid, executable, directory):
        native_host()
        test_identity(vid, pid)
        self._initialize(executable, session.port_bus(sysfs), directory)
        self.argv[self.argv.index('duration:105')] = 'duration:30'


def capture_test(sysfs, vid, pid, executable, directory, *, ready=None):
    native_host()
    vid, pid = test_identity(vid, pid)
    session.port_bus(sysfs)
    if _metadata(sysfs, vid, pid) is not None:
        raise Rejected('Test device must be unplugged before starting passive capture')
    collector = _PassiveTestCollector(sysfs, vid, pid, executable, directory)
    report = {'passive_test_only': True, 'VERSION_commands_sent': 0, 'physical_gates': gates()}
    owns_directory = False
    try:
        collector.start()
        owns_directory = True
        deadline = time.monotonic() + 3
        while not collector.ready():
            if time.monotonic() >= deadline:
                raise TimeoutError('Test collector readiness deadline')
            time.sleep(.005)
        if _metadata(sysfs, vid, pid) is not None:
            raise Rejected('Test insertion preceded readiness; repeat only as a new test run')
        if ready is not None:
            ready()
        def snapshot():
            if not collector.alive():
                raise Rejected('Test collector exited during observation')
            return _metadata(sysfs, vid, pid)
        report['monitor'] = observe_test(sysfs, vid, pid, snapshot=snapshot)
        # Allow enumeration to finish after the first metadata observation.
        time.sleep(1)
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        try:
            report['collector'] = collector.stop()
        except Exception as error:
            report['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
    arrival = report.get('monitor', {}).get('arrival')
    if arrival and report.get('collector', {}).get('process_reaped') and 'error' not in report:
        try:
            report['offline'] = review_test_capture(Path(directory)/'usbmon.pcap', Path(directory)/'dumpcap.stderr',
                                                   bus=arrival['bus'], device=arrival['device'], vid=vid, pid=pid)
        except Exception as error:
            report['offline_error'] = {'type': type(error).__name__, 'message': str(error)}
    report['test_capture_accepted'] = (report.get('collector', {}).get('clean') is True and
                                     report.get('offline', {}).get('passive_capture_bytes_and_zero_loss') is True)
    if owns_directory:
        with (Path(directory)/'test-result.json').open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    modes.add_argument('--host-check', action='store_true')
    modes.add_argument('--libc-null-probe', action='store_true')
    modes.add_argument('--observe-test', action='store_true')
    modes.add_argument('--capture-test', action='store_true')
    modes.add_argument('--review-test', type=Path)
    p.add_argument('--sysfs'); p.add_argument('--vid'); p.add_argument('--pid')
    p.add_argument('--seconds', type=int, default=20)
    p.add_argument('--bus', type=int); p.add_argument('--device', type=int); p.add_argument('--stderr', type=Path)
    p.add_argument('--dumpcap', default='/usr/bin/dumpcap'); p.add_argument('--output-dir', type=Path)
    args = p.parse_args()
    if args.host_check:
        result = native_host()
    elif args.libc_null_probe:
        result = libc_null_probe()
    elif args.observe_test:
        result = observe_test(args.sysfs, args.vid, args.pid, seconds=args.seconds)
    elif args.capture_test:
        if args.output_dir is None: p.error('--output-dir required for passive test capture')
        def ready():
            print(json.dumps({'test_capture_ready': True, 'action': 'Connect only the reviewed test device to its port'}), flush=True)
        result = capture_test(args.sysfs, args.vid, args.pid, args.dumpcap, args.output_dir, ready=ready)
    elif args.review_test:
        if args.stderr is None: p.error('--stderr required for offline review')
        result = review_test_capture(args.review_test, args.stderr, bus=args.bus, device=args.device, vid=args.vid, pid=args.pid)
    elif args.sysfs is not None:
        result = plan(args.sysfs, args.vid, args.pid)
    else:
        result = {'preview_only': True, 'physical_gates': gates(), 'installs': False,
                  'passive_test_capture_available_on_native_linux': True, 'VERSION_execution_implemented': False,
                  'usage': 'See VALIDACAO-LINUX-NATIVO-PREPARADA.md; explicit test VID/PID and physical port required'}
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
