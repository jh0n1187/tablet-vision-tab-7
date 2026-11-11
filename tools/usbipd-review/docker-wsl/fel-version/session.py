"""WSL USB/IP one-import/one-VERSION preparation. CLI never opens USB.

run_once is reserved for the reviewed, explicitly authorized physical attempt.
No reboot, capture startup, policy change, payload or storage command here.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'fel-readonly'))
import linux_version_only as version
from version_only import Rejected

USBIP = '/mnt/c/Program Files/usbipd-win/WSL/usbip'
STATUS = Path('/sys/devices/platform/vhci_hcd.0/status')


def validate_profile(p):
    if (p['busid'], p['hardware_id'], p['gateway'], p['guest_ip']) != (
            '1-2', '1f3a:efe8', '172.26.160.1', '172.26.161.170'):
        raise Rejected('Only the reviewed EFE8/port/network profile is supported')
    if not re.fullmatch('[0-9a-f]{64}', p['usbip_sha256']):
        raise Rejected('Reviewed installed USB/IP client hash required')
    if not re.fullmatch('[0-9a-f]{16}', p['efe8_key']):
        raise Rejected('Exact reviewed EFE8 device-tree key required')
    if not re.fullmatch('[0-9a-f]{32}', p['nonce']):
        raise Rejected('Run-specific nonce required')


def plan(p):
    validate_profile(p)
    return {'preview_only': True, 'maximum_imports': 1, 'maximum_queries': 1,
            'policy_add': ['policy', 'add', '--effect', 'Allow', '--operation', 'AutoBind',
                           '--busid', p['busid'], '--hardware-id', p['hardware_id']],
            'import_argv': [USBIP, 'attach', '--remote=' + p['gateway'], '--busid=' + p['busid']],
            'physical_enabled': version.LIVE_LINUX_VERSION_ENABLED,
            'automatic_retry': False, 'payload': False, 'storage_write': False}


def parse_ports(text):
    rows = []
    if text.splitlines()[0].split() != ['hub', 'port', 'sta', 'spd', 'dev', 'sockfd', 'local_busid']:
        raise Rejected('Unknown VHCI status header')
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) != 7 or parts[0] not in ('hs', 'ss'):
            raise Rejected('Unknown VHCI row')
        row = dict(zip(('hub', 'port', 'state', 'speed', 'devid', 'socket', 'local'), parts))
        for field in ('port', 'state', 'speed', 'socket'):
            row[field] = int(row[field], 10)
        int(row['devid'], 16)
        if not re.fullmatch(r'[0-9]+-[0-9]+', row['local']):
            raise Rejected('Unknown local VHCI bus ID')
        rows.append(row)
    if len(rows) != 16 or {r['port'] for r in rows} != set(range(16)):
        raise Rejected('Expected the reviewed 16-port VHCI controller')
    return rows


def validate_trigger(t, p, now):
    if set(t) != {'nonce', 'key', 'pid', 'time'}:
        raise Rejected('Unknown trigger fields')
    if (t['nonce'], t['key'], t['pid']) != (p['nonce'], p['efe8_key'], 'EFE8'):
        raise Rejected('Wrong trigger target/run')
    if type(t['time']) not in (int, float) or not 0 <= now - t['time'] <= 0.5:
        raise Rejected('Stale/future trigger; no import')


def owned_port(rows, records, p):
    active = [r for r in rows if r['state'] != 4]
    if not active:
        return None
    if len(active) != 1:
        raise Rejected('Ambiguous imported ports; do not query/detach')
    r = active[0]
    if (r['hub'], r['state'], r['speed']) != ('hs', 6, 3):
        return None  # Wait only for completed high-speed enumeration.
    if records(r['port']).split() != [p['gateway'], '3240', p['busid']]:
        raise Rejected('Import ownership record mismatch')
    if not re.fullmatch(r'1-[1-9][0-9]*', r['local']):
        raise Rejected('Only usbmon1 high-speed root reviewed')
    return r


def query_once(path, sysfs):
    # Process-local gate only; no source edits and no generic FEL gate enabled.
    if version.LIVE_LINUX_VERSION_ENABLED:
        raise Rejected('Unexpected already-enabled physical gate')
    query = None
    result = {}
    try:
        version.LIVE_LINUX_VERSION_ENABLED = True
        query = version.prepare_linux(path, sysfs)
        result['version'] = query.query()
        result['state'] = 'VERSION_RECEIVED'
    except Exception as error:
        result.update(state='QUERY_FAILED', error_type=type(error).__name__, error=str(error))
    finally:
        version.LIVE_LINUX_VERSION_ENABLED = False
        if query is not None:
            result['audit'] = query.audit
            result['native_io'] = query.native_io_snapshot()
    return result


def run_once(profile, directory, *, execute=False):
    if not execute:
        raise Rejected('Physical execution not authorized in this invocation')
    validate_profile(profile)
    if sys.platform != 'linux' or 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower():
        raise Rejected('This explicit profile is WSL USB/IP, not native Linux')
    import os
    if os.geteuid() != 0:
        raise Rejected('USBFS node access requires the dedicated WSL root child')
    if hashlib.sha256(Path(USBIP).read_bytes()).hexdigest() != profile['usbip_sha256']:
        raise Rejected('USB/IP client changed')
    directory = Path(directory)
    # Unique directory must already exist, with no previous ready/result/trigger.
    for name in ('ready.json', 'result.json', 'trigger.json'):
        if (directory / name).exists():
            raise Rejected('Used run directory; no retry')
    if any(r['state'] != 4 for r in parse_ports(STATUS.read_text())):
        raise Rejected('Preexisting imported ports; refuse to arm')
    result = {'imports': 0, 'queries': 0, 'physical_gate_final': False}
    port = None
    def record(number):
        return Path('/run/vhci_hcd', 'port' + str(number)).read_text()
    def save(name, value):
        with (directory / name).open('x') as stream:
            json.dump(value, stream, indent=2)
    try:
        save('ready.json', {'nonce': profile['nonce'], 'ready': True, 'time': time.time()})
        deadline = time.monotonic() + 45
        while not (directory / 'trigger.json').exists():
            if (directory / 'cancel').exists():
                raise Rejected('Cancelled before import')
            if time.monotonic() > deadline:
                raise Rejected('No arrival within 45 seconds')
            time.sleep(.002)
        validate_trigger(json.loads((directory / 'trigger.json').read_text()), profile, time.time())
        if any(r['state'] != 4 for r in parse_ports(STATUS.read_text())):
            raise Rejected('VHCI state changed before import')
        result['imports'] = 1  # Consume before the single subprocess, even on failure.
        imported = subprocess.run(plan(profile)['import_argv'], capture_output=True, text=True, timeout=2)
        result['import'] = {'exit_code': imported.returncode, 'stdout': imported.stdout, 'stderr': imported.stderr}
        if imported.returncode:
            raise Rejected('Import failed; no retry')
        deadline = time.monotonic() + 1
        while port is None:
            port = owned_port(parse_ports(STATUS.read_text()), record, profile)
            if time.monotonic() > deadline:
                raise Rejected('Enumeration deadline; no query')
            if port is None:
                time.sleep(.002)
        result['owned_port'] = port
        sysfs = '/sys/bus/usb/devices/' + port['local']
        devnum = int(Path(sysfs, 'devnum').read_text())
        result['queries'] = 1
        result.update(query_once(f'/dev/bus/usb/001/{devnum:03d}', sysfs))
    except Exception as error:
        result.update(state='STOPPED', error_type=type(error).__name__, error=str(error))
    finally:
        version.LIVE_LINUX_VERSION_ENABLED = False
        # Revalidate ownership even if import timed out after kernel attach.
        try:
            current = owned_port(parse_ports(STATUS.read_text()), record, profile) if result['imports'] else None
            if current is not None:
                detached = subprocess.run([USBIP, 'detach', '--port=' + str(current['port'])],
                                          capture_output=True, text=True, timeout=2)
                result['detach'] = {'port': current['port'], 'exit_code': detached.returncode,
                                    'stdout': detached.stdout, 'stderr': detached.stderr}
            result['ports_final'] = parse_ports(STATUS.read_text())
            result['ports_empty_final'] = all(r['state'] == 4 for r in result['ports_final'])
        except Exception as error:
            result['cleanup_error'] = str(error)
        result['physical_gate_final'] = version.LIVE_LINUX_VERSION_ENABLED
        save('result.json', result)
    return result


if __name__ == '__main__':
    # No live switch: physical invocation requires a separately reviewed coordinator.
    print(json.dumps(plan(json.loads(Path(sys.argv[1]).read_text())), indent=2))
