"""Explicit one-reboot USB/IP VERSION coordinator. Default is preview."""
import os
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

import session
from linux_capture_session import inspect_header, drop_counters

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
USBIPD = r'C:\Program Files\usbipd-win\usbipd.exe'
ADB = r'C:\Users\Jonathan\AppData\Local\Android\Sdk\platform-tools\adb.exe'
SERIAL = os.environ.get('T307F_SERIAL', 'SET_T307F_SERIAL_BEFORE_DEVICE_ACCESS')
IMAGE = 'sha256:1e93577cd0691db5e947de4c2bcd4476ae8438ccb33a123ff428c0841ae515be'
PWSH = r'C:\Users\Jonathan\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe'


def linux_path(path):
    path = Path(path).resolve()
    return '/mnt/' + path.drive[0].lower() + '/' + '/'.join(path.parts[1:])


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def attempt():
    if sys.platform != 'win32':
        raise RuntimeError('Reviewed Windows coordinator only')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    run = ROOT / 'analise-firmware/revisao-fel/independent-capture' / ('usbip-version-' + stamp + '-' + uuid.uuid4().hex[:8])
    run.mkdir()
    (HERE / 'latest-attempt.txt').write_text(str(run))
    print('RUN_DIRECTORY=' + str(run), flush=True)
    profile = json.loads((HERE / 'profile.json').read_text())
    profile['nonce'] = uuid.uuid4().hex
    session.validate_profile(profile)
    (run / 'profile.json').write_text(json.dumps(profile, indent=2))
    report = {'reboots': 0, 'payload': False, 'partition_write_commands': False, 'state': 'PREPARING'}
    keep = collector = worker = bridge = None
    streams = []
    name = 'tablet-version-' + profile['nonce'][:12]
    capture_started = False

    def command(argv, label, timeout=15, check=True):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace')
        (run / (label + '.json')).write_text(json.dumps({'argv': argv, 'exit_code': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}, indent=2))
        if check and result.returncode:
            raise RuntimeError(label + ' failed; see receipt')
        return result

    def launch(argv, label):
        stream = (run / (label + '.log')).open('w')
        streams.append(stream)
        return subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT)

    def wait_file(name, seconds, process=None):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if (run / name).exists():
                return json.loads((run / name).read_text(encoding='utf-8-sig'))
            if (run / 'elevation-error.json').exists():
                raise RuntimeError('Elevation failed; see elevation-error.json')
            if process is not None and process.poll() is not None:
                raise RuntimeError('Child exited before ' + name)
            time.sleep(.05)
        raise RuntimeError('Deadline waiting for ' + name)

    try:
        devices = json.loads(command([USBIPD, 'state'], 'devices-before').stdout)['Devices']
        normal = [d for d in devices if d['InstanceId'] == 'USB\\VID_1F3A&PID_4EE7\\' + SERIAL]
        if len(normal) != 1 or normal[0]['BusId'] != '1-2' or any(normal[0][k] for k in ('IsForced', 'PersistedGuid', 'ClientIPAddress')):
            raise RuntimeError('ADB port/sharing baseline changed')
        if command([ADB, '-s', SERIAL, 'get-state'], 'adb-before').stdout.strip() != 'device':
            raise RuntimeError('ADB not ready')
        keep = subprocess.Popen(['wsl', '-d', 'Ubuntu', '--', 'python3', '-c', 'import sys;sys.stdin.read()'],
                                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        command(['wsl', '-d', 'Ubuntu', '-u', 'root', '--', 'python3',
                 linux_path(HERE.parent / 'module_control.py'), 'load'], 'modules', 30)
        network = json.loads(command(['wsl', '-d', 'Ubuntu', '--', 'ip', '-4', '-j', 'addr', 'show', 'eth0'], 'wsl-ip').stdout)
        addresses = [a['local'] for row in network for a in row['addr_info'] if a['scope'] == 'global']
        route = json.loads(command(['wsl', '-d', 'Ubuntu', '--', 'ip', '-j', 'route', 'show', 'default'], 'wsl-route').stdout)
        if addresses != [profile['guest_ip']] or len(route) != 1 or route[0]['gateway'] != profile['gateway']:
            raise RuntimeError('WSL addresses changed; do not broaden firewall')
        firewall_script = "$r=Get-NetFirewallRule -Name '{5D9A972C-A54A-4CC3-A65B-A38B12A16DC1}';$a=$r|Get-NetFirewallAddressFilter;$i=$r|Get-NetFirewallInterfaceFilter;[pscustomobject]@{Enabled=[string]$r.Enabled;Local=@($a.LocalAddress);Remote=@($a.RemoteAddress);Interface=@($i.InterfaceAlias)}|ConvertTo-Json -Compress"
        fw = json.loads(command([PWSH, '-NoProfile', '-Command', firewall_script], 'firewall').stdout)
        if fw != {'Enabled': 'True', 'Local': [profile['gateway']], 'Remote': [profile['guest_ip']], 'Interface': ['vEthernet (WSL (Hyper-V firewall))']}:
            raise RuntimeError('Firewall differs from reviewed scope')
        if any(r['state'] != 4 for r in session.parse_ports(command(['wsl', '-d', 'Ubuntu', '--', 'cat', session.STATUS.as_posix()], 'vhci-before').stdout)):
            raise RuntimeError('VHCI ports already occupied')
        # Run UAC only after PC preflight, before the short-lived armed children.
        admin = run / 'policy-admin.ps1'
        admin.write_text("try { & " + ps_literal(HERE / 'policy-owned.ps1') + ' -Execute -RunDirectory ' + ps_literal(run) +
            " } catch { @{error=$_.Exception.Message}|ConvertTo-Json|Set-Content -Encoding utf8 -LiteralPath " +
            ps_literal(run / 'elevation-error.json') + '; exit 1 }')
        argline = subprocess.list2cmdline(['-NoProfile', '-File', str(admin)])
        launcher = 'Start-Process -FilePath ' + ps_literal(PWSH) + ' -ArgumentList ' + ps_literal(argline) + ' -Verb RunAs -WindowStyle Hidden'
        elevation = launch([PWSH, '-NoProfile', '-Command', launcher], 'elevation')
        print('WAITING_FOR_UAC: temporary EFE8-only policy; no reboot sent', flush=True)
        wait_file('policy-ready.json', 75)
        print('POLICY_READY', flush=True)
        collector = launch(['docker', 'run', '--rm', '--pull=never', '--name', name,
            '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '32', '--memory', '128m', '--user', '0:0',
            '--device', '/dev/usbmon1:/dev/usbmon1:r', '--mount', 'type=bind,source=' + str(run) + ',target=/out',
            '--tmpfs', '/tmp:rw,nosuid,noexec,size=16m', IMAGE,
            '-i', 'usbmon1', '-F', 'pcap', '-s', '4096', '-B', '8', '-a', 'duration:60',
            '-a', 'filesize:32768', '-w', '/out/usbmon.pcap'], 'capture')
        capture_started = True
        end = time.monotonic() + 10
        while True:
            if collector.poll() is not None:
                raise RuntimeError('Collector exited before ready')
            path = run / 'usbmon.pcap'
            if path.exists() and inspect_header(path.read_bytes()[:24]):
                break
            if time.monotonic() > end:
                raise RuntimeError('Capture readiness deadline')
            time.sleep(.05)
        code = "import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import session;session.run_once(json.loads(Path(sys.argv[2]).read_text()),sys.argv[3],execute=True)"
        worker = launch(['wsl', '-d', 'Ubuntu', '-u', 'root', '--', 'python3', '-c', code,
                         linux_path(HERE), linux_path(run / 'profile.json'), linux_path(run)], 'wsl-client')
        ready = wait_file('ready.json', 8, worker)
        bridge = launch([sys.executable, str(HERE / 'arrival_bridge.py'), '--arm', str(run / 'profile.json'), str(run)], 'bridge')
        armed = wait_file('bridge-ready.json', 5, bridge)
        if (ready['nonce'] != profile['nonce'] or armed['nonce'] != profile['nonce'] or
                not 0 <= time.time() - ready['time'] < 12 or not 0 <= time.time() - armed['time'] < 3 or
                collector.poll() is not None or bridge.poll() is not None or worker.poll() is not None):
            raise RuntimeError('Pre-reboot readiness expired or child exited')
        (run / 'reboot-started.json').write_text(json.dumps({'time': time.time(), 'maximum': 1}))
        report['reboots'] = 1  # Consume before subprocess; never retry on error.
        command([ADB, '-s', SERIAL, 'reboot', 'efex'], 'adb-reboot', 10)
        print('ONE_REBOOT_SENT; waiting for the first EFE8 only', flush=True)
        report['version_attempt'] = wait_file('result.json', 48, worker)
        report['state'] = 'ATTEMPT_COMPLETED'
    except Exception as error:
        report.update(state='STOPPED', error_type=type(error).__name__, error=str(error))
        print('STOPPED: ' + str(error), flush=True)
    finally:
        (run / 'cancel').touch()
        for process, label in ((worker, 'client'), (bridge, 'bridge')):
            if process is not None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
                    report[label + '_forced_stop'] = True
        if capture_started:
            command(['docker', 'kill', '--signal', 'SIGINT', name], 'capture-stop', check=False)
            try:
                collector.wait(timeout=5)
                report['capture_exit_code'] = collector.returncode
            except subprocess.TimeoutExpired:
                report['capture_forced_stop'] = True
            report['capture_drops'] = drop_counters((run / 'capture.log').read_text(), 1)
        (run / 'finished').touch()
        if (run / 'policy-started.json').exists():
            try:
                report['policy_cleanup'] = wait_file('policy-cleanup.json', 10)
            except Exception as error:
                report['policy_cleanup_error'] = str(error)
        if keep is not None:
            keep.stdin.close()
            try:
                keep.wait(timeout=5)
            except subprocess.TimeoutExpired:
                keep.terminate()
        for stream in streams:
            stream.close()
        (run / 'attempt-summary.json').write_text(json.dumps(report, indent=2))
        print(json.dumps(report), flush=True)
    return run


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-one-authorized-attempt', action='store_true')
    args = parser.parse_args()
    if args.execute_one_authorized_attempt:
        attempt()
    else:
        print(json.dumps({'preview_only': True, 'maximum_reboots': 1, 'maximum_imports': 1,
                          'maximum_VERSION': 1, 'payload': False, 'partition_writes': False}))
