"""Windows metadata-only arrival bridge; never opens USB or reboots Android."""
import argparse
import json
import os
from pathlib import Path
import sys
import time

from session import validate_profile
from pnp_fast_capture import DeviceTree
from version_only import Rejected


def select_arrival(devices, profile):
    candidates = [d for d in devices if d['pid'] == 'EFE8']
    if not candidates:
        return None
    if len(candidates) != 1 or candidates[0]['key'] != profile['efe8_key']:
        raise Rejected('Ambiguous/wrong EFE8 arrival; no import trigger')
    device = candidates[0]
    if device['configret'] != 0 or device['has_problem']:
        raise Rejected('EFE8 has a Windows PnP problem; no import trigger')
    return device


def run(profile, directory):
    if os.name != 'nt':
        raise Rejected('Windows device-tree bridge only')
    validate_profile(profile)
    directory = Path(directory)
    ready = json.loads((directory / 'ready.json').read_text())
    if ready.get('nonce') != profile['nonce'] or ready.get('ready') is not True or not 0 <= time.time() - ready['time'] < 15:
        raise Rejected('Fresh, run-specific WSL ready receipt required')
    if (directory / 'trigger.json').exists():
        raise Rejected('Already triggered; never repeat')
    tree = DeviceTree(canonical_keys=True)
    initial = tree.snapshot()
    if select_arrival(initial, profile) is not None:
        raise Rejected('EFE8 already present before arming')
    if not any(d['key'] == profile['normal_key'] and d['pid'] == '4EE7' and not d['has_problem'] for d in initial):
        raise Rejected('Reviewed Android identity not present')
    with (directory / 'bridge-ready.json').open('x') as stream:
        json.dump({'nonce': profile['nonce'], 'time': time.time()}, stream)
    consumed = False
    previous = None
    deadline = time.monotonic() + 40
    with (directory / 'pnp.jsonl').open('x') as log:
        while time.monotonic() < deadline and not (directory / 'cancel').exists():
            devices = tree.snapshot()
            if devices != previous:
                log.write(json.dumps({'time': time.time(), 'devices': devices}) + '\n')
                log.flush()
                previous = devices
            if not consumed and select_arrival(devices, profile) is not None:
                consumed = True  # Consume before writing; second pulse never triggers.
                value = {'nonce': profile['nonce'], 'key': profile['efe8_key'], 'pid': 'EFE8', 'time': time.time()}
                temporary = directory / 'trigger.tmp'
                with temporary.open('x') as stream:
                    json.dump(value, stream)
                temporary.rename(directory / 'trigger.json')
            time.sleep(.005)
    return {'triggered': consumed, 'device_tree_only': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', action='store_true')
    parser.add_argument('profile', type=Path)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    if not args.arm:
        parser.error('Explicit --arm required; this is metadata-only, with no reboot')
    print(json.dumps(run(json.loads(args.profile.read_text()), args.directory)))
