"""Explicitly authorized one-shot VERSION runner. No ADB or payload path.

Default is preview. The VERSION gate is enabled only in this process and is
restored in finally. The generic reader backend must remain disabled.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import time

import version_only as v
from version_arrival import InterfaceMetadata, watch_once


def utc():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-version-once', action='store_true')
    parser.add_argument('--target', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.run_version_once:
        print(json.dumps({'preview_only': True, 'physical_gate': v.LIVE_VERSION_ENABLED,
                          'maximum_attempts': 1, 'payload': False, 'reboot': False}))
        return
    if not args.target or not args.output or not args.output.is_dir():
        parser.error('Reviewed target file and existing fresh capture directory required')
    for name in ('version-started.json', 'version-ready.json', 'version-result.json'):
        if (args.output / name).exists():
            raise v.Rejected('One-shot evidence exists; do not restart runner')
    import winusb_backend
    if winusb_backend.LIVE_USB_ENABLED or v.LIVE_VERSION_ENABLED:
        raise v.Rejected('Unexpected pre-enabled physical gate')
    target = json.loads(args.target.read_text(encoding='utf-8-sig'))
    v.validate_path(target['interface_path'])
    metadata = InterfaceMetadata(target['instance'])
    if [p.casefold() for p in metadata.paths(present=False)] != [target['interface_path'].casefold()]:
        raise v.Rejected('Registered interface differs from reviewed target')
    state = {'started_utc': utc(), 'attempts': 0, 'payload_loaded': False,
             'reboot_sent': False, 'partition_write_commands_sent': False,
             'generic_backend_enabled': False, 'status': 'PREPARING', 'audit': []}
    with (args.output / 'version-started.json').open('x', encoding='utf-8') as f:
        json.dump(state, f, indent=2)
    try:
        state['bindings'] = v.preload_system_bindings()
        v.LIVE_VERSION_ENABLED = True

        def factory(path):
            state['attempts'] += 1
            if state['attempts'] != 1:
                raise v.Rejected('Attempt budget exceeded')
            state['arrival_utc'] = utc()
            state['status'] = 'OPENING'
            start = time.perf_counter()
            try:
                probe = v.prepare_native(path)
            finally:
                state['open_elapsed_ms'] = (time.perf_counter() - start) * 1000
            state['opened_utc'] = utc()

            class Query:
                def query(self):
                    state['status'] = 'QUERYING'
                    try:
                        return probe.query()
                    finally:
                        state['audit'] = probe.audit
                        state['native_io'] = probe.native_io_snapshot()
            return Query()

        def ready():
            state['status'] = 'ARMED'
            with (args.output / 'version-ready.json').open('x', encoding='utf-8') as f:
                json.dump({'utc': utc(), 'ready': True, 'generic_backend_enabled': False}, f)

        state['response'] = watch_once(metadata, target['interface_path'], factory=factory,
                                       seconds=100, interval=0.005, ready=ready)
        state['status'] = 'VERSION_RECEIVED'
    except BaseException as error:
        state['status'] = 'FAILED'
        state['error_type'] = type(error).__name__
        state['error'] = str(error)
        state['winerror'] = getattr(error, 'winerror', None)
        if hasattr(error, 'result'):
            state['response'] = error.result
        if hasattr(error, 'profile'):
            state['observed_profile'] = error.profile
    finally:
        v.LIVE_VERSION_ENABLED = False
        state['ended_utc'] = utc()
        state['version_gate_restored_disabled'] = not v.LIVE_VERSION_ENABLED
        state['generic_gate_still_disabled'] = not winusb_backend.LIVE_USB_ENABLED
        with (args.output / 'version-result.json').open('x', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
    print(json.dumps(state, indent=2))


if __name__ == '__main__':
    main()
