"""Pure filter-delta planning and file-hash review. No installation/registry API.

This file cannot apply a change. TEMPLATE is not an ownership receipt.
"""
import hashlib
import json
from pathlib import Path

CLASS_KEY = r'HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}'
INSTALLER_SHA256 = '87A7EDF9BBBCF07B5F4373D9A192A6770D2FF3ADD7AA1E276E82E38582CCB622'
FILTER = 'USBPcap'


def _values(exists, values):
    if type(exists) is not bool:
        raise ValueError('Existence must be boolean')
    if not exists:
        if values not in (None, []): raise ValueError('Absent value cannot contain filters')
        return []
    if not isinstance(values, list) or any(not isinstance(v, str) or not v or '\0' in v for v in values):
        raise ValueError('Expected REG_MULTI_SZ string list')
    if len({v.casefold() for v in values}) != len(values):
        raise ValueError('Duplicate filter entries require review')
    return list(values)


def installation_delta(exists, values):
    before = _values(exists, values)
    present = FILTER.casefold() in [v.casefold() for v in before]
    return {'preview_only': True, 'key': CLASS_KEY, 'value': 'UpperFilters',
            'before_exists': exists, 'before_values': before,
            'proposed_values': before if present else before + [FILTER],
            'would_add': not present, 'ownership_if_preexisting': False}


def rollback_delta(receipt, current_exists, current_values):
    if receipt.get('schema') != 1 or receipt.get('state') != 'APPLIED':
        raise ValueError('Applied ownership receipt required; template cannot authorize removal')
    if receipt.get('class_key') != CLASS_KEY or receipt.get('installer_sha256') != INSTALLER_SHA256:
        raise ValueError('Receipt identity mismatch')
    added = receipt.get('added_by_this_operation')
    if type(added) is not bool:
        raise ValueError('Ownership flag must be boolean')
    before_exists = receipt.get('upper_filters_before_exists')
    before = _values(before_exists, receipt.get('upper_filters_before'))
    current = _values(current_exists, current_values)
    preexisting = FILTER.casefold() in [v.casefold() for v in before]
    if added and preexisting:
        raise ValueError('Contradictory ownership: filter preexisted')
    owned = added and not preexisting
    after = [v for v in current if v.casefold() != FILTER.casefold()] if owned else current
    return {'preview_only': True, 'key': CLASS_KEY, 'value': 'UpperFilters',
            'remove_string_only': FILTER if owned and after != current else None,
            'preserved_values': after,
            'may_remove_empty_value_after_uninstall': owned and current_exists and not after and not before_exists,
            'restore_whole_registry_key': False, 'registry_mutation_performed': False}


def main():
    root = Path(__file__).resolve().parent
    installer = root / 'downloads/USBPcapSetup-1.5.4.0.exe'
    if hashlib.sha256(installer.read_bytes()).hexdigest().upper() != INSTALLER_SHA256:
        raise ValueError('Reviewed installer hash mismatch')
    state = json.loads((root / 'evidence/usbpcap-state-before.json').read_text(encoding='utf-8-sig'))
    plan = {'state': 'REVIEW_ONLY_NOT_EXECUTABLE', 'installer': str(installer),
            'installer_sha256': INSTALLER_SHA256,
            'installation': {'method': 'official interactive installer, future authorization required',
                'silent_mode': False, 'optional_detect_usb3_selected': False,
                'reboot_now_authorized': False, 'restart_usb_devices_authorized': False,
                'filter_delta': installation_delta(state['upper_filters_exists'], state['upper_filters'])},
            'rollback': {'method': 'official installed Uninstall.exe after identity/signature review',
                'uninstaller_path_not_yet_created': True, 'force_delete_driver': False,
                'delete_other_filters': False, 'touch_adb_inf_or_guid': False},
            'receipt_template': {'schema': 1, 'state': 'TEMPLATE_NOT_AN_INSTALL_RECEIPT',
                'class_key': CLASS_KEY, 'installer_sha256': INSTALLER_SHA256,
                'upper_filters_before_exists': state['upper_filters_exists'],
                'upper_filters_before': state['upper_filters'], 'added_by_this_operation': False},
            'installation_performed': False, 'reboot_performed': False,
            'physical_version_enabled': False, 'generic_backend_enabled': False}
    print(json.dumps(plan, indent=2))


if __name__ == '__main__': main()
