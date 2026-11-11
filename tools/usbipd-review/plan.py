"""Installation/rollback preview only. No subprocess, Registry or device APIs."""
import json
from pathlib import Path

SHA256 = '1c984914aec944de19b64eff232421439629699f8138e3ddc29301175bc6d938'
PRODUCT_CODE = '{EA1D5623-E6A7-4E4A-9259-E39722050300}'
VERSION = '5.3.0'


def clean_initial_state(host):
    if host.get('architecture') != 'X64':
        raise ValueError('Only reviewed native x64 package allowed')
    for key in ('services','vbox_drivers','firewall_rules','matching_oem_infs'):
        if type(host.get(key)) is not list or host[key]:
            raise ValueError('Existing/unknown usbipd/VirtualBox resources require separate review')
    if host.get('program_directory_exists') is not False:
        raise ValueError('Existing/unknown program directory state')
    if any(item.get('exists') is not False for item in host.get('registry', [])) or len(host.get('registry', [])) != 3:
        raise ValueError('Existing/unknown product registry state')


def install_preview(host, package, root):
    clean_initial_state(host)
    if package.get('sha256') != SHA256 or package.get('status') != 'Valid' or package.get('bytes') != 4501504:
        raise ValueError('Expected exact official signed MSI')
    root = Path(root).resolve()
    return {'preview_only': True, 'executable': r'C:\Windows\System32\msiexec.exe',
            'arguments': ['/i', str(root/'downloads/usbipd-win_5.3.0_x64.msi'),
                          '/norestart', 'REBOOT=ReallySuppress', '/L*v', str(root/'evidence/FUTURE-install-NEW-ID.log')],
            'interactive_UI': True, 'product_code': PRODUCT_CODE, 'package_sha256': SHA256,
            'reboot_authorized': False, 'device_commands': [],
            'effects': ['machine-wide program files and PATH entry',
                        'VBoxUSB package staged in Driver Store',
                        'VBoxUSBMon demand kernel service; may load through dependency',
                        'usbipd automatic LocalSystem service; start attempted',
                        'inbound TCP3240 usbipd application rule, all profiles, LocalSubnet',
                        'HKLM product/devices/policy and event sources'],
            'receipt_template': {'state': 'TEMPLATE_NOT_APPLIED', 'product_code': PRODUCT_CODE,
                                 'version': VERSION, 'package_sha256': SHA256,
                                 'owns_installation': False, 'initial_state_clear': True},
            'execution_ready': False,
            'outstanding': ['Review open VBoxUSBMon 7.2.2 BSOD report before installation',
                            'HVCI/runtime compatibility not proven',
                            'Capture fresh before inventory and concrete receipt if later authorized',
                            'Review firewall scope before any sharing; do not bind/attach tablet']}


def rollback_preview(receipt, current, root):
    if (receipt.get('state') != 'APPLIED' or receipt.get('owns_installation') is not True or
        receipt.get('initial_state_clear') is not True or receipt.get('product_code') != PRODUCT_CODE or
        receipt.get('package_sha256') != SHA256 or receipt.get('version') != VERSION):
        raise ValueError('Real matching ownership receipt required, not a template')
    if current.get('product_code') != PRODUCT_CODE or current.get('version') != VERSION:
        raise ValueError('Installed product differs from reviewed receipt')
    if type(current.get('bound_device_count')) is not int or current['bound_device_count'] != 0:
        raise ValueError('Official uninstall invokes unbind --all; inspect all bindings before rollback')
    if current.get('shared_virtualbox_use') is not False:
        raise ValueError('Shared VirtualBox/unknown ownership requires separate review')
    root = Path(root).resolve()
    return {'preview_only': True, 'executable': r'C:\Windows\System32\msiexec.exe',
            'arguments': ['/x', PRODUCT_CODE, '/norestart', 'REBOOT=ReallySuppress',
                          '/L*v', str(root/'evidence/FUTURE-uninstall-NEW-ID.log')],
            'reboot_authorized': False, 'device_commands': [],
            'ownership_scoped': True,
            'manual_cleanup': 'None automatic; reconcile exact owned residuals against before/after receipt',
            'must_preserve': ['ADB 4EE7 winusb.inf/WINUSB/interface GUID', 'EFE8 oem61.inf',
                              'all other OEM INFs, class filters, certificates and security settings']}


def main():
    root = Path(__file__).resolve().parent
    host = json.loads((root/'evidence/host-before.json').read_text(encoding='utf-8-sig'))
    package = json.loads((root/'evidence/msi-authenticode.json').read_text(encoding='utf-8-sig'))
    preview = install_preview(host, package, root)
    print(json.dumps({'install': preview,
                      'uninstall_template_only': {'executable': r'C:\Windows\System32\msiexec.exe',
                                                 'arguments': ['/x', PRODUCT_CODE, '/norestart', 'REBOOT=ReallySuppress'],
                                                 'not_executable_until_receipt_validated': True}}, indent=2))


if __name__ == '__main__': main()
