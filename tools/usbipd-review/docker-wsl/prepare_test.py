"""Data-only WSL USB/IP test and owned firewall restriction previews.

No subprocess, device API, module load, firewall update, bind or attach execution.
"""
import ipaddress
import json
from pathlib import Path
import re


def firewall_preview(rule, network, owned_rule_name):
    if rule.get('Name') != owned_rule_name or rule.get('DisplayName') != 'usbipd':
        raise ValueError('Exact installation-owned firewall rule required')
    expected = {'Enabled':'True','Direction':'Inbound','Action':'Allow','Profile':'Any',
                'Protocol':'TCP','LocalPort':'3240','RemotePort':'Any','PolicyStoreSourceType':'Local'}
    if any(rule.get(k) != v for k,v in expected.items()):
        raise ValueError('Firewall state differs from reviewed MSI rule')
    if rule.get('Program','').lower() != r'c:\program files\usbipd-win\usbipd.exe':
        raise ValueError('Unexpected firewall program')
    if any(rule.get(k) != v for k,v in {'LocalAddress':['Any'],'RemoteAddress':['LocalSubnet'],'InterfaceAlias':['Any']}.items()):
        raise ValueError('Existing scope is not the reviewed baseline; do not broaden it')
    if network.get('mode') != 'nat':
        raise ValueError('Only observed WSL NAT topology reviewed')
    guest = ipaddress.IPv4Address(network['guest_ip'])
    gateway = ipaddress.IPv4Address(network['gateway'])
    prefix = network['prefixlen']
    if type(prefix) is not int or not 16 <= prefix <= 30:
        raise ValueError('Unexpected WSL subnet size')
    subnet = ipaddress.IPv4Network(f'{gateway}/{prefix}',strict=False)
    if not guest.is_private or not gateway.is_private or guest == gateway or guest not in subnet:
        raise ValueError('Expected distinct private WSL addresses in one subnet')
    alias = network['interface_alias']
    if not isinstance(alias,str) or not alias.startswith('vEthernet (WSL'):
        raise ValueError('Exact Windows WSL virtual interface required')
    return {'preview_only':True,'applied':False,'command':'Set-NetFirewallRule',
            'proposed_parameters':{'Name':owned_rule_name,'LocalAddress':[str(gateway)],
                                   'RemoteAddress':[str(guest)],'InterfaceAlias':[alias]},
            'rollback_parameters':{'Name':owned_rule_name,'LocalAddress':rule['LocalAddress'],
                                   'RemoteAddress':rule['RemoteAddress'],'InterfaceAlias':rule['InterfaceAlias']},
            'unchanged_fields':expected,'program_unchanged':rule['Program'],
            'fresh_snapshot_and_IP_confirmation_required':True,
            'scope_claim':'Restricts this owned rule only; not a proof of entire firewall isolation'}


def device_preview(busid, vid, pid):
    if not isinstance(busid,str) or not re.fullmatch(r'[1-9][0-9]{0,2}-[1-9][0-9]{0,2}',busid):
        raise ValueError('Explicit single Windows BUSID required')
    if not isinstance(vid,str) or not isinstance(pid,str) or not re.fullmatch('[0-9A-Fa-f]{4}',vid) or not re.fullmatch('[0-9A-Fa-f]{4}',pid):
        raise ValueError('Explicit test VID/PID required')
    if vid.lower() in ('0000','1f3a') or pid.lower() in ('0000','efe8','4ee7'):
        raise ValueError('Tablet/Allwinner identities forbidden')
    return {'preview_only':True,'device_identity':{'windows_busid':busid,'vid':vid.lower(),'pid':pid.lower()},
            'requires_fresh_identity_and_single_target_verification':True,
            'bind_argv':['bind','--busid',busid],
            'attach_argv':['attach','--wsl','Ubuntu','--busid',busid],
            'detach_argv':['detach','--busid',busid],
            'unbind_argv':['unbind','--busid',busid],
            'automatic_retry':False,'force':False,'auto_attach':False,
            'physical_VERSION_allowed':False}


def main():
    root=Path(__file__).resolve().parents[3]
    evidence=root/'analise-firmware/revisao-fel/independent-capture/usbip-wsl'
    rule=json.loads((evidence/'firewall-before.json').read_text(encoding='utf-8-sig'))
    net=json.loads((evidence/'wsl-network.json').read_text())
    mode=net[0]['stdout'].strip()
    addresses=json.loads(net[1]['stdout']);routes=json.loads(net[2]['stdout'])
    windows=json.loads((evidence/'windows-wsl-interface.json').read_text(encoding='utf-8-sig'))
    if not isinstance(windows,dict) or len(addresses)!=1:
        raise ValueError('Ambiguous WSL interface')
    globals_=[a for a in addresses[0]['addr_info'] if a['family']=='inet' and a['scope']=='global']
    defaults=[r for r in routes if r['dst']=='default']
    if len(globals_)!=1 or len(defaults)!=1 or defaults[0]['gateway']!=windows['IPAddress']:
        raise ValueError('Ambiguous/mismatched WSL NAT route')
    if globals_[0]['prefixlen'] != windows['PrefixLength']:
        raise ValueError('Prefix mismatch')
    network={'mode':mode,'guest_ip':globals_[0]['local'],'prefixlen':globals_[0]['prefixlen'],
             'gateway':defaults[0]['gateway'],'interface_alias':windows['InterfaceAlias']}
    run=Path((root/'tools/usbipd-review/latest-installation-path.txt').read_text(encoding='utf-8-sig').strip())
    owner=json.loads((run/'installation-receipt.json').read_text())
    owned=owner['owned_resources']['firewall_rules']['rule']['Name']
    if owner.get('state')!='APPLIED' or owner.get('owns_installation') is not True:
        raise ValueError('Real applied installation receipt required')
    print(json.dumps({'firewall':firewall_preview(rule,network,owned),'observed_network':network,
                      'device_test':{'selection_required':True,'bind_attach_executed':False},
                      'modules':{'activation_performed':False,'future_load_only':['usbmon','vhci_hcd'],
                                 'usbip_core_is_dependency':True,'load_in_host_WSL_not_privileged_container':True},
                      'capture_device_mapping':'Verify exact future /dev/usbmonN in Docker daemon before mapping read-only',
                      'physical_VERSION_allowed':False},indent=2))


if __name__=='__main__':main()
