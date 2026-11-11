import unittest
import prepare_test as p


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.rule={'Name':'owned-guid','DisplayName':'usbipd','Enabled':'True','Direction':'Inbound',
                   'Action':'Allow','Profile':'Any','Protocol':'TCP','LocalPort':'3240','RemotePort':'Any',
                   'PolicyStoreSourceType':'Local','Program':r'C:\Program Files\usbipd-win\usbipd.exe',
                   'LocalAddress':['Any'],'RemoteAddress':['LocalSubnet'],'InterfaceAlias':['Any']}
        self.network={'mode':'nat','guest_ip':'172.26.161.170','gateway':'172.26.160.1',
                      'prefixlen':20,'interface_alias':'vEthernet (WSL (Hyper-V firewall))'}

    def test_exact_guest_scope_and_reversal(self):
        result=p.firewall_preview(self.rule,self.network,'owned-guid')
        self.assertEqual(result['proposed_parameters']['RemoteAddress'],['172.26.161.170'])
        self.assertEqual(result['rollback_parameters']['RemoteAddress'],['LocalSubnet'])
        self.assertEqual(result['proposed_parameters']['LocalAddress'],['172.26.160.1'])
        self.assertFalse(result['applied'])

    def test_reject_unowned_modified_or_already_scoped_rule(self):
        for key,value in [('Name','another-guid'),('Program','other.exe'),('LocalPort','80'),
                          ('Profile','Private'),('RemoteAddress',['172.26.161.170']),('Direction','Outbound')]:
            rule=dict(self.rule);rule[key]=value
            with self.assertRaises(ValueError):p.firewall_preview(rule,self.network,'owned-guid')

    def test_reject_unknown_network_mode_or_addresses(self):
        for key,value in [('mode','mirrored'),('guest_ip','8.8.8.8'),('guest_ip','172.27.1.1'),
                          ('guest_ip','172.26.160.1'),('gateway','::1'),('prefixlen',False),
                          ('interface_alias','Wi-Fi')]:
            network=dict(self.network);network[key]=value
            with self.assertRaises(ValueError):p.firewall_preview(self.rule,network,'owned-guid')

    def test_test_device_plan_is_scoped_and_no_retry(self):
        result=p.device_preview('4-3','1234','5678')
        self.assertEqual(result['attach_argv'],['attach','--wsl','Ubuntu','--busid','4-3'])
        self.assertEqual(result['unbind_argv'],['unbind','--busid','4-3'])
        self.assertFalse(result['automatic_retry'])
        self.assertFalse(result['physical_VERSION_allowed'])

    def test_refuse_tablet_and_ambiguous_busids(self):
        for bus,vid,pid in [('4-3','1f3a','5678'),('4-3','1234','EFE8'),('4-3','1234','4ee7'),
                            ('--all','1234','5678'),('4-3;reboot','1234','5678'),('0-0','1234','5678')]:
            with self.assertRaises(ValueError):p.device_preview(bus,vid,pid)


if __name__=='__main__':unittest.main()
