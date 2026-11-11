import copy
import unittest
import plan as p


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.host = dict(architecture='X64',services=[],vbox_drivers=[],firewall_rules=[],
                         matching_oem_infs=[],program_directory_exists=False,
                         registry=[{'exists':False} for _ in range(3)])
        self.package = dict(sha256=p.SHA256,status='Valid',bytes=4501504)
        self.receipt = dict(state='APPLIED',owns_installation=True,initial_state_clear=True,
                            product_code=p.PRODUCT_CODE,version=p.VERSION,package_sha256=p.SHA256)
        self.current = dict(product_code=p.PRODUCT_CODE,version=p.VERSION,bound_device_count=0,shared_virtualbox_use=False)

    def test_install_preview_suppresses_reboot_and_has_no_device_commands(self):
        result = p.install_preview(self.host,self.package,'.')
        self.assertIn('/norestart',result['arguments'])
        self.assertIn('REBOOT=ReallySuppress',result['arguments'])
        self.assertEqual(result['device_commands'],[])
        self.assertFalse(result['execution_ready'])

    def test_reject_altered_hash_signature_and_size(self):
        for key,value in [('sha256','0'*64),('status','UnknownError'),('bytes',1)]:
            package=dict(self.package);package[key]=value
            with self.assertRaises(ValueError):p.install_preview(self.host,package,'.')

    def test_reject_existing_virtualbox_usbipd_firewall_oem_state(self):
        for key in ['services','vbox_drivers','firewall_rules','matching_oem_infs','program_directory_exists']:
            host=copy.deepcopy(self.host);host[key]=True
            with self.assertRaises(ValueError):p.install_preview(host,self.package,'.')

    def test_reject_wrong_architecture_and_unknown_registry(self):
        for key,value in [('architecture','ARM64'),('registry',[]),('registry',[{'exists':True}]*3)]:
            host=dict(self.host);host[key]=value
            with self.assertRaises(ValueError):p.install_preview(host,self.package,'.')

    def test_template_cannot_be_used_for_rollback(self):
        template=p.install_preview(self.host,self.package,'.')['receipt_template']
        with self.assertRaises(ValueError):p.rollback_preview(template,self.current,'.')

    def test_rollback_exact_product_and_reboot_policy(self):
        result=p.rollback_preview(self.receipt,self.current,'.')
        self.assertEqual(result['arguments'][:2],['/x',p.PRODUCT_CODE])
        self.assertIn('REBOOT=ReallySuppress',result['arguments'])
        self.assertEqual(result['device_commands'],[])

    def test_reject_wrong_receipt_identity_or_ownership(self):
        for key,value in [('product_code','wrong'),('package_sha256','wrong'),('version','5.2.0'),
                          ('owns_installation',False),('initial_state_clear',False)]:
            receipt=dict(self.receipt);receipt[key]=value
            with self.assertRaises(ValueError):p.rollback_preview(receipt,self.current,'.')

    def test_reject_changed_installed_version_or_product(self):
        for key in ['version','product_code']:
            current=dict(self.current);current[key]='different'
            with self.assertRaises(ValueError):p.rollback_preview(self.receipt,current,'.')

    def test_reject_active_or_unknown_bindings(self):
        for count in [1,None,False,-1]:
            current=dict(self.current);current['bound_device_count']=count
            with self.assertRaises(ValueError):p.rollback_preview(self.receipt,current,'.')

    def test_reject_shared_or_unknown_virtualbox_use(self):
        for state in [True,None]:
            current=dict(self.current);current['shared_virtualbox_use']=state
            with self.assertRaises(ValueError):p.rollback_preview(self.receipt,current,'.')


if __name__=='__main__':unittest.main()
