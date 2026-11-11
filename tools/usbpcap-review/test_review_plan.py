import unittest
from review_plan import CLASS_KEY, INSTALLER_SHA256, installation_delta, rollback_delta


def receipt(**extra):
    return dict(schema=1, state='APPLIED', class_key=CLASS_KEY,
                installer_sha256=INSTALLER_SHA256, upper_filters_before_exists=False,
                upper_filters_before=None, added_by_this_operation=True) | extra


class ReviewTests(unittest.TestCase):
    def test_absent_value_appends_one_filter(self):
        self.assertEqual(installation_delta(False, None)['proposed_values'], ['USBPcap'])

    def test_existing_filters_preserved_in_order(self):
        self.assertEqual(installation_delta(True, ['Alpha', 'Beta'])['proposed_values'], ['Alpha', 'Beta', 'USBPcap'])

    def test_preexisting_usbpcap_not_owned(self):
        self.assertFalse(installation_delta(True, ['usbpcap'])['would_add'])
        r = receipt(upper_filters_before_exists=True, upper_filters_before=['USBPcap'], added_by_this_operation=False)
        self.assertIsNone(rollback_delta(r, True, ['USBPcap'])['remove_string_only'])

    def test_remove_owned_string_only_preserves_concurrent_filter(self):
        p = rollback_delta(receipt(), True, ['OtherAdded', 'USBPcap'])
        self.assertEqual(p['preserved_values'], ['OtherAdded'])
        self.assertFalse(p['may_remove_empty_value_after_uninstall'])

    def test_original_absence_restorable_only_when_empty(self):
        self.assertTrue(rollback_delta(receipt(), True, ['USBPcap'])['may_remove_empty_value_after_uninstall'])

    def test_original_empty_value_should_remain(self):
        p = rollback_delta(receipt(upper_filters_before_exists=True, upper_filters_before=[]), True, ['USBPcap'])
        self.assertFalse(p['may_remove_empty_value_after_uninstall'])

    def test_template_and_wrong_identity_rejected(self):
        for field, value in (('state', 'TEMPLATE_NOT_AN_INSTALL_RECEIPT'), ('class_key', 'HKLM\\OTHER'), ('installer_sha256', '0' * 64)):
            with self.assertRaises(ValueError): rollback_delta(receipt(**{field: value}), True, ['USBPcap'])

    def test_contradictory_ownership_rejected(self):
        with self.assertRaises(ValueError): rollback_delta(receipt(upper_filters_before_exists=True, upper_filters_before=['USBPcap']), True, ['USBPcap'])

    def test_malformed_types_and_duplicates_rejected(self):
        for exists, values in (('yes', None), (False, ['Other']), (True, 'USBPcap'), (True, ['USBPcap', 'usbpcap'])):
            with self.assertRaises(ValueError): installation_delta(exists, values)

    def test_already_removed_is_noop(self):
        self.assertIsNone(rollback_delta(receipt(), False, None)['remove_string_only'])


if __name__ == '__main__': unittest.main()
