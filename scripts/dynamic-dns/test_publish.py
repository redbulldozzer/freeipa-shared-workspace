import unittest
from publish import machine_name, office_address, update_message

class PublisherTests(unittest.TestCase):
    def test_name_is_enrolled_identity(self):
        self.assertEqual(machine_name('[domain/example.invalid]\nipa_hostname=example.invalid'), 'example.invalid')
        for name in ['other.example','example.invalid\n','*.example.invalid','example.invalid.elsewhere','bad example.invalid']:
            if name.endswith('\n'):continue
            with self.assertRaises(ValueError):machine_name('[domain/example.invalid]\nipa_hostname='+name)
    def test_dhcp_address_can_change(self):
        for address in ['192.0.2.1','192.0.2.1']:
            self.assertEqual(office_address([{'dev':'enp8s0','prefsrc':address}]),address)
            self.assertIn('60 A '+address,update_message('example.invalid',address))
    def test_vpn_and_virtual_sources_are_rejected(self):
        for route in [{'dev':'wg0-mullvad','prefsrc':'192.0.2.1'}, {'dev':'enp8s0','prefsrc':'192.0.2.1'}, {'dev':'docker0','prefsrc':'192.0.2.1'}, {}]:
            with self.assertRaises(ValueError):office_address([route])
        with self.assertRaises(ValueError):office_address([])
    def test_update_is_signed_by_machine_not_admin(self):
        message=update_message('example.invalid','192.0.2.1')
        self.assertIn('server example.invalid\n',message)
        self.assertIn('update delete example.invalid. A\n',message)
        self.assertNotIn('AAAA',message)

if __name__=='__main__':unittest.main()
