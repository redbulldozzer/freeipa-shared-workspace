import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('remote_tested', ROOT / 'internal/remote.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
p = r.publisher
S = dict(server='192.0.2.1', server_name='example.invalid', domain='example.invalid', realm='example.invalid', network='192.0.2.1/24')


class DNS(unittest.TestCase):
    def test_dhcp_changes_keep_enrolled_name(self):
        host = p.machine_name('[domain/example.invalid]\nid_provider=ipa\nipa_hostname=example.invalid', S)
        for address in ('192.0.2.1', '192.0.2.1'):
            self.assertEqual(p.office_address([{'dev': 'enp8s0', 'prefsrc': address}], S), address)
            self.assertIn(f'update add {host}. 60 A {address}', p.update_message(host, address, S))

    def test_other_domain_does_not_publish_to_office(self):
        s = dict(server='192.0.2.1', server_name='ipa.example.test', domain='example.test', realm='EXAMPLE.TEST', network='192.0.2.1/24')
        p.validate(s)
        host = p.machine_name('[domain/example.test]\nid_provider=ipa\nipa_hostname=pc77.example.test', s)
        update = p.update_message(host, '192.0.2.1', s)
        self.assertIn('server ipa.example.test\nzone example.test.', update)
        self.assertNotIn('office', update)

    def test_invalid_routes_cannot_replace_record(self):
        routes = [[{'dev': 'wg0-mullvad', 'prefsrc': '192.0.2.1'}],
                  [{'dev': 'enp8s0', 'prefsrc': '192.0.2.1'}], [], [{}, {}],
                  [{'dev': 'enp8s0', 'prefsrc': '192.0.2.1'}]]
        for route in routes:
            with self.assertRaises(ValueError):
                p.office_address(route, S)

    def test_update_injection_and_wrong_domains_rejected(self):
        for host in ('other.example.invalid', '*.example.invalid', 'example.invalid\nsend', 'example.invalid'):
            with self.assertRaises(ValueError):
                p.update_message(host, '192.0.2.1', S)
        with self.assertRaises(ValueError):
            p.validate(dict(S, server='192.0.2.1'))
        with self.assertRaises(ValueError):
            p.validate(dict(S, server_name='example.invalid\nsend'))


class SSH(unittest.TestCase):
    def test_conflicting_key_provider_refused_before_mutation(self):
        with patch.object(Path, 'exists', return_value=True), \
             patch.object(r, 'ssh_values', return_value={'authorizedkeyscommand': '/custom/helper'}), \
             patch.object(r, 'backup') as backup, self.assertRaises(RuntimeError):
            r.configure_ssh('admin')
        backup.assert_not_called()

    def check_rollback(self, existing):
        with tempfile.TemporaryDirectory() as tmp:
            ssh = Path(tmp) / '04.conf'
            sssd = Path(tmp) / 'sssd.conf'
            sssd.write_text('[sssd]\nservices=nss,pam,ssh\n')
            if existing:
                ssh.write_text('# original\n')
            values = {'authorizedkeyscommand': 'none'}
            with patch.object(r, 'SSH', ssh), patch.object(r, 'SSSD', sssd), \
                 patch.object(r, 'KEY_COMMAND', str(sssd)), \
                 patch.object(r, 'ssh_values', return_value=values), \
                 patch.object(r, 'backup'), patch.object(r, 'output', return_value='ssh-rsa AAA test'), \
                 patch.object(r, 'run'), self.assertRaises(RuntimeError):
                r.configure_ssh('admin')
            if existing:
                self.assertEqual(ssh.read_text(), '# original\n')
            else:
                self.assertFalse(ssh.exists())

    def test_failed_validation_restores_existing_file(self):
        self.check_rollback(True)

    def test_failed_validation_removes_new_file(self):
        self.check_rollback(False)

    def test_missing_key_does_not_enable_ssh_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            sssd = Path(tmp) / 'sssd'; sssd.write_text('[sssd]\nservices=nss,pam,ssh\n')
            ssh = Path(tmp) / 'ssh'
            with patch.object(r, 'SSSD', sssd), patch.object(r, 'SSH', ssh), \
                 patch.object(r, 'KEY_COMMAND', str(sssd)), patch.object(r, 'ssh_values', return_value={'authorizedkeyscommand': 'none'}), \
                 patch.object(r, 'backup'), patch.object(r, 'run'), patch.object(r, 'output', return_value=''), self.assertRaises(RuntimeError):
                r.configure_ssh('admin')
            self.assertFalse(ssh.exists())


if __name__ == '__main__':
    unittest.main()
