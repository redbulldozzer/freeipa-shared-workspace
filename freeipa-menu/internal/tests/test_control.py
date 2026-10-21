import fcntl
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('control', Path(__file__).resolve().parents[1] / 'control.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class Control(unittest.TestCase):
    def test_socket_activated_ssh_gets_runtime_directory_before_validation(self):
        state = {'directory': False, 'validated': False, 'started': False}
        def command(args, **kwargs):
            if args[0] == 'install':
                self.assertEqual(args, ['install', '-d', '-o', 'root', '-g', 'root', '-m', '0755', '/run/sshd'])
                state['directory'] = True
            if args == ['/usr/sbin/sshd', '-t']:
                self.assertTrue(state['directory'], 'sshd -t needs its runtime directory even before startup')
                state['validated'] = True
            if args == ['systemctl', 'enable', '--now', 'ssh.service']:
                self.assertTrue(state['validated'])
                state['started'] = True
            return SimpleNamespace(stdout='Status: inactive\n')
        with patch.object(c, 'run', side_effect=command):
            c.enable_ssh()
        self.assertTrue(state['started'])

    def test_invalid_ssh_config_does_not_start_service(self):
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            if args == ['/usr/sbin/sshd', '-t']:
                raise c.subprocess.CalledProcessError(255, args)
        with patch.object(c, 'run', side_effect=command), self.assertRaises(c.subprocess.CalledProcessError):
            c.enable_ssh()
        self.assertNotIn(['systemctl', 'enable', '--now', 'ssh.service'], calls)

    def test_selection_validates_every_user_before_replacing_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'selected'
            path.write_text('existing\n')
            with patch.object(c, 'SELECTED', path), patch.object(c, 'eligible', side_effect=[None, ValueError('denied')]):
                with self.assertRaises(ValueError):
                    c.save_selected(['employee1', 'outsider'], 'shared')
            self.assertEqual(path.read_text(), 'existing\n')

    def test_selection_deduplicates_and_preserves_order(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(c, 'SELECTED', Path(tmp) / 'users'), patch.object(c, 'eligible'):
            c.save_selected(['employee2', 'employee1', 'employee2'], 'shared')
            self.assertEqual(c.SELECTED.read_text(), 'employee2\nseller1\n')
            c.save_selected([], 'shared')
            self.assertTrue(c.SELECTED.exists())
            self.assertEqual(c.SELECTED.read_text(), '')

    def test_too_many_buttons_rejected(self):
        with self.assertRaises(ValueError):
            c.save_selected([f'user{i}' for i in range(9)], 'shared')

    def test_local_collision_cannot_gain_domain_admin_rights(self):
        with patch.object(c, 'local_names', return_value={'admin'}), self.assertRaises(ValueError):
            c.administrator('admin')

    def test_employee_must_be_in_access_group(self):
        with patch.object(c, 'local_names', return_value=set()), \
             patch.object(c.pwd, 'getpwnam', return_value=SimpleNamespace(pw_gid=100)), \
             patch.object(c.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=200)), \
             patch.object(c.os, 'getgrouplist', return_value=[100]), self.assertRaises(ValueError):
            c.eligible('outsider', 'shared')

    def test_stale_current_is_not_an_active_employee(self):
        with tempfile.TemporaryDirectory() as tmp:
            current, lock = Path(tmp) / 'current', Path(tmp) / 'lock'
            current.write_text('employee=employee1\n')
            lock.touch()
            with patch.object(c, 'CURRENT', current), patch.object(c, 'LOCK', lock):
                self.assertIsNone(c.current_employee())
                with lock.open('rb') as held:
                    fcntl.flock(held, fcntl.LOCK_EX)
                    self.assertEqual(c.current_employee(), 'employee1')

    def test_policy_requires_admin_each_time_and_only_fixed_entry(self):
        sudo, rules, policy = c.admin_files('admin')
        self.assertNotIn('NOPASSWD', sudo)
        self.assertIn('admin ALL=(ALL:ALL) ALL', sudo)
        self.assertIn('unix-group:sudo', rules)
        self.assertIn('unix-user:admin', rules)
        root = ET.fromstring(policy)
        self.assertEqual(root.find('.//annotate').text, c.ENTRY)
        self.assertTrue(all(node.text == 'auth_admin' for node in root.find('.//defaults')))
        self.assertNotIn('office-workspace', rules)

    def test_admin_name_cannot_inject_sudo_rule(self):
        for value in ('admin\nALL ALL=ALL', '%sudo', 'admin ALL=ALL'):
            with self.assertRaises(ValueError):
                c.admin_files(value)

    def test_desktop_config_not_executed_and_outside_home_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / '.config').mkdir()
            (home / '.config/user-dirs.dirs').write_text('XDG_DESKTOP_DIR="/etc"\n')
            account = SimpleNamespace(pw_dir=tmp)
            self.assertEqual(c.desktop_path(account), home / 'Desktop')
            (home / '.config/user-dirs.dirs').write_text('XDG_DESKTOP_DIR="$HOME/Рабочий стол"\n')
            self.assertEqual(c.desktop_path(account), home / 'Рабочий стол')


if __name__ == '__main__':
    unittest.main()
