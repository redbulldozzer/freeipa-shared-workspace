import fcntl
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
import sys

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import panel_helper as helper
import install as installer


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.lock = (self.root / 'session.lock').open('w')
        os.fchmod(self.lock.fileno(), 0o644)
        fcntl.flock(self.lock, fcntl.LOCK_EX)
        self.current = self.root / 'current'
        self.current.write_text('employee=avi1\nshift=' + 'a' * 32 + '\npid=99999999\n')
        self.current.chmod(0o644)

    def tearDown(self):
        self.lock.close()
        self.temp.cleanup()

    def test_live_lock_not_pid_proves_identity(self):
        self.assertEqual(helper.identity(self.root, os.getuid()), ('avi1', 'a' * 32))

    def test_stale_identity_rejected(self):
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        with self.assertRaisesRegex(ValueError, 'no_live_session'):
            helper.identity(self.root, os.getuid())

    def test_untrusted_and_symlink_rejected(self):
        self.current.chmod(0o666)
        with self.assertRaises(ValueError): helper.identity(self.root, os.getuid())
        self.current.unlink()
        self.current.symlink_to('/etc/passwd')
        with self.assertRaises(OSError): helper.identity(self.root, os.getuid())

    def test_invalid_identity_rejected(self):
        self.current.write_text('employee=$(bad)\nshift=' + 'a' * 32)
        with self.assertRaises(ValueError): helper.identity(self.root, os.getuid())

    def test_takeover_during_name_lookup_rejected(self):
        with patch.object(helper, 'require_workspace'), patch.object(helper, 'identity', side_effect=[('avi1', 'a'*32), ('avi2', 'b'*32)]), patch.object(helper.pwd, 'getpwnam', return_value=Mock(pw_gecos='Имя')):
            with self.assertRaisesRegex(ValueError, 'identity_changed'): helper.status()

    def test_name_unavailable_uses_login(self):
        with patch.object(helper, 'require_workspace'), patch.object(helper, 'identity', return_value=('avi1', 'a'*32)), patch.object(helper.pwd, 'getpwnam', side_effect=KeyError):
            self.assertEqual(helper.status()['name'], 'avi1')


class PanelTests(unittest.TestCase):
    def test_preserves_panel_entries_and_unique_id(self):
        original = ['panel2:right:3:employee@example.invalid:12', 'panel1:left:0:employee@example.invalid:8']
        result, next_id = helper.panel_entries(original, 0, ['1:0:bottom', '2:1:bottom'])
        self.assertEqual(result[:-1], original)
        self.assertEqual(result[-1], f'panel2:right:4:{helper.UUID}:13')
        self.assertEqual(next_id, 14)
        self.assertEqual(helper.panel_entries(result, next_id, []), (result, next_id))

    def test_no_clock_fallback_and_no_panel(self):
        self.assertTrue(helper.panel_entries([], 0, ['3:0:bottom'])[0][0].startswith('panel3:right:'))
        with self.assertRaises(ValueError): helper.panel_entries([], 0, [])


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for rel in ['etc/shared-workspace.conf', 'usr/bin/cinnamon', 'usr/bin/dm-tool', 'usr/local/libexec/shared-workspace-lock-bridge']:
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('target=office-workspace\n')

    def tearDown(self): self.temp.cleanup()

    def test_install_idempotent_rollback_preserves_old_file(self):
        target = self.root / installer.FILES['panel_helper.py'][0]
        target.write_text('previous version')
        target.chmod(0o750)
        result = installer.install(self.root)
        self.assertTrue(result['changed'])
        self.assertFalse(installer.install(self.root)['changed'])
        installer.restore(self.root, Path(result['backup']))
        self.assertEqual(target.read_text(), 'previous version')
        self.assertEqual(target.stat().st_mode & 0o777, 0o750)
        self.assertFalse((self.root / installer.FILES['applet/applet.js'][0]).exists())

    def test_rollback_refuses_later_edits(self):
        result = installer.install(self.root)
        (self.root / installer.FILES['panel_helper.py'][0]).write_text('local edit')
        with self.assertRaisesRegex(ValueError, 'Changed since'):
            installer.restore(self.root, Path(result['backup']))

    def test_symlink_parent_rejected(self):
        (self.root / 'usr/share').symlink_to(self.root / 'etc')
        with self.assertRaisesRegex(ValueError, 'Symlink'): installer.install(self.root)

    def test_failed_install_restores_previous_state(self):
        real_write = installer.atomic_write
        calls = 0
        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('simulated disk failure')
            return real_write(*args, **kwargs)
        with patch.object(installer, 'atomic_write', side_effect=fail_second):
            with self.assertRaises(OSError): installer.install(self.root)
        for rel, _ in installer.FILES.values(): self.assertFalse((self.root / rel).exists())

    def test_missing_prerequisite_no_payload(self):
        (self.root / 'usr/bin/dm-tool').unlink()
        with self.assertRaises(ValueError): installer.install(self.root)
        self.assertFalse((self.root / installer.FILES['panel_helper.py'][0]).exists())


class SwitchTests(unittest.TestCase):
    def test_lock_before_greeter_and_lock_failure_stops(self):
        from gi.repository import Gio
        bus = Mock()
        bus.call_sync.return_value.unpack.return_value = (True,)
        with patch.object(helper, 'require_workspace'), patch.object(Gio, 'bus_get_sync', return_value=bus), patch.object(helper.subprocess, 'run') as run:
            helper.switch_employee()
            args = bus.call_sync.call_args_list
            self.assertEqual(args[0].args[3], 'Lock')
            self.assertEqual(args[0].args[4].unpack(), ('',))
            self.assertEqual(args[1].args[3], 'GetActive')
            run.assert_called_once()
            run.reset_mock()
            bus.call_sync.side_effect = RuntimeError('lock unavailable')
            with self.assertRaises(RuntimeError): helper.switch_employee()
            run.assert_not_called()


if __name__ == '__main__': unittest.main()
