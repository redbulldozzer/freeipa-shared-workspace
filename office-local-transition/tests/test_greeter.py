import configparser
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from transition.greeter import main, select_user


class GreeterTests(unittest.TestCase):
    def test_every_start_resets_manual_selection_and_preserves_other_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'slick-greeter/state'
            state.parent.mkdir()
            original = '[greeter]\nlast-user=*other\nlast-session=cinnamon\nformat=100%\n'
            state.write_text(original)
            for _ in range(2):
                select_user(directory, 'office-workspace')
                parsed = configparser.ConfigParser(interpolation=None)
                parsed.read(state)
                self.assertEqual(parsed['greeter']['last-user'], 'office-workspace')
                self.assertEqual(parsed['greeter']['last-session'], 'cinnamon')
                self.assertEqual(parsed['greeter']['format'], '100%')
                self.assertEqual(state.stat().st_mode & 0o777, 0o600)
                state.write_text(original)

    def test_root_privileges_dropped_before_touching_cache(self):
        user = SimpleNamespace(pw_uid=114, pw_gid=120, pw_dir='/var/lib/lightdm')
        with patch('transition.greeter.pwd.getpwnam', return_value=user), \
             patch('transition.greeter.os.geteuid', side_effect=[0, 114]), \
             patch('transition.greeter.os.setgroups') as groups, \
             patch('transition.greeter.os.setgid') as gid, \
             patch('transition.greeter.os.setuid') as uid, \
             patch('transition.greeter.os.umask'), \
             patch('transition.greeter.select_user') as select:
            def check(*args):
                groups.assert_called_once_with([])
                gid.assert_called_once_with(120)
                uid.assert_called_once_with(114)
            select.side_effect = check
            main('office-workspace')
            self.assertEqual(select.call_args.args[:2], (Path('/var/lib/lightdm/.cache'), 'office-workspace'))

    def test_symlink_cache_does_not_write_through(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            other = root/'other'
            other.mkdir()
            (root/'slick-greeter').symlink_to(other, target_is_directory=True)
            with self.assertRaises(ValueError):
                select_user(root, 'office-workspace')
            self.assertEqual(list(other.iterdir()), [])
