import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('menu', ROOT / 'menu.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Menu(unittest.TestCase):
    def test_employee_panel_requires_shared_configuration(self):
        with patch.object(m, 'current_config', return_value={}), patch.object(m, 'run') as run:
            m.install_employee_panel()
            run.assert_not_called()

    def test_employee_panel_uses_protected_copy_and_propagates_failure(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            installed = Path(tmp)
            with patch.object(m, 'INSTALLED', installed), \
                 patch.object(m, 'current_config', return_value={'target': 'office-workspace'}), \
                 patch.object(m, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'отсутствует'):
                    m.install_employee_panel()
                run.assert_not_called()
                installer = installed / 'employee-panel/install.py'
                installer.parent.mkdir()
                installer.touch()
                m.install_employee_panel()
                run.assert_called_once_with(['/usr/bin/python3', installer, 'install'])
                run.side_effect = subprocess.CalledProcessError(1, 'install')
                with self.assertRaises(subprocess.CalledProcessError):
                    m.install_employee_panel()

    def test_management_installs_panel_after_runtime_in_all_paths(self):
        from contextlib import ExitStack
        for runtime, shortcuts in [(False, False), (False, True), (True, True)]:
            with self.subTest(runtime=runtime, shortcuts=shortcuts), ExitStack() as stack:
                events = []
                for obj, name in [(m, 'validate'), (m.control, 'administrator'),
                                  (m.base, 'wait_for_group'), (m.base, 'backup_files'),
                                  (m.control, 'enable_ssh'), (m.control, 'install_admin'),
                                  (m.autokey_compat, 'install'), (m.remote, 'setup'),
                                  (m.base, 'atomic_write'), (m.control, 'install_shortcuts'),
                                  (m.transfer, 'write_json')]:
                    stack.enter_context(patch.object(obj, name))
                stack.enter_context(patch.object(m, 'current_config', return_value={'target': 'office-workspace'}))
                stack.enter_context(patch.object(m, 'install_self', side_effect=lambda: events.append('copy')))
                stack.enter_context(patch.object(m, 'run', side_effect=lambda *a: events.append('runtime')))
                stack.enter_context(patch.object(m, 'install_employee_panel', side_effect=lambda: events.append('panel')))
                m.management_install({'domain_admin': 'admin', 'access_group': 'shared',
                                      'workspace_user': 'office-workspace', 'source_user': 'source'},
                                     update_runtime=runtime, shortcuts=shortcuts)
                self.assertEqual(events, ['copy', 'runtime', 'panel'] if runtime else ['copy', 'panel'])

    def test_desktop_helpers_require_known_executable_and_manager(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / 'cgroup').write_text('0::/user.slice/user-1000.slice/employee@example.invalid/app.slice\n')
            with patch.object(Path, 'resolve', return_value=Path('/usr/libexec/gvfsd')):
                self.assertTrue(m.session_helper(proc, 1000))
                self.assertFalse(m.session_helper(proc, 100))
                (proc / 'cgroup').write_text('0::/user.slice/session-3.scope\n')
                self.assertFalse(m.session_helper(proc, 1000))
            (proc / 'cgroup').write_text('0::/user.slice/employee@example.invalid/app.slice\n')
            for executable in ('/usr/lib/firefox/firefox', '/usr/lib/virtualbox/VBoxHeadless',
                               '/home/example-user/gvfsd', '/usr/libexec/evolution'):
                with patch.object(Path, 'resolve', return_value=Path(executable)):
                    self.assertFalse(m.session_helper(proc, 1000))

    def test_helper_must_be_gone_after_manager_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / '987654'
            proc.mkdir()
            (proc / 'comm').write_text('gvfsd\n')
            account = SimpleNamespace(pw_uid=proc.stat().st_uid)
            with patch.object(m.os, 'getpid', return_value=1), \
                 patch.object(m.base, 'local_account', return_value=account), \
                 patch.object(m, 'check_graphical_sessions'), \
                 patch.object(m, 'session_helper', return_value=True), \
                 patch.object(Path, 'iterdir', return_value=[proc]):
                s = {'source_user':'example-user', 'workspace_user':'office-workspace'}
                m.accounts_idle(s)
                with self.assertRaisesRegex(RuntimeError, 'gvfsd'):
                    m.accounts_idle(s, allow_session_services=False)

    def check_session(self, state='active', uid=1000, kind='x11', cls='user'):
        result = SimpleNamespace(returncode=0, stdout=f'User={uid}\nName=example-user\nType={kind}\nState={state}\nClass={cls}\nDisplay=:0\n')
        with patch.object(m, 'run', return_value=SimpleNamespace(stdout='c2 1000 example-user\n')), \
             patch.object(m.subprocess, 'run', return_value=result):
            m.check_graphical_sessions({1000})

    def test_closing_session_does_not_block_on_registration_alone(self):
        self.check_session(state='closing')

    def test_active_and_background_graphical_sessions_are_rejected(self):
        for state in ('active', 'online', ''):
            with self.subTest(state=state), self.assertRaisesRegex(RuntimeError, 'сеанс c2.*example-user'):
                self.check_session(state=state)

    def test_tty_greeter_and_other_users_are_not_profile_sessions(self):
        self.check_session(kind='tty')
        self.check_session(cls='greeter')
        self.check_session(uid=1234)

    def test_closing_session_still_checks_running_applications(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / '987654'
            proc.mkdir()
            (proc / 'comm').write_text('firefox\n')
            account = SimpleNamespace(pw_uid=proc.stat().st_uid)
            detail = SimpleNamespace(returncode=0, stdout=f'User={account.pw_uid}\nType=x11\nState=closing\n')
            with patch.object(m.os, 'getpid', return_value=1), \
                 patch.object(m.base, 'local_account', return_value=account), \
                 patch.object(m, 'run', return_value=SimpleNamespace(stdout='c2\n')), \
                 patch.object(m.subprocess, 'run', return_value=detail), \
                 patch.object(Path, 'iterdir', return_value=iter([proc])), \
                 self.assertRaisesRegex(RuntimeError, 'firefox'):
                m.accounts_idle({'source_user':'example-user', 'workspace_user':'office-workspace'})

    def test_disappeared_session_during_inspection_is_ignored(self):
        with patch.object(m, 'run', side_effect=[SimpleNamespace(stdout='c2\n'), SimpleNamespace(stdout='')]), \
             patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stderr='gone')):
            m.check_graphical_sessions({1000})

    def test_inspection_failure_for_existing_session_blocks_transfer(self):
        with patch.object(m, 'run', return_value=SimpleNamespace(stdout='c2\n')), \
             patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stderr='denied')), \
             self.assertRaisesRegex(RuntimeError, 'Не удалось проверить'):
            m.check_graphical_sessions({1000})

    def test_defaults_use_actual_hostname_and_common_group(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'SETTINGS', Path(tmp)/'settings'), \
             patch.object(m, 'current_config', return_value={}), \
             patch.object(m.socket, 'gethostname', return_value='pc-new'):
            result = m.defaults()
            self.assertEqual(result['fqdn'], 'example.invalid')
            self.assertEqual(result['access_group'], 'shared')
            self.assertEqual(result['ipa_address'], '192.0.2.1')
            self.assertTrue(result['managed_access'])
            self.assertFalse(any('password' in key for key in result))

    def test_menu_can_exit_without_installing(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'STATE', Path(tmp)), \
             patch.object(m.os, 'geteuid', return_value=0), patch('builtins.input', return_value='0'), \
             patch.object(m, 'defaults', return_value={}), patch.object(m, 'install') as install:
            self.assertEqual(m.main(), 0)
            install.assert_not_called()

    def test_result_waits_for_enter_before_next_menu(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'STATE', Path(tmp)), \
             patch.object(m.os, 'geteuid', return_value=0), \
             patch('builtins.input', side_effect=['8', '', '0']) as answers, \
             patch.object(m, 'defaults', return_value={}), patch.object(m, 'current_user') as current:
            self.assertEqual(m.main(), 0)
            current.assert_called_once()
            self.assertIn('Нажми Enter', answers.call_args_list[1].args[0])

    def test_background_dispatch_exits_menu_without_holding_lock_for_pause(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'STATE', Path(tmp)), \
             patch.object(m.os, 'geteuid', return_value=0), \
             patch('builtins.input', side_effect=['1']) as answers, \
             patch.object(m, 'defaults', return_value={}), patch.object(m, 'install', return_value='background'):
            self.assertEqual(m.main(), 0)
            self.assertEqual(answers.call_count, 1)

    def test_quiesce_refuses_to_stop_manager_containing_menu(self):
        s = {'source_user': 'example-user', 'workspace_user': 'office-workspace'}
        account = SimpleNamespace(pw_uid=1000)
        with patch.object(m, 'accounts_idle'), patch.object(m.base, 'local_account', return_value=account), \
             patch.object(Path, 'read_text', return_value='0::/user.slice/user-1000.slice/employee@example.invalid/app.slice'), \
             patch.object(m, 'run') as run, self.assertRaises(RuntimeError):
            m.quiesce_users(s)
        run.assert_not_called()

    def test_quiesce_leaves_normal_console_scope_alive(self):
        s = {'source_user': 'example-user', 'workspace_user': 'office-workspace'}
        account = SimpleNamespace(pw_uid=1000)
        with patch.object(m, 'accounts_idle') as idle, patch.object(m.base, 'local_account', return_value=account), \
             patch.object(Path, 'read_text', return_value='0::/user.slice/user-1000.slice/session-3.scope'), \
             patch.object(m, 'run') as run:
            m.quiesce_users(s)
        run.assert_called_once_with(['systemctl', 'stop', 'employee@example.invalid'])
        self.assertEqual(idle.call_count, 2)


if __name__ == '__main__':
    unittest.main()
