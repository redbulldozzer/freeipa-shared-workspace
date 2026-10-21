import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

INTERNAL = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, INTERNAL / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


b = load('background')
t = load('transfer')


class Background(unittest.TestCase):
    def offline_context(self, processes):
        self.enterContext(patch.object(b, 'stop_abandoned_sessions'))
        self.enterContext(patch.object(b.os, 'geteuid', return_value=0))
        self.enterContext(patch.object(Path, 'read_text', return_value='0::/system.slice/freeipa-migration.service\n'))
        self.enterContext(patch.object(b, 'set_status'))
        self.enterContext(patch.object(b, 'user_processes', side_effect=processes))
        self.enterContext(patch.object(b.time, 'sleep'))
        command = self.enterContext(patch.object(b.subprocess, 'run', return_value=SimpleNamespace(returncode=0)))
        return command

    def test_abandoned_scope_is_stopped_once_after_ownership_check(self):
        group = '/user.slice/user-1000.slice/session-c2.scope'
        attrs = f'SubState=abandoned\nControlGroup={group}\nSlice=user-1000.slice\n'
        with patch.object(b, 'user_processes', return_value=[(4659, 1000, 'agent'), (4660, 1000, 'agent')]), \
             patch.object(Path, 'read_text', return_value=f'1:net_cls:/\n0::{group}\n'), \
             patch.object(b, 'check_virtual_machines') as vm, \
             patch.object(b, 'run', return_value=SimpleNamespace(stdout=attrs)) as command:
            b.stop_abandoned_sessions({1000})
        self.assertEqual([c.args[0] for c in command.call_args_list], [
            ['systemctl', 'show', 'session-c2.scope', '-p', 'SubState', '-p', 'ControlGroup', '-p', 'Slice'],
            ['systemctl', 'stop', 'session-c2.scope']])
        vm.assert_called_once_with({1000})

    def test_active_or_mismatched_scope_is_never_stopped(self):
        group = '/user.slice/user-1000.slice/session-c2.scope'
        for attrs in (f'SubState=running\nControlGroup={group}\nSlice=user-1000.slice',
                      f'SubState=abandoned\nControlGroup={group}\nSlice=user-1001.slice',
                      'SubState=abandoned\nControlGroup=/other\nSlice=user-1000.slice'):
            with self.subTest(attrs=attrs), patch.object(b, 'user_processes', return_value=[(4659, 1000, 'agent')]), \
                 patch.object(Path, 'read_text', return_value=f'0::{group}\n'), \
                 patch.object(b, 'run', return_value=SimpleNamespace(stdout=attrs)) as command:
                b.stop_abandoned_sessions({1000})
                self.assertEqual(command.call_count, 1)

    def test_system_services_and_other_users_are_not_abandoned_candidates(self):
        for group in ('/system.slice/agent.service', '/user.slice/user-1001.slice/session-c2.scope',
                      '/user.slice/user-1000.slice/employee@example.invalid/app.slice'):
            with self.subTest(group=group), patch.object(b, 'user_processes', return_value=[(4659, 1000, 'agent')]), \
                 patch.object(Path, 'read_text', return_value=f'0::{group}\n'), patch.object(b, 'run') as command:
                b.stop_abandoned_sessions({1000})
                command.assert_not_called()

    def test_offline_logout_stops_agents_and_waits_for_exit(self):
        leftovers = [(1, 1000, 'aw-server'), (2, 1000, 'sh'), (3, 1001, 'agent'),
                     (4, 1000, 'xdg-document-po'), (5, 1000, 'pulseaudio')]
        command = self.offline_context([leftovers, leftovers, []])
        b.quiesce_offline(Mock(), {1000, 1001})
        self.assertEqual([c.args[0] for c in command.call_args_list], [
            ['loginctl', 'terminate-user', '1000'], ['systemctl', 'stop', 'employee@example.invalid'],
            ['loginctl', 'terminate-user', '1001'], ['systemctl', 'stop', 'employee@example.invalid']])

    def test_offline_logout_rejects_live_vm_without_any_stop(self):
        for name in ('VirtualBoxVM', 'VBoxHeadless', 'qemu-system-x86', 'vmware-vmx'):
            with self.subTest(name=name), patch.object(b, 'user_processes', return_value=[(10, 1000, name)]), \
                 patch.object(b.os, 'geteuid', return_value=0), \
                 patch.object(Path, 'read_text', return_value='0::/system.slice/freeipa-migration.service'), \
                 patch.object(b.subprocess, 'run') as command, self.assertRaisesRegex(RuntimeError, 'виртуальные'):
                b.quiesce_offline(Mock(), {1000})
            command.assert_not_called()

    def test_surviving_or_respawning_service_blocks_offline_transfer(self):
        command = self.offline_context([[], [(10, 1000, 'agent')]])
        with patch.object(b.time, 'monotonic', side_effect=[0, 46]), \
             self.assertRaisesRegex(RuntimeError, 'системная служба'):
            b.quiesce_offline(Mock(), {1000})

    def test_offline_logout_is_not_available_from_admin_terminal(self):
        with patch.object(Path, 'read_text', return_value='0::/user.slice/session-3.scope'), \
             patch.object(b.os, 'geteuid', return_value=0), patch.object(b.subprocess, 'run') as command, \
             self.assertRaisesRegex(RuntimeError, 'фоновой службы'):
            b.quiesce_offline(Mock(), {1000})
        command.assert_not_called()

    def test_process_inventory_filters_uid_and_zombies_but_not_audio_or_aw(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for pid, name, state in [(1, 'aw-server', 'S'), (2, 'pulseaudio', 'S'), (3, 'sh', 'Z')]:
                proc = root / str(pid); proc.mkdir()
                (proc / 'comm').write_text(name)
                (proc / 'stat').write_text(f'{pid} ({name}) {state} 1 2 3')
            with patch.object(Path, 'iterdir', return_value=list(root.iterdir())):
                self.assertEqual(sorted(b.user_processes({os.getuid()})),
                                 [(1, os.getuid(), 'aw-server'), (2, os.getuid(), 'pulseaudio')])
                self.assertEqual(b.user_processes({os.getuid() + 1}), [])

    def test_vm_blocks_before_lightdm_or_data_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            m, job, src, dst = self.setup_job(Path(tmp))
            self.vm_check.side_effect = RuntimeError('VM is running')
            with patch.object(b, 'run') as command, self.assertRaisesRegex(RuntimeError, 'VM'):
                b.perform(m, job)
            command.assert_not_called()
            self.offline_stop.assert_not_called()
            self.assertTrue((src / 'document.txt').exists())
            self.assertFalse(m.JOURNAL.exists())

    def test_fallback_preserves_readable_error_and_controls(self):
        value = b.ascii_text('Ошибка: нет места. Стажёр — ENTER → вход…')
        self.assertTrue(value.isascii())
        self.assertIn('Oshibka', value)
        self.assertIn('ENTER', value)
        self.assertIn('net mesta', value)

    def test_console_font_is_loaded_for_vt8_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            font = Path(tmp) / 'Uni2-Terminus32x16.psf.gz'; font.touch()
            with patch.object(b, 'FONTS', Path(tmp)), patch.object(b.locale, 'setlocale'), \
                 patch.object(b.os, 'write'), patch.object(b.sys.stdout, 'fileno', return_value=1), \
                 patch.object(b.os, 'get_terminal_size', return_value=os.terminal_size((240, 67))), \
                 patch.object(b.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as command:
                self.assertTrue(b.prepare_console())
                self.assertEqual(command.call_args.args[0], ['setfont', '-C', '/dev/tty8', str(font)])

    def test_missing_font_uses_ascii_instead_of_claiming_unicode_ready(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b, 'FONTS', Path(tmp)), \
             patch.object(b.locale, 'setlocale'), patch.object(b.os, 'write'), \
             patch.object(b.sys.stdout, 'fileno', return_value=1), \
             patch.object(b.os, 'get_terminal_size', return_value=os.terminal_size((80, 25))):
            self.assertFalse(b.prepare_console())

    def test_units_validate_without_starting_services(self):
        if not shutil.which('systemd-analyze'):
            self.skipTest('systemd-analyze unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for name, contents in b.units().items():
                path = Path(tmp) / name
                path.write_text(contents)
                paths.append(str(path))
            result = subprocess.run(['systemd-analyze', 'verify', *paths], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_partial_transfer_cannot_be_cancelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = Path(tmp) / 'journal'; journal.touch()
            m = SimpleNamespace(JOURNAL=journal)
            with patch.object(b, 'worker_active', return_value=False), self.assertRaises(RuntimeError):
                b.cancel_before_transfer(m)

    def setup_job(self, directory):
        self.offline_stop = self.enterContext(patch.object(b, 'quiesce_offline'))
        self.vm_check = self.enterContext(patch.object(b, 'check_virtual_machines'))
        src, dst = directory / 'source', directory / 'target'
        src.mkdir(); dst.mkdir()
        (src / 'document.txt').write_text('important document')
        job = dict(settings={'source_user':'example-user', 'workspace_user':'office-workspace'}, mode='move', extra=[])
        account = lambda path: SimpleNamespace(pw_dir=str(path), pw_uid=os.getuid(), pw_gid=os.getgid())
        m = SimpleNamespace(validate=Mock(), recovery=Mock(return_value=account(src)),
                            existing_target=Mock(return_value=account(dst)), accounts_idle=Mock(),
                            quiesce_users=Mock(), transfer=t, JOURNAL=directory / 'journal.json',
                            configure_login=Mock(), control=SimpleNamespace(install_shortcuts=Mock()))
        return m, job, src, dst

    def test_offline_move_and_completion_without_restarting_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            m, job, src, dst = self.setup_job(root)
            inode = (src / 'document.txt').stat().st_ino
            with patch.object(b, 'STATUS', root / 'status'), patch.object(b, 'run') as run:
                b.perform(m, job)
                self.assertEqual(run.call_args_list[0].args[0], ['systemctl','stop','lightdm.service'])
                self.assertFalse(any('start' in call.args[0] for call in run.call_args_list))
            self.assertEqual((dst / 'document.txt').stat().st_ino, inode)
            self.assertFalse((src / 'document.txt').exists())
            self.assertEqual(json.loads((root / 'status').read_text())['phase'], 'complete')
            m.configure_login.assert_called_once_with('enable')

    def test_busy_process_blocks_transfer_after_logout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            m, job, src, dst = self.setup_job(root)
            self.offline_stop.side_effect = RuntimeError('process survived logout')
            with patch.object(b, 'STATUS', root / 'status'), patch.object(b, 'run'), \
                 patch.object(b.time, 'monotonic', side_effect=[0, 46]), self.assertRaises(RuntimeError):
                b.perform(m, job)
            self.assertTrue((src / 'document.txt').exists())
            self.assertEqual(list(dst.iterdir()), [])
            m.configure_login.assert_not_called()

    def test_retry_after_post_transfer_failure_keeps_user_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            m, job, src, dst = self.setup_job(root)
            m.configure_login.side_effect = RuntimeError('configuration failure')
            with patch.object(b, 'STATUS', root / 'status'), patch.object(b, 'run'):
                with self.assertRaises(RuntimeError):
                    b.perform(m, job)
                m.configure_login.side_effect = None
                b.perform(m, job)
            self.assertEqual((dst / 'document.txt').read_text(), 'important document')
            self.assertEqual(json.loads((root / 'status').read_text())['phase'], 'complete')

    def test_worker_failure_keeps_login_gate_and_records_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'gate').touch()
            (root / 'job').write_text('{}')
            m = SimpleNamespace(transfer=t)
            with patch.object(b, 'STATE', root), patch.object(b, 'GATE', root / 'gate'), \
                 patch.object(b, 'JOB', root / 'job'), patch.object(b, 'STATUS', root / 'status'), \
                 patch.object(b, 'module', return_value=m), patch.object(b, 'perform', side_effect=RuntimeError('disk full')):
                self.assertEqual(b.worker(), 1)
            self.assertTrue((root / 'gate').exists())
            self.assertEqual(json.loads((root / 'status').read_text())['message'], 'disk full')

    def test_cannot_open_login_before_complete_or_while_worker_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gate, status = root / 'gate', root / 'status'
            gate.touch()
            with patch.object(b, 'GATE', gate), patch.object(b, 'STATUS', status), patch.object(b, 'run') as run:
                for active, phase in [(False, 'error'), (True, 'complete')]:
                    status.write_text(json.dumps(dict(phase=phase)))
                    with patch.object(b, 'worker_active', return_value=active), self.assertRaises(RuntimeError):
                        b.finish(None)
                    self.assertTrue(gate.exists())
                run.assert_not_called()

    def test_service_start_failure_removes_unstarted_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            m = SimpleNamespace(control=SimpleNamespace(write=Mock()), transfer=t)
            with patch.object(b, 'GATE', root / 'gate'), patch.object(b, 'JOB', root / 'job'), \
                 patch.object(b, 'STATUS', root / 'status'), patch.object(b, 'run', side_effect=RuntimeError('unit error')), \
                 patch.object(b.subprocess, 'run'), self.assertRaises(RuntimeError):
                b.schedule(m, {}, 'move', [])
            self.assertFalse((root / 'gate').exists())

    def test_existing_job_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = Path(tmp) / 'gate'; gate.touch()
            with patch.object(b, 'GATE', gate), self.assertRaises(RuntimeError):
                b.schedule(None, {}, 'copy', [])

    def test_uncertain_dispatch_keeps_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gate = root / 'gate'
            def write(path, text, mode=0o644):
                if path == gate:
                    gate.write_text(text)
            def command(args, **kwargs):
                if args == ['systemctl', 'start', '--no-block', b.WORKER]:
                    raise RuntimeError('connection interrupted during dispatch')
                return SimpleNamespace(stdout='')
            m = SimpleNamespace(control=SimpleNamespace(write=write), transfer=t)
            with patch.object(b, 'GATE', gate), patch.object(b, 'JOB', root / 'job'), \
                 patch.object(b, 'STATUS', root / 'status'), patch.object(b, 'run', side_effect=command), \
                 self.assertRaises(RuntimeError):
                b.schedule(m, {}, 'move', [])
            self.assertTrue(gate.exists())

    def test_occupied_status_console_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = SimpleNamespace(control=SimpleNamespace(write=Mock()))
            with patch.object(b, 'GATE', Path(tmp) / 'gate'), \
                 patch.object(b, 'run', side_effect=[SimpleNamespace(stdout='9\n'), SimpleNamespace(stdout='tty8\n')]), \
                 self.assertRaisesRegex(RuntimeError, 'tty8'):
                b.schedule(m, {}, 'copy', [])
            m.control.write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
