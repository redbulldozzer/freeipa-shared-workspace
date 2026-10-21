import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from transition.core import Job, System, TransitionError, password_hash, plan
from transition.engine import execute, rollback, accept, LOGIN_GUARD, GUARD_DROPIN
from transition.core import matches_password


class FixtureSystem(System):
    """All commands are modeled inside one temp directory; none run on the host."""
    def __init__(self, root):
        super().__init__(root)
        self.calls = []
        self.fail_uninstall = False

    def run(self, args, check=True, input=None, **kwargs):
        self.calls.append(list(args))
        out = ''
        if args[0] == 'getent':
            return subprocess.CompletedProcess(args, 2, '', '')
        elif args[0] == 'useradd':
            name = args[-1]
            with self.path('/etc/passwd').open('a') as f:
                f.write(f'{name}:x:1002:1002::/home/{name}:/bin/bash\n')
            with self.path('/etc/shadow').open('a') as f:
                f.write(f'{name}:!:1:0:99999:7:::\n')
            self.path('/home/'+name).mkdir(parents=True)
        elif args[0] == 'chpasswd':
            name, hashed = input.strip().split(':', 1)
            rows = []
            for line in self.read('/etc/shadow').splitlines():
                fields = line.split(':')
                if fields[0] == name:
                    fields[1] = hashed
                rows.append(':'.join(fields))
            self.path('/etc/shadow').write_text('\n'.join(rows)+'\n')
        elif args[0] == 'ipa-client-install':
            if self.fail_uninstall:
                raise TransitionError('Injected uninstall interruption')
            self.path('/etc/ipa/default.conf').unlink()
        elif args[0] == 'systemctl' and args[1] == 'is-active':
            out = 'active\n'
        elif args[0] == 'lightdm':
            out = self.read('/etc/lightdm/lightdm.conf.d/95-office-local-transition.conf')
        elif args[0] in ('systemctl', 'usermod', 'chage', 'pamtester', 'visudo', 'runuser',
                         '/usr/sbin/sshd', 'loginctl', 'pam-auth-update', 'nmcli'):
            pass
        else:
            raise AssertionError('Unmodeled command: '+args[0])
        return subprocess.CompletedProcess(args, 0, out, '')

    def inspect(self):
        value = super().inspect()
        value['blockers'] = [v for v in value['blockers'] if 'Владелец' not in v]
        return value


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.system = FixtureSystem(self.tmp.name)
        self.source_hash = password_hash('Fixture-local-123')
        files = {'/etc/passwd': 'example-user:x:1000:1000::/home/example-user:/bin/bash\n'
                 'office-workspace:x:1001:1003::/home/office-workspace:/bin/bash\n',
                 '/etc/shadow': 'example-user:'+self.source_hash+':1:0:99999:7:::\n'
                 'office-workspace:!:1:0:99999:7:::\n',
                 '/etc/hostname': 'workstation01', '/etc/machine-id': 'fixture-machine',
                 '/etc/shared-workspace.conf': 'target=office-workspace\ngroup=shared\n',
                 '/etc/pam.d/lightdm': '@include common-auth\n@include common-account\n',
                 '/etc/pam.d/cinnamon-screensaver': '@include common-auth\n@include common-account\n',
                 '/etc/pam.d/common-auth': 'auth required pam_unix.so\n',
                 '/etc/pam.d/common-account': 'account required pam_unix.so\n',
                 '/etc/ipa/default.conf': '[global]\nrealm=example.invalid\n'}
        for path, value in files.items():
            p = self.system.path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(value)
        home = self.system.path('/home/office-workspace')
        home.mkdir(parents=True)
        (home/'document.txt').write_text('existing work')
        self.identity = home.stat()
        opts = {'password_mode': 'local', 'source_user': 'example-user', 'admin_user': 'office-admin',
                'close_session': True, 'queue_policy': 'archive'}
        self.job = Job.create(self.system, plan(self.system, opts))
        self.secrets = {'password': 'Fixture-local-123', 'admin_password': 'Fixture-admin-123'}

    def tearDown(self):
        self.tmp.cleanup()

    def run_job(self):
        with patch('time.sleep', lambda _: None):
            return execute(self.job, self.secrets)

    def test_complete_transition_preserves_profile_and_copies_only_hash(self):
        result = self.run_job()
        self.assertEqual(result['status'], 'awaiting_user_check')
        user = self.system.local_users()['office-workspace']
        self.assertEqual((user['uid'], user['gid'], user['home']), (1001, 1003, '/home/office-workspace'))
        self.assertEqual(user['hash'], self.source_hash)
        self.assertEqual(self.system.path('/home/office-workspace/document.txt').read_text(), 'existing work')
        self.assertEqual(self.system.path('/home/office-workspace').stat().st_ino, self.identity.st_ino)
        self.assertFalse(self.system.path('/etc/ipa/default.conf').exists())
        self.assertTrue(result['verified']['display_manager'])
        self.assertFalse(self.system.path(LOGIN_GUARD).exists())
        text = self.system.read('/etc/lightdm/lightdm.conf.d/95-office-local-transition.conf')
        self.assertNotIn('display-setup-script=', text)
        accounts = self.system.read('/var/lib/AccountsService/users/office-workspace')
        self.assertIn('SystemAccount = false', accounts)
        self.assertIn('Language = ', accounts)
        serialized = self.job.public.read_text()+self.job.directory.joinpath('plan.json').read_text()
        self.assertNotIn('Fixture-local-123', serialized)
        self.assertNotIn(self.source_hash, serialized)
        commands = [a[0] for a in self.system.calls]
        self.assertLess(commands.index('pamtester'), commands.index('ipa-client-install'))

    def test_interruption_keeps_local_access_and_resumes_same_job(self):
        self.system.fail_uninstall = True
        first = self.run_job()
        self.assertEqual(first['status'], 'blocked')
        self.assertTrue(first['unenrollment_started'])
        self.assertEqual(self.system.local_users()['office-workspace']['hash'], self.source_hash)
        calls_before = sum(a[0] == 'useradd' for a in self.system.calls)
        self.system.fail_uninstall = False
        second = self.run_job()
        self.assertEqual(second['status'], 'awaiting_user_check')
        self.assertEqual(sum(a[0] == 'useradd' for a in self.system.calls), calls_before)
        self.assertEqual(self.system.path('/home/office-workspace/document.txt').read_text(), 'existing work')

    def test_admin_hidden_without_changing_authentication_or_work_profile(self):
        cache = self.system.path('/var/lib/AccountsService/users/office-workspace')
        cache.parent.mkdir(parents=True)
        cache.write_text('[User]\nXSession=cinnamon\nIcon=/home/office-workspace/.face\n'
                         'Language=ru_RU.UTF-8\nSystemAccount=true\n')
        self.run_job()
        self.assertIn('SystemAccount = true', self.system.read('/var/lib/AccountsService/users/office-admin'))
        self.assertIn('SystemAccount = false', cache.read_text())
        self.assertIn('XSession = cinnamon', cache.read_text())
        users = self.system.local_users()
        self.assertEqual(users['office-admin']['uid'], 1002)
        self.assertTrue(matches_password(self.secrets['admin_password'], users['office-admin']['hash']))
        self.assertEqual(users['example-user']['hash'], self.source_hash)
        config = self.system.read('/etc/lightdm/lightdm.conf.d/95-office-local-transition.conf')
        self.assertIn('greeter-setup-script=/usr/local/libexec/office-local-login-select', config)
        self.assertIn('autologin-user=\n', config)
        self.assertIn('greeter-show-manual-login=true', config)

    def test_rollback_restores_admin_visibility_and_removes_selection_hook(self):
        cache = self.system.path('/var/lib/AccountsService/users/office-admin')
        cache.parent.mkdir(parents=True)
        original = '[User]\nSystemAccount=false\nIcon=/home/office-admin/.face\n'
        cache.write_text(original)
        with patch('transition.engine.unenroll', side_effect=TransitionError('Stop before IPA boundary')):
            result = self.run_job()
        self.assertEqual(result['status'], 'blocked')
        self.assertFalse(result.get('unenrollment_started'))
        with patch('os.chown'):
            rollback(self.job)
        self.assertEqual(cache.read_text(), original)
        self.assertFalse(self.system.path('/usr/local/libexec/office-local-login-select').exists())

    def test_rollback_refusal_does_not_remove_persistent_gate(self):
        self.job.update(unenrollment_started=True)
        self.system.path(LOGIN_GUARD).write_text(self.job.id)
        calls = len(self.system.calls)
        with self.assertRaises(TransitionError):
            rollback(self.job)
        self.assertTrue(self.system.path(LOGIN_GUARD).exists())
        self.assertEqual(len(self.system.calls), calls)

    def test_home_replacement_rejected_before_backup(self):
        home = self.system.path('/home/office-workspace')
        home.rename(home.with_name('old-workspace'))
        home.mkdir()
        (home/'document.txt').write_text('different profile')
        result = self.run_job()
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['steps'], [])
        self.assertEqual(self.system.calls, [])

    def test_acceptance_requires_real_active_work_session(self):
        self.run_job()
        with self.assertRaises(TransitionError):
            accept(self.job, applications=True)
        self.system.sessions = lambda: [{'Name': 'office-workspace', 'State': 'active'}]
        result = accept(self.job, applications=True)
        self.assertTrue(result['verified']['graphical_login'])
        self.assertEqual(result['status'], 'awaiting_reboot')

    def test_reboot_cannot_be_marked_without_changed_boot_id(self):
        self.run_job()
        self.system.sessions = lambda: [{'Name': 'office-workspace', 'State': 'active'}]
        with self.assertRaises(TransitionError):
            accept(self.job, applications=True, reboot=True)
