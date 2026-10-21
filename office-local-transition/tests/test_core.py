import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from transition.core import (Job, System, TransitionError, json_write, matches_password,
                             options_from, password_hash, plan, usable_hash)
from transition.engine import validate_secrets, edit, remove, collector_command


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.system = System(self.tmp.name)
        self.hash = password_hash('Local-fixture-123')
        for name, value in {'/etc/passwd': 'example-user:x:1000:1000::/home/example-user:/bin/bash\n'
                            'office-workspace:x:1001:1003::/home/office-workspace:/bin/bash\n',
                            '/etc/shadow': 'example-user:'+self.hash+':1:0:99999:7:::\n'
                            'office-workspace:!:1:0:99999:7:::\n',
                            '/etc/shared-workspace.conf': 'target=office-workspace\ngroup=shared\n',
                            '/etc/machine-id': 'machine-fixture', '/etc/hostname': 'workstation01'}.items():
            p = self.system.path(name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(value)
        home = self.system.path('/home/office-workspace')
        home.mkdir(parents=True)
        (home/'work.txt').write_text('existing user work')
        # Fixtures have the test user's uid, avoiding privileged filesystem operations.
        text = self.system.read('/etc/passwd').replace('1001:1003', str(os.getuid())+':'+str(os.getgid()))
        self.system.path('/etc/passwd').write_text(text)
        self.options = {'password_mode': 'local', 'source_user': 'example-user', 'admin_user': 'office-admin'}

    def tearDown(self):
        self.tmp.cleanup()

    def usable_inventory(self):
        # Inventory insists on a normal uid; only override this read-only fixture identity.
        actual = self.system.local_users
        def users():
            u = actual()
            u['office-workspace']['uid'] = 1001
            return u
        self.system.local_users = users
        original = self.system.inspect
        def inspect():
            value = original()
            value['blockers'] = [v for v in value['blockers'] if 'Владелец' not in v]
            return value
        self.system.inspect = inspect

    def test_hash_reuse_and_wrong_password(self):
        self.assertTrue(matches_password('Local-fixture-123', self.hash))
        self.assertFalse(matches_password('Wrong-fixture-123', self.hash))
        for value in ('', '!', '*', '!'+self.hash):
            self.assertFalse(usable_hash(value))

    def test_locked_source_rejected(self):
        self.usable_inventory()
        self.system.path('/etc/shadow').write_text('example-user:!:1:0:99999:7:::\noffice-workspace:!:1:0:99999:7:::\n')
        with self.assertRaises(TransitionError):
            plan(self.system, self.options)

    def test_plan_has_no_password_or_hash_and_no_home_mutation(self):
        self.usable_inventory()
        before = self.system.path('/home/office-workspace/work.txt').read_bytes()
        value = plan(self.system, self.options)
        serialized = json.dumps(value)
        self.assertNotIn(self.hash, serialized)
        self.assertNotIn('Local-fixture-123', serialized)
        self.assertEqual(before, self.system.path('/home/office-workspace/work.txt').read_bytes())
        self.assertEqual(value['inventory']['target']['home'], '/home/office-workspace')

    def test_wrong_source_password_rejected_before_job(self):
        self.usable_inventory()
        value = plan(self.system, self.options)
        with self.assertRaises(TransitionError):
            validate_secrets(self.system, value, {'password': 'Wrong-fixture-123', 'admin_password': 'Admin-fixture-123'})
        self.assertFalse(self.system.path('/var/lib/office-local-transition/jobs').exists())

    def test_pending_migration_rejected(self):
        self.usable_inventory()
        json_write(self.system.path('/var/lib/freeipa-menu/migration.json'), {'phase': 'copy'})
        with self.assertRaises(TransitionError):
            plan(self.system, self.options)

    def test_vm_blocks_plan(self):
        self.usable_inventory()
        self.system.vm_processes = lambda: [{'name': 'VBoxHeadless'}]
        with self.assertRaises(TransitionError):
            plan(self.system, self.options)

    def test_session_requires_ack(self):
        self.usable_inventory()
        self.system.sessions = lambda: [{'Name': 'office-workspace'}]
        with self.assertRaises(TransitionError):
            plan(self.system, self.options)
        self.options['close_session'] = True
        self.assertEqual(plan(self.system, self.options)['options']['close_session'], True)

    def test_injection_and_unknown_fields_rejected(self):
        for value in ('admin;id', '../admin', 'root\n'):
            with self.assertRaises(TransitionError):
                options_from({'admin_user': value})
        with self.assertRaises(TransitionError):
            options_from({'password': 'never in plan'})

    def test_symlink_parent_rejected(self):
        self.system.path('/home/office-workspace/link').symlink_to('/tmp')
        with self.assertRaises(TransitionError):
            self.system.path('/home/office-workspace/link/test')

    def test_checkpoint_repeat_and_interrupt(self):
        self.usable_inventory()
        job = Job.create(self.system, plan(self.system, self.options))
        called = []
        job.step('one', lambda: called.append(1))
        Job(self.system, job.id).step('one', lambda: called.append(2))
        self.assertEqual(called, [1])
        def fail():
            raise TransitionError('interrupted')
        with self.assertRaises(TransitionError):
            job.step('two', fail)
        self.assertNotIn('two', job.state()['steps'])
        self.assertEqual(job.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(job.public.stat().st_mode & 0o777, 0o644)

    def test_backup_before_edit_and_no_overwrite_of_backup(self):
        self.usable_inventory()
        job = Job.create(self.system, plan(self.system, self.options))
        p = self.system.path('/etc/test.conf')
        p.write_text('original')
        edit(job, '/etc/test.conf', 'updated')
        edit(job, '/etc/test.conf', 'updated again')
        self.assertEqual((job.backup/'files/etc/test.conf').read_text(), 'original')
        remove(job, '/etc/test.conf')
        self.assertFalse(p.exists())
        self.assertEqual((job.backup/'files/etc/test.conf').read_text(), 'original')

    def test_fake_root_cannot_run_native_command(self):
        with self.assertRaises(TransitionError):
            self.system.run(['useradd', 'someone'])

    def test_system_account_cannot_become_office_admin(self):
        self.usable_inventory()
        with self.system.path('/etc/passwd').open('a') as out:
            out.write('root:x:0:0:root:/root:/bin/bash\n')
        self.options['admin_user'] = 'root'
        with self.assertRaises(TransitionError):
            plan(self.system, self.options)

    def test_public_status_readable_with_private_umask(self):
        self.usable_inventory()
        old = os.umask(0o077)
        try:
            job = Job.create(self.system, plan(self.system, self.options))
        finally:
            os.umask(old)
        self.assertEqual(job.public.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(job.directory.parent.stat().st_mode & 0o777, 0o700)

    def test_other_sssd_provider_blocks_uninstall(self):
        self.usable_inventory()
        path = self.system.path('/etc/sssd/conf.d/another.conf')
        path.parent.mkdir(parents=True)
        path.write_text('[domain/another]\nid_provider = ldap\n')
        with self.assertRaises(TransitionError):
            plan(self.system, self.options)

    def test_collector_classification_is_narrow(self):
        roots = ['/usr/local/lib/office-activity', '/home/example-user/activitywatch']
        self.assertTrue(collector_command(['python3', '/usr/local/lib/office-activity/main.py'], roots))
        self.assertTrue(collector_command(['/home/example-user/activitywatch/aw-qt'], roots))
        self.assertFalse(collector_command(['python3', '/usr/local/lib/office-activity-other/app.py'], roots))
        self.assertFalse(collector_command(['python3', '-c', "print('/home/example-user/activitywatch')"], roots))
        self.assertFalse(collector_command(['/usr/local/lib/office-local-transition/entry.py', 'worker'], roots))


if __name__ == '__main__':
    unittest.main()
