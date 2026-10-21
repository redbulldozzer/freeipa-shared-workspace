import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('transfer', ROOT / 'internal/transfer.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


class Transfers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / 'old'
        self.dst = self.root / 'new'
        self.src.mkdir(); self.dst.mkdir()
        self.journal = self.root / 'state/migration.json'
        (self.src / 'Documents').mkdir()
        (self.src / 'Documents/report.txt').write_text('test data')
        (self.src / '.ssh').mkdir()
        (self.src / '.ssh/id_private').write_text('must stay local')
        (self.src / '.config/activitywatch').mkdir(parents=True)
        (self.src / '.config/activitywatch/data').write_text('untouched')
        (self.src / '.local/share/keyrings').mkdir(parents=True)
        (self.src / '.local/share/keyrings/login.keyring').write_text('old secret storage')
        (self.src / 'Desktop').mkdir()
        (self.src / 'Desktop/app.desktop').write_text(f'Path={self.src}/Documents/\n')
        (self.src / 'link').symlink_to(str(self.src / 'Documents'))

    def prepare(self, mode):
        return t.prepare(self.src, self.dst, mode, self.journal)

    def execute(self, data, **kwargs):
        t.execute(data, self.journal, os.getuid(), os.getgid(), **kwargs)

    def assert_exclusions(self):
        for rel in ('.ssh/id_private', '.config/activitywatch/data', '.local/share/keyrings/login.keyring'):
            self.assertTrue((self.src / rel).exists())
            self.assertFalse((self.dst / rel).exists())

    def test_move_preserves_file_inode_and_private_data(self):
        inode = (self.src / 'Documents/report.txt').stat().st_ino
        data = self.prepare('move')
        self.execute(data)
        self.assertFalse((self.src / 'Documents/report.txt').exists())
        self.assertEqual(inode, (self.dst / 'Documents/report.txt').stat().st_ino)
        self.assertEqual(os.readlink(self.dst / 'link'), str(self.dst / 'Documents'))
        self.assertIn(str(self.dst), (self.dst / 'Desktop/app.desktop').read_text())
        self.assertEqual(json.loads(self.journal.read_text())['phase'], 'complete')
        self.assert_exclusions()

    def test_copy_retains_source_and_checks_contents(self):
        before = (self.src / 'Documents/report.txt').read_bytes()
        self.execute(self.prepare('copy'))
        self.assertEqual((self.src / 'Documents/report.txt').read_bytes(), before)
        self.assertEqual((self.dst / 'Documents/report.txt').read_bytes(), before)
        self.assertNotEqual((self.src / 'Documents/report.txt').stat().st_ino,
                            (self.dst / 'Documents/report.txt').stat().st_ino)
        self.assert_exclusions()

    def test_move_updates_folder_bookmarks_and_dbus_launcher(self):
        bookmarks = self.src / '.config/gtk-3.0/bookmarks'
        bookmarks.parent.mkdir(parents=True)
        bookmarks.write_text(f'file://{self.src}/Documents Documents\nfile:///srv/team Team\n')
        service = self.src / '.local/share/dbus-1/services/org.telegram.test.service'
        service.parent.mkdir(parents=True)
        service.write_text(f'[D-BUS Service]\nName=org.telegram.test\nExec={self.src}/Telegram/Telegram\n')
        untouched = self.src / 'Documents/example.service'
        untouched.write_text(f'Example path: {self.src}/Documents\n')
        self.execute(self.prepare('move'))
        self.assertEqual((self.dst / bookmarks.relative_to(self.src)).read_text(),
                         f'file://{self.dst}/Documents Documents\nfile:///srv/team Team\n')
        self.assertIn(f'Exec={self.dst}/Telegram/Telegram',
                      (self.dst / service.relative_to(self.src)).read_text())
        self.assertEqual((self.dst / 'Documents/example.service').read_text(),
                         f'Example path: {self.src}/Documents\n')

    def test_autokey_localhost_gets_public_host_trust_without_private_keys(self):
        launcher = self.src / 'Desktop/autokey.sh'
        launcher.write_text('ssh -XY Prototype3@localhost /usr/bin/autokey-gtk -c\n')
        keys = self.root / 'host-keys'
        keys.mkdir()
        (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 TEST_PUBLIC_KEY host\n')
        data = self.prepare('move')
        original = t.prepare_local_autokey_ssh
        with patch.object(t, 'prepare_local_autokey_ssh',
                          side_effect=lambda d, u, g: original(d, u, g, keys)):
            self.execute(data)
        known = self.dst / '.ssh/known_hosts'
        self.assertEqual(known.read_text(), 'localhost,127.0.0.1,::1 ssh-ed25519 TEST_PUBLIC_KEY\n')
        self.assertEqual(known.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.dst / '.ssh/id_private').exists())
        original(data, os.getuid(), os.getgid(), keys)
        self.assertEqual(len(known.read_text().splitlines()), 1)
        known.unlink()
        outside = self.root / 'untouched'
        outside.write_text('keep')
        known.symlink_to(outside)
        with self.assertRaises(RuntimeError):
            original(data, os.getuid(), os.getgid(), keys)
        self.assertEqual(outside.read_text(), 'keep')

    def test_telegram_recovery_metadata_survives_profile_overwrite(self):
        rel = Path('.local/share/TelegramDesktop/tdata')
        folder = self.src / rel
        folder.mkdir(parents=True)
        (folder / 'key_datas').write_bytes(b'original recovery key')
        (folder / 'ABCDEF0123456789').mkdir()
        (folder / 'ABCDEF0123456789/maps').write_bytes(b'original map')
        (folder / 'user_data').mkdir()
        (folder / 'user_data/cache').write_bytes(b'cache not backed up')
        self.execute(self.prepare('move'))
        saved = self.journal.parent / 'telegram-before-migration' / rel
        (self.dst / rel / 'key_datas').write_bytes(b'new empty profile')
        self.assertEqual((saved / 'key_datas').read_bytes(), b'original recovery key')
        self.assertEqual((saved / 'ABCDEF0123456789/maps').read_bytes(), b'original map')
        self.assertFalse((saved / 'user_data').exists())
        self.assertFalse((folder / 'key_datas').exists())

    def test_interruption_after_rename_resumes_from_original_journal(self):
        initial = self.prepare('move')
        def interrupt(n):
            if (self.dst / 'Documents/report.txt').exists():
                raise InterruptedError('simulated crash')
        with self.assertRaises(InterruptedError):
            self.execute(initial, after_item=interrupt)
        # Reload persisted state, exactly as restarting menu would do.
        self.execute(self.prepare('move'))
        self.assertEqual((self.dst / 'Documents/report.txt').read_text(), 'test data')
        self.assert_exclusions()

    def test_copy_interruption_resumes_without_overwrite(self):
        def interrupt(n):
            if n == 6:
                raise InterruptedError('simulated crash')
        with self.assertRaises(InterruptedError):
            self.execute(self.prepare('copy'), after_item=interrupt)
        self.execute(self.prepare('copy'))
        self.assert_exclusions()

    def test_finalize_interruption_is_recoverable(self):
        real = t.finalize
        def partial(data, uid, gid):
            real(data, uid, gid)
            raise InterruptedError('crash before complete marker')
        with patch.object(t, 'finalize', partial), self.assertRaises(InterruptedError):
            self.execute(self.prepare('move'))
        self.execute(self.prepare('move'))
        self.assertEqual(os.readlink(self.dst / 'link'), str(self.dst / 'Documents'))

    def test_existing_profile_not_overwritten(self):
        (self.dst / 'keep.txt').write_text('mine')
        with self.assertRaises(RuntimeError):
            self.prepare('move')
        self.assertEqual((self.dst / 'keep.txt').read_text(), 'mine')
        self.assertTrue((self.src / 'Documents/report.txt').exists())

    def test_changed_source_is_refused(self):
        data = self.prepare('move')
        (self.src / 'Documents/report.txt').write_text('changed while running')
        with self.assertRaises(RuntimeError):
            self.execute(data)
        self.assertTrue((self.src / 'Documents/report.txt').exists())

    def test_conflicting_resume_refused(self):
        data = self.prepare('move')
        (self.dst / 'Documents').mkdir()
        (self.dst / 'Documents/report.txt').write_text('different')
        with self.assertRaises(RuntimeError):
            self.execute(data)
        self.assertEqual((self.dst / 'Documents/report.txt').read_text(), 'different')

    def test_external_hardlink_refused_before_moving(self):
        os.link(self.src / '.ssh/id_private', self.src / 'public-name')
        with self.assertRaises(RuntimeError):
            self.prepare('move')
        self.assertFalse(self.journal.exists())
        self.assertTrue((self.src / 'Documents/report.txt').exists())

    def test_internal_hardlinks_preserved(self):
        os.link(self.src / 'Documents/report.txt', self.src / 'another')
        self.execute(self.prepare('move'))
        self.assertEqual((self.dst / 'Documents/report.txt').stat().st_ino,
                         (self.dst / 'another').stat().st_ino)

    def test_symlink_parent_cannot_redirect_destination(self):
        data = self.prepare('move')
        outside = self.root / 'outside'; outside.mkdir()
        (self.dst / 'Documents').symlink_to(outside)
        with self.assertRaises(RuntimeError):
            self.execute(data)
        self.assertFalse(list(outside.iterdir()))

    def test_sparse_vm_moves_without_allocating_a_second_image(self):
        image = self.src / 'VM.vdi'
        with image.open('wb') as out:
            out.seek(512 * 1024 * 1024)
            out.write(b'VM')
        inode, blocks = image.stat().st_ino, image.stat().st_blocks
        self.execute(self.prepare('move'))
        dest = self.dst / 'VM.vdi'
        self.assertEqual(dest.stat().st_ino, inode)
        self.assertEqual(dest.stat().st_blocks, blocks)

    def test_move_never_falls_back_to_copy_across_devices(self):
        with patch.object(t, 'rename_no_replace', side_effect=OSError(18, 'EXDEV')), \
             patch.object(t, 'copy_file') as copy, self.assertRaises(OSError):
            self.execute(self.prepare('move'))
        copy.assert_not_called()
        self.assertTrue((self.src / 'Documents/report.txt').exists())

    def test_completed_rerun_does_not_replace_user_edits(self):
        self.execute(self.prepare('move'))
        (self.dst / 'Documents/report.txt').write_text('new user content')
        self.execute(self.prepare('move'))
        self.assertEqual((self.dst / 'Documents/report.txt').read_text(), 'new user content')

    def test_insufficient_space_does_not_start_transfer(self):
        from types import SimpleNamespace
        no_space = SimpleNamespace(f_bavail=0, f_frsize=4096)
        with patch.object(t.os, 'statvfs', return_value=no_space), self.assertRaises(RuntimeError):
            self.prepare('copy')
        self.assertFalse(self.journal.exists())
        self.assertTrue((self.src / 'Documents/report.txt').exists())
        self.assertFalse(list(self.dst.iterdir()))

    def test_orphaned_partial_copy_is_discarded_before_retry(self):
        data = self.prepare('copy')
        stage = self.dst / '.freeipa-menu-stage'
        stage.mkdir()
        (stage / 'incomplete').write_bytes(b'unfinished VM copy')
        self.execute(data)
        self.assertFalse(stage.exists())
        self.assertEqual((self.dst / 'Documents/report.txt').read_text(), 'test data')

    def test_activitywatch_autostart_stays_at_source(self):
        folder = self.src / '.config/autostart'
        folder.mkdir()
        (folder / 'tracking.desktop').write_text('[Desktop Entry]\nExec=/opt/activitywatch/aw-qt\n')
        self.execute(self.prepare('move'))
        self.assertTrue((folder / 'tracking.desktop').exists())
        self.assertFalse((self.dst / '.config/autostart/tracking.desktop').exists())

    def test_no_mode_switch_mid_transfer(self):
        self.prepare('move')
        with self.assertRaises(RuntimeError):
            self.prepare('copy')

    def test_installer_folder_can_be_excluded(self):
        (self.src / 'Downloads/kit').mkdir(parents=True)
        (self.src / 'Downloads/kit/start.sh').write_text('installer')
        data = t.prepare(self.src, self.dst, 'move', self.journal, ['Downloads/kit'])
        self.execute(data)
        self.assertTrue((self.src / 'Downloads/kit/start.sh').exists())
        self.assertFalse((self.dst / 'Downloads/kit').exists())


if __name__ == '__main__':
    unittest.main()
