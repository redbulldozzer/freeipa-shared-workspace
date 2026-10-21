import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

p = load('profile_paths', ROOT / 'profile_paths.py')
t = load('transfer', ROOT / 'transfer.py')
fixtures = load('telegram_fixtures', ROOT / 'tests/test_telegram_paths.py')


class ProfilePaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source, self.dest = self.root / 'старый профиль', self.root / 'new'
        self.source.mkdir(); self.dest.mkdir()
        self.journal = self.root / 'state/migration.json'

    def add(self, rel, raw):
        file = self.source / rel
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(raw)
        file.chmod(0o640)
        return file

    def test_path_boundaries_and_file_uris(self):
        for value in ['/home/user2/a', '/srv/team', 'file://server/home/user/a', 'file:///home/user/a?q=1']:
            self.assertEqual(p.relocate(value, '/home/user', '/home/new'), value)
        self.assertEqual(p.relocate('/home/user', '/home/user', '/home/new'), '/home/new')
        self.assertEqual(p.relocate('file:///home/user/%D0%A4%D0%B0%D0%B9%D0%BB', '/home/user', '/home/new'),
                         'file:///home/new/%D0%A4%D0%B0%D0%B9%D0%BB')

    def test_qt_changes_only_last_visited_in_file_dialog(self):
        raw = '[Other]\nlastVisited=/home/user\n[FileDialog]\nhistory=opaque /home/user\nlastVisited=file:///home/user\n'
        result = p.qt_paths(raw, '/home/user', '/home/new')
        self.assertEqual(result, raw.replace('lastVisited=file:///home/user', 'lastVisited=file:///home/new'))
        self.assertEqual(p.qt_paths(result, '/home/user', '/home/new'), result)

    def launcher(self, binary, identity_path=None):
        name = 'org.telegram.desktop._' + hashlib.md5(str(identity_path or binary).encode()).hexdigest() + '.desktop'
        text = (f'[Desktop Entry]\nType=Application\nName=Telegram\nTryExec={binary}\n'
                f'Exec="{binary}" -- %U\nDBusActivatable=true\nActions=quit;\n'
                f'[Desktop Action quit]\nName=Quit Telegram\nExec="{binary}" -quit\n')
        return name, text

    def test_legacy_telegram_pin_launches_directly_after_copy_or_move(self):
        for mode in ('copy', 'move'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as name:
                root = Path(name);source = root / 'old home';dest = root / 'new home'
                source.mkdir();dest.mkdir()
                executable = source / 'Desktop/Telegram/Telegram'
                executable.parent.mkdir(parents=True);executable.write_bytes(b'test executable');executable.chmod(0o755)
                name, text = self.launcher(executable)
                rel = '.local/share/applications/' + name
                desktop = source / rel;desktop.parent.mkdir(parents=True);desktop.write_text(text);desktop.chmod(0o744)
                # References need no renaming when the old desktop filename survives.
                pins = source / '.config/cinnamon/spices/employee@example.invalid/2.json'
                pins.parent.mkdir(parents=True);pins.write_text(json.dumps({'pinned-apps': {'value': [name, 'firefox.desktop']}}))
                mime = source / '.config/mimeapps.list';mime.write_text('[Default Applications]\nx-scheme-handler/tg='+name+';\n')
                journal = root / 'state/migration.json'
                data = t.prepare(source, dest, mode, journal)
                t.execute(data, journal, os.getuid(), os.getgid())
                expected = text.replace(str(source) + '/', str(dest) + '/').replace('DBusActivatable=true', 'DBusActivatable=false')
                self.assertEqual((dest / rel).read_text(), expected)
                self.assertEqual((dest / rel).stat().st_mode & 0o777, 0o744)
                self.assertEqual((dest / pins.relative_to(source)).read_text(), pins.read_text() if mode=='copy' else json.dumps({'pinned-apps': {'value': [name, 'firefox.desktop']}}))
                self.assertIn(name, (dest / '.config/mimeapps.list').read_text())
                self.assertIn('DBusActivatable=true', (journal.parent / 'profile-paths-before-migration' / rel).read_text())
                self.assertEqual(data['profile_path_repairs']['warnings'], [])
                self.assertIn(rel, data['profile_path_repairs']['changed'])
                data['phase'] = 'finalize'
                t.execute(data, journal, os.getuid(), os.getgid())
                self.assertEqual((dest / rel).read_text(), expected)
                if mode == 'copy':self.assertEqual(desktop.read_text(), text)

    def test_canonical_and_system_telegram_launchers_are_untouched(self):
        for executable in (self.dest / 'Telegram/Telegram', Path('/opt/Telegram/Telegram')):
            name, text = self.launcher(executable)
            self.assertEqual(p.telegram_launcher(text, name, self.source, self.dest), text)

    def test_unproven_telegram_launcher_is_not_changed(self):
        binary = self.dest / 'Desktop/Telegram/Telegram'
        name, text = self.launcher(binary, self.source / 'Desktop/Telegram/Telegram')
        with self.assertRaises(RuntimeError):
            p.telegram_launcher(text, name, self.source, self.dest)
        binary.parent.mkdir(parents=True);binary.write_bytes(b'x');binary.chmod(0o755)
        unknown, _ = self.launcher('/unrelated/Telegram')
        with self.assertRaises(ValueError):
            p.telegram_launcher(text, unknown, self.source, self.dest)
        with self.assertRaises(ValueError):
            p.telegram_launcher(text.replace('Exec="', 'Exec=env "'), name, self.source, self.dest)
        binary.unlink();binary.symlink_to('/usr/bin/true')
        with self.assertRaisesRegex(RuntimeError, 'Симлинк'):
            p.telegram_launcher(text, name, self.source, self.dest)

    def test_pc39_observed_identity_matches_old_executable(self):
        old = '/home/pc-39/Desktop/Telegram/Telegram'
        new = '/home/office-workspace/Desktop/Telegram/Telegram'
        self.assertEqual(hashlib.md5(old.encode()).hexdigest(), 'e413835da67f7f372d7ea818fcc2a76c')
        self.assertEqual(hashlib.md5(new.encode()).hexdigest(), '21276835d0cd00b2c76d58d2f914edfc')

    def test_copy_and_move_integrate_qt_telegram_backup_and_retry(self):
        for mode in ('copy', 'move'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as name:
                root = Path(name); source, dest = root / 'old', root / 'new'
                source.mkdir();dest.mkdir()
                qt = source / '.config/QtProject.conf';qt.parent.mkdir()
                qt.write_text('[FileDialog]\nlastVisited=' + source.as_uri() + '\n')
                tg = source / '.local/share/TelegramDesktop/tdata/settingss';tg.parent.mkdir(parents=True)
                tg.write_bytes(fixtures.fixture(str(source)))
                originals = {str(f.relative_to(source)): f.read_bytes() for f in (qt, tg)}
                journal = root / 'state/migration.json'
                data = t.prepare(source, dest, mode, journal)
                t.execute(data, journal, os.getuid(), os.getgid())
                self.assertEqual(data['phase'], 'complete')
                self.assertEqual(data['profile_path_repairs']['warnings'], [])
                self.assertEqual(len(data['profile_path_repairs']['changed']), 2)
                for rel, raw in originals.items():
                    self.assertEqual((journal.parent / 'profile-paths-before-migration' / rel).read_bytes(), raw)
                    if mode == 'copy':self.assertEqual((source / rel).read_bytes(), raw)
                final = dest / tg.relative_to(source)
                self.assertEqual(fixtures.t._dialog_field(fixtures.t._decode(final.read_bytes())[3])[2], str(dest))
                corrected = final.read_bytes()
                data['phase'] = 'finalize'
                t.execute(data, journal, os.getuid(), os.getgid())
                self.assertEqual(final.read_bytes(), corrected)
                self.assertEqual(len(data['profile_path_repairs']['changed']), 2)

    def test_unsupported_telegram_is_left_intact_with_persistent_warning(self):
        self.add('.local/share/TelegramDesktop/tdata/settingss', b'unknown format')
        data = t.prepare(self.source, self.dest, 'move', self.journal)
        t.execute(data, self.journal, os.getuid(), os.getgid())
        self.assertEqual((self.dest / '.local/share/TelegramDesktop/tdata/settingss').read_bytes(), b'unknown format')
        report = json.loads(self.journal.read_text())['profile_path_repairs']
        self.assertEqual(report['changed'], [])
        self.assertEqual(len(report['warnings']), 1)

    def test_symlink_parent_is_rejected_before_reading(self):
        (self.dest / '.config').symlink_to(self.source, target_is_directory=True)
        (self.source / 'QtProject.conf').write_text('do not touch')
        with self.assertRaisesRegex(RuntimeError, 'Симлинк'):
            p.safe_file(self.dest, '.config/QtProject.conf')

    def test_retry_recovers_audit_after_replace_before_journal_commit(self):
        rel = '.config/QtProject.conf'
        old = ('[FileDialog]\nlastVisited=' + self.source.as_uri() + '\n').encode()
        new = ('[FileDialog]\nlastVisited=' + self.dest.as_uri() + '\n').encode()
        path = self.dest / rel;path.parent.mkdir();path.write_bytes(new)
        backup = self.journal.parent / 'profile-paths-before-migration'
        backup.parent.mkdir()
        p.backup_file(backup, rel, old)
        data = {'source': str(self.source), 'dest': str(self.dest),
                'entries': [{'path': rel, 'kind': 'file'}]}
        report = p.repair(data, self.journal, os.getuid(), os.getgid())
        self.assertEqual(report['changed'], [rel])
        self.assertEqual((backup / rel).read_bytes(), old)

    def test_live_target_telegram_blocks_repair(self):
        from types import SimpleNamespace
        class Proc:
            name = '42'
            def stat(self):return SimpleNamespace(st_uid=12345)
            def __truediv__(self, name):
                return SimpleNamespace(read_text=lambda: 'Telegram\n',
                                       read_bytes=lambda: b'HOME=/home/target\0')
        with patch.object(p.Path, 'iterdir', return_value=iter([Proc()])):
            with self.assertRaisesRegex(RuntimeError, 'завершить Telegram'):
                p.assert_apps_stopped(12345, '/home/target')

    def test_failed_dconf_stage_never_replaces_original(self):
        self.add('.config/dconf/user', b'database')
        with patch.object(p.subprocess, 'run', return_value=type('Result', (), {'returncode': 1})()):
            with self.assertRaises(RuntimeError):
                p.screenshot_settings(b'database', self.source, self.dest, os.getuid(), os.getgid())
        self.assertEqual((self.source / '.config/dconf/user').read_bytes(), b'database')

    @unittest.skipUnless(shutil.which('dconf') and shutil.which('dbus-run-session'), 'dconf tools unavailable')
    def test_real_offline_dconf_roundtrip_preserves_unrelated_settings(self):
        stage = self.root / 'seed';stage.mkdir()
        config = stage / '.config';config.mkdir()
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(stage), 'XDG_CONFIG_HOME': str(config), 'LC_ALL': 'C.UTF-8'}
        profile = stage / 'profile';profile.write_text('user-db:user\n');env['DCONF_PROFILE'] = str(profile)
        source = str(self.source)
        script = ('import subprocess;'
                  'subprocess.run(["dconf","write","/org/gnome/gnome-screenshot/last-save-directory",'+repr(repr(self.source.as_uri() + '/Pictures'))+'],check=True);'
                  'subprocess.run(["dconf","write","/org/gnome/gnome-screenshot/auto-save-directory",'+repr(repr(source + '/Pictures'))+'],check=True);'
                  'subprocess.run(["dconf","write","/org/test/unrelated", "\'keep me\'"],check=True)')
        subprocess.run(['dbus-run-session', '--', '/usr/bin/python3', '-I', '-c', script], env=env,
                       check=True, capture_output=True, text=True, timeout=15)
        raw = (config / 'dconf/user').read_bytes()
        repaired, keys = p.screenshot_settings(raw, self.source, self.dest, os.getuid(), os.getgid())
        self.assertEqual(set(keys), {'last-save-directory', 'auto-save-directory'})
        self.assertNotEqual(repaired, raw)
        again, keys = p.screenshot_settings(repaired, self.source, self.dest, os.getuid(), os.getgid())
        self.assertEqual(again, repaired)
        self.assertEqual(keys, [])


if __name__ == '__main__':
    unittest.main()
