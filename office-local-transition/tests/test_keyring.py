import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ENTRY = Path(__file__).resolve().parents[1]/'entry.py'


@unittest.skipUnless(shutil.which('gnome-keyring-daemon') and shutil.which('dbus-run-session'), 'GNOME keyring unavailable')
class RealKeyringTests(unittest.TestCase):
    def test_rekey_survives_daemon_restart_and_rejects_wrong_password(self):
        with tempfile.TemporaryDirectory(prefix='transition-keyring-test-') as tmp:
            home = Path(tmp)/'home'
            home.mkdir()
            runtime = Path(tmp)/'run'
            runtime.mkdir(mode=0o700)
            env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(home),
                   'XDG_DATA_HOME': str(home/'.local/share'), 'XDG_RUNTIME_DIR': str(runtime)}
            def run(request):
                p = subprocess.run(['dbus-run-session', '--', '/usr/bin/python3', str(ENTRY), 'keyring-helper'],
                    env=env, input=json.dumps(request)+'\n', text=True, capture_output=True, timeout=30)
                self.assertNotIn('fixture-secret', p.stdout+p.stderr)
                self.assertNotIn(request['old'], p.stdout+p.stderr)
                self.assertNotIn(request['new'], p.stdout+p.stderr)
                return p.returncode, json.loads(p.stdout.strip().splitlines()[-1])
            request = {'mode': 'fixture', 'old': 'Test-old-123', 'new': 'Test-new-456'}
            rc, result = run(request)
            self.assertEqual(rc, 0)
            self.assertEqual(result['items'], 1)
            path = home/'.local/share/keyrings/login.keyring'
            before = hashlib.sha256(path.read_bytes()).digest()
            rc, result = run({'old': 'Wrong-old-123', 'new': 'Wrong-new-123'})
            self.assertEqual(rc, 1)
            self.assertFalse(result['ok'])
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)
            rc, result = run({'old': 'Test-old-123', 'new': 'Test-new-456'})
            self.assertEqual(rc, 0)
            self.assertEqual(result['items'], 1)
