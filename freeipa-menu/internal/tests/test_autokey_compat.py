import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('compat', Path(__file__).parents[1] / 'autokey_compat.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
SOURCE = '''class Interface:
    def _restore_clipboard_text(self, backup):
        time.sleep(0.2)
        self.clipboard.text = backup if backup is not None else ""
'''


class ClipboardCompatibility(unittest.TestCase):
    def test_delayed_page_receives_phrase_before_old_clipboard_restored(self):
        for source, expected in ((SOURCE, 'old clipboard'), (c.patched_source(SOURCE), 'phrase')):
            clipboard = SimpleNamespace(text='phrase')
            page = []
            def sleep(delay):
                # A renderer requests clipboard data 0.5 seconds after Ctrl+V.
                if delay >= 0.5:
                    page.append(clipboard.text)
            scope = {'time': SimpleNamespace(sleep=sleep)}
            exec(source, scope)
            instance = scope['Interface']()
            instance.clipboard = clipboard
            instance._restore_clipboard_text('old clipboard')
            if not page:
                page.append(clipboard.text)
            self.assertEqual(page, [expected])
            self.assertEqual(clipboard.text, 'old clipboard')

    def test_backup_and_idempotence(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'interface.py'
            p.write_text(SOURCE)
            b = Path(tmp) / 'backup'
            self.assertEqual(c.install(p, b), 'fixed')
            self.assertEqual(c.install(p, b), 'already_fixed')
            self.assertEqual(next(b.iterdir()).read_text(), SOURCE)

    def test_unknown_version_untouched(self):
        self.assertIsNone(c.patched_source(SOURCE.replace('0.2', 'custom_delay')))


if __name__ == '__main__':
    unittest.main()
