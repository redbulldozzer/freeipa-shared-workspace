"""Guarded compatibility fix for the stock AutoKey clipboard restore race."""
import ast
import hashlib
import os
from pathlib import Path
import shutil
import tempfile

INTERFACE = Path('/usr/lib/python3/dist-packages/autokey/interface.py')
BACKUPS = Path('/var/backups/freeipa-menu/autokey-compat')


def patched_source(source):
    tree = ast.parse(source)
    methods = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
               and n.name == '_restore_clipboard_text']
    if len(methods) != 1:
        return None
    method = methods[0]
    sleeps = [n for n in ast.walk(method) if isinstance(n, ast.Call)
              and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
              and n.func.value.id == 'time' and n.func.attr == 'sleep']
    if len(sleeps) != 1 or len(sleeps[0].args) != 1:
        return None
    value = sleeps[0].args[0]
    if not isinstance(value, ast.Constant):
        return None
    if value.value == 2.0:
        return source
    if value.value != 0.2:
        return None
    lines = source.splitlines(keepends=True)
    line = lines[value.lineno - 1]
    lines[value.lineno - 1] = line[:value.col_offset] + '2.0' + line[value.end_col_offset:]
    result = ''.join(lines)
    compile(result, str(INTERFACE), 'exec')
    return result


def install(path=INTERFACE, backups=BACKUPS):
    if not path.exists():
        return 'absent'
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise RuntimeError('Небезопасный путь модуля AutoKey; исправление не применено.')
    original = path.read_text()
    updated = patched_source(original)
    if updated is None:
        print('AutoKey: неизвестная версия метода вставки; автоматическое исправление пропущено.')
        return 'unsupported'
    if updated == original:
        return 'already_fixed'
    backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = backups / (hashlib.sha256(original.encode()).hexdigest() + '.py')
    if not backup.exists():
        shutil.copy2(path, backup)
        os.chmod(backup, 0o600)
    before = path.stat()
    fd, filename = tempfile.mkstemp(prefix='.autokey-compat-', dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(updated)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, before.st_mode & 0o777)
        os.chown(temporary, before.st_uid, before.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    print('AutoKey: задержка восстановления буфера 2 секунды; требуется перезапуск AutoKey. Копия:', backup)
    return 'fixed'
