"""Repair migrated application paths offline, preserving unrelated preferences."""
import configparser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import tempfile
from urllib.parse import quote, unquote, urlsplit


def relocate(value, source, dest):
    """Only a whole home or its descendants, including percent-encoded file URIs."""
    source, dest = str(source).rstrip('/'), str(dest).rstrip('/')
    uri = value.startswith('file:')
    if uri:
        parsed = urlsplit(value)
        if parsed.netloc not in ('', 'localhost') or parsed.query or parsed.fragment:
            return value
        path = unquote(parsed.path)
    else:
        path = value
    if path != source and not path.startswith(source + '/'):
        return value
    new = dest + path[len(source):]
    return 'file://' + quote(new, safe='/') if uri else new


def qt_paths(text, source, dest):
    section = ''
    result = []
    for line in text.splitlines(keepends=True):
        if line.strip().startswith('['):
            section = line.strip()
        if section == '[FileDialog]' and line.startswith('lastVisited='):
            ending = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
            line = 'lastVisited=' + relocate(line.rstrip('\r\n').split('=', 1)[1], source, dest) + ending
        result.append(line)
    return ''.join(result)


def telegram_launcher(text, name, source, dest):
    """Keep pinned desktop IDs usable after Telegram's path-based bus ID changes.

    Fresh sessions must launch migrated legacy desktop files through Exec instead
    of requesting the obsolete D-Bus name. Keep the filename: Cinnamon pins and
    MIME associations still refer to it. Telegram can generate its new canonical
    launcher itself; no account data or bus services are modified here.
    """
    match = re.fullmatch(r'org\.telegram\.desktop\._([0-9a-f]{32})\.desktop', name)
    if not match:
        return text
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    try:
        parser.read_string(text)
        entry = parser['Desktop Entry']
        if entry.get('DBusActivatable') != 'true':
            return text
        if entry.get('Type') != 'Application':
            raise ValueError('Неизвестный тип ярлыка Telegram.')
        executable = entry.get('TryExec', '')
        command = shlex.split(entry.get('Exec', ''))
    except (configparser.Error, KeyError, ValueError):
        raise ValueError('Неподдерживаемый формат ярлыка Telegram.') from None
    prefix = str(dest).rstrip('/') + '/'
    if not executable.startswith(prefix):
        return text  # System-wide installations do not change their identity.
    if (not command or command[0] != executable or '\\' in executable or
            Path(executable).name != 'Telegram'):
        raise ValueError('Неоднозначный путь запуска Telegram.')
    digest = lambda value: hashlib.md5(value.encode('utf-8')).hexdigest()
    if match[1] == digest(executable):
        return text
    previous = str(source).rstrip('/') + executable[len(str(dest).rstrip('/')):]
    if match[1] != digest(previous):
        raise ValueError('Идентификатор Telegram не соответствует исходному пути.')
    binary = safe_file(dest, Path(executable).relative_to(dest))
    if not binary.stat().st_mode & 0o111:
        raise ValueError('Исполняемый файл Telegram недоступен.')
    section = ''
    output = []
    for line in text.splitlines(keepends=True):
        if line.strip().startswith('['):
            section = line.strip()
        if section == '[Desktop Entry]' and re.fullmatch(r'DBusActivatable\s*=\s*true', line.strip()):
            line = line.replace('true', 'false', 1)
        output.append(line)
    return ''.join(output)


def safe_file(root, rel):
    rel = Path(rel)
    if rel.is_absolute() or '..' in rel.parts:
        raise RuntimeError('Небезопасный путь настройки профиля.')
    current = Path(root)
    if current.is_symlink() or not current.is_dir():
        raise RuntimeError('Небезопасный каталог профиля.')
    for part in rel.parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError('Симлинк вместо настройки профиля: ' + str(rel))
    if not current.is_file():
        raise RuntimeError('Отсутствует обычный файл настройки: ' + str(rel))
    return current


def atomic_bytes(path, data, uid, gid, mode):
    fd, name = tempfile.mkstemp(prefix='.profile-paths-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fchmod(out.fileno(), mode)
            os.fchown(out.fileno(), uid, gid)
            os.fsync(out.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def backup_file(root, rel, raw):
    current = Path(root)
    if current.is_symlink():
        raise RuntimeError('Небезопасный каталог резервной копии путей.')
    current.mkdir(mode=0o700, exist_ok=True)
    os.chmod(current, 0o700)
    for part in Path(rel).parts[:-1]:
        current /= part
        if current.is_symlink():
            raise RuntimeError('Небезопасный каталог резервной копии путей.')
        current.mkdir(mode=0o700, exist_ok=True)
    target = current / Path(rel).name
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file():
            raise RuntimeError('Небезопасная резервная копия путей.')
        return  # A finalize retry must preserve the original backup.
    atomic_bytes(target, raw, os.getuid(), os.getgid(), 0o600)


# Executed with the target user's privileges and an isolated copy of dconf.
# Never connects to the real desktop bus, and never prints other preferences.
DCONF_WORKER = r'''
import ast, configparser, json, subprocess, sys
from urllib.parse import quote, unquote, urlsplit
def cmd(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout
def other_settings():
    p = configparser.ConfigParser(interpolation=None)
    p.optionxform = str
    p.read_string(cmd('dconf', 'dump', '/'))
    if p.has_section('org/gnome/gnome-screenshot'):
        for key in ('last-save-directory', 'auto-save-directory'):
            p.remove_option('org/gnome/gnome-screenshot', key)
        if not dict(p['org/gnome/gnome-screenshot']):
            p.remove_section('org/gnome/gnome-screenshot')
    return {s: dict(p[s]) for s in p.sections()}
source, dest = sys.argv[1:]
before = other_settings()
changed = []
for name in ('last-save-directory', 'auto-save-directory'):
    key = '/org/gnome/gnome-screenshot/' + name
    value = cmd('dconf', 'read', key).strip()
    if not value:
        continue
    value = ast.literal_eval(value)
    if not isinstance(value, str):
        raise ValueError('Non-string screenshot path')
    is_uri = value.startswith('file:')
    parsed = urlsplit(value) if is_uri else None
    if is_uri and (parsed.netloc not in ('', 'localhost') or parsed.query or parsed.fragment):
        continue
    path = unquote(parsed.path) if is_uri else value
    if path != source and not path.startswith(source + '/'):
        continue
    new = dest + path[len(source):]
    if is_uri:
        new = 'file://' + quote(new, safe='/')
    cmd('dconf', 'write', key, repr(new))
    if ast.literal_eval(cmd('dconf', 'read', key).strip()) != new:
        raise ValueError('Screenshot path verification failed')
    changed.append(name)
if other_settings() != before:
    raise ValueError('Unrelated dconf preferences changed')
print(json.dumps(changed))
'''


def screenshot_settings(raw, source, dest, uid, gid):
    """Modify a staged database, then return it only after verification succeeds."""
    with tempfile.TemporaryDirectory(prefix='freeipa-dialog-paths-') as name:
        stage = Path(name)
        os.chown(stage, uid, gid)
        for rel in ('.config', '.config/dconf', 'runtime'):
            directory = stage / rel
            directory.mkdir(mode=0o700)
            os.chown(directory, uid, gid)
        database = stage / '.config/dconf/user'
        atomic_bytes(database, raw, uid, gid, 0o600)
        profile = stage / 'dconf-profile'
        profile.write_text('user-db:user\n')
        profile.chmod(0o644)
        command = ['env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C.UTF-8',
                   'HOME=' + str(stage), 'XDG_CONFIG_HOME=' + str(stage / '.config'),
                   'XDG_RUNTIME_DIR=' + str(stage / 'runtime'), 'DCONF_PROFILE=' + str(profile),
                   'dbus-run-session', '--', '/usr/bin/python3', '-I', '-c', DCONF_WORKER,
                   str(source), str(dest)]
        if os.geteuid() == 0:
            command = ['runuser', '-u', pwd.getpwuid(uid).pw_name, '--', *command]
        elif os.getuid() != uid:
            raise RuntimeError('Нельзя проверить dconf от имени владельца профиля.')
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        if result.returncode:
            raise RuntimeError('Не удалось проверить копию dconf; исходные настройки не изменены.')
        changed = json.loads(result.stdout)
        return (database.read_bytes() if changed else raw), changed


def telegram_module():
    spec = importlib.util.spec_from_file_location('workspace_telegram_paths',
                                                Path(__file__).with_name('telegram_paths.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_apps_stopped(uid, home):
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if proc.stat().st_uid == uid and (proc / 'comm').read_text().strip().lower() in (
                    'telegram', 'telegram-deskto', 'gnome-screensho'):
                environment = dict(value.split(b'=', 1) for value in
                                   (proc / 'environ').read_bytes().split(b'\0') if b'=' in value)
                process_home = environment.get(b'HOME')
                if process_home is None or os.fsdecode(process_home) == str(home):
                    raise RuntimeError('Перед исправлением путей нужно завершить Telegram и программу снимков экрана.')
        except (FileNotFoundError, ProcessLookupError):
            continue


def repair(data, journal, uid, gid):
    """Called only after the offline transfer and ownership finalization."""
    source, dest = Path(data['source']), Path(data['dest'])
    assert_apps_stopped(uid, dest)
    report = data.setdefault('profile_path_repairs', {'changed': [], 'warnings': []})
    report['warnings'] = []
    backup = Path(journal).parent / 'profile-paths-before-migration'
    for item in data['entries']:
        rel = Path(item['path'])
        if item['kind'] != 'file':
            continue
        qt = rel.as_posix() == '.config/QtProject.conf'
        dconf = rel.as_posix() == '.config/dconf/user'
        telegram = rel.parent.name == 'tdata' and re.fullmatch(r'settings[01s]?', rel.name)
        launcher = re.fullmatch(r'org\.telegram\.desktop\._[0-9a-f]{32}\.desktop', rel.name)
        if not (qt or dconf or telegram or launcher):
            continue
        path = safe_file(dest, rel)
        if path.stat().st_size > 16 * 1024 * 1024:
            report['warnings'].append(f'{rel}: слишком большой файл; требуется отдельная проверка.')
            continue
        raw = path.read_bytes()
        try:
            if launcher:
                new = telegram_launcher(raw.decode('utf-8'), rel.name, source, dest).encode('utf-8')
            elif qt:
                new = qt_paths(raw.decode('utf-8'), source, dest).encode('utf-8')
            elif dconf:
                new, _ = screenshot_settings(raw, source, dest, uid, gid)
            else:
                new = telegram_module().repair_settings_bytes(raw, str(source), str(dest))
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
            check = 'запуска Telegram' if launcher else 'сохранения файлов'
            report['warnings'].append(f'{rel}: формат или обработчик не поддержан; файл не изменён. Нужна проверка {check}.')
            continue
        if new != raw:
            backup_file(backup, rel, raw)
            if path.read_bytes() != raw:
                raise RuntimeError('Настройки изменились во время переноса: ' + str(rel))
            atomic_bytes(path, new, uid, gid, stat.S_IMODE(path.stat().st_mode))
            if path.read_bytes() != new:
                raise RuntimeError('Не прошла проверка исправленного файла: ' + str(rel))
            if str(rel) not in report['changed']:
                report['changed'].append(str(rel))
        elif (backup / rel).exists() or (backup / rel).is_symlink():
            # A crash may follow atomic replace but precede the journal commit.
            # Recover the audit entry from the retained original on a retry.
            original = safe_file(backup, rel)
            if original.read_bytes() != raw and str(rel) not in report['changed']:
                report['changed'].append(str(rel))
    for warning in report['warnings']:
        print('ВНИМАНИЕ: ' + warning, flush=True)
    return report
