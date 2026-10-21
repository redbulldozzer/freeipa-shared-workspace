"""Offline, journalled home migration. Move uses renameat2, never copy+delete."""
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

# These stay with the original local account in BOTH modes.
PRIVATE = ('.ssh', '.gnupg', '.aws', '.azure', '.kube', '.docker', '.ecryptfs',
           '.Private', '.cache', '.dbus', '.Xauthority', '.ICEauthority',
           '.bash_history', '.zsh_history', '.sudo_as_admin_successful',
           '.config/activitywatch', '.local/share/activitywatch',
           '.local/share/keyrings', '.config/systemd/user',
           '.config/cinnamon-session/saved-session', '.config/pulse',
           '.local/share/gvfs-metadata', 'activitywatch', '.local/opt/activitywatch')
LOCKS = {'SingletonLock', 'SingletonCookie', 'SingletonSocket', '.parentlock'}


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, ensure_ascii=False, indent=2)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        sync_dir(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def present(path):
    return path.exists() or path.is_symlink()


def signature(path):
    st = path.lstat()
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as inp:
        for block in iter(lambda: inp.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def excluded(rel, extra):
    name = rel.as_posix()
    return rel.name in LOCKS or any(name == x or name.startswith(x + '/') for x in (*PRIVATE, *extra))


def scan(source, extra=()):
    source = Path(source)
    device = source.stat().st_dev
    entries = []
    stack = [source]
    while stack:
        directory = stack.pop()
        for path in sorted(directory.iterdir()):
            rel = path.relative_to(source)
            if rel.as_posix() in ('.config/autostart/start-av.desktop', '.config/autostart/desktop-cleaner.desktop'):
                continue
            if excluded(rel, extra):
                continue
            st = path.lstat()
            if rel.parts[:2] == ('.config', 'autostart') and path.suffix == '.desktop' and stat.S_ISREG(st.st_mode):
                if st.st_size < 1024 * 1024:
                    text = path.read_text(errors='replace').lower()
                    if any(token in text for token in ('activitywatch', 'aw-qt', 'aw-server', 'aw-watcher')):
                        continue
            if st.st_dev != device or (not path.is_symlink() and os.path.ismount(path)):
                raise RuntimeError(f'Внутри home есть отдельный диск/точка монтирования: {path}. Перенеси его отдельно.')
            if stat.S_ISLNK(st.st_mode):
                kind = 'link'
            elif stat.S_ISDIR(st.st_mode):
                kind = 'dir'
                stack.append(path)
            elif stat.S_ISREG(st.st_mode):
                kind = 'file'
            else:
                raise RuntimeError(f'В home остался сокет/специальный файл: {path}. Заверши приложения.')
            entries.append({'path': str(rel), 'kind': kind, 'signature': signature(path),
                            'mode': stat.S_IMODE(st.st_mode) & ~0o6000,
                            'atime': st.st_atime_ns, 'mtime': st.st_mtime_ns,
                            'blocks': st.st_blocks * 512, 'links': st.st_nlink,
                            'link': os.readlink(path) if kind == 'link' else None})
    return sorted(entries, key=lambda x: (len(Path(x['path']).parts), x['path']))


def rename_no_replace(source, dest):
    # Linux renameat2 refuses an existing destination and EXDEV, unlike shutil.move.
    libc = ctypes.CDLL(None, use_errno=True)
    func = libc.renameat2
    func.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    func.restype = ctypes.c_int
    if func(-100, os.fsencode(source), -100, os.fsencode(dest), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(dest))
    sync_dir(dest.parent)
    if source.parent != dest.parent:
        sync_dir(source.parent)


def prepare(source, dest, mode, journal, extra=()):
    source, dest, journal = Path(source), Path(dest), Path(journal)
    if source.is_symlink() or dest.is_symlink():
        raise RuntimeError('Сам home не должен быть симлинком.')
    source, dest = source.resolve(), dest.resolve()
    if source == dest or source in dest.parents or dest in source.parents:
        raise RuntimeError('Исходный и общий home должны быть отдельными каталогами.')
    if mode not in ('copy', 'move'):
        raise ValueError(mode)
    if journal.exists():
        data = json.loads(journal.read_text())
        if (data['source'], data['dest'], data['mode']) != (str(source), str(dest), mode):
            raise RuntimeError('Сохранён другой перенос. Сначала продолжи его с прежними параметрами.')
        return data
    if not dest.is_dir() or any(dest.iterdir()):
        raise RuntimeError('Для первого переноса общий home должен быть пустым. Существующие данные не перезаписываются.')
    if present(source / '.freeipa-menu-stage'):
        raise RuntimeError('В исходном home занято служебное имя .freeipa-menu-stage. Переименуй этот каталог.')
    entries = scan(source, extra)
    if mode == 'move':
        if source.stat().st_dev != dest.stat().st_dev:
            raise RuntimeError('Вырезать без копирования можно только внутри одной файловой системы. Выбери копирование.')
        # Chown must not alter files linked to private files outside the migration.
        counts = {}
        for item in entries:
            if item['kind'] == 'file':
                key = tuple(item['signature'][:2])
                counts[key] = counts.get(key, 0) + 1
        for item in entries:
            if item['kind'] == 'file' and item['links'] != counts[tuple(item['signature'][:2])]:
                raise RuntimeError(f"У файла есть жёсткие ссылки за пределами переноса: {item['path']}. Используй копирование.")
    required = sum(x['blocks'] for x in entries if x['kind'] == 'file') if mode == 'copy' else 0
    free = os.statvfs(dest).f_bavail * os.statvfs(dest).f_frsize
    # Leave space for journal, directory entries, and small rewritten text configs.
    reserve = max(32 * 1024 * 1024, len(entries) * 2048)
    if free < required + reserve:
        raise RuntimeError(f'Свободно {free / 2**30:.2f} ГБ, нужно около {(required + reserve) / 2**30:.2f} ГБ. '
                           'Освободи место или выбери «вырезать».')
    data = {'source': str(source), 'dest': str(dest), 'mode': mode,
            'phase': 'transfer', 'entries': entries, 'excluded': list(PRIVATE) + list(extra)}
    write_json(journal, data)
    return data


def safe_parents(root, rel):
    for parent in rel.parents:
        path = root / parent
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError(f'Небезопасный родительский каталог: {path}')


def copy_file(src, dst, item, first_hardlink=None, staging=None):
    if item['signature'][2] >= 256 * 1024 * 1024:
        print(f'  Копирование и проверка большого файла: {src.name} ({item["signature"][2] / 2**30:.1f} ГБ)', flush=True)
    # One known temporary file: after SIGKILL a partial VM copy is removed before retry,
    # so resuming cannot accumulate multiple full-sized temporary images.
    temp = staging / 'incomplete'
    if present(temp):
        if temp.is_symlink() or not temp.is_file():
            raise RuntimeError(f'Некорректный временный файл: {temp}')
        temp.unlink()
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        if first_hardlink:
            temp.unlink()
            os.link(first_hardlink, temp)
        else:
            subprocess.run(['cp', '--sparse=always', '--reflink=auto',
                            '--preserve=mode,timestamps', '--', str(src), str(temp)], check=True)
        if signature(src) != item['signature'] or digest(src) != digest(temp):
            raise RuntimeError(f'Файл изменился во время копирования: {src}')
        with temp.open('rb') as inp:
            os.fsync(inp.fileno())
        rename_no_replace(temp, dst)
    finally:
        temp.unlink(missing_ok=True)


def execute(data, journal, uid, gid, after_item=None):
    """Resume by proving each already-committed item, not by overwriting it."""
    source, dest = Path(data['source']), Path(data['dest'])
    if data['phase'] == 'complete':
        return
    if data['phase'] == 'transfer':
        backup_telegram_metadata(data, journal)
        hardlinks = {}
        staging = dest / '.freeipa-menu-stage'
        if data['mode'] == 'copy':
            if staging.is_symlink():
                raise RuntimeError('Временный каталог не должен быть симлинком.')
            staging.mkdir(exist_ok=True, mode=0o700)
            os.chmod(staging, 0o700)
        for number, item in enumerate(data['entries'], 1):
            rel = Path(item['path'])
            src, dst = source / rel, dest / rel
            safe_parents(dest, rel)
            safe_parents(source, rel)
            kind = item['kind']
            if kind == 'dir':
                if present(dst) and (dst.is_symlink() or not dst.is_dir()):
                    raise RuntimeError(f'Конфликт каталога: {dst}')
                dst.mkdir(exist_ok=True, mode=0o700)
            elif data['mode'] == 'move':
                if present(src):
                    if present(dst) or signature(src) != item['signature']:
                        raise RuntimeError(f'Конфликт/изменение файла: {src}')
                    if kind == 'file':
                        with src.open('rb') as inp:
                            os.fsync(inp.fileno())
                    rename_no_replace(src, dst)
                elif not present(dst) or signature(dst) != item['signature']:
                    raise RuntimeError(f'Нельзя подтвердить ранее перемещённый файл: {dst}')
            else:
                if not present(src) or signature(src) != item['signature']:
                    raise RuntimeError(f'Исходный файл изменился: {src}')
                if present(dst):
                    equal = (dst.is_symlink() and os.readlink(dst) == item['link']) if kind == 'link' else (
                        not dst.is_symlink() and dst.is_file() and digest(src) == digest(dst))
                    if not equal:
                        raise RuntimeError(f'Конфликт с общим профилем: {dst}')
                elif kind == 'link':
                    dst.symlink_to(item['link'])
                    sync_dir(dst.parent)
                else:
                    key = tuple(item['signature'][:2])
                    copy_file(src, dst, item, hardlinks.get(key), staging)
                if kind == 'file':
                    hardlinks.setdefault(tuple(item['signature'][:2]), dst)
            if after_item:
                after_item(number)
        if data['mode'] == 'copy':
            staging.rmdir()
            sync_dir(dest)
        data['phase'] = 'finalize'
        write_json(journal, data)
    finalize(data, uid, gid)
    spec = importlib.util.spec_from_file_location('workspace_profile_paths',
                                                Path(__file__).with_name('profile_paths.py'))
    profile_paths = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile_paths)
    profile_paths.repair(data, journal, uid, gid)
    data['phase'] = 'complete'
    write_json(journal, data)


def backup_telegram_metadata(data, journal):
    """Keep small recovery files before a mismatched Telegram binary can rewrite them."""
    profiles = {Path(e['path']).parent for e in data['entries']
                if e['kind'] == 'file' and Path(e['path']).parent.name == 'tdata'
                and re.fullmatch(r'key_data[01s]?', Path(e['path']).name)}
    if not profiles:
        return
    backup = Path(journal).parent / 'telegram-before-migration'
    if backup.is_symlink():
        raise RuntimeError('Каталог резервной копии Telegram не должен быть симлинком.')
    backup.mkdir(mode=0o700, exist_ok=True)
    os.chmod(backup, 0o700)
    source, dest = Path(data['source']), Path(data['dest'])
    for item in data['entries']:
        rel = Path(item['path'])
        if item['kind'] != 'file' or item['signature'][2] > 16 * 1024 * 1024:
            continue
        direct = rel.parent in profiles
        account = (rel.parent.parent in profiles and
                   re.fullmatch(r'[0-9A-Fa-f]{16}', rel.parent.name) and
                   rel.name in ('maps', 'map0', 'map1', 'configs', 'config0', 'config1'))
        if not direct and not account:
            continue
        parent = backup
        for part in rel.parts[:-1]:
            parent = parent / part
            if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                raise RuntimeError('Небезопасный каталог резервной копии Telegram.')
            parent.mkdir(mode=0o700, exist_ok=True)
        safe_parents(backup, rel)
        target = backup / rel
        if present(target):
            if target.is_symlink() or not target.is_file():
                raise RuntimeError('Небезопасный файл резервной копии Telegram.')
            continue
        root = source if present(source / rel) else dest
        safe_parents(root, rel)
        src = root / rel
        if src.is_symlink() or not src.is_file() or signature(src) != item['signature']:
            raise RuntimeError(f'Не удалось проверить исходные метаданные Telegram: {rel}')
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, filename = tempfile.mkstemp(prefix='.telegram-backup-', dir=target.parent)
        temp = Path(filename)
        try:
            with os.fdopen(fd, 'wb') as out, src.open('rb') as inp:
                out.write(inp.read())
                out.flush()
                os.fsync(out.fileno())
            rename_no_replace(temp, target)
            sync_dir(target.parent)
        finally:
            temp.unlink(missing_ok=True)


def prepare_local_autokey_ssh(data, uid, gid, key_directory=Path('/etc/ssh')):
    """Trust only this machine's public host keys for migrated localhost launchers.

    Private SSH credentials still remain excluded from the migration.
    Never execute a discovered launcher or weaken host key checking.
    """
    dest = Path(data['dest'])
    found = False
    for item in data['entries']:
        rel = Path(item['path'])
        if item['kind'] != 'file' or rel.suffix not in ('.sh', '.desktop'):
            continue
        safe_parents(dest, rel)
        path = dest / rel
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
            continue
        text = path.read_text(errors='replace')
        if 'autokey' in text and re.search(r'\bssh\s', text) and re.search(r'\b[\w.-]+@localhost\b', text):
            found = True
            break
    if not found:
        return False
    keys = []
    for algorithm in ('ed25519', 'ecdsa', 'rsa'):
        path = key_directory / f'ssh_host_{algorithm}_key.pub'
        if path.is_file():
            fields = path.read_text().split()
            if len(fields) >= 2:
                keys.append('localhost,127.0.0.1,::1 ' + ' '.join(fields[:2]))
    if not keys:
        raise RuntimeError('AutoKey использует localhost SSH, но публичные ключи SSH-сервера не найдены.')
    directory = dest / '.ssh'
    if directory.is_symlink():
        raise RuntimeError('Нельзя записать SSH-настройку AutoKey: .ssh является симлинком.')
    directory.mkdir(mode=0o700, exist_ok=True)
    target = directory / 'known_hosts'
    if target.is_symlink() or (target.exists() and (not target.is_file() or target.stat().st_nlink != 1)):
        raise RuntimeError('Небезопасный файл known_hosts; настройки AutoKey не изменены.')
    old = target.read_text() if target.exists() else ''
    additions = [key for key in keys if key not in old.splitlines()]
    if additions:
        fd, filename = tempfile.mkstemp(prefix='.autokey-host-', dir=directory)
        temporary = Path(filename)
        try:
            with os.fdopen(fd, 'w') as output:
                output.write(old.rstrip('\n') + ('\n' if old else '') + '\n'.join(additions) + '\n')
                output.flush()
                os.fsync(output.fileno())
            os.chown(temporary, uid, gid)
            os.replace(temporary, target)
            sync_dir(directory)
        finally:
            temporary.unlink(missing_ok=True)
    os.chown(directory, uid, gid)
    os.chmod(directory, 0o700)
    os.chown(target, uid, gid)
    os.chmod(target, 0o600)
    return True


def finalize(data, uid, gid):
    source, dest = Path(data['source']), Path(data['dest'])
    for item in reversed(data['entries']):
        rel = Path(item['path'])
        dst = dest / rel
        safe_parents(dest, rel)
        if item['kind'] == 'link':
            link = os.readlink(dst)
            if link == str(source) or link.startswith(str(source) + '/'):
                new = str(dest) + link[len(str(source)):]
                # Atomic link replacement also makes a finalize retry harmless.
                fd, filename = tempfile.mkstemp(prefix='.workspace-link-', dir=dst.parent)
                os.close(fd)
                temp = Path(filename)
                try:
                    temp.unlink()
                    temp.symlink_to(new)
                    os.replace(temp, dst)
                    sync_dir(dst.parent)
                finally:
                    temp.unlink(missing_ok=True)
            os.chown(dst, uid, gid, follow_symlinks=False)
            continue
        if dst.is_symlink():
            raise RuntimeError(f'Тип файла неожиданно изменился: {dst}')
        if item['kind'] == 'file':
            known_text = (dst.suffix in ('.desktop', '.vbox') or
                          (rel.parts[:2] == ('.config', 'VirtualBox') and dst.suffix == '.xml') or
                          (rel.parts[:4] == ('.local', 'share', 'dbus-1', 'services') and dst.suffix == '.service') or
                          rel.as_posix() in ('.gtk-bookmarks', '.config/gtk-3.0/bookmarks',
                                             '.config/gtk-4.0/bookmarks') or
                          dst.name in ('profiles.ini', 'installs.ini', 'user-dirs.dirs', 'user-dirs.locale'))
            if known_text and dst.stat().st_size < 16 * 1024 * 1024:
                try:
                    old = dst.read_text()
                    new = old.replace(str(source) + '/', str(dest) + '/')
                    if new != old:
                        # Commit text rewrites atomically: never truncate the only moved copy.
                        fd, filename = tempfile.mkstemp(prefix='.workspace-text-', dir=dst.parent)
                        temp = Path(filename)
                        try:
                            with os.fdopen(fd, 'w') as out:
                                out.write(new)
                                out.flush()
                                os.fsync(out.fileno())
                            os.replace(temp, dst)
                            sync_dir(dst.parent)
                        finally:
                            temp.unlink(missing_ok=True)
                except UnicodeDecodeError:
                    pass
        os.chown(dst, uid, gid, follow_symlinks=False)
        os.chmod(dst, item['mode'])
        if item['kind'] == 'dir':
            os.utime(dst, ns=(item['atime'], item['mtime']))
    prepare_local_autokey_ssh(data, uid, gid)
    os.chown(dest, uid, gid)
    os.chmod(dest, 0o700)
    sync_dir(dest)
    # Do not remove source account, private data, or directories used by its TTY.
