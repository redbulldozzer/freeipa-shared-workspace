#!/usr/bin/python3
"""Narrow, offline installer. Does not touch PAM, services, users or live sessions."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

BASE = Path(__file__).resolve().parent
UUID = 'employee@example.invalid'
FILES = {
    'panel_helper.py': ('usr/local/libexec/office-employee-panel', 0o755),
    'applet/applet.js': (f'usr/share/cinnamon/applets/{UUID}/applet.js', 0o644),
    'applet/metadata.json': (f'usr/share/cinnamon/applets/{UUID}/metadata.json', 0o644),
    'office-employee-panel.desktop': ('etc/xdg/autostart/office-employee-panel.desktop', 0o644),
}
BACKUPS = 'var/backups/office-employee-panel'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def safe_path(root, relative):
    path = root / relative
    if Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('Invalid relative path')
    for item in [path, *path.parents]:
        if item == root.parent:
            break
        if item.is_symlink():
            raise ValueError(f'Symlink not allowed: {item}')
    if path.exists() and not path.is_file():
        raise ValueError(f'Expected regular file: {path}')
    return path


def atomic_write(path, data, mode, uid=None, gid=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.employee-panel-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fchmod(out.fileno(), mode)
            if uid is not None:
                os.fchown(out.fileno(), uid, gid)
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def preflight(root):
    for relative in ['etc/shared-workspace.conf', 'usr/bin/cinnamon', 'usr/bin/dm-tool',
                     'usr/local/libexec/shared-workspace-lock-bridge']:
        if not safe_path(root, relative).is_file():
            raise ValueError(f'Missing prerequisite: /{relative}')
    if root == Path('/'):
        import pwd
        from gi.repository import Gio
        if not Gio.SettingsSchemaSource.get_default().lookup('org.cinnamon', True):
            raise ValueError('Cinnamon settings schema missing')
        values = dict(line.split('=', 1) for line in (root / 'etc/shared-workspace.conf').read_text().splitlines() if '=' in line)
        user = values.get('target', '')
        if not user or pwd.getpwnam(user).pw_uid < 1000:
            raise ValueError('Invalid workspace user')
    return {'prerequisites': 'ok', 'version': '1.0.0'}


def install(root):
    preflight(root)
    planned = []
    for src, (rel, mode) in FILES.items():
        target = safe_path(root, rel)
        data = (BASE / src).read_bytes()
        planned.append((rel, target, data, mode))
    if all(target.exists() and target.read_bytes() == data and stat.S_IMODE(target.stat().st_mode) == mode
           and (root != Path('/') or target.stat().st_uid == 0)
           for _, target, data, mode in planned):
        return {'changed': False, 'version': '1.0.0'}
    backup = root / BACKUPS / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True, mode=0o700)
    records = []
    for rel, target, data, mode in planned:
        record = {'path': rel, 'installed_sha256': hashlib.sha256(data).hexdigest(), 'existed': target.exists()}
        if target.exists():
            st = target.stat()
            saved = backup / rel
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(target.read_bytes())
            record.update(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid, previous_sha256=digest(saved))
        records.append(record)
    manifest = backup / 'manifest.json'
    manifest.write_text(json.dumps({'files': records}, indent=2))
    try:
        for rel, target, data, mode in planned:
            atomic_write(target, data, mode, 0 if root == Path('/') else None, 0)
    except Exception:
        restore(root, backup, verify_installed=False)
        raise
    return {'changed': True, 'version': '1.0.0', 'backup': str(backup), 'activation': 'next_login_or_explicit_enable'}


def restore(root, backup, verify_installed=True):
    backup = backup.resolve()
    if backup.parent != (root / BACKUPS).resolve():
        raise ValueError('Backup must be an immediate child of the component backup directory')
    manifest = json.loads(safe_path(backup, 'manifest.json').read_text())
    records = manifest['files']
    expected = {rel for rel, _ in FILES.values()}
    if len(records) != len(expected) or {r['path'] for r in records} != expected:
        raise ValueError('Invalid backup manifest')
    for r in records:
        target = safe_path(root, r['path'])
        if verify_installed and digest(target) != r['installed_sha256']:
            raise ValueError(f"Changed since installation; refusing overwrite: {r['path']}")
        if r['existed'] and digest(safe_path(backup, r['path'])) != r['previous_sha256']:
            raise ValueError('Backup checksum mismatch')
    for r in records:
        target = safe_path(root, r['path'])
        if r['existed']:
            atomic_write(target, (backup / r['path']).read_bytes(), r['mode'],
                         r['uid'] if root == Path('/') else None, r['gid'])
        else:
            target.unlink(missing_ok=True)
    return {'restored': True, 'backup': str(backup)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['check', 'install', 'rollback', 'status'])
    parser.add_argument('--backup', type=Path)
    parser.add_argument('--root', type=Path, default=Path('/'), help='Alternate filesystem for local tests only')
    args = parser.parse_args()
    root = args.root.resolve()
    if args.command in ('install', 'rollback') and root == Path('/') and os.geteuid() != 0:
        parser.error('Run installation/rollback as root')
    try:
        if args.command == 'check':
            result = preflight(root)
        elif args.command == 'status':
            result = {'files': {rel: {'exists': safe_path(root, rel).exists(), 'matches_package': digest(safe_path(root, rel)) == digest(BASE / src)} for src, (rel, _) in FILES.items()}}
        else:
            # Serialize updates and reject symlinked backup directories before writing.
            lock = safe_path(root, BACKUPS + '/.install.lock')
            lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with lock.open('a') as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if args.command == 'install':
                    result = install(root)
                else:
                    if not args.backup:
                        raise ValueError('--backup is required')
                    result = restore(root, args.backup)
        print(json.dumps(result, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
