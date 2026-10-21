#!/usr/bin/python3
"""Root-only installer; shared login/PAM and user application data stay intact."""
import argparse
import datetime
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import uuid

SOURCE = Path(__file__).resolve().parent
CODE = Path('/usr/local/lib/office-activity')
CONFIG = Path('/etc/office-activity/config.json')
FILES = ['/usr/local/bin/office-activity', '/usr/local/bin/office-activity-session',
         '/etc/systemd/user/office-activity.service', '/etc/xdg/autostart/office-activity.desktop',
         str(CONFIG)]
OLD_UNITS = ['aw-client-stack.service', 'aw-input.service', 'aw-qt.service']
BACKUPS = Path('/var/backups/office-activity')
ACTIVE_BACKUP = None


def user_command(user, args, check=False, env=None, input=None):
    p = pwd.getpwnam(user)
    user_env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': p.pw_dir, 'USER': user,
        'LOGNAME': user, 'XDG_RUNTIME_DIR': f'/run/user/{p.pw_uid}',
        'DBUS_SESSION_BUS_ADDRESS': f'unix:path=/run/user/{p.pw_uid}/bus', **(env or {})}
    return subprocess.run(['/usr/sbin/runuser', '-u', user, '--', '/usr/bin/env', '-i',
                           *[k+'='+v for k,v in user_env.items()], *args],
                           capture_output=True, text=True, check=check, input=input)


def write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', prefix=path.name+'.', dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            os.fchmod(f.fileno(), mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)


def session_environment(user):
    uid = pwd.getpwnam(user).pw_uid
    # Only read the Cinnamon session environment of the requested desktop user.
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if proc.stat().st_uid != uid or (proc/'comm').read_text().strip() not in ('cinnamon-session', 'cinnamon-sessio'):
                continue
            values = dict(x.split(b'=', 1) for x in (proc/'environ').read_bytes().split(b'\0') if b'=' in x)
            allowed = ('DISPLAY', 'XAUTHORITY', 'XDG_SESSION_ID', 'XDG_SESSION_TYPE')
            env = {k: values[k.encode()].decode() for k in allowed if k.encode() in values}
            if env.get('DISPLAY') and env.get('XDG_SESSION_ID'):
                env.setdefault('XDG_SESSION_TYPE', 'x11')
                return env
        except (OSError, ValueError):
            continue
    return None


def legacy(user):
    result = {'user': user, 'units': {}, 'autostart': {}, 'enable_links': {}}
    for unit in OLD_UNITS:
        enabled = user_command(user, ['systemctl', '--user', 'is-enabled', unit]).stdout.strip()
        active = user_command(user, ['systemctl', '--user', 'is-active', unit]).stdout.strip() == 'active'
        result['units'][unit] = {'enabled': enabled, 'active': active}
    # All home writes execute as that user, never following their links as root.
    script = '''import pathlib,json
p=pathlib.Path.home()/'.config/autostart'
names={'aw-qt.desktop','activitywatch.desktop'}
for base in [p,pathlib.Path('/etc/xdg/autostart')]:
 for f in base.glob('*.desktop'):
  try:
   text=f.read_text()
   if '/opt/activitywatch/' in text or 'Exec=aw-qt' in text:names.add(f.name)
  except OSError:pass
saved={}
for name in names:
 f=p/name
 if f.is_symlink():raise RuntimeError('autostart symlink requires manual review: '+name)
 saved[name]=f.read_text() if f.exists() else None
print(json.dumps(saved))
'''
    result['autostart'] = json.loads(user_command(user, ['/usr/bin/python3', '-c', script], check=True).stdout)
    script = '''import pathlib,json,os,sys
p=pathlib.Path.home()/'.config/systemd/user';saved={}
for unit in json.loads(sys.argv[1]):
 for f in p.glob('*.wants/'+unit):
  if f.is_symlink():saved[str(f.relative_to(p))]=os.readlink(f)
print(json.dumps(saved))
'''
    result['enable_links'] = json.loads(user_command(user, ['/usr/bin/python3', '-c', script, json.dumps(OLD_UNITS)], check=True).stdout)
    return result


def retire(entry):
    user = entry['user']
    for unit in OLD_UNITS:
        user_command(user, ['systemctl', '--user', 'disable', '--now', unit])
    script = '''import pathlib,json,sys
p=pathlib.Path.home()/'.config/autostart';p.mkdir(parents=True,exist_ok=True)
for name in json.loads(sys.argv[1]):
 f=p/name
 if f.is_symlink():raise RuntimeError('autostart became a symlink')
 f.write_text('[Desktop Entry]\\nType=Application\\nName=ActivityWatch legacy disabled\\nHidden=true\\n')
'''
    user_command(user, ['/usr/bin/python3', '-c', script, json.dumps(entry['autostart'])], check=True)
    # An offline user's systemd bus may not exist. Disable saved wants links as
    # that user as well, so the old stack cannot reappear at their next login.
    script = '''import pathlib,json,sys
p=pathlib.Path.home()/'.config/systemd/user'
for relative in json.loads(sys.argv[1]):
 f=p/relative
 if f.is_symlink():f.unlink()
'''
    user_command(user, ['/usr/bin/python3', '-c', script, json.dumps(entry.get('enable_links', {}))], check=True)
    # Stop leftover legacy launchers/watchers only, without killing unrelated apps.
    uid = pwd.getpwnam(user).pw_uid
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if proc.stat().st_uid != uid:
                continue
            args = (proc/'cmdline').read_bytes().split(b'\0')[:2]
            old = any(a.startswith(b'/opt/activitywatch/') or
                      (a.endswith(b'/aw-watcher-input') and b'/.local/' in a) for a in args)
            if old:
                os.kill(int(proc.name), 15)
        except (OSError, ProcessLookupError):
            pass


def start(user):
    env = session_environment(user)
    if not env:
        return 'will_start_at_next_graphical_login'
    user_command(user, ['systemctl', '--user', 'daemon-reload'], check=True)
    # A stale failed start should not delay a corrected install.
    user_command(user, ['systemctl', '--user', 'reset-failed', 'office-activity.service'])
    user_command(user, ['systemctl', '--user', 'import-environment', *env], check=True, env=env)
    user_command(user, ['systemctl', '--user', 'restart', 'office-activity.service'], check=True)
    return 'started'


def install(args):
    global ACTIVE_BACKUP
    users = list(dict.fromkeys(args.user))
    for user in users:
        if pwd.getpwnam(user).pw_uid < 1000:
            raise ValueError('Only regular desktop users supported')
    deps = subprocess.run(['/usr/bin/python3', '-c', 'import gi,Xlib'], capture_output=True)
    if deps.returncode:
        raise RuntimeError('Install dependencies first: apt install python3-gi python3-xlib libxss1')
    if args.check:
        print(json.dumps({'users': users, 'replace_legacy': args.replace_legacy,
                          'current_config': CONFIG.exists(), 'dependencies': 'ok'}, indent=2))
        return
    os.umask(0o077)
    backup = BACKUPS / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    backup.mkdir(parents=True)
    manifest = {'users': users, 'files': {}, 'legacy': [], 'code_existed': CODE.exists()}
    if CODE.exists():
        shutil.copytree(CODE, backup/'code', symlinks=True)
    for name in FILES:
        p = Path(name)
        if p.exists() or p.is_symlink():
            saved = backup/'files'/p.relative_to('/')
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, saved, follow_symlinks=False)
            manifest['files'][name] = str(saved.relative_to(backup))
        else:
            manifest['files'][name] = None
    def save():
        (backup/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    save()
    ACTIVE_BACKUP = backup
    print('ROLLBACK_BACKUP='+str(backup), flush=True)
    # Save every retired user immediately, so a later failure can be rolled back.
    if args.replace_legacy:
        for user in users:
            manifest['legacy'].append(legacy(user))
            save()
        for entry in manifest['legacy']:
            retire(entry)
    CODE.mkdir(parents=True, exist_ok=True)
    os.chmod(CODE, 0o755)
    shutil.copytree(SOURCE/'office_activity', CODE/'office_activity', dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for p in (CODE/'office_activity').rglob('*'):
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
    write(CODE/'entry.py', "import sys\nsys.path.insert(0, '/usr/local/lib/office-activity')\nfrom office_activity.main import main\nraise SystemExit(main())\n")
    write('/usr/local/bin/office-activity', '#!/bin/sh\nexec /usr/bin/python3 -I /usr/local/lib/office-activity/entry.py "$@"\n', 0o755)
    write('/usr/local/bin/office-activity-session', (SOURCE/'session-start').read_text(), 0o755)
    for source, dest in [('office-activity.service', '/etc/systemd/user/office-activity.service'),
                         ('office-activity.desktop', '/etc/xdg/autostart/office-activity.desktop')]:
        write(dest, (SOURCE/'systemd'/source).read_text())
    if not CONFIG.exists():
        identity_path = Path('/var/lib/office-activity/device-id')
        if not identity_path.exists():
            write(identity_path, str(uuid.uuid4())+'\n')
        device_id = identity_path.read_text().strip()
        uuid.UUID(device_id)
        write(CONFIG, json.dumps({'device_id': device_id, 'endpoint': '',
            'afk_seconds': 180, 'flush_seconds': 15, 'max_queue_mb': 512}, indent=2)+'\n')
    identity_path = Path('/var/lib/office-activity/device-id')
    if not identity_path.exists():
        write(identity_path, json.loads(CONFIG.read_text())['device_id']+'\n')
    os.chmod(CONFIG.parent, 0o755)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    results = {user: start(user) for user in users}
    print(json.dumps({'backup': str(backup), 'result': results}, ensure_ascii=False, indent=2))


def rollback(backup):
    backup = backup.resolve()
    if backup.parent != BACKUPS or backup.is_symlink():
        raise ValueError('Expected a backup directory inside /var/backups/office-activity')
    data = json.loads((backup/'manifest.json').read_text())
    # Preserve machine identity even after uninstall/reinstall. Keep user queues.
    identity_path = Path('/var/lib/office-activity/device-id')
    if CONFIG.exists() and not identity_path.exists():
        write(identity_path, json.loads(CONFIG.read_text())['device_id']+'\n')
    for user in data['users']:
        user_command(user, ['systemctl', '--user', 'stop', 'office-activity.service'])
    for name, saved in data['files'].items():
        p = Path(name)
        p.unlink(missing_ok=True)
        if saved:
            shutil.copy2(backup/saved, p, follow_symlinks=False)
    if CODE.exists():
        shutil.rmtree(CODE)
    if data['code_existed']:
        shutil.copytree(backup/'code', CODE, symlinks=True)
    for entry in data['legacy']:
        script = '''import pathlib,json,sys
p=pathlib.Path.home()/'.config/autostart'
for name,content in json.loads(sys.argv[1]).items():
 f=p/name
 if content is None:f.unlink(missing_ok=True)
 else:f.write_text(content)
'''
        user_command(entry['user'], ['/usr/bin/python3', '-c', script, json.dumps(entry['autostart'])], check=True)
        script = '''import pathlib,json,sys
p=pathlib.Path.home()/'.config/systemd/user'
for relative,target in json.loads(sys.argv[1]).items():
 f=p/relative;f.parent.mkdir(parents=True,exist_ok=True)
 if not f.is_symlink() and not f.exists():f.symlink_to(target)
'''
        user_command(entry['user'], ['/usr/bin/python3', '-c', script, json.dumps(entry.get('enable_links', {}))], check=True)
        user_command(entry['user'], ['systemctl', '--user', 'daemon-reload'])
        for unit, state in entry['units'].items():
            if state['enabled'] == 'enabled':
                user_command(entry['user'], ['systemctl', '--user', 'enable', unit])
            if state['active']:
                user_command(entry['user'], ['systemctl', '--user', 'start', unit])
    for user in data['users']:
        user_command(user, ['systemctl', '--user', 'daemon-reload'])
        if data['code_existed']:
            start(user)
    print('Rolled back code/config. Collected data retained. Legacy desktop autostart restored for next login.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user', action='append', default=[])
    parser.add_argument('--replace-legacy', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--rollback', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run installer as root; collector itself runs as a desktop user')
    if args.rollback:
        rollback(args.rollback)
    elif args.user:
        try:
            install(args)
        except Exception:
            if ACTIVE_BACKUP is not None:
                print('Installation failed; restoring '+str(ACTIVE_BACKUP), file=sys.stderr)
                rollback(ACTIVE_BACKUP)
            raise
    else:
        parser.error('Specify desktop --user (repeatable)')


if __name__ == '__main__':
    main()
