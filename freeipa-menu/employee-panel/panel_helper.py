#!/usr/bin/python3
"""Unprivileged companion for the shared-workspace Cinnamon applet."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time

UUID = 'employee@example.invalid'
VERSION = '1.0.0'


def read_trusted(path, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_mode & 0o022:
            raise ValueError('untrusted_file')
        with os.fdopen(fd, encoding='utf-8') as stream:
            fd = -1
            return stream.read(8192)
    finally:
        if fd >= 0:
            os.close(fd)


def target_user():
    values = dict(line.split('=', 1) for line in read_trusted('/etc/shared-workspace.conf').splitlines() if '=' in line)
    return values.get('target', '')


def require_workspace():
    if os.getuid() == 0 or pwd.getpwuid(os.getuid()).pw_name != target_user():
        raise ValueError('not_shared_workspace')


def identity(directory=Path('/run/shared-workspace'), owner=0):
    st = directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != owner or st.st_mode & 0o022:
        raise ValueError('untrusted_directory')
    fd = os.open(directory / 'session.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_mode & 0o022:
            raise ValueError('untrusted_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise ValueError('no_live_session')
        values = dict(line.split('=', 1) for line in read_trusted(directory / 'current', owner).splitlines() if '=' in line)
        login, shift = values.get('employee', ''), values.get('shift', '')
        if not re.fullmatch(r'[a-z0-9_.@-]{1,127}', login) or not re.fullmatch(r'[0-9a-f]{32}', shift):
            raise ValueError('invalid_identity')
        return login, shift
    finally:
        os.close(fd)


def status():
    require_workspace()
    login, shift = identity()
    try:
        name = pwd.getpwnam(login).pw_gecos.split(',', 1)[0].strip() or login
    except KeyError:
        name = login
    # NSS may have taken time: never publish a name for a shift already replaced.
    if identity() != (login, shift):
        raise ValueError('identity_changed')
    name = ''.join(c for c in name if c.isprintable())[:120]
    return dict(state='ok', login=login, name=name or login, version=VERSION)


def panel_entries(entries, next_id, panels):
    """Keep existing entries verbatim; append our applet beside the clock."""
    if any(len(e.split(':')) >= 4 and e.split(':')[3].lstrip('!') == UUID for e in entries):
        return entries, next_id
    clocks = [e.split(':') for e in entries if len(e.split(':')) >= 4 and e.split(':')[3] == 'employee@example.invalid']
    if clocks:
        panel, zone = clocks[0][:2]
    elif panels:
        panel, zone = 'panel' + panels[0].split(':')[0], 'right'
    else:
        raise ValueError('no_panel')
    slots = [int(p[2]) for e in entries if len(p := e.split(':')) >= 4 and p[:2] == [panel, zone] and p[2].isdigit()]
    ids = [int(p[4]) for e in entries if len(p := e.split(':')) >= 5 and p[4].isdigit()]
    ident = max([next_id, *(i + 1 for i in ids)])
    return [*entries, f'{panel}:{zone}:{max(slots, default=-1) + 1}:{UUID}:{ident}'], ident + 1


def configure_panel(disable=False):
    require_workspace()
    from gi.repository import Gio
    settings = Gio.Settings.new('org.cinnamon')
    entries = settings.get_strv('enabled-applets')
    if disable:
        updated = [e for e in entries if not (len(e.split(':')) >= 4 and e.split(':')[3].lstrip('!') == UUID)]
        next_id = settings.get_int('next-applet-id')
    else:
        updated, next_id = panel_entries(entries, settings.get_int('next-applet-id'), settings.get_strv('panels-enabled'))
    if updated != entries:
        if not all(settings.is_writable(k) for k in ('next-applet-id', 'enabled-applets')):
            raise ValueError('panel_settings_locked')
        settings.delay()
        settings.set_int('next-applet-id', next_id)
        settings.set_strv('enabled-applets', updated)
        settings.apply()
        Gio.Settings.sync()


def switch_employee():
    require_workspace()
    from gi.repository import Gio, GLib
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    def call(method):
        return bus.call_sync('org.cinnamon.ScreenSaver', '/org/cinnamon/ScreenSaver',
                             'org.cinnamon.ScreenSaver', method, GLib.Variant('(s)', ('',)) if method == 'Lock' else None, None,
                             Gio.DBusCallFlags.NONE, 3000, None)
    call('Lock')
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if call('GetActive').unpack()[0]:
            subprocess.run(['/usr/bin/dm-tool', 'switch-to-greeter'], check=True, timeout=5)
            return
        time.sleep(0.1)
    raise RuntimeError('lock_not_confirmed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['status', 'enable', 'disable', 'switch', 'version'])
    args = parser.parse_args()
    try:
        if args.command == 'status':
            print(json.dumps(status(), ensure_ascii=False))
        elif args.command == 'version':
            print(VERSION)
        elif args.command == 'switch':
            switch_employee()
        else:
            configure_panel(args.command == 'disable')
    except Exception as exc:
        # No passwords or raw NSS/DBus output in UI/logs.
        print(json.dumps({'state': 'unknown', 'error': type(exc).__name__, 'version': VERSION}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
