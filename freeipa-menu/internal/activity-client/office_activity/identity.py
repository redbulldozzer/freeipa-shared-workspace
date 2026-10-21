import configparser
import fcntl
import os
from pathlib import Path
import pwd
import re
import stat

from .core import Identity, Snapshot


def trusted_file(path, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_mode & 0o022:
        os.close(fd)
        raise ValueError('untrusted_identity_file')
    return fd


def shared_identity(directory=Path('/run/shared-workspace'), owner=0):
    """Hold a descriptor to the session lock while reading an atomic identity.

    pid in current belongs to the authenticating PAM and may exit after takeover;
    the live flock, rather than pid, is the authoritative liveness check.
    """
    st = directory.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != owner or st.st_mode & 0o022:
        raise ValueError('untrusted_identity_directory')
    fd = trusted_file(directory / 'session.lock', owner)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise ValueError('no_live_shared_session')
        with os.fdopen(trusted_file(directory / 'current', owner)) as stream:
            values = dict(line.rstrip('\n').split('=', 1) for line in stream if '=' in line)
        if not re.fullmatch(r'[a-z0-9_.@-]{1,127}', values.get('employee', '')):
            raise ValueError('invalid_employee')
        if not re.fullmatch(r'[0-9a-f]{32}', values.get('shift', '')):
            raise ValueError('invalid_shift')
        return values['employee'], values['shift']
    finally:
        os.close(fd)


def workspace_target(path=Path('/etc/shared-workspace.conf')):
    try:
        with os.fdopen(trusted_file(path)) as stream:
            for line in stream:
                if line.startswith('target='):
                    return line.strip().split('=', 1)[1]
    except FileNotFoundError:
        return ''
    return ''


def realm_name():
    c = configparser.ConfigParser(interpolation=None)
    c.read('/etc/ipa/default.conf')
    return c.get('global', 'realm', fallback='')


class Resolver:
    def __init__(self, session, uid=None):
        self.uid = os.getuid() if uid is None else uid
        self.user = pwd.getpwuid(self.uid).pw_name
        self.session = session
        self.target = workspace_target()
        self.realm = realm_name()
        self.local = {line.split(':', 1)[0] for line in Path('/etc/passwd').read_text().splitlines()}
        self.domain_ids = {}

    def resolve(self, properties, screen_locked=False, idle_seconds=0, afk_seconds=180):
        if int(properties.get('User', (-1, ''))[0]) != self.uid:
            return Snapshot(None, 'unknown', 'session_uid_mismatch')
        if properties.get('Class') != 'user' or properties.get('Remote') or properties.get('Type') != 'x11':
            return Snapshot(None, 'unknown', 'unsupported_session')
        if properties.get('State') == 'closing':
            return Snapshot(None, 'unknown', 'session_closing')
        if self.user == self.target:
            try:
                principal, shift = shared_identity()
                # Freeze the NSS domain UID for this authenticated shift. It helps
                # the server reject a deleted/recreated login after delayed upload.
                key = (principal, shift)
                if key not in self.domain_ids:
                    self.domain_ids = {key: pwd.getpwnam(principal).pw_uid}
                identity = Identity('domain_shared', principal, self.realm, self.user, self.uid,
                                    shift, self.session, self.domain_ids[key])
            except (OSError, ValueError, KeyError):
                return Snapshot(None, 'unknown', 'shared_identity_unavailable')
        else:
            kind = 'local' if self.user in self.local else 'domain'
            identity = Identity(kind, self.user, self.realm if kind == 'domain' else '',
                                self.user, self.uid, '', self.session, self.uid if kind == 'domain' else None)
        if not properties.get('Active'):
            # The shared desktop remains alive while the greeter/another VT is active.
            return Snapshot(identity, 'locked', 'desktop_inactive')
        if properties.get('LockedHint') or screen_locked:
            return Snapshot(identity, 'locked', 'screen_locked')
        if screen_locked is None or idle_seconds is None:
            return Snapshot(identity, 'unknown', 'sensor_unavailable')
        return Snapshot(identity, 'afk' if idle_seconds >= afk_seconds else 'active')
