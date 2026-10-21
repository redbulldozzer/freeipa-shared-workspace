"""Select the work account before Slick Greeter starts; never enable autologin."""
import configparser
import io
import os
from pathlib import Path
import pwd
import re
import sys

from .core import atomic, TransitionError


def select_user(cache, username, seat='seat0'):
    if not re.fullmatch(r'[a-z][a-z0-9_.-]{0,31}', username):
        raise ValueError('Invalid local username')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', seat):
        raise ValueError('Invalid seat')
    directory = Path(cache)/'slick-greeter'
    state = directory/('state' if seat == 'seat0' else seat+'-state')
    for path in (state, *state.parents):
        if path.is_symlink():
            raise ValueError('Symlink in greeter state path')
    directory.mkdir(parents=True, exist_ok=True)
    parsed = configparser.ConfigParser(interpolation=None)
    parsed.optionxform = str
    if state.exists():
        parsed.read_string(state.read_text())
    if not parsed.has_section('greeter'):
        parsed.add_section('greeter')
    parsed['greeter']['last-user'] = username
    data = io.StringIO()
    parsed.write(data, space_around_delimiters=False)
    atomic(state, data.getvalue(), 0o600)


def main(username):
    # The setup hook runs as root. Drop privileges before touching greeter-owned
    # cache directories, so a compromised cache cannot cause privileged writes.
    try:
        user = pwd.getpwnam('lightdm')
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
        if os.geteuid() != user.pw_uid:
            raise PermissionError('Expected lightdm identity')
        os.umask(0o077)
        select_user(Path(user.pw_dir)/'.cache', username, os.environ.get('XDG_SEAT') or 'seat0')
    except (OSError, ValueError, KeyError, configparser.Error, TransitionError) as error:
        # A cache failure must leave the normal password screen available.
        print('Work account selection unavailable: '+type(error).__name__, file=sys.stderr)
