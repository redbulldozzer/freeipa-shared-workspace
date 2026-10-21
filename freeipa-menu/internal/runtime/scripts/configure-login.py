#!/usr/bin/env python3
"""Enable/disable the tested pilot; never restarts the display manager."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

AUTH = "auth [success=done ignore=ignore default=die] /usr/local/lib/security/pam_shared_workspace.so # shared-workspace-pilot\n"
SESSION = "session requisite /usr/local/lib/security/pam_shared_workspace.so # shared-workspace-pilot\n"
LIGHTDM = Path('/etc/pam.d/lightdm')
LOCKER = Path('/etc/pam.d/cinnamon-screensaver')
DISPLAY = Path('/etc/lightdm/lightdm.conf.d/90-shared-workspace.conf')
LOGIN = Path('/etc/pam.d/shared-workspace-login')
BACKUP = Path('/var/backups/freeipa-menu/pre-activation')


def validate_effective_config(result):
    # LightDM on Mint 21 writes --show-config to stderr even on successful exit.
    effective = result.stdout + '\n' + result.stderr
    required = ('pam-service=shared-workspace-login',
                'greeter-session=shared-workspace-greeter',
                'display-setup-script=/usr/local/libexec/shared-workspace-display-setup')
    if any(item not in effective for item in required):
        raise SystemExit('Another LightDM file overrides the pilot configuration; review lightdm --show-config.')


def write_atomic(path, text):
    temp = path.with_name(path.name + '.shared-workspace-new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def main():
    if os.geteuid() or len(sys.argv) != 2 or sys.argv[1] not in ('enable', 'disable'):
        raise SystemExit('Run as root: configure-login.py enable|disable')
    mode = sys.argv[1]
    if mode == 'disable':
        for path in (LIGHTDM, LOCKER):
            text = path.read_text().replace(AUTH, '').replace(SESSION, '')
            write_atomic(path, text)
        DISPLAY.unlink(missing_ok=True)
        LOGIN.unlink(missing_ok=True)
        Path('/etc/xdg/autostart/shared-workspace-lock-bridge.desktop').unlink(missing_ok=True)
        print('Pilot login disabled. IPA enrollment and user data retained. No sessions restarted.')
        return

    subprocess.run(['sssctl', 'config-check'], check=True)
    settings = {}
    for line in Path('/etc/shared-workspace.conf').read_text().splitlines():
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            settings[key] = value
    if not settings.get('target') or not settings.get('group'):
        raise SystemExit('shared-workspace.conf must define target and group.')
    subprocess.run(['getent', 'passwd', settings['target']], check=True)
    subprocess.run(['getent', 'group', settings['group']], check=True)
    if not Path('/usr/local/lib/security/pam_shared_workspace.so').is_file():
        raise SystemExit('Install and test the module first.')

    # Validate both source files before changing either of them.
    lightdm = LIGHTDM.read_text().replace(AUTH, '').replace(SESSION, '')
    locker = LOCKER.read_text().replace(AUTH, '').replace(SESSION, '')
    lines = lightdm.splitlines(keepends=True)
    anchors = [i for i, line in enumerate(lines) if line.startswith('auth') and 'pam_nologin.so' in line]
    if len(anchors) != 1 or '@include common-auth' not in locker or '@include common-account' not in lightdm:
        raise SystemExit('Unexpected PAM layout. Review the installed distribution files.')
    # A dedicated service keeps the distribution's original LightDM PAM file.
    # substack counts as one item: successful domain remapping skips local auth,
    # then gnome-keyring receives the machine key set in PAM_AUTHTOK.
    suffix = lightdm[lightdm.index('@include common-account'):]
    login = ('# Shared workspace pilot; generated from local LightDM session settings.\n'
             'auth requisite pam_nologin.so\n'
             'auth [success=1 ignore=ignore default=die] /usr/local/lib/security/pam_shared_workspace.so\n'
             'auth substack common-auth\n'
             '-auth optional pam_gnome_keyring.so\n'
             + SESSION + suffix)
    BACKUP.mkdir(mode=0o700, parents=True, exist_ok=True)
    for path in (LIGHTDM, LOCKER):
        backup = BACKUP / path.name
        if not backup.exists():
            shutil.copy2(path, backup)
    write_atomic(LIGHTDM, lightdm)
    write_atomic(LOCKER, locker)
    write_atomic(LOGIN, login)
    source_autostart = Path('/usr/local/share/freeipa-menu/internal/runtime/config/shared-workspace-lock-bridge.desktop')
    if not source_autostart.is_file():
        raise SystemExit('Installed lock bridge autostart file is missing.')
    shutil.copy2(source_autostart, '/etc/xdg/autostart/shared-workspace-lock-bridge.desktop')
    DISPLAY.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(DISPLAY, '[Seat:*]\npam-service=shared-workspace-login\ngreeter-session=shared-workspace-greeter\nuser-session=cinnamon\ndisplay-setup-script=/usr/local/libexec/shared-workspace-display-setup\ngreeter-show-manual-login=true\ngreeter-hide-users=true\nallow-user-switching=true\nautologin-user=\n')
    effective = subprocess.run(['lightdm', '--show-config'], check=True,
                               capture_output=True, text=True)
    validate_effective_config(effective)
    print('Pilot enabled. No running session was stopped; LightDM config applies on its next restart.')


if __name__ == '__main__':
    main()
