#!/usr/bin/env python3
"""One-time copy into an unused workspace. Original data is never deleted."""
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
from datetime import datetime, timezone

EXCLUDES = [
    '/.ssh/', '/.gnupg/', '/.aws/', '/.azure/', '/.kube/', '/.docker/',
    '/.ecryptfs', '/.Private', '/.cache/', '/.dbus/', '/.Xauthority', '/.ICEauthority',
    '/.bash_history', '/.zsh_history', '/.sudo_as_admin_successful',
    '/.config/activitywatch/', '/.local/share/activitywatch/',
    '/shared-workspace-pilot/', '/shared-workspace-rollout/',
    '/.config/cinnamon-session/saved-session/',
    '/.config/pulse/',
    '/.local/share/keyrings/',  # Migrate/rekey separately; never remove encryption.
    '/.local/share/gvfs-metadata/',
    '/.config/systemd/user/',
    'SingletonLock', 'SingletonCookie', 'SingletonSocket', '.parentlock',
]


def encrypted_backing(path):
    source = subprocess.check_output(['findmnt', '-n', '-o', 'SOURCE', '-T', str(path)],
                                     text=True).strip().split('[', 1)[0]
    if not source.startswith('/dev/'):
        return False
    result = subprocess.run(['lsblk', '-s', '-n', '-o', 'TYPE', source],
                            capture_output=True, text=True)
    return result.returncode == 0 and 'crypt' in result.stdout.split()


def main():
    if os.geteuid() or len(sys.argv) not in (2, 3, 4):
        raise SystemExit('Run as root: migrate-home.py SOURCE_LOCAL_USER [WORKSPACE_USER] [PROJECT_EXCLUDE]')
    source = pwd.getpwnam(sys.argv[1])
    target_name = sys.argv[2] if len(sys.argv) == 3 else 'office-workspace'
    target = pwd.getpwnam(target_name)
    if source.pw_uid == target.pw_uid or source.pw_uid < 1000:
        raise SystemExit('Source must be a separate ordinary local account.')
    home, dest = Path(source.pw_dir), Path(target.pw_dir)
    state_dir = Path('/var/lib/shared-workspace')
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = state_dir / 'migration.json'
    if marker.exists():
        print('Migration already completed; existing workspace left unchanged.')
        return
    # Refuse overwriting a workspace that has already been used graphically.
    if (dest / '.config/dconf/user').exists():
        raise SystemExit('Workspace is already in use; review before overwriting it.')
    for user in (source, target):
        result = subprocess.run(['pgrep', '-u', str(user.pw_uid), '-x',
                                 'firefox|firefox-bin|chrome|chromium|Telegram|VirtualBox|VirtualBoxVM|VBoxHeadless'],
                                stdout=subprocess.DEVNULL)
        if result.returncode == 0:
            raise SystemExit(f'Close browser, Telegram and VirtualBox for {user.pw_name} first.')
        if result.returncode != 1:
            raise SystemExit('Could not check running applications.')
    # Avoid copying an encrypted home's unmounted placeholder.
    if (home / '.Private').is_symlink():
        fs = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(home)], text=True).strip()
        if fs not in ('ecryptfs', 'ecrypt'):
            raise SystemExit('Encrypted source home is not mounted.')
        if not encrypted_backing(dest.parent) and os.environ.get('SHARED_WORKSPACE_ALLOW_UNENCRYPTED') != '1':
            raise SystemExit('Source uses eCryptfs but the shared home is not on dm-crypt/LUKS. '
                             'Encrypt the disk or use the explicit deployment override.')

    command = ['rsync', '-aHS', '--no-devices', '--no-specials', '--chmod=u-s,g-s',
               '--info=progress2',
               f'--chown={target.pw_name}:{target.pw_gid}', '--stats']
    for item in EXCLUDES:
        command += ['--exclude', item]
    if len(sys.argv) == 4:
        project_exclude = sys.argv[3]
        if project_exclude == '/' or not project_exclude.startswith('/') or '..' in Path(project_exclude).parts:
            raise SystemExit('Invalid project exclusion path.')
        command += ['--exclude', project_exclude.rstrip('/') + '/']
    command += [str(home) + '/', str(dest) + '/']
    subprocess.run(command, check=True)
    os.chmod(dest, 0o700)

    # Rewrite only known text configuration formats, never browser databases.
    configs = list((dest / '.local/share/applications').glob('*.desktop'))
    configs += list((dest / '.config/autostart').glob('*.desktop'))
    configs += list((dest / 'Рабочий стол').glob('*.desktop'))
    configs += list((dest / '.config').glob('user-dirs.*'))
    configs += list((dest / '.mozilla').rglob('profiles.ini'))
    configs += list((dest / '.mozilla').rglob('installs.ini'))
    configs += list((dest / '.config/VirtualBox').glob('*.xml'))
    configs += list((dest / 'VirtualBox VMs').rglob('*.vbox'))
    rewritten = []
    for path in configs:
        if path.is_symlink() or not path.is_file():
            continue
        text = path.read_text()
        updated = text.replace(str(home) + '/', str(dest) + '/')
        if updated != text:
            path.write_text(updated)
            rewritten.append(str(path.relative_to(dest)))

    external_links = []
    for directory, dirs, files in os.walk(dest, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if not path.is_symlink():
                continue
            link = os.readlink(path)
            if link == str(home) or link.startswith(str(home) + '/'):
                path.unlink()
                path.symlink_to(str(dest) + link[len(str(home)):])
                os.lchown(path, target.pw_uid, target.pw_gid)
            elif link.startswith('/'):
                external_links.append(str(path.relative_to(dest)))

    # Old custom launchers move desktop files/open many windows. Preserve the
    # files, but keep these actions off during the first physical login test.
    disabled = []
    for name in ('start-av.desktop', 'desktop-cleaner.desktop'):
        path = dest / '.config/autostart' / name
        if path.is_file():
            lines = [line for line in path.read_text().splitlines() if not line.startswith('Hidden=')]
            index = lines.index('[Desktop Entry]') + 1
            lines.insert(index, 'Hidden=true')
            path.write_text('\n'.join(lines) + '\n')
            disabled.append(name)

    record = {'source_user': source.pw_name, 'target_user': target.pw_name,
              'copied_at': datetime.now(timezone.utc).isoformat(),
              'excluded': EXCLUDES, 'rewritten': rewritten,
              'external_symlinks_for_review': external_links,
              'disabled_autostarts_for_pilot': disabled,
              'project_exclude': sys.argv[3] if len(sys.argv) == 4 else None,
              'keyring_migrated': False}
    marker.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
    os.chmod(marker, 0o600)
    print('Copy complete. Source retained; keyring and desktop settings need separate verification.')


if __name__ == '__main__':
    main()
