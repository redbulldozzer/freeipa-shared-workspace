#!/usr/bin/python3
"""Install only this application's explicit manifest. No domain changes."""
import os
from pathlib import Path
import shutil
import subprocess

SOURCE = Path(__file__).resolve().parent
DEST = Path('/usr/local/lib/office-local-transition')


def write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SystemExit('Symlink at install destination')
    path.write_text(text)
    path.chmod(mode)
    os.chown(path, 0, 0)


def main():
    if os.geteuid():
        raise SystemExit('Run installer as root')
    for command in ('pkexec', 'pamtester', 'gnome-keyring-daemon', 'dbus-run-session', 'lightdm'):
        if not shutil.which(command):
            raise SystemExit('Missing dependency: '+command)
    import gi
    gi.require_version('Gtk', '3.0')
    if DEST.is_symlink():
        raise SystemExit('Install directory is a symlink')
    DEST.mkdir(parents=True, exist_ok=True, mode=0o755)
    for directory in (DEST, DEST/'transition'):
        if directory.is_symlink():
            raise SystemExit('Install directory is a symlink')
        directory.mkdir(exist_ok=True, mode=0o755)
        os.chown(directory, 0, 0)
        directory.chmod(0o755)
    for name in ['entry.py', 'gui.py', *['transition/'+p.name for p in (SOURCE/'transition').glob('*.py')]]:
        target = DEST/name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise SystemExit('Install destination is a symlink')
        shutil.copyfile(SOURCE/name, target)
        os.chown(target, 0, 0)
        target.chmod(0o644)
    write(DEST/'backend', "#!/usr/bin/python3\nfrom entry import main\nfrom transition.core import TransitionError\n"
          "import sys\ntry: raise SystemExit(main())\nexcept TransitionError as e: print(str(e),file=sys.stderr);raise SystemExit(1)\n", 0o755)
    write('/usr/local/bin/office-local-transition',
          '#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/office-local-transition/entry.py "$@"\n', 0o755)
    write('/usr/local/bin/office-local-transition-gui',
          '#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/office-local-transition/gui.py "$@"\n', 0o755)
    write('/usr/share/applications/office-local-transition.desktop', '''[Desktop Entry]
Type=Application
Name=Переход на локальную учётку
Comment=Локальный вход и удаление Пульса
Exec=/usr/local/bin/office-local-transition-gui
Icon=preferences-system-users
Terminal=false
Categories=System;Settings;
''')
    write('/usr/share/polkit-1/actions/example.invalid-transition.policy', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig><action id="example.invalid-transition.manage">
<description>Переход на локальную учётку</description>
<message>Введи пароль администратора для настройки локального входа</message>
<defaults><allow_any>auth_admin</allow_any><allow_inactive>auth_admin</allow_inactive><allow_active>auth_admin_keep</allow_active></defaults>
<annotate key="org.freedesktop.policykit.exec.path">/usr/local/lib/office-local-transition/backend</annotate>
</action></policyconfig>
''')
    local = {l.split(':')[0] for l in Path('/etc/passwd').read_text().splitlines()}
    if 'admin' not in local and subprocess.run(['getent', 'passwd', 'admin'], capture_output=True).returncode == 0:
        write('/etc/polkit-1/rules.d/00-office-local-transition-domain-admin.rules', '''polkit.addAdminRule(function(action, subject) {
 if (action.id == "example.invalid-transition.manage") return ["unix-group:sudo", "unix-user:admin"];
});
''')
    print('Installed office-local-transition 0.1.0. Login and domain configuration unchanged.')


if __name__ == '__main__':
    main()
