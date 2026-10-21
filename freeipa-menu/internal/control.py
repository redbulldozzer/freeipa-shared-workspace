"""Local workstation management; no FreeIPA server mutations."""
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile

SELECTED = Path('/etc/shared-workspace-users')
CURRENT = Path('/run/shared-workspace/current')
LOCK = Path('/run/shared-workspace/session.lock')
ACTION = 'org.office.freeipa-center.manage'
ENTRY = '/usr/local/share/freeipa-menu/internal/admin-entry'
DESKTOP = '''[Desktop Entry]
Type=Application
Name=FreeIPA — центр управления
Comment=Установка, сотрудники, диагностика и настройки FreeIPA
Exec=/usr/local/bin/freeipa-center
Icon=preferences-system
Terminal=true
Categories=System;Settings;
'''


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def write(path, content, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(content.encode())
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


def validate_login(login):
    if not re.fullmatch(r'[a-z][a-z0-9_.-]{0,63}', login):
        raise ValueError('Некорректный логин.')


def local_names():
    return {line.split(':')[0] for line in Path('/etc/passwd').read_text().splitlines()}


def eligible(login, group):
    validate_login(login)
    if login in local_names():
        raise ValueError(f'{login}: это локальная учётка, нужен доменный сотрудник.')
    try:
        user = pwd.getpwnam(login)
        wanted = grp.getgrnam(group)
    except KeyError as error:
        raise ValueError(f'{login}: сотрудник или группа {group} не найдены. Проверь связь с IPA.') from error
    if wanted.gr_gid not in os.getgrouplist(login, user.pw_gid):
        raise ValueError(f'{login} не входит в группу {group}. Членство меняется в FreeIPA.')
    return user


def save_selected(users, group):
    users = list(dict.fromkeys(users))
    if len(users) > 8:
        raise ValueError('На экране помещается максимум 8 сотрудников.')
    for login in users:
        eligible(login, group)
    # Empty file intentionally means only "Other user"; absent file means automatic history.
    write(SELECTED, ''.join(login + '\n' for login in users))


def current_employee():
    try:
        with LOCK.open('rb') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                return None
            values = dict(line.split('=', 1) for line in CURRENT.read_text().splitlines() if '=' in line)
            login = values.get('employee', '')
            validate_login(login)
            return login
    except FileNotFoundError:
        return None


def administrator(login):
    validate_login(login)
    if login in local_names():
        raise ValueError(f'{login} совпадает с локальной учёткой. Выбери доменного администратора.')
    try:
        return pwd.getpwnam(login)
    except KeyError as error:
        raise ValueError(f'Доменный администратор {login} не найден через SSSD.') from error


def admin_files(login):
    validate_login(login)
    sudo = f'# Managed by FreeIPA Center; authenticate with the domain password.\n{login} ALL=(ALL:ALL) ALL\n'
    rules = '''polkit.addAdminRule(function(action, subject) {
    if (action.id == %s) return ["unix-group:sudo", %s];
});
''' % (json.dumps(ACTION), json.dumps('unix-user:' + login))
    policy = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig><action id="%s">
<description>Управление рабочим местом</description>
<message>Выбери локального или доменного администратора и введи его пароль</message>
<defaults><allow_any>auth_admin</allow_any><allow_inactive>auth_admin</allow_inactive><allow_active>auth_admin</allow_active></defaults>
<annotate key="org.freedesktop.policykit.exec.path">%s</annotate>
</action></policyconfig>
''' % (ACTION, ENTRY)
    return sudo, rules, policy


def install_admin(login):
    administrator(login)
    sudo, rules, policy = admin_files(login)
    run(['visudo', '-c'], capture_output=True, text=True)
    with tempfile.TemporaryDirectory(prefix='freeipa-sudo-') as temp:
        candidate = Path(temp) / 'rule'
        write(candidate, sudo, 0o440)
        run(['visudo', '-cf', str(candidate)], capture_output=True, text=True)
    write('/etc/sudoers.d/61-freeipa-center-admin', sudo, 0o440)
    write('/etc/polkit-1/rules.d/00-freeipa-center.rules', rules)
    write('/usr/share/polkit-1/actions/org.office.freeipa-center.policy', policy)
    run(['visudo', '-c'], capture_output=True, text=True)


def enable_ssh():
    run(['apt-get', 'install', '--no-upgrade', '-y', 'openssh-server', 'sudo', 'pkexec'])
    # With socket activation ssh.service may never have started, so systemd has
    # not created its RuntimeDirectory yet. sshd -t still requires that directory.
    run(['install', '-d', '-o', 'root', '-g', 'root', '-m', '0755', '/run/sshd'])
    run(['/usr/sbin/sshd', '-t'])
    run(['systemctl', 'enable', '--now', 'ssh.service'])
    if Path('/usr/sbin/ufw').exists():
        result = run(['/usr/sbin/ufw', 'status'], capture_output=True, text=True,
                     env={**os.environ, 'LC_ALL': 'C'})
        if 'Status: active' in result.stdout:
            config = run(['/usr/sbin/sshd', '-T'], capture_output=True, text=True).stdout
            for line in config.splitlines():
                if line.startswith('port '):
                    port = int(line.split()[1])
                    run(['/usr/sbin/ufw', 'allow', f'{port}/tcp', 'comment', 'FreeIPA Center SSH'])
    run(['systemctl', 'is-active', '--quiet', 'ssh.service'])


def desktop_path(account):
    home = Path(account.pw_dir)
    config = home / '.config/user-dirs.dirs'
    if config.is_file():
        for line in config.read_text().splitlines():
            match = re.fullmatch(r'XDG_DESKTOP_DIR="([^"\n]+)"', line.strip())
            if match:
                value = match[1].replace('${HOME}', str(home)).replace('$HOME', str(home))
                path = Path(value)
                # Parse data only; never source a user-controlled shell file as root.
                if path.is_absolute() and path.resolve().is_relative_to(home.resolve()) and path.resolve() != home.resolve():
                    return path
    return home / ('Рабочий стол' if (home / 'Рабочий стол').is_dir() else 'Desktop')


def install_shortcuts(users):
    write('/usr/local/bin/freeipa-center', '''#!/bin/sh
exec /usr/bin/python3 -I /usr/local/share/freeipa-menu/internal/launch.py
''', 0o755)
    os.chmod(ENTRY, 0o755)
    write('/usr/share/applications/freeipa-center.desktop', DESKTOP)
    for login in dict.fromkeys(users):
        if login not in local_names():
            continue
        account = pwd.getpwnam(login)
        # Write into the home with the user's own privileges to prevent symlink attacks.
        path = desktop_path(account)
        code = ('from pathlib import Path; import sys; '
                'p=Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); '
                'p.write_text(sys.argv[2]); p.chmod(0o755)')
        run(['runuser', '-u', login, '--', '/usr/bin/python3', '-I', '-c', code,
             str(path / 'freeipa-center.desktop'), DESKTOP])
        # Use the target desktop's bus, not root's HOME/GVfs session.
        bus = Path(f'/run/user/{account.pw_uid}/bus')
        if bus.exists():
            command = ['runuser', '-u', login, '--', 'env',
                       f'HOME={account.pw_dir}', f'XDG_RUNTIME_DIR=/run/user/{account.pw_uid}',
                       f'DBUS_SESSION_BUS_ADDRESS=unix:path={bus}', 'XDG_DATA_DIRS=/usr/share',
                       'gio', 'set', str(path / 'freeipa-center.desktop'), 'metadata::trusted', 'true']
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                print('Ярлык создан; при первом открытии разреши запуск:', path / 'freeipa-center.desktop')
        print('Ярлык на рабочем столе:', path / 'freeipa-center.desktop')
