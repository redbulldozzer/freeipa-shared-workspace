"""Staged transition; profile UID, paths and file ownership are never changed."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

from .core import (APPLET, ENTRY, Job, TransitionError, atomic, json_write, matches_password,
                   now, password_hash, public_key, usable_hash, validate_password)

SYSTEM_BACKUPS = ['/etc/pam.d', '/etc/lightdm', '/etc/ipa', '/etc/sssd', '/etc/ssh',
                  '/etc/krb5.conf', '/etc/krb5.keytab', '/etc/nsswitch.conf', '/etc/hosts',
                  '/etc/chrony', '/etc/NetworkManager/system-connections',
                  '/etc/shared-workspace.conf', '/etc/shared-workspace-users',
                  '/etc/shared-workspace.keyring', '/etc/sudoers.d/61-freeipa-center-admin',
                  '/etc/polkit-1/rules.d/00-freeipa-center.rules']
PULSE_FILES = ['/usr/local/bin/office-activity', '/usr/local/bin/office-activity-session',
               '/usr/local/lib/office-activity', '/etc/systemd/user/office-activity.service',
               '/etc/xdg/autostart/office-activity.desktop', '/etc/office-activity',
               '/var/lib/office-activity/device-id']
LOGIN_FILES = ['/etc/lightdm/lightdm.conf.d/90-shared-workspace.conf',
               '/etc/pam.d/shared-workspace-login', '/etc/pam.d/shared-workspace-domain',
               '/etc/pam.d/shared-workspace-check', '/etc/shared-workspace.conf',
               '/etc/shared-workspace-users', '/etc/xdg/autostart/shared-workspace-lock-bridge.desktop',
               '/usr/local/lib/security/pam_shared_workspace.so',
               '/usr/local/libexec/shared-workspace-greeter',
               '/usr/local/libexec/shared-workspace-lock-bridge',
               '/usr/local/libexec/shared-workspace-display-setup',
               '/usr/share/xgreeters/shared-workspace-greeter.desktop',
               '/usr/share/cinnamon/applets/'+APPLET,
               '/usr/local/libexec/office-employee-panel',
               '/etc/xdg/autostart/office-employee-panel.desktop',
               '/usr/local/bin/freeipa-center', '/usr/local/bin/shared-workspacectl',
               '/etc/sudoers.d/61-freeipa-center-admin',
               '/etc/polkit-1/rules.d/00-freeipa-center.rules',
               '/etc/polkit-1/rules.d/00-office-local-transition-domain-admin.rules',
               '/usr/share/polkit-1/actions/org.office.freeipa-center.policy',
               '/usr/share/applications/freeipa-center.desktop',
               '/etc/ssh/sshd_config.d/04-freeipa-menu-keys.conf']
PUBLISHER_FILES = ['/etc/systemd/system/office-dns-publish.service',
                   '/etc/systemd/system/office-dns-publish.timer',
                   '/etc/NetworkManager/dispatcher.d/90-office-dns',
                   '/usr/local/sbin/office-dns-publish', '/etc/office-dynamic-dns.json']
LEGACY_UNITS = ['aw-client-stack.service', 'aw-input.service', 'aw-qt.service']
LOGIN_GUARD = '/var/lib/office-local-transition/login-in-progress'
GUARD_DROPIN = '/etc/systemd/system/lightdm.service.d/80-office-local-transition.conf'
GREETER_SELECT = '/usr/local/libexec/office-local-login-select'


def collector_command(args, roots):
    for i, value in enumerate(args[:5]):
        if value == '-m' and i+1 < len(args) and args[i+1] in ('office_activity', 'aw_qt', 'aw_server', 'aw_watcher_window', 'aw_watcher_afk'):
            return True
        if any(value == root or value.startswith(root+'/') for root in roots):
            return True
    return False


def collector_processes(system):
    if not system.native:
        return []
    roots = ['/usr/local/bin/office-activity', '/usr/local/bin/office-activity-session',
             '/usr/local/lib/office-activity', '/opt/activitywatch']
    for user in system.local_users().values():
        if 1000 <= user['uid'] < 60000 and user['home'].startswith('/home/'):
            roots += [user['home']+'/activitywatch', user['home']+'/.local/opt/activitywatch']
    found = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            args = [v.decode(errors='replace') for v in (proc/'cmdline').read_bytes().split(b'\0') if v]
            if collector_command(args, roots):
                found.append(int(proc.name))
        except OSError:
            pass
    return found


def stop_collectors(job):
    import signal, time
    system = job.system
    for user in system.local_users().values():
        if 1000 <= user['uid'] < 60000 and user['home'].startswith('/home/'):
            for unit in ['office-activity.service', *LEGACY_UNITS]:
                user_run(system, user, ['systemctl', '--user', 'stop', unit], check=False)
    for pid in collector_processes(system):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    if collector_processes(system):
        time.sleep(2)
    if collector_processes(system):
        raise TransitionError('Коллектор Пульса не остановился; продолжение отложено до его завершения.')


def user_run(system, user, args, input=None, check=True):
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': user['home'], 'USER': user['name'],
           'LOGNAME': user['name'], 'XDG_RUNTIME_DIR': '/run/user/'+str(user['uid']),
           'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/'+str(user['uid'])+'/bus'}
    return system.run(['runuser', '-u', user['name'], '--', 'env', '-i',
                       *[k+'='+v for k, v in env.items()], *args], input=input, check=check, timeout=80)


def backup_path(job, absolute):
    source = job.system.path(absolute)
    destination = job.backup/'files'/absolute.lstrip('/')
    manifest_path = job.directory/'backup-manifest.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    if absolute in manifest:
        return
    present = source.exists() or source.is_symlink()
    info = {'present': present}
    if present:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if source.is_symlink():
            info['link'] = os.readlink(source)
            destination.symlink_to(info['link'])
        elif source.is_dir():
            shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copy2(source, destination, follow_symlinks=False)
        st = source.lstat()
        info.update(uid=st.st_uid, gid=st.st_gid, mode=stat.S_IMODE(st.st_mode))
        entries = [destination, *destination.rglob('*')] if destination.is_dir() and not destination.is_symlink() else [destination]
        for item in entries:
            if item.is_file() and not item.is_symlink():
                fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    manifest[absolute] = info
    json_write(manifest_path, manifest)


def remove(job, absolute):
    p = job.system.path(absolute)
    backup_path(job, absolute)
    if p.is_dir() and not p.is_symlink():
        if not shutil.rmtree.avoids_symlink_attacks:
            raise TransitionError('Удаление каталога без защиты от ссылок запрещено.')
        shutil.rmtree(p)
    else:
        p.unlink(missing_ok=True)


def edit(job, absolute, text, mode=0o644):
    backup_path(job, absolute)
    p = job.system.path(absolute)
    owner = (p.stat().st_uid, p.stat().st_gid) if p.exists() else (0, 0)
    atomic(p, text, mode, owner if job.system.native else None)


def validate_secrets(system, planned, secrets):
    if set(secrets) - {'password', 'admin_password', 'old_keyring_password'}:
        raise TransitionError('Неизвестные поля учётных данных.')
    opts = planned['options']
    password = secrets.get('password', '')
    if opts['password_mode'] == 'new':
        validate_password(password)
    elif not isinstance(password, str) or not password or len(password.encode()) > 512 or any(c in password for c in '\n\r\0'):
        raise TransitionError('Нужен пароль выбранной локальной учётки.')
    if opts['password_mode'] == 'local':
        source = system.local_users().get(opts['source_user'])
        if not source or not matches_password(password, source['hash']):
            raise TransitionError('Введённый пароль не совпадает с выбранной локальной учёткой.')
    admin = system.local_users().get(opts['admin_user'])
    if not admin or not usable_hash(admin['hash']):
        validate_password(secrets.get('admin_password', ''))
    elif secrets.get('admin_password') and not matches_password(secrets['admin_password'], admin['hash']):
        raise TransitionError('Пароль существующего локального администратора не совпадает.')
    if not opts['admin_public_key'] and not secrets.get('admin_password'):
        raise TransitionError('Нужен проверяемый локальный пароль администратора или SSH-ключ.')


def prepare(job):
    for name in SYSTEM_BACKUPS:
        backup_path(job, name)
    users = job.system.local_users()
    target = job.planned()['inventory']['target']
    row = next(l.split(':') for l in job.system.read('/etc/shadow').splitlines()
               if l.split(':')[0] == target['name'])
    json_write(job.backup/'target-password.json', {'name': target['name'], 'row': row})
    backup_path(job, target['home']+'/.local/share/keyrings')
    job.event('Сохранены настройки входа и рабочая связка ключей. Рабочие файлы не перемещаются.')


def administrator(job, secrets):
    system = job.system
    opts = job.planned()['options']
    name = opts['admin_user']
    users = system.local_users()
    if name not in users:
        # Require a name absent from NSS as well, to avoid shadowing a live domain identity.
        if system.run(['getent', 'passwd', name], check=False).returncode == 0:
            raise TransitionError('Имя администратора занято доменной учёткой. Выбери другое локальное имя.')
        system.run(['useradd', '--create-home', '--shell', '/bin/bash', '--comment', 'Office local administrator', name])
        job.update(created_admin=name)
    user = system.local_users()[name]
    if not usable_hash(user['hash']):
        hashed = password_hash(secrets['admin_password'])
        system.run(['chpasswd', '--encrypted'], input=name+':'+hashed+'\n')
        system.run(['chage', '-E', '-1', name])
    system.run(['usermod', '-aG', 'sudo', name])
    key = public_key(opts['admin_public_key'])
    if key:
        ssh = system.path(user['home']+'/.ssh')
        if ssh.is_symlink():
            raise TransitionError('Каталог ключей администратора требует ручной проверки.')
        ssh.mkdir(mode=0o700, exist_ok=True)
        ssh.chmod(0o700)
        os.chown(ssh, user['uid'], user['gid'])
        path = system.path(user['home']+'/.ssh/authorized_keys')
        if path.is_symlink():
            raise TransitionError('Файл ключей администратора является ссылкой.')
        previous = path.read_text() if path.exists() else ''
        if key.strip() not in previous:
            atomic(path, previous.rstrip()+'\n'+key, 0o600, (user['uid'], user['gid']))
    if secrets.get('admin_password'):
        system.run(['pamtester', 'login', name, 'authenticate', 'acct_mgmt'],
                   input=secrets['admin_password']+'\n')
        # A freshly authenticated sudo check; no cached domain sudo timestamp.
        user_run(system, user, ['sudo', '-S', '-k', '-p', '', 'true'],
                 input=secrets['admin_password']+'\n')
    system.run(['visudo', '-c'])
    system.run(['/usr/sbin/sshd', '-t'])
    job.event('Локальный администратор подготовлен; пароль/PAM и sudo проверены.')
    if key:
        import time
        job.update(current_step='Проверка нового SSH-входа локального администратора')
        job.event('Ожидается подтверждение через новое SSH-подключение локального администратора.')
        for _ in range(240):
            if (job.directory/'ssh-confirmed').is_file():
                job.update(admin_ssh_verified=True)
                break
            time.sleep(1)
        else:
            raise TransitionError('Новый SSH-вход администратора не подтверждён; домен ещё сохранён.')


def offline(job):
    system = job.system
    planned = job.planned()
    sessions = system.sessions()
    if system.vm_processes():
        raise TransitionError('После планирования запущена VM или Waydroid; переход остановлен.')
    if sessions and not planned['options']['close_session']:
        raise TransitionError('Есть рабочий сеанс без подтверждения его завершения.')
    target = planned['inventory']['target']
    other = [s for s in sessions if s.get('Name') != target['name']]
    if other:
        raise TransitionError('Есть графический сеанс другого пользователя; нужна ручная подготовка.')
    # Persist the gate across power loss; a half-transition must not open a session.
    edit(job, GUARD_DROPIN, '[Service]\nExecStartPre=/usr/bin/test ! -e '+LOGIN_GUARD+'\n')
    atomic(system.path(LOGIN_GUARD), job.id+'\n')
    system.run(['systemctl', 'daemon-reload'])
    job.update(display_stopped=True)
    system.run(['systemctl', 'stop', 'lightdm.service'])
    system.run(['loginctl', 'terminate-user', str(target['uid'])], check=False)
    system.run(['systemctl', 'stop', 'user@'+str(target['uid'])+'.service'], check=False)
    for proc in (Path('/proc').iterdir() if system.native else []):
        if not proc.name.isdigit():
            continue
        try:
            if proc.stat().st_uid == target['uid']:
                raise TransitionError('После выхода остались процессы рабочего пользователя; данные не менялись.')
        except FileNotFoundError:
            pass
    # This is the final rollback image, after all desktop writers have stopped.
    source = system.path(target['home']+'/.local/share/keyrings')
    if source.is_dir():
        destination = job.backup/'keyrings-final'
        if not destination.exists():
            shutil.copytree(source, destination, symlinks=True)
            for item in destination.rglob('*'):
                if item.is_file() and not item.is_symlink():
                    fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)


def keyring(job, secrets):
    system = job.system
    target = job.planned()['inventory']['target']
    directory = system.path(target['home']+'/.local/share/keyrings')
    if not directory.exists() or not list(directory.glob('*.keyring')):
        job.event('Существующих парольных связок нет; сброс данных не выполнялся.')
        return
    if [p.name for p in directory.glob('*.keyring') if p.name != 'login.keyring']:
        raise TransitionError('Найдены дополнительные связки ключей; требуется отдельная проверка.')
    old = secrets.get('old_keyring_password') or system.read('/etc/shared-workspace.keyring').strip()
    if not old:
        raise TransitionError('Нет прежнего ключа рабочей связки; нужен его безопасный ввод.')
    payload = json.dumps({'old': old, 'new': secrets['password']})+'\n'
    result = user_run(system, target, ['dbus-run-session', '--', '/usr/bin/python3', ENTRY, 'keyring-helper'],
                      input=payload, check=False)
    try:
        response = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        response = {}
    if result.returncode or not response.get('ok'):
        raise TransitionError('Рабочая связка ключей не прошла проверку; её оригинал сохранён.')
    job.update(keyring_items=response['items'])
    job.event('Пароль рабочей связки изменён, содержимое сохранено и проверено.')


def target_password(job, secrets):
    system = job.system
    planned = job.planned()
    target = planned['inventory']['target']['name']
    if planned['options']['password_mode'] == 'local':
        hashed = system.local_users()[planned['options']['source_user']]['hash']
    else:
        hashed = password_hash(secrets['password'])
    if not matches_password(secrets['password'], hashed):
        raise TransitionError('Пароль не прошёл локальную проверку.')
    system.run(['chpasswd', '--encrypted'], input=target+':'+hashed+'\n')
    system.run(['chage', '-E', '-1', '-M', '-1', '-I', '-1', target])
    system.run(['pamtester', 'login', target, 'authenticate', 'acct_mgmt'], input=secrets['password']+'\n')


def local_login(job):
    system = job.system
    for path in ('/etc/pam.d/lightdm', '/etc/pam.d/cinnamon-screensaver'):
        text = system.read(path)
        if not text or '@include common-auth' not in text:
            raise TransitionError('Неизвестная конфигурация PAM, нужна ручная проверка.')
        kept = [line for line in text.splitlines() if 'pam_shared_workspace.so' not in line]
        edit(job, path, '\n'.join(kept)+'\n')
    for path in ('/etc/lightdm/lightdm.conf.d/90-shared-workspace.conf', '/etc/pam.d/shared-workspace-login'):
        remove(job, path)
    login_screen(job)


def login_screen(job):
    """Narrow, repeatable greeter configuration, also usable after the pilot."""
    system = job.system
    target = job.planned()['inventory']['target']['name']
    edit(job, GREETER_SELECT, '#!/usr/bin/python3 -I\nimport sys\n'
         "sys.path.insert(0, '/usr/local/lib/office-local-transition')\n"
         'from transition.greeter import main\n'+f'main({target!r})\n', 0o755)
    # Capture existing state for pre-unenrollment rollback. The hook itself writes
    # only as lightdm, on every greeter start, including after an admin login.
    greeter = system.local_users().get('lightdm')
    if greeter:
        directory = system.path(greeter['home']+'/.cache/slick-greeter')
        states = {directory/'state'}
        if directory.exists():
            states.update(directory.glob('*-state'))
        for state in states:
            backup_path(job, '/'+str(state.relative_to(system.root)))
    edit(job, '/etc/lightdm/lightdm.conf.d/95-office-local-transition.conf',
         '[Seat:*]\npam-service=lightdm\ngreeter-session=slick-greeter\nuser-session=cinnamon\n'
         'greeter-hide-users=false\ngreeter-show-manual-login=true\n'
         'greeter-setup-script='+GREETER_SELECT+'\n'
         'autologin-user=\n')
    cache = '/var/lib/AccountsService/users/'+target
    previous = system.read(cache)
    import configparser, io
    parsed = configparser.ConfigParser()
    parsed.optionxform = str
    if previous:
        parsed.read_string(previous)
    if not parsed.has_section('User'):
        parsed.add_section('User')
    # Repair only our two keys if an earlier pilot used ConfigParser's lowercasing.
    prior_language = parsed['User'].pop('language', None)
    parsed['User'].pop('systemaccount', None)
    parsed['User']['SystemAccount'] = 'false'
    parsed['User']['Language'] = parsed['User'].get('Language', prior_language or 'ru_RU.UTF-8')
    out = io.StringIO()
    parsed.write(out)
    edit(job, cache, out.getvalue(), 0o600)
    user = system.local_users()[target]
    if user.get('gecos') == 'Shared office workspace':
        snapshot = job.backup/'profile-displayname.json'
        if not snapshot.exists():
            json_write(snapshot, {'name': target, 'gecos': user['gecos']})
        system.run(['usermod', '--comment', 'Рабочее место', target])
    opts = job.planned()['options']
    hidden = {opts['admin_user']}
    if opts['password_mode'] == 'local':
        hidden.add(opts['source_user'])
    hidden.discard(target)
    for name in sorted(hidden):
        source_cache = '/var/lib/AccountsService/users/'+name
        source_settings = configparser.ConfigParser()
        source_settings.optionxform = str
        old = system.read(source_cache)
        if old:
            source_settings.read_string(old)
        if not source_settings.has_section('User'):
            source_settings.add_section('User')
        source_settings['User']['SystemAccount'] = 'true'
        data = io.StringIO()
        source_settings.write(data)
        edit(job, source_cache, data.getvalue(), 0o600)
    system.run(['systemctl', 'restart', 'accounts-daemon.service'])
    result = system.run(['lightdm', '--show-config'])
    effective = result.stdout+'\n'+result.stderr
    if ('pam-service=shared-workspace' in effective or 'greeter-session=shared-workspace' in effective
            or 'shared-workspace-display-setup' in effective):
        raise TransitionError('Другой конфиг перекрывает стандартный экран входа.')


def unenroll(job):
    system = job.system
    system.run(['systemctl', 'disable', '--now', 'office-dns-publish.timer'], check=False)
    system.run(['systemctl', 'stop', 'office-dns-publish.service'], check=False)
    if system.path('/etc/ipa/default.conf').exists():
        # Write the irreversible boundary before invoking the external uninstaller.
        job.update(unenrollment_started=True)
        result = system.run(['ipa-client-install', '--uninstall', '--unattended'], check=False, timeout=240)
        if system.path('/etc/ipa/default.conf').exists():
            raise TransitionError('Штатное удаление IPA-клиента не завершилось. Локальный доступ сохранён.')
        job.update(server_unenrollment='attempted', server_unenrolled=False)
        if result.returncode:
            state = job.state()
            state['warnings'].append('IPA-клиент снят; ответ uninstaller требует серверной проверки.')
            job.save(state)
    system.run(['systemctl', 'disable', '--now', 'sssd.service'], check=False)
    for name in ('nss', 'pam', 'pam-priv', 'ssh', 'sudo', 'pac', 'ifp', 'autofs'):
        system.run(['systemctl', 'disable', '--now', 'sssd-'+name+'.socket'], check=False)
    system.run(['pam-auth-update', '--remove', 'sss', '--package'], env={
        'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'})
    # Restore current transport settings only, not historic pre-enrollment profiles.
    network = job.backup/'files/etc/NetworkManager/system-connections'
    if network.is_dir():
        shutil.copytree(network, system.path('/etc/NetworkManager/system-connections'),
                        dirs_exist_ok=True, symlinks=True)
        system.run(['nmcli', 'connection', 'reload'])
    state = job.state()
    state['warnings'].append('Действующий инфраструктурный DNS сохранён; вывод DNS-сервера — отдельный этап.')
    job.save(state)


def cleanup_user(job, user):
    system = job.system
    for unit in ['office-activity.service', *LEGACY_UNITS]:
        user_run(system, user, ['systemctl', '--user', 'disable', '--now', unit], check=False)
    home = user['home']
    # Only known product files; PulseAudio is deliberately outside this manifest.
    files = ['.config/autostart/office-activity.desktop', '.config/autostart/office-employee-panel.desktop',
             '.config/autostart/shared-workspace-lock-bridge.desktop', '.config/autostart/aw-qt.desktop',
             '.config/autostart/activitywatch.desktop',
             '.config/systemd/user/office-activity.service',
             '.local/share/applications/freeipa-center.desktop']
    for rel in files:
        p = system.path(home+'/'+rel)
        if p.exists() or p.is_symlink():
            remove(job, home+'/'+rel)
    autostart = system.path(home+'/.config/autostart')
    if autostart.is_dir():
        for p in autostart.glob('*.desktop'):
            text = p.read_text(errors='replace') if p.is_file() and not p.is_symlink() else ''
            if any(token in text for token in ('/activitywatch/', '/aw-qt', '/aw-server', 'Exec=aw-qt', 'office-activity',
                                               'aw-watcher', 'aw-client-stack.service')):
                remove(job, '/'+str(p.relative_to(system.root)))
    root = system.path(home+'/.config/systemd/user')
    if root.is_dir():
        for p in root.glob('*.wants/*'):
            if p.name in ['office-activity.service', *LEGACY_UNITS]:
                remove(job, '/'+str(p.relative_to(system.root)))
        for name in LEGACY_UNITS:
            p = root/name
            if p.exists() or p.is_symlink():
                remove(job, '/'+str(p.relative_to(system.root)))
    state_dir = system.path(home+'/.local/state/office-activity')
    if state_dir.exists():
        # Queue archive excludes the live token. Never include it in a public report.
        if job.planned()['options']['queue_policy'] == 'archive':
            dest = job.backup/'pulse-queues'/user['name']
            shutil.copytree(state_dir, dest, symlinks=True, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('device.token'))
        if state_dir.is_symlink():
            state_dir.unlink()
        else:
            shutil.rmtree(state_dir)
    # Remove only our panel entry, preserving other Cinnamon applets.
    if user['name'] == job.planned()['inventory']['target']['name']:
        code = """from gi.repository import Gio
s=Gio.Settings.new('org.cinnamon'); old=s.get_strv('enabled-applets')
new=[v for v in old if 'employee@example.invalid' not in v]
if old!=new:s.set_strv('enabled-applets',new);Gio.Settings.sync()
"""
        user_run(system, user, ['dbus-run-session', '--', 'python3', '-c', code])
    for directory in ('Desktop', 'Рабочий стол', '.local/share/applications'):
        d = system.path(home+'/'+directory)
        if d.is_dir():
            for p in d.glob('*.desktop'):
                text = p.read_text(errors='replace') if not p.is_symlink() else ''
                if 'Exec=/usr/local/bin/freeipa-center' in text or 'office-employee-panel' in text:
                    remove(job, '/'+str(p.relative_to(system.root)))
    for rel in ('.local/opt/activitywatch', 'activitywatch'):
        directory = system.path(home+'/'+rel)
        if directory.is_dir() and any((directory/name).exists() for name in ('aw-qt', 'aw-server', 'aw-watcher-window')):
            remove(job, home+'/'+rel)


def cleanup(job):
    system = job.system
    for user in system.local_users().values():
        if 1000 <= user['uid'] < 60000 and user['home'].startswith('/home/'):
            if system.path(user['home']).is_dir():
                cleanup_user(job, user)
    for path in [*PULSE_FILES, *LOGIN_FILES, *PUBLISHER_FILES]:
        remove(job, path)
    for name in ('aw-qt.desktop', 'activitywatch.desktop'):
        remove(job, '/etc/xdg/autostart/'+name)
    autostart = system.path('/etc/xdg/autostart')
    if autostart.is_dir():
        for p in autostart.glob('*.desktop'):
            text = p.read_text(errors='replace') if p.is_file() and not p.is_symlink() else ''
            if any(token in text for token in ('/activitywatch/', '/aw-qt', '/aw-server', 'Exec=aw-qt', 'office-activity', 'aw-watcher')):
                remove(job, '/'+str(p.relative_to(system.root)))
    # Keep obsolete collectors masked even if a package-owned unit remains installed.
    for unit in LEGACY_UNITS:
        path = '/etc/systemd/user/'+unit
        remove(job, path)
        target = system.path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to('/dev/null')
    legacy = system.path('/opt/activitywatch')
    if legacy.is_dir() and any((legacy/name).exists() for name in ('aw-qt', 'aw-server', 'aw-watcher-window')):
        remove(job, '/opt/activitywatch')
    # The secret is already backed up and the new keyring password was verified.
    remove(job, '/etc/shared-workspace.keyring')
    system.run(['systemctl', 'daemon-reload'])
    system.run(['visudo', '-c'])
    system.run(['/usr/sbin/sshd', '-t'])
    system.run(['systemctl', 'reload', 'ssh.service'])


def verify(job, secrets):
    system = job.system
    planned = job.planned()
    target = planned['inventory']['target']
    current = system.local_users().get(target['name'])
    if not current or any(current[k] != target[k] for k in ('uid', 'gid', 'home', 'shell')):
        raise TransitionError('Изменилась идентичность рабочего профиля.')
    home = system.path(target['home']).stat()
    expected = planned['inventory']['home_identity']
    attributes = {'uid': 'st_uid', 'gid': 'st_gid', 'inode': 'st_ino', 'device': 'st_dev'}
    if any(getattr(home, attr) != expected[k] for k, attr in attributes.items()):
        raise TransitionError('Изменились владельцы или каталог рабочего профиля.')
    for service in ('login', 'lightdm', 'cinnamon-screensaver', 'sudo'):
        system.run(['pamtester', service, target['name'], 'authenticate', 'acct_mgmt'],
                   input=secrets['password']+'\n')
    if system.path('/etc/ipa/default.conf').exists():
        raise TransitionError('Осталось членство IPA.')
    for path in ('/etc/pam.d/common-auth', '/etc/pam.d/common-account', '/etc/pam.d/lightdm',
                 '/etc/pam.d/cinnamon-screensaver'):
        text = system.read(path)
        if 'pam_shared_workspace.so' in text or 'pam_sss.so' in text:
            raise TransitionError('Осталась зависимость входа от PAM домена.')
    for p in PULSE_FILES:
        if system.path(p).exists():
            raise TransitionError('Остался компонент Пульса.')
    if collector_processes(system):
        raise TransitionError('Остался работающий коллектор Пульса.')
    job.update(verified={'local_auth': True, 'profile_identity': True, 'pulse_removed': True,
                         'display_manager': False, 'graphical_login': False, 'reboot': False,
                         'server_cleanup': False})


def start_display(job):
    import time
    system = job.system
    system.path(LOGIN_GUARD).unlink(missing_ok=True)
    system.run(['systemctl', 'reset-failed', 'lightdm.service'], check=False)
    system.run(['systemctl', 'start', 'lightdm.service'])
    time.sleep(3)
    if system.run(['systemctl', 'is-active', 'lightdm.service'], check=False).stdout.strip() != 'active':
        raise TransitionError('Экран входа не запустился; локальный SSH-доступ сохраняется.')
    state = job.state()
    state.setdefault('verified', {})['display_manager'] = True
    state['display_stopped'] = False
    job.save(state)


def execute(job, secrets):
    system = job.system
    fd = job.lock()
    try:
        planned = job.planned()
        if system.read('/etc/machine-id').strip() != planned['inventory']['machine_id']:
            raise TransitionError('План относится к другому компьютеру.')
        expected_user = planned['inventory']['target']
        actual_user = system.local_users().get(expected_user['name'])
        if not actual_user or any(actual_user[k] != expected_user[k] for k in ('uid', 'gid', 'home', 'shell')):
            raise TransitionError('После планирования изменилась идентичность рабочей учётки.')
        st = system.path(actual_user['home']).stat()
        expected_home = planned['inventory']['home_identity']
        if any(getattr(st, attr) != expected_home[key] for key, attr in
               {'uid': 'st_uid', 'gid': 'st_gid', 'device': 'st_dev', 'inode': 'st_ino'}.items()):
            raise TransitionError('После планирования изменилась рабочая папка.')
        validate_secrets(system, planned, secrets)
        job.update(error='')
        for name, fn in [('Резерв', lambda: prepare(job)),
                         ('Локальный администратор', lambda: administrator(job, secrets)),
                         ('Остановка сбора Пульса', lambda: stop_collectors(job)),
                         ('Завершение рабочего сеанса', lambda: offline(job)),
                         ('Связка ключей', lambda: keyring(job, secrets)),
                         ('Локальный пароль', lambda: target_password(job, secrets)),
                         ('Стандартный экран входа', lambda: local_login(job)),
                         ('Снятие IPA-клиента', lambda: unenroll(job)),
                         ('Удаление Пульса и доменной панели', lambda: cleanup(job)),
                         ('Проверка локального входа', lambda: verify(job, secrets)),
                         ('Запуск стандартного экрана входа', lambda: start_display(job))]:
            job.step(name, fn)
        job.update(status='awaiting_user_check', current_step='Готово к проверке рабочего стола',
                   backup=str(job.backup))
    except Exception as error:
        message = str(error) if isinstance(error, TransitionError) else 'Ошибка системного этапа: '+type(error).__name__
        job.update(status='blocked', error=message)
        job.event(message)
    finally:
        if job.state().get('display_stopped'):
            state = job.state()
            if 'Стандартный экран входа' in state['steps'] and 'Локальный пароль' in state['steps']:
                check = system.run(['pamtester', 'lightdm', job.planned()['inventory']['target']['name'],
                                    'authenticate', 'acct_mgmt'], input=secrets['password']+'\n', check=False)
                if not check.returncode:
                    system.path(LOGIN_GUARD).unlink(missing_ok=True)
            system.run(['systemctl', 'start', 'lightdm.service'], check=False)
        os.close(fd)
    return job.state()


def rollback(job):
    """Local recovery only before the server-side unenrollment boundary."""
    system = job.system
    fd = job.lock()
    completed = False
    try:
        if job.state().get('unenrollment_started'):
            raise TransitionError('Снятие IPA уже началось. Для возврата в домен нужен отдельный план присоединения.')
        if system.sessions() or system.vm_processes():
            raise TransitionError('Перед откатом нужно штатно завершить рабочие сеансы и VM.')
        system.run(['systemctl', 'stop', 'lightdm.service'])
        target = job.planned()['inventory']['target']
        manifest = json.loads((job.directory/'backup-manifest.json').read_text())
        # No restoration of the user's full home or of whole system trees.
        restore = ['/etc/pam.d/lightdm', '/etc/pam.d/cinnamon-screensaver',
                   '/etc/pam.d/shared-workspace-login',
                   '/etc/lightdm/lightdm.conf.d/90-shared-workspace.conf',
                   '/etc/lightdm/lightdm.conf.d/95-office-local-transition.conf',
                   '/var/lib/AccountsService/users/'+target['name'],
                   '/var/lib/AccountsService/users/'+job.planned()['options']['admin_user'],
                   GREETER_SELECT,
                   GUARD_DROPIN,
                   target['home']+'/.local/share/keyrings']
        opts = job.planned()['options']
        if opts['password_mode'] == 'local' and opts['source_user'] not in (target['name'], opts['admin_user']):
            restore.append('/var/lib/AccountsService/users/'+opts['source_user'])
        greeter = system.local_users().get('lightdm')
        if greeter:
            prefix = greeter['home']+'/.cache/slick-greeter/'
            restore.extend(p for p in manifest if p.startswith(prefix)
                           and (p[len(prefix):] == 'state' or
                                ('/' not in p[len(prefix):] and p.endswith('-state'))))
        for name in restore:
            info = manifest.get(name)
            if info is None:
                # A child may have been included in the initial directory snapshot.
                src = job.backup/'files'/name.lstrip('/')
                if not src.exists():
                    continue
                info = {'present': True, 'uid': 0, 'gid': 0}
            dst = system.path(name)
            src = job.backup/'files'/name.lstrip('/')
            if name == target['home']+'/.local/share/keyrings' and (job.backup/'keyrings-final').is_dir():
                src = job.backup/'keyrings-final'
            if dst.is_dir() and not dst.is_symlink():
                shutil.rmtree(dst)
            else:
                dst.unlink(missing_ok=True)
            if not info['present']:
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            if 'link' in info:
                dst.symlink_to(info['link'])
            elif src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
                # Only the saved keyring directory; all original entries have this owner.
                for p in [dst, *dst.rglob('*')]:
                    os.chown(p, target['uid'], target['gid'], follow_symlinks=False)
            else:
                shutil.copy2(src, dst)
                os.chown(dst, info.get('uid', 0), info.get('gid', 0))
        saved = json.loads((job.backup/'target-password.json').read_text())['row']
        system.run(['chpasswd', '--encrypted'], input=saved[0]+':'+saved[1]+'\n')
        system.run(['chage', '-d', saved[2] or '-1', '-m', saved[3] or '0',
                    '-M', saved[4] or '-1', '-W', saved[5] or '7',
                    '-I', saved[6] or '-1', '-E', saved[7] or '-1', saved[0]])
        displayname = job.backup/'profile-displayname.json'
        if displayname.is_file():
            original = json.loads(displayname.read_text())
            system.run(['usermod', '--comment', original['gecos'], original['name']])
        system.run(['systemctl', 'restart', 'accounts-daemon.service'])
        job.update(status='rolled_back', current_step='Локальные настройки восстановлены')
        job.event('Вход и связка восстановлены. Локальный администратор оставлен для восстановления доступа.')
        completed = True
    finally:
        if completed:
            system.path(LOGIN_GUARD).unlink(missing_ok=True)
            system.run(['systemctl', 'daemon-reload'], check=False)
            system.run(['systemctl', 'start', 'lightdm.service'], check=False)
        os.close(fd)
    return job.state()


def accept(job, applications=False, reboot=False):
    if type(applications) is not bool or type(reboot) is not bool:
        raise TransitionError('Некорректные отметки проверки.')
    target = job.planned()['inventory']['target']['name']
    if not any(s.get('Name') == target and s.get('State') == 'active' for s in job.system.sessions()):
        raise TransitionError('Сначала войди на рабочий стол нынешней локальной учётки.')
    state = job.state()
    if not state.get('verified', {}).get('local_auth') or not state['verified'].get('display_manager'):
        raise TransitionError('Технические проверки перехода ещё не завершены.')
    state['verified']['graphical_login'] = True
    state['verified']['applications'] = applications
    if reboot:
        before = job.planned()['inventory'].get('boot_id')
        current = job.system.read('/proc/sys/kernel/random/boot_id').strip()
        if not before or current == before:
            raise TransitionError('Загрузка после перехода ещё не подтверждена сменой boot ID.')
        state['verified']['reboot'] = True
    if not applications:
        state['status'] = 'awaiting_user_check'
    elif not state['verified'].get('reboot'):
        state['status'] = 'awaiting_reboot'
    elif not state['verified'].get('server_cleanup'):
        state['status'] = 'server_cleanup_pending'
    else:
        state['status'] = 'complete'
    state['current_step'] = 'Рабочий вход проверен; оставшиеся проверки указаны в отчёте'
    job.save(state)
    return state
