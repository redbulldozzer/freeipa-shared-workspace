#!/usr/bin/env python3
"""Interactive entry point. The original rollout project is never imported."""
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
INSTALLED = Path('/usr/local/share/freeipa-menu')
STATE = Path('/var/lib/freeipa-menu')
SETTINGS = STATE / 'settings.json'
JOURNAL = STATE / 'migration.json'
RUNTIME = INSTALLED / 'internal/runtime'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_module('workspace_platform', ROOT / 'internal/platform.py')
transfer = load_module('workspace_transfer', ROOT / 'internal/transfer.py')
control = load_module('workspace_control', ROOT / 'internal/control.py')
activity = load_module('workspace_activity', ROOT / 'internal/activity.py')
remote = load_module('workspace_remote', ROOT / 'internal/remote.py')
background = load_module('workspace_background', ROOT / 'internal/background.py')
autokey_compat = load_module('workspace_autokey_compat', ROOT / 'internal/autokey_compat.py')


def ask(label, default='', validate=None):
    while True:
        value = input(f'{label}' + (f' [{default}]' if default else '') + ': ').strip() or str(default)
        try:
            if validate:
                validate(value)
            return value
        except (ValueError, RuntimeError) as error:
            print(error)


def yes(label, default=False):
    return ask(label + ' (д/н)', 'д' if default else 'н',
               lambda x: None if x.lower() in ('д', 'н', 'y', 'n', 'да', 'нет') else
               (_ for _ in ()).throw(ValueError('Введи д или н.'))).lower() in ('д', 'y', 'да')


def name(value):
    if not re.fullmatch(r'[a-z][a-z0-9_.-]{0,63}', value):
        raise ValueError('Используй маленькие латинские буквы, цифры, точку, дефис, подчёркивание.')


def fqdn(value):
    if not base.FQDN.fullmatch(value) or len(value) > 253:
        raise ValueError('Нужно полное DNS-имя, например example.invalid.')


def run(command, **kwargs):
    return subprocess.run([str(x) for x in command], check=True, **kwargs)


def current_config():
    path = Path('/etc/shared-workspace.conf')
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line and not line.startswith('#') and '=' in line) if path.exists() else {}


def defaults():
    host = socket.gethostname().split('.')[0]
    result = dict(domain='example.invalid', realm='example.invalid', ipa_server='example.invalid',
                  ipa_address='192.0.2.1', fqdn=f'{host}.example.invalid', source_user='example-user',
                  workspace_user='office-workspace', access_group='shared', domain_admin='admin',
                  enrollment_principal='admin', enable_dns_updates=False, managed_access=True, force_join=False)
    if SETTINGS.exists():
        result.update(json.loads(SETTINGS.read_text()))
    else:
        installed = current_config()
        result['workspace_user'] = installed.get('target', result['workspace_user'])
        result['access_group'] = installed.get('group', result['access_group'])
        if not base.local_account('example-user'):
            sudo_user = os.environ.get('SUDO_USER', '')
            if sudo_user and sudo_user != 'root':
                result['source_user'] = sudo_user
    return result


def show(s):
    print('\nТекущие параметры:')
    for label, key in [('Компьютер', 'fqdn'), ('Сервер IPA', 'ipa_server'), ('IP IPA', 'ipa_address'),
                       ('Домен', 'domain'), ('Realm', 'realm'), ('Локальный пользователь', 'source_user'),
                       ('Общий пользователь', 'workspace_user'), ('Группа доступа', 'access_group'),
                       ('Администратор IPA для подключения', 'enrollment_principal'),
                       ('Доменный администратор с sudo на этом ПК', 'domain_admin')]:
        print(f'  {label}: {s[key]}')
    print('  DHCP, доменный DNS и SSH-ключи FreeIPA:', 'автоматически' if s.get('managed_access', True) else 'вручную')
    print('  Повторная регистрация имени в IPA:', 'да' if s.get('force_join') else 'нет')


def configure(s):
    print('\nEnter оставляет значение в скобках. Пароли здесь не сохраняются.')
    s['fqdn'] = ask('Уникальное имя этого ПК', s['fqdn'], fqdn)
    s['source_user'] = ask('Из какой локальной учётки переносить данные', s['source_user'], name)
    s['access_group'] = ask('Группа FreeIPA: общая или группа отдела', s['access_group'], name)
    if yes('Изменить сервер, домен или другие дополнительные параметры'):
        s['ipa_server'] = ask('Сервер FreeIPA', s['ipa_server'], fqdn)
        s['ipa_address'] = ask('IP сервера FreeIPA', s['ipa_address'], ipaddress.ip_address)
        s['domain'] = ask('Домен', s['domain'], fqdn)
        s['realm'] = ask('Kerberos realm', s['realm'])
        s['workspace_user'] = ask('Общая локальная учётка', s['workspace_user'], name)
        s['enrollment_principal'] = ask('Администратор FreeIPA', s['enrollment_principal'], name)
        s['domain_admin'] = ask('Доменный администратор с полными правами sudo на этом ПК', s['domain_admin'], name)
        s['managed_access'] = yes('Автоматически настроить DHCP/DNS и SSH-ключи FreeIPA', s.get('managed_access', True))
        s['enable_dns_updates'] = False
        s['force_join'] = yes('Повторно зарегистрировать ранее удалённый/переустановленный ПК с тем же именем в IPA', s.get('force_join', False))
    validate(s)
    transfer.write_json(SETTINGS, s)
    return s


def validate(s):
    for key in ('source_user', 'workspace_user', 'access_group', 'enrollment_principal', 'domain_admin'):
        name(s[key])
    for key in ('fqdn', 'domain', 'ipa_server'):
        fqdn(s[key])
    ipaddress.ip_address(s['ipa_address'])
    if not re.fullmatch(r'[A-Z0-9.-]+', s['realm']):
        raise RuntimeError('Realm должен состоять из заглавных латинских букв, цифр, точек и дефисов.')
    if not s['fqdn'].endswith('.' + s['domain']):
        raise RuntimeError('Имя ПК должно заканчиваться выбранным доменом.')
    if s['source_user'] == s['workspace_user']:
        raise RuntimeError('Исходная и общая учётки должны различаться.')
    configured = current_config()
    if configured and configured.get('target') != s['workspace_user']:
        raise RuntimeError('На этом ПК уже настроена другая общая учётка. Её смена не является обычной установкой.')
    enrolled = Path('/etc/ipa/default.conf')
    if enrolled.exists():
        values = dict((a.strip(), b.strip()) for a, b in
                      (line.split('=', 1) for line in enrolled.read_text().splitlines() if '=' in line))
        if values.get('host') and values['host'] != s['fqdn']:
            raise RuntimeError(f"ПК уже введён в домен как {values['host']}. Оставь это имя.")
        base.enrollment_matches(s['domain'], s['realm'], s['ipa_server'])


def check_graphical_sessions(targets):
    result = run(['loginctl', 'list-sessions', '--no-legend', '--no-pager'], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        session = line.split()[0]
        detail = subprocess.run(['loginctl', 'show-session', session,
                                 '-p', 'User', '-p', 'Name', '-p', 'Type', '-p', 'State',
                                 '-p', 'Class', '-p', 'TTY', '-p', 'Display'],
                                capture_output=True, text=True)
        if detail.returncode:
            # A session may disappear between enumeration and inspection.
            remaining = run(['loginctl', 'list-sessions', '--no-legend', '--no-pager'],
                            capture_output=True, text=True).stdout
            if session not in {row.split()[0] for row in remaining.splitlines() if row.strip()}:
                continue
            raise RuntimeError(f'Не удалось проверить сеанс {session}: {detail.stderr.strip()}')
        attrs = dict(x.split('=', 1) for x in detail.stdout.splitlines() if '=' in x)
        if int(attrs.get('User', '-1')) not in targets or attrs.get('Type') not in ('x11', 'wayland'):
            continue
        if attrs.get('Class') == 'greeter':
            continue
        who = attrs.get('Name') or attrs['User']
        if attrs.get('State') == 'closing':
            print(f'Сеанс {session} ({who}) уже завершается после выхода. Проверяю оставшиеся процессы.')
            continue
        raise RuntimeError(
            f"Ещё открыт графический сеанс {session}: пользователь {who}, "
            f"тип {attrs['Type']}, состояние {attrs.get('State', '?')}, "
            f"экран {attrs.get('Display') or attrs.get('TTY') or '?'}. "
            'Переключение на Ctrl+Alt+F3 или блокировка не завершают рабочий стол. '
            'Выйди из указанного сеанса через меню Cinnamon, затем запусти скрипт в текстовой консоли. '
            'Если сеанс сразу появляется снова, проверь автоматический вход.')


def session_helper(proc, uid):
    """Recognize desktop helpers that stopping this user's manager will terminate."""
    names = {
        'xdg-desktop-portal', 'xdg-desktop-portal-gtk', 'xdg-desktop-portal-xapp',
        'xdg-permission-store', 'gvfsd', 'gvfsd-fuse', 'gvfsd-metadata',
        'gvfsd-trash', 'gvfsd-recent', 'gvfsd-network',
        'gvfs-udisks2-volume-monitor', 'gvfs-afc-volume-monitor',
        'gvfs-goa-volume-monitor', 'gvfs-gphoto2-volume-monitor', 'gvfs-mtp-volume-monitor',
        'evolution-source-registry', 'evolution-calendar-factory',
        'evolution-addressbook-factory', 'goa-daemon', 'goa-identity-service',
        'obexd', 'at-spi-bus-launcher', 'at-spi2-registryd',
    }
    try:
        executable = (proc / 'exe').resolve(strict=True)
        managed = any(f'user@{uid}.service' in line.split('/')
                      for line in (proc / 'cgroup').read_text().splitlines())
        return (managed and executable.name in names and
                any(executable.is_relative_to(root) for root in ('/usr/lib', '/usr/libexec')))
    except (OSError, RuntimeError):
        return False


def accounts_idle(s, allow_session_services=True):
    """Allow this maintenance terminal; reject graphical sessions and user applications."""
    ancestors = set()
    pid = os.getpid()
    while pid > 1 and pid not in ancestors:
        ancestors.add(pid)
        try:
            text = Path(f'/proc/{pid}/stat').read_text()
            pid = int(text[text.rfind(')') + 2:].split()[1])
        except (OSError, ValueError):
            break
    targets = {a.pw_uid for user in (s['source_user'], s['workspace_user'])
               if (a := base.local_account(user))}
    check_graphical_sessions(targets)
    busy = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) in ancestors:
            continue
        try:
            if proc.stat().st_uid not in targets:
                continue
            comm = (proc / 'comm').read_text().strip()
            # Idle session infrastructure is okay; no applications or user services are stopped here.
            if comm in ('systemd', '(sd-pam)', 'dbus-daemon', 'dbus-broker', 'dbus-broker-lau', 'sshd', 'gpg-agent', 'gnome-keyring-d', 'dconf-service', 'pipewire', 'pipewire-pulse', 'wireplumber'):
                continue
            if allow_session_services and session_helper(proc, proc.stat().st_uid):
                continue
            busy.append(f'{proc.name}: {comm}')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    if busy:
        raise RuntimeError('Ещё работают процессы пользователей: ' + ', '.join(busy[:15]) +
                           '. Закрой их штатно перед переносом; меню не завершает приложения само.')


def quiesce_users(s):
    accounts_idle(s)
    # A plain TTY/SSH session lives in session-N.scope, outside employee@example.invalid.
    # A terminal inside a graphical/user-service session would die with its manager.
    cgroup = Path('/proc/self/cgroup').read_text()
    targets = {a.pw_uid for user in (s['source_user'], s['workspace_user'])
               if (a := base.local_account(user))}
    if any(f'user@{uid}.service' in cgroup for uid in targets):
        raise RuntimeError('Запусти меню в обычной текстовой консоли Ctrl+Alt+F3 или по SSH, без tmux/user-service.')
    print('Останавливаю оставшиеся фоновые службы завершённых пользователей перед переносом.')
    # accounts_idle already refused every application, including ActivityWatch.
    # Closing dconf/pipewire here prevents a late write into a moved settings file.
    for uid in targets:
        run(['systemctl', 'stop', f'user@{uid}.service'])
    accounts_idle(s, allow_session_services=False)


def recovery(s):
    source = base.check_recovery_account(s['source_user'])
    if source.pw_uid < 1000:
        raise RuntimeError('Нельзя переносить системного пользователя.')
    home = Path(source.pw_dir)
    if not home.is_dir() or home.is_symlink():
        raise RuntimeError('Не найден обычный локальный home исходного пользователя.')
    fs = run(['findmnt', '-n', '-o', 'FSTYPE', '-T', home], capture_output=True, text=True).stdout.strip()
    if fs in ('ecryptfs', 'ecrypt') or (home / '.Private').is_symlink():
        raise RuntimeError('Эта версия рассчитана на обычные home поверх LUKS; здесь обнаружен eCryptfs.')
    return source


def extra_excludes(source):
    result = ['freeipa-menu', 'shared-workspace-pilot', 'shared-workspace-rollout']
    try:
        rel = ROOT.resolve().relative_to(Path(source.pw_dir).resolve())
        if rel == Path('.'):
            raise RuntimeError('Распакуй комплект в отдельную папку, а не непосредственно в home.')
        result.append(str(rel))
    except ValueError:
        pass
    return result


def install_self():
    for root in (ROOT, INSTALLED):
        if root.is_symlink() or (root.exists() and any(p.is_symlink() for p in root.rglob('*'))):
            raise RuntimeError('Симлинки в каталоге программы запрещены.')
    if ROOT != INSTALLED:
        shutil.copytree(ROOT, INSTALLED, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'build', 'dist', 'tests-menu'))
    for path in [INSTALLED, *INSTALLED.rglob('*')]:
        if path.is_symlink():
            raise RuntimeError('В установочном комплекте не должно быть симлинков.')
        os.chown(path, 0, 0)
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    (INSTALLED / 'internal/ipa_api.py').unlink(missing_ok=True)
    os.chmod(INSTALLED / 'internal/admin-entry', 0o755)
    os.chmod(INSTALLED / 'start.sh', 0o755)


def member_names():
    value = ask('Логины сотрудников через пробел (до 8); пустой список — только «Другой пользователь»')
    names = list(dict.fromkeys(value.split()))
    for user in names:
        name(user)
        if base.local_account(user):
            raise RuntimeError(f'Логин {user} совпадает с локальной учёткой этого ПК.')
    return names


def selected_users(s):
    if control.SELECTED.exists():
        print('Сохранённый ручной список кнопок (не состав группы):')
        users = control.SELECTED.read_text().split()
    else:
        print('Автоматический список: текущий сотрудник и последние входы.')
        recent = Path('/var/lib/shared-workspace/recent-users')
        users = ([control.current_employee()] if control.current_employee() else [])
        users += recent.read_text().split() if recent.exists() else []
        users = list(dict.fromkeys(users))[:8]
    for index, login in enumerate(users, 1):
        try:
            label = pwd.getpwnam(login).pw_gecos.split(',')[0] or login
        except KeyError:
            label = '(учётка сейчас не найдена)'
        print(f'  {index}. {label} — логин: {login}')
    print('  + Другой пользователь')
    print('Изменения видны на новой версии экрана в течение нескольких секунд.')
    print('1 — Задать список\n2 — Вернуть автоматический список\n0 — Назад')
    choice = ask('Пункт', '0')
    if choice == '1':
        users = member_names()
        print('Новый список:', ', '.join(users) or 'только «Другой пользователь»')
        if yes('Сохранить список для этого ПК'):
            control.save_selected(users, s['access_group'])
    elif choice == '2':
        control.SELECTED.unlink(missing_ok=True)
    print('Список появится при следующем открытии экрана входа; право входа определяется группой.')


def current_user():
    login = control.current_employee()
    if not login:
        print('Активного общего сеанса нет. Старая запись о сотруднике не считается текущей.')
        return
    try:
        label = pwd.getpwnam(login).pw_gecos.split(',')[0] or login
    except KeyError:
        label = login
    print(f'Сейчас работает: {label} — доменный логин {login}')
    print('Это сотрудник последней успешной авторизации в общем сеансе.')


def install_employee_panel():
    # Uses the protected copy installed by install_self; never opens a session.
    if not current_config():
        print('Надпись сотрудника: сначала требуется настроить общий вход.')
        return
    installer = INSTALLED / 'employee-panel/install.py'
    if not installer.is_file():
        raise RuntimeError('В комплекте отсутствует установщик надписи сотрудника. Используй полный новый архив.')
    run(['/usr/bin/python3', installer, 'install'])
    print('Надпись сотрудника установлена. Появится при следующем входе в общий рабочий стол.')


def management_install(s, update_runtime=False, shortcuts=True):
    validate(s)
    control.administrator(s['domain_admin'])
    if update_runtime and not current_config():
        raise RuntimeError('Сначала установи общий вход через пункт 1.')
    base.wait_for_group(s['access_group'])
    print('Резервная копия настроек:', base.backup_files(SimpleNamespace(**s)))
    install_self()
    control.enable_ssh()
    control.install_admin(s['domain_admin'])
    autokey_compat.install()
    if s.get('managed_access', True):
        remote.setup(s)
    if update_runtime:
        base.atomic_write(Path('/etc/shared-workspace.conf'),
                          f"target={s['workspace_user']}\ngroup={s['access_group']}\n")
        run(['bash', RUNTIME / 'scripts/install-prototype.sh'])
    install_employee_panel()
    if shortcuts:
        control.install_shortcuts([s['source_user'], s['workspace_user']])
    transfer.write_json(SETTINGS, s)
    print('Центр установлен в /usr/local/share/freeipa-menu, SSH включён.')
    if not shortcuts:
        print('Ярлыки будут созданы после завершения переноса.')
    print(f"Полные права sudo с запросом доменного пароля: {s['domain_admin']}.")


def choose_mode():
    print('\nЧто сделать с пользовательскими данными?')
    print('  1 — Копировать: исходные данные сохранятся, требуется место для второй копии.')
    print('  2 — Вырезать: переместить без второй копии; исходный профиль потеряет перенесённые файлы.')
    return {'1': 'copy', '2': 'move'}[ask('Режим', '1', lambda x: None if x in ('1', '2') else
                                        (_ for _ in ()).throw(ValueError('Выбери 1 или 2.')))]


def check_space(s, mode, source, live=False):
    dest = Path('/home') / s['workspace_user']
    account = base.local_account(s['workspace_user'])
    if account:
        dest = Path(account.pw_dir)
    parent = dest if dest.exists() else dest.parent
    if live:
        # A live profile contains sockets/lock files. The authoritative scan is offline.
        report = subprocess.run(['du', '-sx', '--block-size=1', source.pw_dir], capture_output=True, text=True)
        if not report.stdout.strip():
            raise RuntimeError('Не удалось оценить размер home: ' + report.stderr.strip())
        size = int(report.stdout.split()[0])
        if report.returncode:
            print('Часть файлов менялась во время оценки. Точный размер проверим после выхода.')
        entries = []
        print('Предварительная оценка всего home; точная проверка выполняется после выхода.')
    else:
        entries = transfer.scan(Path(source.pw_dir), extra_excludes(source))
        size = sum(item['blocks'] for item in entries if item['kind'] == 'file')
    free = shutil.disk_usage(parent).free
    print(f'Данные для переноса: около {size / 2**30:.2f} ГБ. Свободно: {free / 2**30:.2f} ГБ.')
    if mode == 'move' and Path(source.pw_dir).stat().st_dev != parent.stat().st_dev:
        raise RuntimeError('Исходный и общий home на разных файловых системах; выбери копирование.')
    if mode == 'copy' and free < size + max(32 * 1024**2, len(entries) * 2048) and not live:
        raise RuntimeError('Для копирования места мало. Выбери установку снова и режим «вырезать».')
    if live and mode == 'copy' and free < size:
        print('Для полного home места мало. После выхода проверим объём с учётом исключений; '
              'если места не хватит, перенос остановится до изменения данных.')
    return dest


def existing_target(s):
    account = base.local_account(s['workspace_user'])
    if account:
        if not (STATE / 'target-created.json').exists():
            raise RuntimeError('Общая учётка уже существует и создана не этим меню. '
                               'Для неё доступны диагностика/смена группы, но автоматический перенос не выполняется.')
        created = json.loads((STATE / 'target-created.json').read_text())
        if created['user'] != account.pw_name or created['uid'] != account.pw_uid:
            raise RuntimeError('Общая учётка отличается от созданной меню.')
    elif pwd_lookup(s['workspace_user']):
        raise RuntimeError('Имя общей учётки уже занято в домене.')
    return account


def pwd_lookup(user):
    try:
        return pwd.getpwnam(user)
    except KeyError:
        return None


def create_target(s):
    account = existing_target(s)
    if account:
        return account
    # Empty skel: migration must never overwrite an unrelated existing profile.
    if Path('/home', s['workspace_user']).exists():
        raise RuntimeError('Каталог будущего общего home уже существует. Автоматическая перезапись запрещена.')
    with tempfile.TemporaryDirectory(prefix='workspace-skel-', dir='/run') as empty:
        run(['useradd', '-m', '-k', empty, '-s', '/bin/bash', '-c', 'Shared office workspace', s['workspace_user']])
    account = base.local_account(s['workspace_user'])
    os.chmod(account.pw_dir, 0o700)
    transfer.write_json(STATE / 'target-created.json', {'user': account.pw_name, 'uid': account.pw_uid})
    return account


def active_shared_session():
    try:
        with open('/run/shared-workspace/session.lock', 'rb') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                fcntl.flock(lock, fcntl.LOCK_UN)
                return False
            except BlockingIOError:
                return True
    except FileNotFoundError:
        return False


def pam_check(s):
    user = ask('Доменный логин для проверки входа', validate=name)
    if base.local_account(user):
        raise RuntimeError('Для этой проверки нужен доменный сотрудник, а не локальная учётка.')
    # Standalone PAM probe also updates recent users, just like the greeter.
    if active_shared_session():
        raise RuntimeError('Сейчас открыта общая смена. Проверяй вход через экран блокировки либо заверши её.')
    run(['/usr/local/sbin/shared-workspace-pam-probe', 'shared-workspace-check', user, 'session'])


def configure_login(mode):
    # Restore the exact files if an activation check fails mid-flight.
    paths = [Path('/etc/pam.d/lightdm'), Path('/etc/pam.d/cinnamon-screensaver'),
             Path('/etc/pam.d/shared-workspace-login'),
             Path('/etc/lightdm/lightdm.conf.d/90-shared-workspace.conf'),
             Path('/etc/xdg/autostart/shared-workspace-lock-bridge.desktop')]
    snapshot = {p: (p.read_bytes(), p.stat().st_mode & 0o777) if p.exists() else None for p in paths}
    try:
        run(['python3', RUNTIME / 'scripts/configure-login.py', mode])
    except BaseException:
        for path, saved in snapshot.items():
            if saved is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(saved[0])
                os.chmod(path, saved[1])
        raise


def install(s):
    if background.GATE.exists():
        print('Уже подготовлено фоновое задание. Его состояние видно на Ctrl+Alt+F8.')
        print('При ошибке устрани причину и нажми R на экране переноса. Параметры задания сохранены.')
        return
    show(s)
    if yes('Изменить параметры перед установкой'):
        configure(s)
    validate(s)
    source = recovery(s)
    if JOURNAL.exists() and json.loads(JOURNAL.read_text())['phase'] == 'complete':
        saved = json.loads(JOURNAL.read_text())
        target_account = base.local_account(s['workspace_user'])
        if not target_account or saved['source'] != str(Path(source.pw_dir).resolve()) or saved['dest'] != str(Path(target_account.pw_dir).resolve()):
            raise RuntimeError('Параметры отличаются от завершённого переноса.')
        configure_login('enable')
        management_install(s, update_runtime=True)
        print('Перенос уже завершён; данные повторно не менялись. Общий вход включён.')
        offer_activity(s)
        return
    print('\nКак выполнить перенос?')
    print('1 — С рабочего стола: подготовка, подтверждение выхода, отдельный экран прогресса')
    print('2 — В этой текстовой консоли / SSH, после ручного выхода из рабочего стола')
    workflow = ask('Режим запуска', '1', lambda x: None if x in ('1', '2') else
                   (_ for _ in ()).throw(ValueError('Выбери 1 или 2.')))
    automatic = workflow == '1'
    if automatic and active_shared_session():
        raise RuntimeError('Общая смена уже открыта. Для обновления существующего ПК используй пункт 9.')
    if not automatic:
        accounts_idle(s)
    account = existing_target(s)
    if account and not JOURNAL.exists() and any(Path(account.pw_dir).iterdir()):
        raise RuntimeError('Общий home уже содержит данные, а журнала этого переноса нет. Перезапись запрещена.')
    manager = Path('/etc/X11/default-display-manager')
    if not manager.exists() or not manager.read_text().strip().endswith('/lightdm'):
        raise RuntimeError('Нужен Linux Mint Cinnamon с LightDM.')
    if not Path('/usr/share/xsessions/cinnamon.desktop').exists():
        raise RuntimeError('Не найден сеанс Cinnamon.')
    if JOURNAL.exists():
        saved = json.loads(JOURNAL.read_text())
        mode = saved['mode']
        saved_target = base.local_account(s['workspace_user'])
        if not saved_target or saved['dest'] != str(Path(saved_target.pw_dir).resolve()):
            raise RuntimeError('Сохранён перенос в другую общую учётку. Верни прежние параметры.')
        if saved['source'] != str(Path(source.pw_dir).resolve()):
            raise RuntimeError('Сохранён перенос другого исходного пользователя. Верни прежние параметры.')
        print('Продолжаем сохранённый перенос:', 'вырезать' if mode == 'move' else 'копировать', saved['phase'])
    else:
        mode = choose_mode()
        check_space(s, mode, source, live=automatic)
    for port in (443, 389, 88):
        try:
            with socket.create_connection((s['ipa_address'], port), timeout=3):
                pass
        except OSError as error:
            raise RuntimeError(f"Нет связи с IPA {s['ipa_address']}:{port}. Проверь сеть и доступ к локальной сети в Mullvad.") from error
    show(s)
    print('Данные:', 'ВЫРЕЗАТЬ — перенесённые файлы исчезнут из исходного home.' if mode == 'move' else 'КОПИРОВАТЬ')
    print('Исходная локальная учётка останется. Не перенесутся личные ключи, ActivityWatch, кэши и старый Keyring.')
    if not yes('Начать установку с этими параметрами'):
        return
    transfer.write_json(SETTINGS, s)
    install_self()
    args = SimpleNamespace(**s)
    backup = base.backup_files(args)
    print('Резервная копия настроек:', backup)
    if not (STATE / 'packages-ready').exists():
        base.install_packages(False)
        (STATE / 'packages-ready').touch()
    if s.get('managed_access', True):
        remote.prepare_dns(s)
        args.enable_dns_updates = False
    if not Path('/etc/ipa/default.conf').exists():
        base.update_hosts(s['fqdn'], s['ipa_server'], s['ipa_address'])
        run(['hostnamectl', 'set-hostname', s['fqdn']])
        print('Сейчас FreeIPA запросит пароль администратора и подтверждение подключения.')
        base.enroll(args)
    else:
        base.enrollment_matches(s['domain'], s['realm'], s['ipa_server'])
    print('\nПроверяем существующую группу FreeIPA. Создание групп и сотрудников выполняется на сервере.')
    base.wait_for_group(s['access_group'])
    target = create_target(s)
    base.atomic_write(Path('/etc/shared-workspace.conf'),
                      f"target={s['workspace_user']}\ngroup={s['access_group']}\n")
    run(['bash', RUNTIME / 'scripts/install-prototype.sh'])
    base.add_device_groups(s['source_user'], s['workspace_user'], [])
    print('\nПеред переносом проверим доменный пароль. При ошибке данные останутся на месте.')
    pam_check(s)
    if automatic:
        # Complete every potentially interactive/network-dependent step before logout.
        if not (background.FONTS / 'Uni2-Terminus16.psf.gz').is_file():
            run(['apt-get', 'install', '-y', 'kbd', 'console-setup-linux'])
        management_install(s, shortcuts=False)
        print('\nПОДГОТОВКА ЗАВЕРШЕНА. Теперь сохрани документы и закрой приложения.')
        print('Штатно выключи виртуальные машины. После подтверждения будут завершены графические сеансы.')
        print('Также завершатся фоновые программы, TTY и SSH-сеансы исходной и общей локальных учёток.')
        print('Появится отдельный экран прогресса; в конце нажмёшь Enter для входа.')
        print('Фоновая служба продолжит работу после закрытия этого терминала. Пароли ей не передаются.')
        if yes('Всё сохранено, приложения и VM закрыты — завершить сеансы этих учёток и начать перенос'):
            background.schedule(sys.modules[__name__], s, mode, extra_excludes(source))
            return 'background'
        print('Подготовка сохранена. Данные ещё не переносились. Повтори пункт 1, когда будешь готов.')
        return
    quiesce_users(s)
    data = transfer.prepare(source.pw_dir, target.pw_dir, mode, JOURNAL, extra_excludes(source))
    print('Перенос начат. Для больших профилей копирование и проверка могут занять время.')
    transfer.execute(data, JOURNAL, target.pw_uid, target.pw_gid,
                     after_item=lambda n: print(f'  Обработано: {n}', flush=True) if n % 1000 == 0 else None)
    configure_login('enable')
    management_install(s)
    print('\nГОТОВО. Данные перенесены, новый вход включён. Графические сеансы не запускались.')
    print('Перезагрузи ПК через меню, войди сотрудником, затем проверь блокировку и вход второго сотрудника.')
    offer_activity(s)


def offer_activity(s):
    if yes('Настроить Пульс — учёт активности сотрудника на этом ПК', True):
        activity.setup(s, ask, yes)


def access(s):
    print('\n1 — Сотрудники на экране входа и блокировки\n4 — Выбрать существующую группу доступа для этого ПК\n0 — Назад')
    action = ask('Пункт', '0')
    if action == '1':
        selected_users(s)
    elif action == '4':
        chosen = ask('Общая группа или группа отдела', s['access_group'], name)
        if Path('/etc/shared-workspace.conf').exists():
            base.wait_for_group(chosen)
            old = current_config()
            base.atomic_write(Path('/etc/shared-workspace.conf'), f"target={old['target']}\ngroup={chosen}\n")
        s['access_group'] = chosen
        transfer.write_json(SETTINGS, s)
        print('Группа для этого ПК:', chosen)


def status(s):
    show(s)
    current_user()
    print('SSH:', subprocess.run(['systemctl', 'is-active', 'ssh.service'], capture_output=True, text=True).stdout.strip())
    if JOURNAL.exists():
        data = json.loads(JOURNAL.read_text())
        print('Перенос:', data['mode'], data['phase'], data['source'], '→', data['dest'])
        for warning in data.get('profile_path_repairs', {}).get('warnings', []):
            print('Проверить настройки приложений:', warning)
    if Path('/usr/local/sbin/shared-workspacectl').exists():
        subprocess.run(['/usr/local/sbin/shared-workspacectl', 'status'], check=False)
    else:
        print('Компоненты общего входа ещё не установлены.')


def main():
    if os.geteuid() != 0:
        print('Запусти: sudo bash start.sh')
        return 1
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    with (STATE / 'menu.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('На этом ПК уже запущено другое меню.'); return 1
        s = defaults()
        while True:
            print('\n=== Центр управления рабочим местом — FreeIPA ===')
            print('1 — Установить на этот ПК / продолжить перенос')
            print('2 — Посмотреть или изменить параметры')
            print('3 — Сотрудники и группа доступа')
            print('4 — Проверить состояние')
            print('5 — Проверить доменный пароль')
            print('6 — Отключить / включить общий вход')
            print('7 — Перезагрузить компьютер')
            print('8 — Кто сейчас работает (доменный сотрудник)')
            print('9 — Установить / обновить центр, ярлыки, sudo администратора и SSH')
            print('10 — Пульс: установка, обновление и диагностика клиента')
            print('11 — Доступ по имени и SSH: настройка и проверка')
            print('0 — Выход')
            try:
                choice = ask('Выбери пункт', '0')
                if choice == '0':
                    return 0
                if choice == '1':
                    if install(s) == 'background':
                        return 0
                elif choice == '2':
                    show(s)
                    if yes('Изменить'):
                        configure(s)
                elif choice == '3':
                    access(s)
                elif choice == '4':
                    status(s)
                elif choice == '5':
                    pam_check(s)
                elif choice == '6':
                    if not RUNTIME.exists():
                        install_self()
                    enable = yes('Включить общий вход? «Нет» — отключить')
                    if enable and JOURNAL.exists() and json.loads(JOURNAL.read_text())['phase'] != 'complete':
                        raise RuntimeError('Сначала заверши перенос через пункт 1.')
                    if yes('Применить? Данные остаются на месте; изменения входа действуют после перезагрузки'):
                        if enable:
                            pam_check(s)
                        configure_login('enable' if enable else 'disable')
                        print('Готово. Отключение входа не возвращает вырезанные данные обратно.')
                elif choice == '7':
                    if yes('Сохранены документы и можно перезагрузить компьютер'):
                        run(['systemctl', 'reboot'])
                        return 0
                elif choice == '8':
                    current_user()
                elif choice == '9':
                    show(s)
                    if yes('Применить настройки центра и обновить компоненты общего входа без переноса данных'):
                        management_install(s, update_runtime=True)
                elif choice == '10':
                    activity.menu(s, ask, yes)
                elif choice == '11':
                    validate(s)
                    remote.menu(s, ask, yes, install_self, control.enable_ssh, control.install_admin)
                else:
                    print('Нет такого пункта.')
            except (KeyboardInterrupt, EOFError):
                print('\nОстановлено. Если перенос начат, продолжи пунктом 1.'); return 0
            except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError, SystemExit) as error:
                print('\nНе завершено:', error)
                print('Исправь причину и повтори нужный пункт. Успешные предыдущие этапы сохраняются.')
            try:
                input('\nГотово. Нажми Enter, чтобы вернуться в меню… ')
            except (KeyboardInterrupt, EOFError):
                print(); return 0


if __name__ == '__main__':
    sys.exit(main())
