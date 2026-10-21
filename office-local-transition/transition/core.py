"""Read-only inventory, validated options, and durable private job state."""
import configparser
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

STATE = '/var/lib/office-local-transition'
BACKUP = '/var/backups/office-local-transition'
ENTRY = '/usr/local/lib/office-local-transition/entry.py'
APPLET = 'employee@example.invalid'
PASSWORD_KEYS = {'password', 'admin_password', 'old_keyring_password'}


class TransitionError(RuntimeError):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def login_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9_.-]{0,31}', value):
        raise TransitionError('Некорректное имя локальной учётки.')
    return value


def atomic(path, data, mode=0o600, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise TransitionError('Символическая ссылка вместо изменяемого файла.')
    fd, name = tempfile.mkstemp(prefix='.transition-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data.encode() if isinstance(data, str) else data)
            os.fchmod(out.fileno(), mode)
            if owner is not None:
                os.fchown(out.fileno(), *owner)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def json_write(path, value, mode=0o600):
    atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n', mode)


def password_hash(value):
    """libcrypt through a private in-memory call, never a command argument."""
    validate_password(value)
    lib = ctypes.CDLL('libcrypt.so.1')
    lib.crypt_gensalt.argtypes = [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int]
    lib.crypt_gensalt.restype = ctypes.c_char_p
    lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.crypt.restype = ctypes.c_char_p
    random = os.urandom(32)
    salt = lib.crypt_gensalt(b'$6$', 100000, random, len(random))
    result = lib.crypt(value.encode(), salt) if salt else None
    if not result or result.startswith(b'*'):
        raise TransitionError('Не удалось подготовить локальный пароль.')
    return result.decode()


def matches_password(value, hashed):
    if not usable_hash(hashed):
        return False
    lib = ctypes.CDLL('libcrypt.so.1')
    lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.crypt.restype = ctypes.c_char_p
    result = lib.crypt(value.encode(), hashed.encode())
    import hmac
    return bool(result and hmac.compare_digest(result.decode(), hashed))


def usable_hash(value):
    return bool(isinstance(value, str) and re.fullmatch(r'\$(?:6|5|y|2[aby])\$[^:\s]+', value))


def validate_password(value):
    if not isinstance(value, str) or len(value) < 8 or len(value.encode()) > 512 or any(c in value for c in '\n\r\0'):
        raise TransitionError('Пароль должен содержать не менее 8 символов без перевода строки.')


def public_key(value):
    if not value:
        return ''
    if not isinstance(value, str) or len(value) > 16000 or '\n' in value.strip():
        raise TransitionError('Нужен один публичный SSH-ключ.')
    fields = value.strip().split()
    if len(fields) < 2 or fields[0] not in ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256'):
        raise TransitionError('Неподдерживаемый публичный SSH-ключ.')
    import base64
    try:
        blob = base64.b64decode(fields[1], validate=True)
        n = int.from_bytes(blob[:4], 'big')
        if blob[4:4+n].decode() != fields[0]:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise TransitionError('Некорректный публичный SSH-ключ.') from None
    return ' '.join(fields[:2]) + '\n'


class System:
    def __init__(self, root='/'):
        self.root = Path(root).resolve()
        self.native = self.root == Path('/')

    def path(self, value):
        if not value.startswith('/') or '..' in Path(value).parts:
            raise TransitionError('Некорректный путь.')
        p = self.root / value.lstrip('/')
        for parent in p.parents:
            if parent == self.root:
                break
            if parent.is_symlink():
                raise TransitionError('Ссылка в родительском каталоге; нужна ручная проверка.')
        return p

    def read(self, value, default=''):
        p = self.path(value)
        if p.is_symlink():
            raise TransitionError('Конфигурация является символической ссылкой.')
        return p.read_text() if p.is_file() else default

    def run(self, args, check=True, input=None, timeout=40, env=None):
        if not self.native:
            raise TransitionError('Системные команды запрещены для тестового корня.')
        p = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout,
                           env=env or {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
        if check and p.returncode:
            # Do not echo argv, stdin, or command output: those may contain credentials.
            raise TransitionError(f'Не выполнена команда {Path(args[0]).name}, код {p.returncode}.')
        return p

    def local_users(self):
        users = {}
        shadows = {}
        for line in self.read('/etc/shadow').splitlines():
            fields = line.split(':')
            if len(fields) >= 2:
                shadows[fields[0]] = fields[1]
        for line in self.read('/etc/passwd').splitlines():
            f = line.split(':')
            if len(f) != 7:
                continue
            users[f[0]] = dict(name=f[0], uid=int(f[2]), gid=int(f[3]), gecos=f[4], home=f[5], shell=f[6],
                               hash=shadows.get(f[0], ''))
        return users

    def sessions(self):
        if not self.native:
            return []
        found = []
        out = self.run(['loginctl', 'list-sessions', '--no-legend'], check=False).stdout
        for line in out.splitlines():
            fields = line.split()
            if not fields:
                continue
            details = self.run(['loginctl', 'show-session', fields[0], '-p', 'Name', '-p', 'Type',
                                '-p', 'Class', '-p', 'State'], check=False).stdout
            values = dict(x.split('=', 1) for x in details.splitlines() if '=' in x)
            if values.get('Class') == 'user' and values.get('Type') in ('x11', 'wayland'):
                found.append({'id': fields[0], **values})
        return found

    def vm_processes(self):
        if not self.native:
            return []
        found = []
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                name = (proc/'comm').read_text().strip()
                if name in ('VirtualBoxVM', 'VBoxHeadless', 'qemu-system-x86', 'waydroid'):
                    found.append({'pid': int(proc.name), 'uid': proc.stat().st_uid, 'name': name})
            except OSError:
                pass
        return found

    def inspect(self):
        users = self.local_users()
        conf = dict(line.split('=', 1) for line in self.read('/etc/shared-workspace.conf').splitlines()
                    if '=' in line and not line.startswith('#'))
        target = conf.get('target', 'office-workspace')
        user = users.get(target)
        issues = []
        if not user or user['uid'] < 1000:
            issues.append('Не найдена нынешняя локальная рабочая учётка.')
        home_info = None
        if user:
            home = self.path(user['home'])
            if not user['home'].startswith('/home/') or home.is_symlink() or not home.is_dir():
                issues.append('Рабочая папка требует ручной проверки.')
            else:
                st = home.stat()
                home_info = {'device': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid, 'gid': st.st_gid}
                if st.st_uid != user['uid']:
                    issues.append('Владелец рабочей папки не совпадает с локальной учёткой.')
                contents = [p.name for p in home.iterdir() if p.name not in ('.cache', '.config')]
                if not contents:
                    issues.append('Рабочий профиль пуст; автоматический переход остановлен.')
        migration = self.path('/var/lib/freeipa-menu/migration.json')
        if migration.is_file() and json.loads(migration.read_text()).get('phase') != 'complete':
            issues.append('Найден незавершённый перенос установщика.')
        if self.path('/var/lib/freeipa-menu/migration-block').exists():
            issues.append('Найден блокирующий маркер переноса.')
        sssd = self.read('/etc/sssd/sssd.conf')
        snippets = self.path('/etc/sssd/conf.d')
        if snippets.is_dir():
            for fragment in snippets.glob('*.conf'):
                sssd += '\n'+self.read('/'+str(fragment.relative_to(self.root)))
        sections = re.findall(r'^\s*\[domain/([^]]+)\]', sssd, re.M)
        if len(set(sections)) > 1:
            issues.append('В SSSD несколько доменов; требуется отдельный план.')
        if re.search(r'^\s*id_provider\s*=\s*(?!ipa\b)\S+', sssd, re.M | re.I):
            issues.append('В SSSD есть другой провайдер учёток; автоматическое удаление остановлено.')
        sources = []
        for u in users.values():
            if 1000 <= u['uid'] < 60000 and u['name'] != target:
                sources.append({'name': u['name'], 'available': usable_hash(u['hash']),
                                'reason': '' if usable_hash(u['hash']) else 'Пароль заблокирован или запись непригодна'})
            if 1000 <= u['uid'] < 60000 and u['home'].startswith('/home/'):
                for relative in ('.config/autostart', '.config/systemd/user', '.local/state/office-activity'):
                    try:
                        candidate = self.path(u['home']+'/'+relative)
                        if candidate.is_symlink():
                            issues.append('Автозапуск или состояние клиента находится по ссылке: '+u['name'])
                    except TransitionError:
                        issues.append('Родительский каталог автозапуска находится по ссылке: '+u['name'])
        keyrings = []
        if user and home_info:
            directory = self.path(user['home']+'/.local/share/keyrings')
            if directory.is_symlink():
                issues.append('Связка ключей находится по символической ссылке.')
            elif directory.is_dir():
                keyrings = [p.name for p in directory.glob('*.keyring')]
        machine = self.read('/etc/machine-id').strip()
        hostname = self.run(['hostname', '-f'], check=False).stdout.strip() if self.native else self.read('/etc/hostname').strip()
        safe_user = {k: v for k, v in user.items() if k != 'hash'} if user else None
        return dict(version='0.1.0', hostname=hostname, machine_id=machine, target=safe_user,
                    boot_id=self.read('/proc/sys/kernel/random/boot_id').strip(),
                    home_identity=home_info, password_sources=sources, keyrings=keyrings,
                    ipa_enrolled=self.path('/etc/ipa/default.conf').exists(),
                    already_local=self.path('/etc/lightdm/lightdm.conf.d/95-office-local-transition.conf').exists()
                                  and not self.path('/etc/ipa/default.conf').exists(),
                    sessions=self.sessions(), vm_processes=self.vm_processes(), blockers=issues,
                    admins=[u['name'] for u in users.values() if 1000 <= u['uid'] < 60000 and u['name'] != target],
                    free_bytes=shutil.disk_usage(self.root).free)


def options_from(request):
    allowed = {'password_mode', 'source_user', 'admin_user', 'admin_public_key', 'close_session', 'queue_policy'}
    if set(request) - allowed:
        raise TransitionError('Неизвестные параметры перехода.')
    opts = {'password_mode': request.get('password_mode', 'new'),
            'source_user': request.get('source_user', ''),
            'admin_user': login_name(request.get('admin_user', 'office-admin')),
            'admin_public_key': public_key(request.get('admin_public_key', '')),
            'close_session': request.get('close_session', False),
            'queue_policy': request.get('queue_policy', 'archive')}
    if opts['password_mode'] not in ('new', 'local') or opts['queue_policy'] not in ('archive', 'delete'):
        raise TransitionError('Неизвестный вариант пароля или очереди.')
    if type(opts['close_session']) is not bool:
        raise TransitionError('Некорректное подтверждение завершения сеанса.')
    if opts['password_mode'] == 'local':
        login_name(opts['source_user'])
    return opts


def plan(system, options):
    options = options_from(options)
    inventory = system.inspect()
    if inventory['blockers']:
        raise TransitionError('; '.join(inventory['blockers']))
    if inventory.get('already_local'):
        raise TransitionError('Компьютер уже переведён. Открой отчёт существующего задания.')
    if inventory['vm_processes']:
        raise TransitionError('Работает виртуальная машина или Waydroid. Заверши её штатно.')
    if options['admin_user'] == inventory['target']['name']:
        raise TransitionError('Администратор должен быть отдельной учёткой.')
    existing_admin = system.local_users().get(options['admin_user'])
    if existing_admin and existing_admin['uid'] < 1000:
        raise TransitionError('Системную служебную учётку нельзя использовать как рабочего администратора.')
    if inventory['sessions'] and not options['close_session']:
        raise TransitionError('Нужно сохранить работу и подтвердить завершение сеанса.')
    if options['password_mode'] == 'local':
        sources = {u['name']: u for u in inventory['password_sources']}
        if not sources.get(options['source_user'], {}).get('available'):
            raise TransitionError('Выбранная локальная учётка не имеет пригодного пароля.')
    return {'schema': 1, 'created_at': now(), 'options': options, 'inventory': inventory,
            'actions': ['Резерв настроек и связки ключей', 'Локальный администратор',
                        'Пароль нынешней рабочей учётки', 'Обычный экран входа Mint',
                        *(['Прежняя учётка — источник пароля — скрыта в списке входа']
                          if options['password_mode'] == 'local' and options['source_user'] != options['admin_user'] else []),
                        'Выход из FreeIPA', 'Удаление Пульса и панели', 'Проверка локальной работы'],
            'data_policy': 'UID/GID, home, владельцы и рабочие файлы сохраняются; перенос отсутствует',
            'network_policy': 'Действующий DNS и сеть сохраняются до отдельного вывода инфраструктуры'}


class Job:
    def __init__(self, system, job_id):
        if not re.fullmatch(r'[0-9a-f]{32}', job_id):
            raise TransitionError('Некорректный идентификатор задания.')
        self.system = system
        self.id = job_id
        self.directory = system.path(STATE+'/jobs/'+job_id)
        self.backup = system.path(BACKUP+'/'+job_id)
        self.public = system.path(STATE+'/public/'+job_id+'.json')

    @classmethod
    def create(cls, system, planned):
        job = cls(system, uuid.uuid4().hex)
        for path in (system.path(STATE+'/jobs'), system.path(BACKUP), job.directory, job.backup):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)
        system.path(STATE).chmod(0o755)
        system.path(STATE+'/public').mkdir(mode=0o755, exist_ok=True)
        system.path(STATE+'/public').chmod(0o755)
        json_write(job.directory/'plan.json', planned)
        job.save({'id': job.id, 'hostname': planned['inventory']['hostname'], 'status': 'prepared',
                  'steps': [], 'events': [], 'warnings': [], 'created_at': now(), 'server_unenrolled': False})
        return job

    def planned(self):
        return json.loads((self.directory/'plan.json').read_text())

    def state(self):
        return json.loads((self.directory/'state.json').read_text())

    def save(self, value):
        value['updated_at'] = now()
        json_write(self.directory/'state.json', value)
        json_write(self.public, value, 0o644)

    def update(self, **values):
        state = self.state()
        state.update(values)
        self.save(state)

    def event(self, message):
        state = self.state()
        state['events'].append({'time': now(), 'message': message})
        self.save(state)

    def step(self, name, fn):
        state = self.state()
        if name in state['steps']:
            return
        self.update(status='running', current_step=name)
        self.event(name)
        fn()
        state = self.state()
        state['steps'].append(name)
        self.save(state)

    def lock(self):
        path = self.system.path(STATE+'/transition.lock')
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise TransitionError('Уже выполняется другое задание перехода.') from None
        return fd
