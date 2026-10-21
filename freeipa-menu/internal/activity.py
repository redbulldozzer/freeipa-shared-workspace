"""Office Activity installation and HTTPS enrollment. No directory or VPN changes."""
import getpass
import hashlib
import http.cookiejar
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import ssl
import subprocess
import time
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
CONFIG = Path('/etc/office-activity/config.json')
IDENTITY = Path('/var/lib/office-activity/device-id')
TOKEN = Path('/var/lib/office-activity/enrollment.token')
CA = Path('/etc/office-activity/ca.crt')
SERVER = 'https://example.invalid'
ADDRESS = '192.0.2.1'

def installer():
    spec=importlib.util.spec_from_file_location('activity_installer',ROOT/'activity-client/install.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def validate_url(value):
    u=urllib.parse.urlsplit(value)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/'):
        raise ValueError('Нужен адрес вида https://example.invalid без пути и паролей.')
    if not all(c.isalnum() or c in '.-' for c in u.hostname):
        raise ValueError('Некорректное имя сервера.')
    u.port  # validate the port
    return value.rstrip('/')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise RuntimeError('Сервер перенаправляет запрос. Проверь его адрес.')

def api_client(server, ca):
    validate_url(server)
    context=ssl.create_default_context(cafile=str(ca))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
        urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def request(api,server,path,body=None,csrf=''):
    headers={'Origin':server}
    if body is not None:headers['Content-Type']='application/json'
    if csrf:headers['X-CSRF-Token']=csrf
    req=urllib.request.Request(server+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
    try:
        with api.open(req,timeout=15) as response:
            raw=response.read(1024*1024+1)
            if len(raw)>1024*1024:raise RuntimeError('Слишком большой ответ сервера.')
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        messages={401:'Неверный логин/пароль или вход истёк.',403:'Нужны права администратора Пульса.',
                  409:'ПК уже зарегистрирован с другим токеном либо отключён. Проверь его на сервере.',
                  404:'Сервер нужно обновить для регистрации из меню.',429:'Слишком много попыток входа. Попробуй позже.',
                  503:'Справочник LDAP временно недоступен.'}
        raise RuntimeError(messages.get(e.code,f'Сервер вернул HTTP {e.code}.')) from None

def enroll(api,server,device_id,token,label,login,password):
    csrf=''
    request(api,server,'/api/v1/auth/login',{'login':login,'password':password})
    try:
        user=request(api,server,'/api/v1/auth/me');csrf=user['csrf_token']
        return request(api,server,'/api/v1/admin/devices/enroll',
            {'device_id':device_id,'label':label,'token':token},csrf)
    finally:
        if csrf:
            request(api,server,'/api/v1/auth/logout',{},csrf)

def host_entry(host,address,write):
    ipaddress.ip_address(address)
    p=Path('/etc/hosts'); original=p.read_text()
    entries=[line.split('#')[0].split() for line in original.splitlines()]
    found=[parts[0] for parts in entries if len(parts)>1 and host in parts[1:]]
    if found:
        if any(ipaddress.ip_address(x)!=ipaddress.ip_address(address) for x in found):
            raise RuntimeError('Для сервера уже указан другой IP в /etc/hosts. Исправь конфликт вручную.')
        return
    backup=Path('/var/backups/office-activity')/('hosts-'+str(time.time_ns()))
    backup.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,backup)
    write(p,original.rstrip()+'\n'+address+' '+host+' # Office Activity\n')

def account_list(value):
    users=list(dict.fromkeys(value.split()))
    if not users:raise ValueError('Укажи хотя бы одну локальную учётку рабочего стола.')
    local={line.split(':')[0] for line in Path('/etc/passwd').read_text().splitlines()}
    for name in users:
        if name not in local or pwd.getpwnam(name).pw_uid<1000:
            raise ValueError('Нужна существующая обычная локальная учётка: '+name)
    return users

def read_user_token(inst,user):
    script="from pathlib import Path; p=Path.home()/'.local/state/office-activity/device.token'; print(p.read_text().strip() if p.is_file() else '')"
    return inst.user_command(user,['/usr/bin/python3','-c',script],check=True).stdout.strip()

def choose_token(inst,users):
    tokens={read_user_token(inst,u) for u in users}-{''}
    if TOKEN.exists():tokens.add(TOKEN.read_text().strip())
    if len(tokens)>1:raise RuntimeError('У выбранных учёток разные токены. Автоматическая замена запрещена.')
    token=next(iter(tokens),None)
    if token is None:token=secrets.token_urlsafe(48)
    if len(token)<48 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-' for c in token):
        raise RuntimeError('Некорректный сохранённый токен. Проверь регистрацию ПК.')
    return token

def save_user_token(inst,user,token):
    # File operations in home run as its owner, never as root through user links.
    script='''import os,sys,tempfile
from pathlib import Path
p=Path.home()/'.local/state/office-activity';p.mkdir(parents=True,exist_ok=True,mode=0o700)
os.chmod(p,0o700)
fd,name=tempfile.mkstemp(dir=p)
try:
 with os.fdopen(fd,'w') as f:f.write(sys.stdin.read().strip()+'\\n');f.flush();os.fsync(f.fileno())
 os.replace(name,p/'device.token')
finally:
 Path(name).unlink(missing_ok=True)
'''
    # Never pass credentials in argv or environment.
    inst.user_command(user,['/usr/bin/python3','-c',script],check=True, input=token)

def status(users):
    if not CONFIG.exists():print('Пульс ещё не установлен.');return
    config=json.loads(CONFIG.read_text())
    print('ПК:',config.get('device_id'),'\nСервер:',config.get('endpoint') or 'не подключён')
    inst=installer()
    for user in users:
        print('\nУчётка рабочего стола:',user)
        state=inst.user_command(user,['systemctl','--user','is-active','office-activity.service']).stdout.strip()
        print('Служба:',state or 'нет активного сеанса')
        result=inst.user_command(user,['/usr/local/bin/office-activity','status'])
        if result.returncode==0:print(result.stdout)
        else:print('Статус ещё не доступен; войди в графический сеанс после установки.')
    print('Смотри last_seen и pending: старый статус сам по себе не означает, что клиент сейчас работает.')

def setup(settings,ask,yes):
    inst=installer()
    default=settings['workspace_user'] if any(x.split(':')[0]==settings['workspace_user'] for x in Path('/etc/passwd').read_text().splitlines()) else settings['source_user']
    users=account_list(ask('Локальные учётки для сбора (через пробел)',default,account_list))
    current=json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    existing=current.get('endpoint','')
    default_server=existing.removesuffix('/api/v1/events') if existing else SERVER
    server=validate_url(ask('Сервер Пульса',default_server,validate_url))
    if existing and server!=default_server:raise RuntimeError('Смена рабочего сервера требует отдельного переноса. Обновление сохраняет текущий сервер.')
    ca=Path(current.get('ca_file') or (ROOT/'activity-ca.crt'))
    if not ca.is_file():raise RuntimeError('Не найден доверенный сертификат центра FreeIPA: '+str(ca))
    print('Пульс считает нажатия клавиш, активность, AFK и блокировку. Текст и клики мышью не сохраняются.')
    print('Локальная личная учётка на ПК вне домена связывается с LDAP-сотрудником в настройках дашборда.')
    print('CA SHA-256:',hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).hexdigest())
    if not yes('Установить / обновить клиент и заменить автозапуск старого ActivityWatch',True):return
    host=urllib.parse.urlsplit(server).hostname
    if server==SERVER:host_entry(host,ADDRESS,inst.write)
    api=api_client(server,ca)
    request(api,server,'/healthz')
    device=str(uuid.UUID(current['device_id'] if current else IDENTITY.read_text().strip() if IDENTITY.exists() else str(uuid.uuid4())))
    inst.write(IDENTITY,device+'\n')
    token=choose_token(inst,users)
    # Persist before sending: a lost response can safely retry the same registration.
    had_token=any(read_user_token(inst,u) for u in users)
    inst.write(TOKEN,token+'\n',0o600)
    if not existing or not had_token:
        login=ask('Администратор LDAP для регистрации ПК',settings.get('enrollment_principal','admin'))
        password=getpass.getpass('Пароль LDAP (не сохраняется): ')
        try:enroll(api,server,device,token,socket.gethostname(),login,password)
        finally:password=None
    subprocess.run(['apt-get','install','--no-upgrade','-y','python3-gi','python3-xlib','libxss1'],check=True)
    inst.write(CA,ca.read_text())
    config={**current,'device_id':device,'endpoint':server+'/api/v1/events','ca_file':str(CA)}
    config.setdefault('afk_seconds',180);config.setdefault('flush_seconds',15);config.setdefault('max_queue_mb',512)
    inst.write(CONFIG,json.dumps(config,indent=2)+'\n')
    os.chmod(CONFIG.parent,0o755)
    for user in users:save_user_token(inst,user,token)
    try:inst.install(SimpleNamespace(user=users,replace_legacy=True,check=False))
    except Exception:
        if inst.ACTIVE_BACKUP is not None:inst.rollback(inst.ACTIVE_BACKUP)
        raise
    print('Пульс установлен. Идентификатор ПК и очередь сохранены. Адрес:',server)
    status(users)

def menu(settings,ask,yes):
    print('\nПульс — Office Activity\n1 — Установить / обновить и подключить\n2 — Диагностика\n0 — Назад')
    action=ask('Пункт','0')
    if action=='1':setup(settings,ask,yes)
    elif action=='2':
        users=account_list(ask('Локальные учётки рабочего стола',settings['workspace_user'],account_list))
        status(users)
