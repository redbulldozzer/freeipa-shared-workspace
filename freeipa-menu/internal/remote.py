#!/usr/bin/env python3
"""DHCP DNS and directory-managed SSH access for Mint workstations."""
import configparser
from datetime import datetime, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SSSD = Path('/etc/sssd/sssd.conf')
SSH = Path('/etc/ssh/sshd_config.d/04-freeipa-menu-keys.conf')
SSH_MAIN = Path('/etc/ssh/sshd_config')
KEY_COMMAND = '/usr/bin/sss_ssh_authorizedkeys'
spec = importlib.util.spec_from_file_location('office_dns_publisher', ROOT / 'dynamic_dns/publish.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, text=True, **kwargs)


def output(args):
    return run(args, capture_output=True, timeout=30).stdout.strip()


def network_settings(s):
    routes = json.loads(output(['ip', '-j', '-4', 'route', 'get', s['ipa_address']]))
    if len(routes) != 1 or not re.fullmatch(r'[a-zA-Z0-9_.:-]+', routes[0].get('dev', '')):
        raise RuntimeError('Не удалось однозначно определить сетевой интерфейс до FreeIPA.')
    route = routes[0]
    interface = route['dev']
    source = route.get('prefsrc', route.get('src'))
    addresses = json.loads(output(['ip', '-j', '-4', 'address', 'show', 'dev', interface]))
    matches = [a for device in addresses for a in device.get('addr_info', []) if a.get('local') == source]
    if len(matches) != 1:
        raise RuntimeError('Не найден адрес выбранного интерфейса.')
    network = str(ipaddress.IPv4Network(f"{source}/{matches[0]['prefixlen']}", strict=False))
    settings = publisher.validate(dict(server=s['ipa_address'], server_name=s['ipa_server'],
                                       domain=s['domain'], realm=s['realm'], network=network))
    publisher.office_address(routes, settings)
    kind = output(['nmcli', '-g', 'GENERAL.TYPE', 'device', 'show', interface])
    if kind not in ('ethernet', 'wifi'):
        raise RuntimeError('Нужен обычный Ethernet или Wi-Fi, обнаружен: ' + kind)
    connection = output(['nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', interface])
    if not re.fullmatch(r'[a-fA-F0-9-]{36}', connection):
        raise RuntimeError('Подключение должно управляться NetworkManager.')
    if output(['nmcli', '-g', 'ipv4.method', 'connection', 'show', connection]) != 'auto':
        raise RuntimeError('На этом подключении не DHCP. IP не менялся; сначала проверь настройки сети.')
    return settings, interface, connection


def prepare_dns(s, publish=False):
    settings, interface, connection = network_settings(s)
    missing = [package for command, package in (('nft', 'nftables'), ('dig', 'dnsutils')) if not shutil.which(command)]
    if missing:
        run(['apt-get', 'install', '--no-upgrade', '-y', *missing])
    args = [sys.executable, ROOT / 'dynamic_dns/configure.py', '--interface', interface,
            '--connection', connection]
    for key, value in settings.items():
        args += ['--' + key.replace('_', '-'), value]
    if publish:
        args.append('--publish')
    print(f'Настраиваем доменный DNS: {interface}, DHCP, {settings["domain"]}. VPN остаётся включён.', flush=True)
    run(args)


def backup(paths):
    directory = Path('/var/backups/freeipa-menu/remote') / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    directory.mkdir(parents=True, mode=0o700)
    os.chmod(directory.parent, 0o700)
    for path in paths:
        if path.exists():
            target = directory / str(path).lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    print('Резервная копия SSH:', directory)
    return directory


def atomic_write(path, value, mode):
    temp = path.with_name(path.name + '.freeipa-menu-new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def ssh_values(login):
    text = output(['/usr/sbin/sshd', '-T', '-C', f'user={login},host=localhost,addr=127.0.0.1'])
    return dict(line.split(' ', 1) for line in text.splitlines() if ' ' in line)


def configure_ssh(login):
    if not re.fullmatch(r'[a-z][a-z0-9_.-]{0,63}', login):
        raise ValueError('Invalid administrator login')
    if not Path(KEY_COMMAND).exists():
        raise RuntimeError('Не установлен sss_ssh_authorizedkeys из пакета sssd-common.')
    # Do not silently replace another organization's key provider.
    previous = ssh_values(login)
    if previous.get('authorizedkeyscommand') not in ('none', KEY_COMMAND, KEY_COMMAND + ' %u'):
        raise RuntimeError('SSH уже использует другой источник ключей; требуется разбор его конфигурации.')
    text = SSSD.read_text()
    parsed = configparser.RawConfigParser()
    parsed.read_string(text)
    services = parsed.get('sssd', 'services', fallback='').replace(' ', '').split(',')
    paths = [SSH, SSSD]
    saved = backup(paths)
    old_ssh = SSH.read_bytes() if SSH.exists() else None
    if 'ssh' not in services:
        # Supported Mint packages use socket activation. Do not enable both mechanisms.
        if not output(['systemctl', 'show', 'sssd-ssh.socket', '-p', 'LoadState', '--value']) == 'loaded':
            raise RuntimeError('Нет sssd-ssh.socket. Эта версия меню рассчитана на Mint с SSSD socket activation.')
        run(['systemctl', 'enable', '--now', 'sssd-ssh.socket'])
    # Invalidate this user only; never remove caches or offline credentials.
    run(['sss_cache', '-u', login])
    keys = output(['runuser', '-u', 'nobody', '--', KEY_COMMAND, login])
    if not keys.strip():
        raise RuntimeError(f'У {login} не найден SSH-ключ в FreeIPA. Добавь открытый ключ в его профиль и повтори пункт 11.')
    if not any(line.startswith(('ssh-', 'ecdsa-')) for line in keys.splitlines()):
        raise RuntimeError('FreeIPA не вернула подходящий открытый ключ.')
    fingerprints = run(['ssh-keygen', '-lf', '-'], input=keys, capture_output=True).stdout.strip()
    # Use the standard FreeIPA key provider; PAM/HBAC still checks account access.
    # Global directives avoid changing the parsing scope of the main sshd_config.
    content = '# Managed by FreeIPA Menu. Public keys come from FreeIPA via SSSD.\nPubkeyAuthentication yes\nAuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys\nAuthorizedKeysCommandUser nobody\n'
    SSH.parent.mkdir(exist_ok=True)
    try:
        atomic_write(SSH, content, 0o644)
        run(['/usr/sbin/sshd', '-t'])
        effective = ssh_values(login)
        for key, expected in [('pubkeyauthentication', 'yes'), ('authorizedkeyscommand', KEY_COMMAND), ('authorizedkeyscommanduser', 'nobody')]:
            if effective.get(key) != expected:
                raise RuntimeError('Другие настройки SSH перекрывают ' + key)
        for key in ('passwordauthentication', 'permitrootlogin', 'usepam', 'authenticationmethods', 'port'):
            if effective.get(key) != previous.get(key):
                raise RuntimeError('Неожиданно изменилась настройка SSH: ' + key)
        run(['systemctl', 'reload', 'ssh.service'])
    except Exception:
        if old_ssh is None:
            SSH.unlink(missing_ok=True)
        else:
            atomic_write(SSH, old_ssh.decode(), 0o644)
        run(['/usr/sbin/sshd', '-t'])
        run(['systemctl', 'reload', 'ssh.service'])
        print('Предыдущая конфигурация SSH восстановлена. Копия:', saved)
        raise
    print('Ключи администратора из FreeIPA:\n' + fingerprints)


def setup(s):
    prepare_dns(s, publish=True)
    configure_ssh(s['domain_admin'])
    check(s)


def check(s):
    settings, interface, connection = network_settings(s)
    host = publisher.machine_name(SSSD.read_text(), settings)
    address = publisher.office_address(json.loads(output(['ip', '-j', '-4', 'route', 'get', settings['server']])), settings)
    found = output(['dig', '+short', '+time=2', '+tries=1', '@' + settings['server'], host + '.', 'A']).splitlines()
    failures = []
    print(f'Имя ПК: {host}\nСеть: {interface}, DHCP, текущий IP {address}')
    print('Запись в FreeIPA:', ', '.join(found) or 'нет')
    runtime_dns = output(['resolvectl', 'dns', interface])
    runtime_domain = output(['resolvectl', 'domain', interface])
    print(runtime_dns + '\n' + runtime_domain)
    if runtime_dns.partition(':')[2].split() != [settings['server']]:
        failures.append('DNS интерфейса отличается от сервера IPA')
    if '~' + settings['domain'] not in runtime_domain.partition(':')[2].split():
        failures.append('нет доменного маршрута DNS')
    if found != [address]:
        failures.append('DNS-адрес не совпадает с текущим')
    for service in ('office-ipa-dns.service', 'office-dns-publish.timer', 'ssh.service', 'sssd.service'):
        value = subprocess.run(['systemctl', 'is-active', service], text=True, capture_output=True).stdout.strip()
        print(service + ': ' + value)
        if value != 'active':
            failures.append(service)
    # A timer may be active while its last publication failed.
    result = output(['systemctl', 'show', 'office-dns-publish.service', '-p', 'Result', '--value'])
    if result != 'success':
        failures.append('последнее обновление DNS: ' + result)
    effective = ssh_values(s['domain_admin'])
    if effective.get('authorizedkeyscommand') != KEY_COMMAND or effective.get('authorizedkeyscommanduser') != 'nobody' or effective.get('pubkeyauthentication') != 'yes':
        failures.append('SSH ещё не настроен на ключи FreeIPA')
    keys = output(['runuser', '-u', 'nobody', '--', KEY_COMMAND, s['domain_admin']])
    print('SSH-ключ администратора:', 'получен из FreeIPA' if keys else 'не найден')
    if not keys:
        failures.append('нет SSH-ключа администратора')
    if shutil.which('mullvad'):
        print(output(['mullvad', 'status']))
    if failures:
        raise RuntimeError('Не пройдены проверки: ' + '; '.join(failures))
    print(f"Проверки пройдены. С компьютера с ключом: ssh {s['domain_admin']}@{host}")
    print('Окончательная проверка входа выполняется с компьютера администратора.')


def menu(s, ask, yes, install_self, enable_ssh, install_admin):
    print('\n1 — Настроить DHCP/DNS и SSH-ключи FreeIPA на этом ПК\n2 — Проверить доступ по имени и SSH\n0 — Назад')
    choice = ask('Пункт', '2')
    if choice == '1':
        if not yes('Применить DNS и SSH без переноса данных и перезагрузки'):
            return
        install_self()
        enable_ssh()
        install_admin(s['domain_admin'])
        setup(s)
    elif choice == '2':
        check(s)
