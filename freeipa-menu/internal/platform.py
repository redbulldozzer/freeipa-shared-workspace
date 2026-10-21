#!/usr/bin/env python3
"""Enroll a Linux Mint workstation and install the shared-domain-login stack."""
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import time


CONFIG = Path('/etc/shared-workspace.conf')
STATE = Path('/var/lib/shared-workspace')
NAME = re.compile(r'^[a-z][a-z0-9_.-]{0,126}$')
FQDN = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')
PACKAGES = (
    'kbd', 'console-setup-linux', 'dconf-cli', 'dbus-daemon',
    'nftables', 'dnsutils', 'freeipa-client', 'sssd-tools', 'libpam-sss', 'libpam0g-dev',
    'build-essential', 'pkg-config', 'libgtk-3-dev', 'python3-ipalib',
    'liblightdm-gobject-1-dev', 'libx11-dev', 'rsync',
    'x11-xserver-utils', 'x11-xkb-utils', 'python3-gi', 'libpam-gnome-keyring',
)
SAFE_DEVICE_GROUPS = {'audio', 'video', 'render', 'plugdev', 'dialout',
                      'cdrom', 'floppy', 'scanner', 'vboxusers'}
HOSTS_BEGIN = '# BEGIN shared-workspace FreeIPA'
HOSTS_END = '# END shared-workspace FreeIPA'


def run(command, **kwargs):
    print('+', ' '.join(str(part) for part in command), flush=True)
    return subprocess.run([str(part) for part in command], check=True, **kwargs)


def local_account(name):
    for line in Path('/etc/passwd').read_text().splitlines():
        fields = line.split(':')
        if fields[0] == name:
            return pwd.struct_passwd((fields[0], fields[1], int(fields[2]), int(fields[3]),
                                      fields[4], fields[5], fields[6]))
    return None


def atomic_write(path, content, mode=0o644):
    temp = path.with_name(path.name + '.shared-workspace-new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def backup_files(arguments):
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    destination = Path('/var/backups/freeipa-menu/rollouts') / stamp
    destination.mkdir(parents=True, mode=0o700)
    paths = [Path('/etc/hostname'), Path('/etc/hosts'), CONFIG,
             Path('/etc/pam.d/lightdm'), Path('/etc/pam.d/cinnamon-screensaver'),
             Path('/etc/lightdm/lightdm.conf.d/90-shared-workspace.conf'),
             Path('/etc/ipa/default.conf'), Path('/etc/sssd/sssd.conf'),
             Path('/etc/shared-workspace-users'),
             Path('/etc/sudoers.d/61-freeipa-center-admin'),
             Path('/etc/polkit-1/rules.d/00-freeipa-center.rules'),
             Path('/usr/share/polkit-1/actions/org.office.freeipa-center.policy')]
    for source in paths:
        if source.is_file():
            target = destination / source.relative_to('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    manifest = vars(arguments).copy()
    manifest['created_at'] = datetime.now(timezone.utc).isoformat()
    (destination / 'arguments.json').write_text(json.dumps(manifest, indent=2) + '\n')
    os.chmod(destination / 'arguments.json', 0o600)
    return destination


def update_hosts(fqdn, ipa_server, ipa_address):
    hosts = Path('/etc/hosts')
    original = hosts.read_text()
    kept, inside = [], False
    for line in original.splitlines():
        if line == HOSTS_BEGIN:
            inside = True
            continue
        if line == HOSTS_END:
            inside = False
            continue
        if not inside:
            kept.append(line)
    entries = []
    if ipa_address:
        try:
            address = ipaddress.ip_address(ipa_address)
        except ValueError as error:
            raise SystemExit(f'Invalid --ipa-address: {ipa_address}') from error
        entries.append(f'{ipa_address}\t{ipa_server}\t{ipa_server.split(".", 1)[0]}')
        family = '-4' if address.version == 4 else '-6'
        route = subprocess.run(['ip', family, 'route', 'get', ipa_address],
                               capture_output=True, text=True)
        match = re.search(r'\bsrc\s+([0-9a-fA-F:.]+)', route.stdout)
        if match:
            entries.append(f'{match.group(1)}\t{fqdn}\t{fqdn.split(".", 1)[0]}')
    block = [HOSTS_BEGIN] + entries + [HOSTS_END]
    atomic_write(hosts, '\n'.join(kept + block) + '\n')


def check_recovery_account(source):
    account = local_account(source)
    if not account or account.pw_uid < 1000:
        raise SystemExit(f'{source} must be an existing local recovery account with UID >= 1000.')
    status = subprocess.run(['passwd', '-S', source], capture_output=True, text=True, check=True)
    fields = status.stdout.split()
    if len(fields) < 2 or fields[1] not in ('P', 'PS'):
        raise SystemExit(f'Local recovery account {source} has no usable password. Set one before deployment.')
    return account


def install_packages(skip_update):
    if not skip_update:
        run(['apt-get', 'update'])
    environment = os.environ.copy()
    environment['DEBIAN_FRONTEND'] = 'noninteractive'
    run(['apt-get', 'install', '-y', *PACKAGES], env=environment)


def enrollment_matches(domain, realm, server):
    config = Path('/etc/ipa/default.conf')
    if not config.is_file():
        return False
    values = {}
    for line in config.read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key.strip().lower()] = value.strip().lower()
    expected = {'domain': domain.lower(), 'realm': realm.lower()}
    mismatches = [key for key, value in expected.items() if values.get(key) != value]
    configured_servers = [item.strip() for item in values.get('server', '').split(',')]
    if configured_servers and '_srv_' not in configured_servers and server.lower() not in configured_servers:
        mismatches.append('server')
    if mismatches:
        raise SystemExit('PC is already enrolled with different IPA settings: ' + ', '.join(mismatches))
    return True


def enroll(args):
    if enrollment_matches(args.domain, args.realm, args.ipa_server):
        print('FreeIPA enrollment already matches; leaving it in place.')
        return
    command = ['ipa-client-install', '--server', args.ipa_server,
               '--domain', args.domain, '--realm', args.realm,
               '--hostname', args.fqdn, '--mkhomedir', '--fixed-primary',
               '--principal', args.enrollment_principal]
    if args.enable_dns_updates:
        command.append('--enable-dns-updates')
    if args.force_join:
        command.append('--force-join')
    print('\nFreeIPA will now ask for confirmation and the enrollment principal password.')
    print('The password is read by ipa-client-install and is never stored by this script.\n')
    run(command)


def wait_for_group(group):
    run(['sssctl', 'config-check'])
    subprocess.run(['sss_cache', '-E'], check=False)
    for _ in range(15):
        result = subprocess.run(['getent', 'group', group], capture_output=True, text=True)
        if result.returncode == 0:
            print('FreeIPA access group:', result.stdout.strip())
            return
        time.sleep(1)
    raise SystemExit(f'FreeIPA group {group} is not visible. Create it before enabling this PC.')


def add_device_groups(source, target, requested):
    source_groups = set(subprocess.check_output(['id', '-nG', source], text=True).split())
    local_groups = {line.split(':', 1)[0] for line in Path('/etc/group').read_text().splitlines()
                    if ':' in line}
    candidates = (source_groups & SAFE_DEVICE_GROUPS) | {item.lower() for item in requested}
    if 'vboxusers' in local_groups:
        candidates.add('vboxusers')
    existing = sorted(candidates & local_groups)
    if existing:
        run(['usermod', '-a', '-G', ','.join(existing), target])
        print('Workspace device groups:', ', '.join(existing))
