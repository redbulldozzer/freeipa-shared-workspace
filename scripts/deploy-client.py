#!/usr/bin/env python3
"""Enroll a Linux Mint workstation and install the shared-domain-login stack."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import time


PROJECT = Path(__file__).resolve().parent.parent
INSTALLED_PROJECT = Path('/usr/local/share/shared-workspace-pilot')
CONFIG = Path('/etc/shared-workspace.conf')
STATE = Path('/var/lib/shared-workspace')
NAME = re.compile(r'^[a-z][a-z0-9_.-]{0,126}$')
FQDN = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')
PACKAGES = (
    'freeipa-client', 'sssd-tools', 'libpam-sss', 'libpam0g-dev',
    'build-essential', 'pkg-config', 'libgtk-3-dev',
    'liblightdm-gobject-1-dev', 'libx11-dev', 'rsync',
    'x11-xserver-utils', 'x11-xkb-utils', 'python3-gi',
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


def valid_name(value, label):
    value = value.lower()
    if not NAME.fullmatch(value):
        raise SystemExit(f'Invalid {label}: {value!r}')
    return value


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
    destination = Path('/var/backups/shared-workspace-pilot/rollouts') / stamp
    destination.mkdir(parents=True, mode=0o700)
    paths = [Path('/etc/hostname'), Path('/etc/hosts'), CONFIG,
             Path('/etc/pam.d/lightdm'), Path('/etc/pam.d/cinnamon-screensaver'),
             Path('/etc/lightdm/lightdm.conf.d/90-shared-workspace.conf'),
             Path('/etc/ipa/default.conf'), Path('/etc/sssd/sssd.conf')]
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


def encrypted_backing(path):
    result = subprocess.run(['findmnt', '-n', '-o', 'SOURCE', '-T', str(path)],
                            capture_output=True, text=True)
    if result.returncode:
        return False
    source = result.stdout.strip().split('[', 1)[0]
    if not source.startswith('/dev/'):
        return False
    types = subprocess.run(['lsblk', '-s', '-n', '-o', 'TYPE', source],
                           capture_output=True, text=True)
    return types.returncode == 0 and 'crypt' in types.stdout.split()


def check_desktop_and_apps(source, skip_migration, allow_unencrypted):
    manager = Path('/etc/X11/default-display-manager')
    if not manager.is_file() or not manager.read_text().strip().endswith('/lightdm'):
        raise SystemExit('This implementation requires LightDM as the active display manager.')
    if not Path('/usr/share/cinnamon').exists():
        raise SystemExit('This implementation requires a Cinnamon desktop session.')
    if skip_migration:
        return
    account = local_account(source)
    home = Path(account.pw_dir)
    if (home / '.Private').is_symlink():
        filesystem = subprocess.run(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(home)],
                                    capture_output=True, text=True)
        if filesystem.returncode or filesystem.stdout.strip() not in ('ecryptfs', 'ecrypt'):
            raise SystemExit('The eCryptfs source home is not mounted; stay logged into the source account.')
        if not encrypted_backing(Path('/home')) and not allow_unencrypted:
            raise SystemExit('Source uses eCryptfs but /home is not backed by dm-crypt/LUKS. '
                             'Encrypt the disk or pass --allow-unencrypted-workspace explicitly.')
    patterns = ('firefox', 'firefox-bin', 'chrome', 'chromium', 'Telegram',
                'VirtualBox', 'VirtualBoxVM', 'VBoxHeadless')
    result = subprocess.run(['pgrep', '-u', str(account.pw_uid), '-x', '|'.join(patterns)],
                            capture_output=True, text=True)
    if result.returncode == 0:
        raise SystemExit('Close Firefox/Chrome/Chromium, Telegram and VirtualBox before migration.')
    if result.returncode != 1:
        raise SystemExit('Could not inspect running applications.')


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


def install_project():
    if PROJECT != INSTALLED_PROJECT:
        shutil.copytree(PROJECT, INSTALLED_PROJECT, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('build', '.git', '__pycache__',
                                                     '*.pyc', '*.key', '*.keytab', '.secrets'))
    run(['bash', INSTALLED_PROJECT / 'scripts/install-prototype.sh'])


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


def write_manifest(args, backup, target, group):
    STATE.mkdir(parents=True, exist_ok=True)
    record = {'installed_at': datetime.now(timezone.utc).isoformat(),
              'fqdn': args.fqdn, 'ipa_server': args.ipa_server,
              'domain': args.domain, 'realm': args.realm,
              'workspace_user': target, 'access_group': group,
              'source_user': args.source_user,
              'migration_skipped': args.skip_migration,
              'backup': str(backup)}
    atomic_write(STATE / 'deployment.json', json.dumps(record, indent=2) + '\n', 0o600)


def arguments():
    parser = argparse.ArgumentParser(
        description='Prepare one Linux Mint PC for personal FreeIPA login into a common desktop.')
    parser.add_argument('--fqdn', required=True, help='Unique client FQDN, e.g. example.invalid')
    parser.add_argument('--ipa-server', required=True, help='FreeIPA server FQDN')
    parser.add_argument('--ipa-address', help='FreeIPA IP address for a persistent /etc/hosts fallback')
    parser.add_argument('--domain', required=True, help='IPA DNS domain, e.g. example.invalid')
    parser.add_argument('--realm', help='Kerberos realm; defaults to upper-case domain')
    parser.add_argument('--source-user', required=True, help='Existing local account whose home is copied')
    parser.add_argument('--workspace-user', default='office-workspace')
    parser.add_argument('--access-group', help='Defaults to SHORT_HOST-workspace-users')
    parser.add_argument('--enrollment-principal', default='admin')
    parser.add_argument('--enable-dns-updates', action='store_true')
    parser.add_argument('--force-join', action='store_true')
    parser.add_argument('--skip-apt-update', action='store_true')
    parser.add_argument('--skip-packages', action='store_true')
    parser.add_argument('--skip-migration', action='store_true')
    parser.add_argument('--allow-unencrypted-workspace', action='store_true',
                        help='Allow decrypted copy from eCryptfs onto a filesystem without dm-crypt')
    parser.add_argument('--preflight-only', action='store_true',
                        help='Validate local prerequisites and print derived names without changing the PC')
    parser.add_argument('--extra-group', action='append', default=[],
                        help='Additional local device group for the common UID; repeat as needed')
    return parser.parse_args()


def main():
    args = arguments()
    if os.geteuid():
        raise SystemExit('Run this script as root with sudo.')
    args.fqdn = args.fqdn.lower()
    args.ipa_server = args.ipa_server.lower()
    args.domain = args.domain.lower()
    args.realm = (args.realm or args.domain.upper()).upper()
    if not FQDN.fullmatch(args.fqdn) or not FQDN.fullmatch(args.ipa_server):
        raise SystemExit('Client and IPA server names must be full DNS names.')
    if not args.fqdn.endswith('.' + args.domain):
        raise SystemExit('Client FQDN must be inside --domain.')
    args.source_user = valid_name(args.source_user, 'source user')
    target = valid_name(args.workspace_user, 'workspace user')
    group = valid_name(args.access_group or f'{args.fqdn.split(".", 1)[0]}-workspace-users',
                       'access group')
    if target == args.source_user:
        raise SystemExit('Source and workspace users must be different accounts.')
    for item in args.extra_group:
        valid_name(item, 'extra group')

    check_recovery_account(args.source_user)
    check_desktop_and_apps(args.source_user, args.skip_migration,
                           args.allow_unencrypted_workspace)
    if args.preflight_only:
        print('Preflight passed.')
        print('Client FQDN:', args.fqdn)
        print('Workspace user:', target)
        print('FreeIPA access group:', group)
        return
    backup = backup_files(args)
    print('Pre-change backup:', backup)
    if not args.skip_packages:
        install_packages(args.skip_apt_update)
    update_hosts(args.fqdn, args.ipa_server, args.ipa_address)
    run(['hostnamectl', 'set-hostname', args.fqdn])
    enroll(args)
    wait_for_group(group)

    atomic_write(CONFIG, '# Generated by deploy-client.py\n'
                 f'target={target}\n'
                 f'group={group}\n')
    install_project()
    add_device_groups(args.source_user, target, args.extra_group)
    if not args.skip_migration:
        migration_environment = os.environ.copy()
        if args.allow_unencrypted_workspace:
            migration_environment['SHARED_WORKSPACE_ALLOW_UNENCRYPTED'] = '1'
        migration_command = ['python3', INSTALLED_PROJECT / 'scripts/migrate-home.py',
                             args.source_user, target]
        source_home = Path(local_account(args.source_user).pw_dir).resolve()
        try:
            relative_project = PROJECT.resolve().relative_to(source_home)
            migration_command.append('/' + str(relative_project))
        except ValueError:
            pass
        run(migration_command, env=migration_environment)
    run(['python3', INSTALLED_PROJECT / 'scripts/configure-login.py', 'enable'])
    write_manifest(args, backup, target, group)
    run(['/usr/local/sbin/shared-workspacectl', 'status'])
    print('\nDeployment is ready. The current graphical session was not interrupted.')
    print('When convenient, reboot the PC and test two domain users plus the local recovery login.')
    print('ActivityWatch data and configuration were deliberately left out of the migration.')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
