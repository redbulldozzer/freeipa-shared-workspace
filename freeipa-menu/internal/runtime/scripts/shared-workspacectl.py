#!/usr/bin/env python3
"""Inspect, enable, disable, or restart the shared-workspace login stack."""
import argparse
import fcntl
import os
from pathlib import Path
import pwd
import grp
import subprocess
import sys


CONFIG = Path('/etc/shared-workspace.conf')
PROJECT = Path('/usr/local/share/freeipa-menu/internal/runtime')


def settings():
    result = {}
    if CONFIG.is_file():
        for line in CONFIG.read_text().splitlines():
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                result[key] = value
    return result


def command_ok(command):
    return subprocess.run(command, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def status():
    failures = 0

    def report(ok, text, detail=''):
        nonlocal failures
        print(f"[{'OK' if ok else 'FAIL'}] {text}" + (f': {detail}' if detail else ''))
        failures += not ok

    config = settings()
    target, access_group = config.get('target'), config.get('group')
    report(bool(target and access_group), 'configuration',
           f'target={target or "?"}, group={access_group or "?"}')
    try:
        account = pwd.getpwnam(target) if target else None
    except KeyError:
        account = None
    report(bool(account and account.pw_uid >= 1000), 'local workspace account', target or '?')
    if account:
        home = Path(account.pw_dir)
        try:
            home_stat = home.stat()
            home_ok = home.is_dir() and home_stat.st_uid == account.pw_uid and (home_stat.st_mode & 0o077) == 0
        except OSError:
            home_ok = False
        report(home_ok, 'workspace home ownership and mode', str(home))
        password = subprocess.run(['passwd', '-S', target], capture_output=True, text=True)
        fields = password.stdout.split()
        report(password.returncode == 0 and len(fields) > 1 and fields[1] in ('L', 'LK'),
               'direct password for workspace account is locked')
    try:
        group = grp.getgrnam(access_group) if access_group else None
    except KeyError:
        group = None
    report(group is not None, 'FreeIPA access group visible through NSS', access_group or '?')
    report(command_ok(['sssctl', 'config-check']), 'SSSD configuration')
    report(Path('/etc/ipa/default.conf').is_file(), 'FreeIPA client enrollment')
    report(Path('/usr/local/lib/security/pam_shared_workspace.so').is_file(), 'PAM module installed')
    report(Path('/usr/local/libexec/shared-workspace-greeter').is_file(), 'LightDM greeter installed')
    report(Path('/usr/local/libexec/shared-workspace-lock-bridge').is_file(), 'Cinnamon lock bridge installed')
    display = Path('/etc/lightdm/lightdm.conf.d/90-shared-workspace.conf')
    enabled = display.is_file() and 'pam-service=shared-workspace-login' in display.read_text()
    report(enabled, 'shared login enabled in LightDM')
    effective = subprocess.run(['lightdm', '--show-config'], capture_output=True, text=True)
    effective_text = effective.stdout + '\n' + effective.stderr
    effective_ok = (effective.returncode == 0 and
                    'pam-service=shared-workspace-login' in effective_text and
                    'greeter-session=shared-workspace-greeter' in effective_text)
    report(effective_ok, 'effective LightDM configuration')
    report(command_ok(['systemctl', 'is-active', '--quiet', 'lightdm']), 'LightDM service running')
    current = Path('/run/shared-workspace/current')
    if current.is_file():
        lock_active = False
        try:
            with open('/run/shared-workspace/session.lock', 'rb') as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    fcntl.flock(lock, fcntl.LOCK_UN)
                except BlockingIOError:
                    lock_active = True
        except OSError:
            pass
        report(lock_active, 'active shared-session lock')
        print('[INFO] current shift:\n' + current.read_text().rstrip())
    else:
        print('[INFO] no active shared graphical session')
    recent = Path('/var/lib/shared-workspace/recent-users')
    if recent.is_file():
        print('[INFO] recent domain users: ' + ', '.join(recent.read_text().split()))
    return 1 if failures else 0


def require_root():
    if os.geteuid():
        raise SystemExit('This action must be run as root.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('status', 'enable', 'disable', 'restart-lightdm'))
    args = parser.parse_args()
    if args.action == 'status':
        require_root()
        raise SystemExit(status())
    require_root()
    if args.action in ('enable', 'disable'):
        subprocess.run(['python3', str(PROJECT / 'scripts/configure-login.py'), args.action], check=True)
    else:
        subprocess.run(['systemctl', 'restart', 'lightdm'], check=True)
        print('LightDM restarted. Any graphical session that was open has been terminated.')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
