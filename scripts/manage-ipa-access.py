#!/usr/bin/env python3
"""Create and maintain the FreeIPA access group for a shared workstation."""
import argparse
import re
import shutil
import subprocess
import sys


NAME = re.compile(r'^[a-z][a-z0-9_.-]{0,126}$')
PRINCIPAL = re.compile(r'^[A-Za-z0-9_.-]+(?:@[A-Za-z0-9.-]+)?$')


def run(command, check=True, quiet=False):
    return subprocess.run(command, check=check,
                          stdout=subprocess.DEVNULL if quiet else None,
                          stderr=subprocess.DEVNULL if quiet else None)


def valid(value, label):
    if not NAME.fullmatch(value):
        raise SystemExit(f'Invalid {label}: {value!r}')
    return value


def ensure_ticket(principal):
    if run(['klist', '-s'], check=False, quiet=True).returncode:
        print(f'Kerberos ticket is required; enter the password for {principal}.')
        run(['kinit', principal])


def group_for(args):
    if args.group:
        return valid(args.group, 'group name')
    short = valid(args.host.split('.', 1)[0].lower(), 'host name')
    return f'{short}-workspace-users'


def main():
    parser = argparse.ArgumentParser(
        description='Manage the FreeIPA group allowed to open one shared desktop.')
    parser.add_argument('action', choices=('ensure', 'remove-users', 'show'))
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument('--host', help='PC hostname; derives HOST-workspace-users')
    selector.add_argument('--group', help='Explicit FreeIPA group name')
    parser.add_argument('--users', nargs='*', default=[], help='FreeIPA user logins')
    parser.add_argument('--principal', default='admin', help='Principal used by kinit')
    args = parser.parse_args()

    for binary in ('ipa', 'kinit', 'klist'):
        if not shutil.which(binary):
            raise SystemExit(f'{binary} is not installed; run this on an IPA server or enrolled admin client.')
    group = group_for(args)
    users = [valid(user.lower(), 'user name') for user in args.users]
    if not PRINCIPAL.fullmatch(args.principal):
        raise SystemExit(f'Invalid principal: {args.principal!r}')
    ensure_ticket(args.principal)

    exists = run(['ipa', 'group-show', group], check=False, quiet=True).returncode == 0
    if args.action == 'show':
        if not exists:
            raise SystemExit(f'FreeIPA group {group} does not exist.')
        run(['ipa', 'group-show', group, '--all'])
        return

    if args.action == 'ensure' and not exists:
        run(['ipa', 'group-add', group,
             '--desc', f'Users allowed to open the shared desktop on {args.host or group}'])
        exists = True
    if not exists:
        raise SystemExit(f'FreeIPA group {group} does not exist.')
    if not users:
        print(f'Group {group} is ready; no membership changes requested.')
        return

    # Validate every login before changing membership, avoiding partial updates.
    missing = [user for user in users
               if run(['ipa', 'user-show', user], check=False, quiet=True).returncode]
    if missing:
        raise SystemExit('Unknown FreeIPA users: ' + ', '.join(missing))
    verb = 'group-add-member' if args.action == 'ensure' else 'group-remove-member'
    command = ['ipa', verb, group] + [f'--users={user}' for user in users]
    run(command)
    run(['ipa', 'group-show', group])


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
