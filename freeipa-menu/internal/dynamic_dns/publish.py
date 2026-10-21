#!/usr/bin/env python3
"""Publish only this IPA machine's LAN address using its host keytab."""
import configparser
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

CONFIG = Path('/etc/office-dynamic-dns.json')
NAME = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'


def validate(settings):
    for key in ('domain', 'server_name'):
        if not re.fullmatch(NAME + r'(?:\.' + NAME + r')+', settings[key]):
            raise ValueError('Invalid DNS ' + key)
    if not re.fullmatch(r'[A-Z0-9.-]+', settings['realm']):
        raise ValueError('Invalid Kerberos realm')
    address = ipaddress.IPv4Address(settings['server'])
    network = ipaddress.IPv4Network(settings['network'])
    if address not in network or not address.is_private or network.prefixlen < 16:
        raise ValueError('IPA must be on the selected private office LAN (/16 or smaller)')
    return settings


def machine_name(text, settings):
    config = configparser.RawConfigParser()
    config.read_string(text)
    section = 'domain/' + settings['domain']
    if config.get(section, 'id_provider') != 'ipa':
        raise ValueError('Expected an IPA domain')
    name = config.get(section, 'ipa_hostname').lower()
    if not re.fullmatch(NAME + r'\.' + re.escape(settings['domain']), name):
        raise ValueError('Unexpected IPA hostname')
    return name


def office_address(routes, settings):
    if len(routes) != 1:
        raise ValueError('Ambiguous route to IPA')
    route = routes[0]
    address = ipaddress.IPv4Address(route.get('prefsrc', route.get('src', '0.0.0.0')))
    network = ipaddress.IPv4Network(settings['network'])
    if address not in network or address in (network.network_address, network.broadcast_address) or not route.get('dev') or route['dev'].startswith(('wg', 'tun', 'docker', 'virbr', 'lo')):
        raise ValueError('No office LAN source address; DNS was left unchanged')
    return str(address)


def update_message(host, address, settings):
    if not re.fullmatch(NAME + r'\.' + re.escape(settings['domain']), host):
        raise ValueError('Invalid host name')
    office_address([{'dev': 'lan', 'prefsrc': address}], settings)
    return (f"server {settings['server_name']}\nzone {settings['domain']}.\n"
            f'update delete {host}. A\nupdate add {host}. 60 A {address}\nsend\n')


def command(args, **kw):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=20, **kw).stdout.strip()


def main():
    settings = validate(json.loads(CONFIG.read_text()))
    host = machine_name(Path('/etc/sssd/sssd.conf').read_text(), settings)
    address = office_address(json.loads(command(['ip', '-j', '-4', 'route', 'get', settings['server']])), settings)
    query = ['dig', '+short', '+time=2', '+tries=1', '@' + settings['server'], host + '.', 'A']
    if command(query).splitlines() == [address]:
        print(f'OK: {host} -> {address}')
        return
    with tempfile.TemporaryDirectory(prefix='office-dns-', dir='/run') as temporary:
        env = {**os.environ, 'KRB5CCNAME': 'FILE:' + temporary + '/ccache'}
        command(['kinit', '-k', '-t', '/etc/krb5.keytab', f"host/{host}@{settings['realm']}"], env=env)
        try:
            command(['nsupdate', '-g'], input=update_message(host, address, settings), env=env)
        finally:
            subprocess.run(['kdestroy'], env=env, capture_output=True, timeout=5)
    if command(query).splitlines() != [address]:
        raise RuntimeError('DNS read-back mismatch')
    print(f'UPDATED: {host} -> {address}')


if __name__ == '__main__':
    main()
