#!/usr/bin/env python3
"""Publish this enrolled machine's current office IPv4 using its own Kerberos key."""
import configparser, ipaddress, json, os, pathlib, re, subprocess, tempfile
SERVER='192.0.2.1'
NETWORK=ipaddress.ip_network('192.0.2.1/24')

def machine_name(text):
    config=configparser.RawConfigParser();config.read_string(text)
    name=config.get('domain/example.invalid','ipa_hostname').lower()
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.office\.local',name):
        raise ValueError('Unexpected IPA hostname')
    return name

def office_address(routes):
    if len(routes)!=1:raise ValueError('Ambiguous route to IPA')
    route=routes[0];address=ipaddress.ip_address(route.get('prefsrc',route.get('src','0.0.0.0')))
    if address not in NETWORK or route.get('dev','').startswith(('wg','tun','docker','virbr','lo')):
        raise ValueError('No office LAN source address; DNS was left unchanged')
    return str(address)

def update_message(host,address):
    if ipaddress.ip_address(address) not in NETWORK:raise ValueError('Invalid LAN address')
    return f'server example.invalid\nzone example.invalid.\nupdate delete {host}. A\nupdate add {host}. 60 A {address}\nsend\n'

def command(args,**kw):return subprocess.run(args,check=True,text=True,capture_output=True,timeout=20,**kw).stdout.strip()

def main():
    host=machine_name(pathlib.Path('/etc/sssd/sssd.conf').read_text())
    address=office_address(json.loads(command(['ip','-j','-4','route','get',SERVER])))
    found=command(['dig','+short','+time=2','+tries=1','@'+SERVER,host+'.','A']).splitlines()
    if found==[address]:
        print(f'OK: {host} -> {address}');return
    with tempfile.TemporaryDirectory(prefix='office-dns-',dir='/run') as temporary:
        env={**os.environ,'KRB5CCNAME':'FILE:'+temporary+'/ccache'}
        command(['kinit','-k','-t','/etc/krb5.keytab',f'host/{host}@example.invalid'],env=env)
        try:command(['nsupdate','-g'],input=update_message(host,address),env=env)
        finally:subprocess.run(['kdestroy'],env=env,capture_output=True,timeout=5)
    found=command(['dig','+short','+time=2','+tries=1','@'+SERVER,host+'.','A']).splitlines()
    if found!=[address]:raise RuntimeError('DNS read-back mismatch')
    print(f'UPDATED: {host} -> {address}')

if __name__=='__main__':main()
