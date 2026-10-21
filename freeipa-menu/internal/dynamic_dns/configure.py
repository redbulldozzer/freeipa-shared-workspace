#!/usr/bin/env python3
"""Configure a Mint IPA client's split DNS; retain DHCP and Mullvad's public DNS."""
import argparse, configparser, datetime, json, os, pathlib, re, shutil, subprocess
import publish
P=pathlib.Path

def run(*args,**kw):
    return subprocess.run(args,check=True,text=True,**kw)

def output(*args):return run(*args,stdout=subprocess.PIPE).stdout.strip()

def main():
    p=argparse.ArgumentParser();p.add_argument('--interface',required=True);p.add_argument('--connection',required=True)
    p.add_argument('--publish',action='store_true');p.add_argument('--refresh',type=int,default=60)
    for key in ('server', 'server-name', 'domain', 'realm', 'network'):
        p.add_argument('--'+key, required=True)
    args=p.parse_args()
    settings=publish.validate(dict(server=args.server, server_name=args.server_name,
                                  domain=args.domain, realm=args.realm, network=args.network))
    if not re.fullmatch(r'[a-fA-F0-9-]{36}', args.connection):raise SystemExit('Invalid connection UUID')
    if args.publish:
        publish.machine_name(P('/etc/sssd/sssd.conf').read_text(), settings)
    if os.geteuid()!=0:raise SystemExit('Run as root')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]+',args.interface) or args.refresh<60:raise SystemExit('Invalid arguments')
    if output('nmcli','-g','ipv4.method','connection','show',args.connection)!='auto':raise SystemExit('Expected DHCP; no IP changes made')
    if output('nmcli','-g','GENERAL.CON-UUID','device','show',args.interface)!=args.connection:raise SystemExit('Connection/interface mismatch')
    if output('systemctl','is-active','systemd-resolved')!='active':raise SystemExit('systemd-resolved required')
    if args.publish and not P(__file__).resolve().with_name('publish.py').is_file():raise SystemExit('publish.py must be next to configure.py')
    for command in ['nft','nmcli','resolvectl']+(['sssctl','kinit','nsupdate','dig'] if args.publish else []):assert shutil.which(command),command+' missing'
    files=['/etc/hosts','/etc/sssd/sssd.conf','/etc/nftables.d/office-ipa-dns.nft','/etc/systemd/system/office-ipa-dns.service','/etc/netplan/zz-office-dns.yaml',
        '/etc/systemd/system/office-dns-publish.service','/etc/systemd/system/office-dns-publish.timer',
        '/etc/NetworkManager/dispatcher.d/90-office-dns','/usr/local/sbin/office-dns-publish']
    files.append('/etc/office-dynamic-dns.json')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup=P('/var/backups/office-dynamic-dns')/stamp;backup.mkdir(parents=True,mode=0o700);os.chmod(backup.parent,0o700)
    for filename in files:
        src=P(filename)
        if src.exists():
            dst=backup/filename.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
    props=['ipv4.method','ipv4.dns','ipv4.dns-search','ipv4.ignore-auto-dns','ipv6.ignore-auto-dns','connection.interface-name']
    old={key:output('nmcli','-g',key,'connection','show',args.connection) for key in props}
    (backup/'network.json').write_text(json.dumps({'uuid':args.connection,'interface':args.interface,'properties':old},indent=2))
    os.chmod(backup/'network.json',0o600)
    rules='''# Only the internal IPA resolver. All other destinations retain Mullvad policy.
add table inet office_ipa_dns
flush table inet office_ipa_dns
table inet office_ipa_dns {
 chain output {
  type filter hook output priority -10; policy accept;
  ip daddr 192.0.2.1 udp dport 53 counter ct mark set 0x00000f41 meta mark set 0x6d6f6c65
  ip daddr 192.0.2.1 tcp dport 53 counter ct mark set 0x00000f41 meta mark set 0x6d6f6c65
 }
}
'''
    rules=rules.replace('192.0.2.1',args.server)
    rules_path=P(files[2]);rules_path.parent.mkdir(exist_ok=True);rules_path.write_text(rules);rules_path.chmod(0o644)
    run('nft','--check','--file',str(rules_path))
    P(files[3]).write_text('''[Unit]
Description=Allow internal FreeIPA DNS alongside Mullvad
Before=NetworkManager.service sssd.service mullvad-daemon.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.d/office-ipa-dns.nft
ExecReload=/usr/sbin/nft -f /etc/nftables.d/office-ipa-dns.nft
ExecStop=/usr/sbin/nft delete table inet office_ipa_dns
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
''')
    run('systemctl','daemon-reload');run('systemctl','enable','--now','office-ipa-dns.service');run('systemctl','reload','office-ipa-dns.service')
    run('nmcli','connection','modify',args.connection,'ipv4.dns',args.server,'ipv4.dns-search','~'+args.domain,'ipv4.ignore-auto-dns','yes','ipv6.ignore-auto-dns','yes')
    if P('/run/netplan',args.interface+'.yaml').exists():
        # An initramfs DHCP profile can reintroduce the router DNS at every boot.
        # Explicit NM passthrough overrides the merged list, without changing DHCP/boot networking.
        override=P('/etc/netplan/zz-office-dns.yaml')
        override.write_text(f"network:\n  version: 2\n  ethernets:\n    {args.interface}:\n      networkmanager:\n        passthrough:\n          connection.interface-name: {args.interface}\n          ipv4.dns: '{args.server};'\n")
        override.chmod(0o600);run('netplan','generate');run('nmcli','connection','reload')
    reapplied=subprocess.run(['nmcli','device','reapply',args.interface],text=True,capture_output=True)
    if reapplied.returncode:
        # Some netplan profiles have unrelated pending changes; never reconnect the NIC here.
        print('Applying DNS live through resolved; saved NetworkManager profile will apply on next activation.')
        run('resolvectl','dns',args.interface,args.server)
        run('resolvectl','domain',args.interface,'~'+args.domain)
    else:print(reapplied.stdout.strip())
    if args.publish:
        config=P('/etc/sssd/sssd.conf');text=config.read_text();parsed=configparser.RawConfigParser();parsed.read_string(text)
        domain='domain/'+args.domain
        if not parsed.has_section(domain) or parsed.get(domain,'id_provider')!='ipa':raise SystemExit('IPA domain config missing')
        hostname=publish.machine_name(text,settings)
        updates={'dyndns_update':'False'}
        obsolete=('dyndns_update','dyndns_iface','dyndns_refresh_interval','dyndns_ttl','dyndns_update_ptr','dyndns_auth')
        # Preserve unrelated settings/comments and update only the selected domain section.
        lines=text.splitlines();new=[];current=None
        for line in lines:
            match=re.match(r'^\s*\[([^]]+)\]',line)
            if match:current=match.group(1)
            if current==domain and re.match(r'^\s*('+'|'.join(obsolete)+r')\s*=',line):continue
            new.append(line)
            if match and current==domain:new.extend(f'{k} = {v}' for k,v in updates.items())
        config.write_text('\n'.join(new)+'\n');config.chmod(0o600)
        try:run('sssctl','config-check')
        except Exception:
            shutil.copy2(backup/'etc/sssd/sssd.conf',config);raise
        # Do not retain a DHCP address as a permanent local hosts override.
        hosts=P('/etc/hosts');result=[];short=hostname.split('.')[0]
        for line in hosts.read_text().splitlines():
            body,mark,comment=line.partition('#');fields=body.split()
            if fields and not fields[0].startswith(('127.','::1')) and any(v in (hostname,short) for v in fields[1:]):
                names=[v for v in fields[1:] if v not in (hostname,short)]
                if names:result.append(fields[0]+' '+ ' '.join(names)+(' #'+comment if mark else ''))
            else:result.append(line)
        hosts.write_text('\n'.join(result)+'\n')
        run('systemctl','restart','sssd')
        P('/etc/office-dynamic-dns.json').write_text(json.dumps(settings,indent=2)+'\n')
        P('/etc/office-dynamic-dns.json').chmod(0o600)
        source=P(__file__).resolve().with_name('publish.py')
        shutil.copy2(source,'/usr/local/sbin/office-dns-publish');P('/usr/local/sbin/office-dns-publish').chmod(0o755)
        P('/etc/systemd/system/office-dns-publish.service').write_text("""[Unit]
Description=Publish this computer's current office DHCP address in FreeIPA
After=NetworkManager.service office-ipa-dns.service
Requires=office-ipa-dns.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/office-dns-publish
UMask=0077
NoNewPrivileges=yes
TimeoutStartSec=70
""")
        P('/etc/systemd/system/office-dns-publish.timer').write_text(f"""[Unit]
Description=Refresh this computer's FreeIPA DNS address

[Timer]
OnBootSec=30s
OnUnitActiveSec={args.refresh}s
AccuracySec=5s
RandomizedDelaySec=5s

[Install]
WantedBy=timers.target
""")
        hook=P('/etc/NetworkManager/dispatcher.d/90-office-dns')
        hook.write_text(f"""#!/bin/sh
# Only the enrolled office connection. Never restart or disconnect the VPN.
case "$2" in
  up|dhcp4-change|reapply)
    [ "$CONNECTION_UUID" = "{args.connection}" ] || exit 0
    systemctl --no-block start office-dns-publish.service
    ;;
esac
""");hook.chmod(0o755)
        run('systemctl','daemon-reload');run('systemctl','enable','--now','office-dns-publish.timer')
        run('systemctl','start','office-dns-publish.service')
    run('resolvectl','flush-caches')
    print('BACKUP:',backup)
    print('DHCP:',output('nmcli','-g','ipv4.method','connection','show',args.connection))
    print(output('ip','-4','-brief','address','show',args.interface))

if __name__=='__main__':main()
