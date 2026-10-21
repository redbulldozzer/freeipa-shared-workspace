"""Isolated GNOME Secret Service helper. Credentials arrive only on stdin."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    from gi.repository import Gio, GLib
    request = json.loads(sys.stdin.readline(16384))
    old, new = request['old'], request['new']
    mode = request.get('mode', 'change')
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    env = dict(os.environ)
    directory = tempfile.TemporaryDirectory(prefix='transition-keyring-')
    daemon = subprocess.Popen(['gnome-keyring-daemon', '--foreground', '--components=secrets',
                                '--control-directory='+directory.name], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    service = '/org/freedesktop/secrets'
    internal = 'org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface'
    last_method = ''

    def call(path, interface, method, signature=None, values=None):
        nonlocal last_method
        last_method = method
        params = GLib.Variant(signature, values) if signature else None
        return bus.call_sync('org.freedesktop.secrets', path, interface, method, params,
                             None, Gio.DBusCallFlags.NO_AUTO_START, 8000, None).unpack()

    try:
        for _ in range(50):
            try:
                session = call(service, 'org.freedesktop.Secret.Service', 'OpenSession',
                               '(sv)', ('plain', GLib.Variant('s', '')))[1]
                break
            except GLib.Error:
                time.sleep(.1)
        else:
            raise RuntimeError('Secret Service недоступен')

        def secret(value):
            return (session, [], list(value.encode()), 'text/plain; charset=utf8')

        collection = '/org/freedesktop/secrets/collection/login'
        if mode == 'fixture':
            collection = call(service, internal, 'CreateWithMasterPassword',
                              '(a{sv}(oayays))',
                              ({'org.freedesktop.Secret.Collection.Label': GLib.Variant('s', 'login')},
                               secret(old)))[0]
            call(service, 'org.freedesktop.Secret.Service', 'SetAlias', '(so)', ('default', collection))
            call(collection, 'org.freedesktop.Secret.Collection', 'CreateItem',
                 '(a{sv}(oayays)b)',
                 ({'org.freedesktop.Secret.Item.Label': GLib.Variant('s', 'Transition test'),
                   'org.freedesktop.Secret.Item.Attributes': GLib.Variant('a{ss}', {'test': 'transition'})},
                  secret('fixture-secret'), False))
        else:
            alias = call(service, 'org.freedesktop.Secret.Service', 'ReadAlias', '(s)', ('login',))[0]
            if alias != '/':
                collection = alias

        def unlock(value):
            call(service, internal, 'UnlockWithMasterPassword', '(o(oayays))',
                 (collection, secret(value)))

        def fingerprint():
            items = call(collection, 'org.freedesktop.DBus.Properties', 'Get', '(ss)',
                         ('org.freedesktop.Secret.Collection', 'Items'))[0]
            secrets = call(service, 'org.freedesktop.Secret.Service', 'GetSecrets', '(aoo)',
                           (items, session))[0] if items else {}
            if len(secrets) != len(items):
                raise RuntimeError('Не все секреты доступны')
            h = hashlib.sha256()
            for item in sorted(secrets):
                h.update(item.encode())
                h.update(bytes(secrets[item][2]))
            return len(items), h.digest()

        # A resumed job may have changed the password before its checkpoint.
        try:
            unlock(new)
            ready = True
        except GLib.Error:
            ready = False
        if not ready:
            unlock(old)
            before = fingerprint()
            call(service, internal, 'ChangeWithMasterPassword', '(o(oayays)(oayays))',
                 (collection, secret(old), secret(new)))
            call(service, 'org.freedesktop.Secret.Service', 'Lock', '(ao)', ([collection],))
            unlock(new)
            if fingerprint() != before:
                raise RuntimeError('Изменилось содержимое связки ключей')
        result = fingerprint()
        print(json.dumps({'ok': True, 'items': result[0]}))
    except Exception as error:
        print(json.dumps({'ok': False, 'error': 'Не удалось проверить и сменить пароль рабочей связки ключей.',
                          'stage': last_method, 'type': type(error).__name__,
                          'dbus_error': Gio.DBusError.get_remote_error(error) if isinstance(error, GLib.Error) else None}))
        return 1
    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
        directory.cleanup()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
