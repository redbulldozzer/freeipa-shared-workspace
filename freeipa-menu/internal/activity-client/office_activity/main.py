import argparse
from dataclasses import asdict
import fcntl
import json
import logging
import os
from pathlib import Path
import signal
import sqlite3
import threading
import time
import uuid

from . import __version__
from .core import Accounting, Snapshot, Store, utc
from .identity import Resolver
from .transport import upload

LOG = logging.getLogger('office-activity')


def state_dir():
    return Path(os.environ.get('XDG_STATE_HOME', str(Path.home()/'.local/state'))) / 'office-activity'


def load_config(path):
    config = json.loads(Path(path).read_text())
    uuid.UUID(config['device_id'])
    if not 1 <= config.get('afk_seconds', 180) <= 3600:
        raise ValueError('invalid_afk_seconds')
    return config


def run(config, directory):
    from .sensors import Idle, Keyboard, SessionBus
    if os.getuid() == 0:
        raise RuntimeError('collector_must_not_run_as_root')
    if os.environ.get('XDG_SESSION_TYPE') != 'x11':
        raise RuntimeError('only_X11_supported_in_pilot')
    session = os.environ.get('XDG_SESSION_ID', '')
    if not session:
        raise RuntimeError('graphical_session_id_missing')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    lock = (directory/'agent.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        LOG.info('collector_already_running')
        return 0
    resolver, bus, idle = Resolver(session), SessionBus(session), Idle()
    props = bus.properties()
    if int(props.get('User', (-1, ''))[0]) != os.getuid() or props.get('Class') != 'user':
        raise RuntimeError('not_a_user_graphical_session')
    store = Store(directory/'events.sqlite3', config.get('max_queue_mb', 512)*1024*1024)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    accounting = Accounting(config['device_id'], boot, store.put, config.get('flush_seconds', 15))
    guard, stop = threading.RLock(), threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    def observe(key=False):
        with guard:
            try:
                properties = bus.properties()
            except Exception as error:
                # A bus outage must cause a supervised retry, not permanent silence.
                accounting.observe(Snapshot(None, 'unknown', 'session_state_unavailable'), time.time(), time.monotonic())
                raise RuntimeError('session_state_unavailable') from error
            if properties.get('State') == 'closing':
                stop.set()
            try:
                # A fresh identity on every key prevents delayed upload/takeover mixing.
                snapshot = resolver.resolve(properties, bus.locked(), idle.seconds(), config.get('afk_seconds', 180))
            except Exception:
                snapshot = Snapshot(None, 'unknown', 'identity_sensor_error')
            now, mono = time.time(), time.monotonic()
            accounting.observe(snapshot, now, mono, key=key)

    keyboard = Keyboard(lambda: observe(True))
    observe()
    keyboard.start()

    def sender():
        delay = 1
        while not stop.wait(delay):
            try:
                result = upload(store, config, directory/'device.token')
                store.meta('delivery', {'state': result, 'checked_at': utc(time.time())})
                delay = 2 if result == 'uploaded' else 30
            except Exception as e:
                # Do not log response bodies, tokens, keystrokes or employee details.
                LOG.warning('delivery_failed: %s', type(e).__name__)
                store.meta('delivery', {'state': 'retrying', 'error': type(e).__name__, 'checked_at': utc(time.time())})
                delay = min(max(10, delay*2), 300)

    delivery = threading.Thread(target=sender, daemon=True)
    delivery.start()
    LOG.info('started version=%s mode=%s', __version__, 'https' if config.get('endpoint') else 'local_only')
    last_status = 0
    try:
        while not stop.wait(0.5):
            if keyboard.failed or not keyboard.thread.is_alive():
                raise RuntimeError('keyboard_sensor_stopped')
            observe()
            if time.monotonic() - last_status >= 5:
                with guard:
                    current = accounting.current
                    store.meta('status', {'version': __version__, 'last_seen': utc(time.time()),
                        'pid': os.getpid(), 'boot_id': boot, 'session': session,
                        'snapshot': asdict(current) if current else None})
                    last_status = time.monotonic()
    finally:
        stop.set()
        keyboard.close()
        delivery.join(12)
        with guard:
            accounting.flush()
            store.meta('stopped_at', utc(time.time()))
        store.close()
        idle.close()
        lock.close()
    return 0


def report(directory, export=False):
    path = directory/'events.sqlite3'
    if not path.exists():
        print(json.dumps({'state': 'not_started', 'data_directory': str(directory)}, ensure_ascii=False))
        return
    connection = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=5)
    if export:
        for row in connection.execute('SELECT payload FROM events ORDER BY seq'):
            print(row[0])
    else:
        metadata = {k: json.loads(v) for k, v in connection.execute('SELECT key,value FROM metadata')}
        counts = connection.execute('SELECT COUNT(*),COALESCE(SUM(delivered=0),0) FROM events').fetchone()
        print(json.dumps({'data_directory': str(directory), 'events': counts[0], 'pending': counts[1],
                          **metadata}, ensure_ascii=False, indent=2))
    connection.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='Office Activity — counts and session state only')
    parser.add_argument('command', choices=['collect', 'status', 'export'])
    parser.add_argument('--config', default='/etc/office-activity/config.json')
    parser.add_argument('--state-dir', type=Path, default=state_dir())
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    if args.command == 'collect':
        return run(load_config(args.config), args.state_dir.resolve())
    report(args.state_dir.resolve(), args.command == 'export')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
