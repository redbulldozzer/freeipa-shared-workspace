"""Interval accounting. No key codes, text, mouse positions or window titles."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import sqlite3
import threading
import uuid


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec='milliseconds')


@dataclass(frozen=True)
class Identity:
    account_type: str
    principal: str
    realm: str
    local_user: str
    uid: int
    shift_id: str
    desktop_session: str
    domain_uid: int | None = None


@dataclass(frozen=True)
class Snapshot:
    identity: Identity | None
    state: str
    reason: str = ''


class Store:
    def __init__(self, path, max_bytes=512 * 1024 * 1024):
        self.path = path
        self.max_bytes = max_bytes
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            payload TEXT NOT NULL,
            delivered INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        ''')

    def put(self, event):
        with self.lock:
            # Refuse to silently evict undelivered data on a full disk/queue.
            pages = self.db.execute('PRAGMA page_count').fetchone()[0] - self.db.execute('PRAGMA freelist_count').fetchone()[0]
            size = pages * self.db.execute('PRAGMA page_size').fetchone()[0]
            if size >= self.max_bytes:
                raise RuntimeError('queue_capacity_reached')
            self.db.execute('INSERT OR IGNORE INTO events(event_id,payload) VALUES(?,?)',
                            (event['event_id'], json.dumps(event, separators=(',', ':'))))
            self.db.commit()

    def pending(self, limit=200):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute(
                'SELECT payload FROM events WHERE delivered=0 ORDER BY seq LIMIT ?', (limit,))]

    def acknowledge(self, ids):
        with self.lock:
            self.db.executemany('UPDATE events SET delivered=1 WHERE event_id=?', [(i,) for i in ids])
            # Keep the last 2000 delivered intervals for local diagnostics.
            self.db.execute('DELETE FROM events WHERE delivered=1 AND seq < '
                            '(SELECT COALESCE(MAX(seq),0)-2000 FROM events)')
            self.db.commit()

    def meta(self, key, value=None):
        with self.lock:
            if value is not None:
                self.db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', (key, json.dumps(value)))
                self.db.commit()
                return value
            row = self.db.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
            return json.loads(row[0]) if row else None

    def close(self):
        with self.lock:
            self.db.close()


class Accounting:
    """Snapshot changes split intervals. Unobserved gaps are never active time.

    Every keyboard callback validates a fresh identity before incrementing. A
    boundary key is discarded, with an explicit quality marker, when the state
    differs from the preceding observation. Identity is never added at upload.
    """
    def __init__(self, device_id, boot_id, sink, flush_seconds=15, max_gap=3):
        self.device_id, self.boot_id, self.sink = device_id, boot_id, sink
        self.flush_seconds, self.max_gap = flush_seconds, max_gap
        self.current = None
        self.start_wall = self.last_wall = self.start_mono = self.last_mono = 0
        self.keys = 0
        self.boundary_drops = 0

    def _emit(self, end_wall, end_mono, reason=None):
        if self.current is None:
            return
        duration = max(0, end_mono - self.start_mono)
        if duration < 0.001 and not self.keys and not self.boundary_drops:
            return
        event = {
            'schema_version': 1, 'event_id': str(uuid.uuid4()),
            'device_id': self.device_id, 'boot_id': self.boot_id,
            'start': utc(self.start_wall), 'end': utc(max(self.start_wall, end_wall)),
            'duration_ms': round(duration * 1000),
            'identity': asdict(self.current.identity) if self.current.identity else None,
            'state': self.current.state, 'reason': reason or self.current.reason,
            'key_presses': self.keys, 'boundary_key_drops': self.boundary_drops,
        }
        self.sink(event)
        self.keys = self.boundary_drops = 0

    def observe(self, snapshot, wall, mono, key=False):
        first = self.current is None
        changed = not first and snapshot != self.current
        wakes_from_afk = changed and self.current.state == 'afk' and snapshot.state == 'active' and self.current.identity == snapshot.identity
        gap = not first and (mono - self.last_mono > self.max_gap or mono < self.last_mono)
        clock_jump = not first and abs((wall-self.last_wall)-(mono-self.last_mono)) > 2
        if first:
            self.current = snapshot
            self.start_wall, self.start_mono = wall, mono
        elif gap or clock_jump:
            self._emit(self.last_wall, self.last_mono)
            if not clock_jump and wall >= self.last_wall:
                self.current = Snapshot(None, 'unknown', 'observation_gap')
                self.start_wall, self.start_mono = self.last_wall, self.last_mono
                self._emit(wall, mono)
            self.current = Snapshot(snapshot.identity, 'unknown', 'clock_changed') if clock_jump else snapshot
            self.start_wall, self.start_mono = wall, mono
        elif changed:
            # The transition occurred since last poll: do not invent its time.
            transition_reason = 'clock_changed' if self.current.reason == 'clock_changed' else 'state_transition'
            self._emit(self.last_wall, self.last_mono)
            self.current = Snapshot(None, 'unknown', transition_reason)
            self.start_wall, self.start_mono = self.last_wall, self.last_mono
            self._emit(wall, mono)
            self.current = snapshot
            self.start_wall, self.start_mono = wall, mono
        if key:
            if not (first or (changed and not wakes_from_afk) or gap or clock_jump) and snapshot.state == 'active' and snapshot.identity:
                self.keys += 1
            elif snapshot.state == 'active' and snapshot.identity:
                self.boundary_drops += 1
        self.last_wall, self.last_mono = wall, mono
        if mono - self.start_mono >= self.flush_seconds:
            self._emit(wall, mono)
            self.start_wall, self.start_mono = wall, mono

    def flush(self):
        self._emit(self.last_wall, self.last_mono)
        self.start_wall, self.start_mono = self.last_wall, self.last_mono
