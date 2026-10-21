"""Persistent offline migration, with an independent status console on VT8."""
import curses
import fcntl
import importlib.util
import json
import locale
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path('/usr/local/share/freeipa-menu')
STATE = Path('/var/lib/freeipa-menu')
JOB = STATE / 'background-job.json'
STATUS = STATE / 'background-status.json'
GATE = STATE / 'migration-block'
WORKER = 'freeipa-migration.service'
SCREEN = 'freeipa-migration-screen.service'
FONTS = Path('/usr/share/consolefonts')


def ascii_text(text):
    letters = dict(zip('абвгдеёжзийклмнопрстуфхцчшщъыьэюя',
                       ['a','b','v','g','d','e','yo','zh','z','i','y','k','l','m','n','o',
                        'p','r','s','t','u','f','kh','ts','ch','sh','shch','','y','','e','yu','ya']))
    letters.update({key.upper(): value.capitalize() for key, value in list(letters.items())})
    letters.update({'—':'-', '–':'-', '…':'...', '«':'"', '»':'"', '→':'->'})
    return ''.join(letters.get(char, char if char.isascii() else '?') for char in str(text))


def prepare_console():
    """Configure only the migration VT. Fall back to ASCII if Unicode cannot be prepared."""
    try:
        locale.setlocale(locale.LC_ALL, 'C.UTF-8')
        os.write(sys.stdout.fileno(), b'\x1b%G')  # Linux console UTF-8 output mode.
        size = os.get_terminal_size()
    except (OSError, ValueError, locale.Error):
        return False
    fonts = ['Uni2-Terminus16.psf.gz', 'CyrSlav-Terminus16.psf.gz']
    if size.columns >= 160 and size.lines >= 50:
        fonts.insert(0, 'Uni2-Terminus32x16.psf.gz')
    for name in fonts:
        font = FONTS / name
        if not font.is_file():
            continue
        try:
            result = subprocess.run(['setfont', '-C', '/dev/tty8', str(font)],
                                    capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return True
    return False


def module():
    spec = importlib.util.spec_from_file_location('migration_menu', ROOT / 'menu.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def set_status(m, phase, message, **extra):
    m.transfer.write_json(STATUS, dict(phase=phase, message=message, updated=time.time(), **extra))


def units():
    command = '/usr/bin/python3 -I /usr/local/share/freeipa-menu/internal/background.py'
    return {
        WORKER: f'''[Unit]
Description=FreeIPA offline home migration
After=systemd-user-sessions.service
ConditionPathExists={GATE}
[Service]
Type=oneshot
ExecStart={command} worker
TimeoutStartSec=infinity
StandardInput=null
StandardOutput=journal
StandardError=journal
UMask=0077
''',
        SCREEN: f'''[Unit]
Description=FreeIPA migration progress screen
After=systemd-user-sessions.service
Conflicts=employee@example.invalid
ConditionPathExists={GATE}
[Service]
ExecStart={command} screen
StandardInput=tty
StandardOutput=tty
StandardError=journal
TTYPath=/dev/tty8
TTYReset=yes
TTYVHangup=yes
Environment=TERM=linux LANG=C.UTF-8
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
'''}


def schedule(m, settings, mode, extra):
    if GATE.exists():
        raise RuntimeError('Уже есть незавершённое фоновое задание. Используй его экран прогресса (Ctrl+Alt+F8).')
    sessions = run(['loginctl', 'list-sessions', '--no-legend', '--no-pager'], capture_output=True, text=True)
    for row in sessions.stdout.splitlines():
        if not row.strip():
            continue
        tty = run(['loginctl', 'show-session', row.split()[0], '-p', 'TTY', '--value'],
                  capture_output=True, text=True).stdout.strip()
        if tty == 'tty8':
            raise RuntimeError('Консоль tty8 занята. Заверши сеанс на Ctrl+Alt+F8 и повтори запуск.')
    for name, contents in units().items():
        m.control.write(Path('/etc/systemd/system') / name, contents)
    m.control.write('/etc/systemd/system/lightdm.service.d/80-freeipa-migration.conf',
                    f'[Unit]\nConditionPathExists=!{GATE}\n')
    m.transfer.write_json(JOB, dict(settings=settings, mode=mode, extra=extra, created=time.time()))
    set_status(m, 'queued', 'Подготовка завершена. Ожидаем закрытия меню.')
    m.control.write(GATE, 'Home migration in progress\n', 0o600)
    dispatched = False
    try:
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', SCREEN])
        run(['systemctl', 'start', SCREEN])
        dispatched = True
        run(['systemctl', 'start', '--no-block', WORKER])
    except BaseException:
        # Once dispatch was attempted, it may have succeeded despite an interrupted reply.
        # Preserve the gate; the independent screen can report/retry the saved job.
        if not dispatched:
            GATE.unlink(missing_ok=True)
            subprocess.run(['systemctl', 'stop', SCREEN], check=False)
        raise


def wait_menu_lock(lock, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise RuntimeError('Другое меню ещё открыто. Закрой его и нажми R для повтора.')
            time.sleep(0.5)


def user_processes(uids):
    """Read all remaining processes, without session-helper exceptions."""
    result = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            uid = proc.stat().st_uid
            if uid not in uids:
                continue
            stat = (proc / 'stat').read_text()
            if stat[stat.rfind(')') + 2:].split()[0] == 'Z':
                continue  # Zombies cannot write to the home directory.
            comm = (proc / 'comm').read_text().strip()
            result.append((int(proc.name), uid, comm))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def check_virtual_machines(uids):
    machines = [f'{pid}: {name}' for pid, uid, name in user_processes(uids)
                if name in ('VirtualBoxVM', 'VBoxHeadless', 'vmware-vmx', 'kvm')
                or name.startswith('qemu-system')]
    if machines:
        raise RuntimeError('Ещё запущены виртуальные машины: ' + ', '.join(machines) +
                           '. Штатно выключи их перед переносом.')


def stop_abandoned_sessions(uids):
    """logind may forget abandoned scopes while their processes remain alive."""
    candidates = {}
    for pid, uid, name in user_processes(uids):
        try:
            lines = Path(f'/proc/{pid}/cgroup').read_text().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue
        for line in lines:
            hierarchy, controllers, group = line.split(':', 2)
            if controllers not in ('', 'name=systemd'):
                continue
            match = re.fullmatch(r'/user\.slice/user-(\d+)\.slice/(session-[A-Za-z0-9_-]+\.scope)', group)
            if match and int(match[1]) == uid and uid in uids:
                candidates[match[2]] = (uid, group)
    for scope, (uid, group) in sorted(candidates.items()):
        details = run(['systemctl', 'show', scope, '-p', 'SubState', '-p', 'ControlGroup', '-p', 'Slice'],
                      capture_output=True, text=True, timeout=15).stdout
        attrs = dict(line.split('=', 1) for line in details.splitlines() if '=' in line)
        if (attrs.get('SubState') != 'abandoned' or attrs.get('ControlGroup') != group
                or attrs.get('Slice') != f'user-{uid}.slice'):
            continue
        check_virtual_machines(uids)
        print(f'Завершаю оставшийся после выхода сеанс {scope} (uid={uid}).', flush=True)
        run(['systemctl', 'stop', scope], timeout=90)


def quiesce_offline(m, uids):
    # This operation is only safe in the independent root worker, never in a user terminal.
    cgroup = Path('/proc/self/cgroup').read_text()
    if os.geteuid() != 0 or not any(WORKER in row.split('/') for row in cgroup.splitlines()):
        raise RuntimeError('Завершать сеансы можно только из фоновой службы переноса.')
    if not uids or any(uid < 1000 for uid in uids):
        raise RuntimeError('Неверные UID учёток для фонового переноса.')
    check_virtual_machines(uids)
    set_status(m, 'waiting', 'Завершаем оставшиеся сеансы и фоновые службы переносимых учёток.')
    for uid in sorted(uids):
        # Standard logind logout also stops the user manager and its services. This
        # handles applets, shell wrappers and agents without an ever-growing name list.
        # An absent logind user is harmless only if the final process check is clear.
        result = subprocess.run(['loginctl', 'terminate-user', str(uid)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            print(f'logout uid={uid}: {result.stderr.strip()}', file=sys.stderr, flush=True)
        run(['systemctl', 'stop', f'user@{uid}.service'], timeout=90)
    stop_abandoned_sessions(uids)
    deadline = time.monotonic() + 45
    while True:
        busy = user_processes(uids)
        if not busy:
            return
        if time.monotonic() >= deadline:
            for pid, uid, name in busy:
                try:
                    group = Path(f'/proc/{pid}/cgroup').read_text().strip()
                except FileNotFoundError:
                    group = '(process exited)'
                print(f'Remaining process: pid={pid} uid={uid} name={name} cgroup={group}',
                      file=sys.stderr, flush=True)
            raise RuntimeError('После завершения сеансов остались процессы: ' +
                               ', '.join(f'{pid}: {name}' for pid, uid, name in busy[:15]) +
                               '. Возможно, их перезапускает системная служба. Данные не переносим; '
                               'нужно остановить эту службу и повторить задание.')
        time.sleep(1)


def perform(m, job):
    s = job['settings']
    m.validate(s)
    source = m.recovery(s)
    target = m.existing_target(s)
    if target is None:
        raise RuntimeError('Подготовленная общая учётка не найдена.')
    uids = {source.pw_uid, target.pw_uid}
    check_virtual_machines(uids)
    set_status(m, 'logout', 'Завершаем графический сеанс. Перенос ещё не начат.')
    run(['systemctl', 'stop', 'lightdm.service'], timeout=90)
    run(['chvt', '8'])
    quiesce_offline(m, uids)
    set_status(m, 'scan', 'Проверяем данные и свободное место. Это может занять время.')
    data = m.transfer.prepare(source.pw_dir, target.pw_dir, job['mode'], m.JOURNAL, job['extra'])
    total = len(data['entries'])
    last = [0.0]

    def progress(count):
        now = time.monotonic()
        if now - last[0] >= 1 or count == total:
            last[0] = now
            set_status(m, 'transfer', 'Перенос и проверка файлов. Большой файл может обрабатываться долго.',
                       done=count, total=total)

    set_status(m, 'transfer', 'Перенос и проверка файлов.', done=0, total=total)
    m.transfer.execute(data, m.JOURNAL, target.pw_uid, target.pw_gid, after_item=progress)
    set_status(m, 'configure', 'Данные перенесены. Завершаем настройку входа и ярлыков.')
    m.configure_login('enable')
    m.control.install_shortcuts([s['source_user'], s['workspace_user']])
    warnings = data.get('profile_path_repairs', {}).get('warnings', [])
    message = 'ГОТОВО — данные перенесены, можно входить.'
    if warnings:
        message += (' Есть предупреждения о настройках приложений: ' + str(len(warnings)) +
                    '. Проверь запуск и сохранение файлов; подробности в migration.json.')
    set_status(m, 'complete', message, done=total, total=total)


def worker():
    m = module()
    try:
        if not GATE.exists():
            raise RuntimeError('Нет подготовленного фонового задания.')
        with (STATE / 'menu.lock').open('a') as lock:
            wait_menu_lock(lock)
            perform(m, json.loads(JOB.read_text()))
        return 0
    except Exception as error:
        set_status(m, 'error', str(error))
        print(str(error), file=sys.stderr, flush=True)
        # GATE remains across failures/reboots: no login into partially moved data.
        return 1


def worker_active():
    result = subprocess.run(['systemctl', 'show', WORKER, '-p', 'ActiveState', '--value'],
                            capture_output=True, text=True)
    if result.returncode:
        return True  # Cannot prove it is safe to retry.
    return result.stdout.strip() in ('active', 'activating', 'deactivating', 'reloading')


def finish(m):
    status = json.loads(STATUS.read_text())
    if worker_active() or status.get('phase') != 'complete':
        raise RuntimeError('Перенос ещё не завершён.')
    GATE.unlink(missing_ok=True)
    try:
        run(['systemctl', 'start', 'lightdm.service'])
    except Exception:
        m.control.write(GATE, 'Login activation failed\n', 0o600)
        raise
    # Keep the unit installed; ConditionPathExists prevents it running next boot.


def cancel_before_transfer(m):
    if worker_active() or m.JOURNAL.exists():
        raise RuntimeError('Данные могли быть частично перенесены. Отмена запрещена; продолжи задание.')
    set_status(m, 'cancelled', 'Фоновый перенос отменён до изменения пользовательских данных.')
    GATE.unlink(missing_ok=True)
    try:
        run(['systemctl', 'start', 'lightdm.service'])
    except Exception:
        m.control.write(GATE, 'Login activation failed\n', 0o600)
        raise


def screen_view(stdscr, m, unicode_ready=True):
    curses.curs_set(0)
    stdscr.timeout(1000)
    local_error = ''
    while GATE.exists():
        try:
            status = json.loads(STATUS.read_text())
            created = json.loads(JOB.read_text()).get('created', time.time())
        except (OSError, ValueError):
            status, created = {'phase': 'error', 'message': 'Не удалось прочитать состояние задания.'}, time.time()
        active = worker_active()
        phase = status.get('phase')
        elapsed = max(0, int(time.time() - created))
        height, width = stdscr.getmaxyx()
        message = str(status.get('message', ''))
        limit = max(40, (width - 4) * 3)
        if len(message) > limit:
            message = message[:limit - 30] + '… Подробнее в журнале службы.'
        lines = ['FreeIPA — перенос рабочего места', '', message, '',
                 f'Время с запуска задания: {elapsed // 60} мин {elapsed % 60} сек',
                 'Экран обновляется каждую секунду: ' + time.strftime('%H:%M:%S')]
        if 'total' in status:
            lines += [f"Обработано объектов: {status.get('done', 0)} / {status['total']}"]
        lines += ['', 'Большой виртуальный диск может долго оставаться одним объектом.']
        if not active and phase == 'complete':
            lines += ['', 'ENTER — открыть экран входа']
        elif not active:
            lines += ['', 'Задание остановлено или прервано. Вход пока заблокирован.',
                      'R — повторить с сохранёнными параметрами',
                      'Ctrl+Alt+F3 — консоль администратора для устранения причины',
                      'Журнал: journalctl -u freeipa-migration.service',
                      'Перед повтором заверши консоль командой exit.',
                      'Ctrl+Alt+F8 — вернуться к этому экрану']
            if not m.JOURNAL.exists():
                lines += ['C — отменить перенос и вернуться ко входу (данные ещё не менялись)']
        else:
            lines += ['', 'Дождись завершения. Не выключай компьютер.']
        if local_error:
            lines += ['', local_error]
        stdscr.erase()
        row = 1
        for line in lines:
            if not unicode_ready:
                line = ascii_text(line)
            clean = ''.join(char if char.isprintable() else ' ' for char in str(line))
            for start in range(0, max(1, len(clean)), max(1, width - 4)):
                if row >= height - 1:
                    break
                stdscr.addnstr(row, 2, clean[start:start + max(1, width - 4)], max(1, width - 4))
                row += 1
        stdscr.refresh()
        key = stdscr.getch()
        try:
            if not active and phase == 'complete' and key in (10, 13, curses.KEY_ENTER):
                finish(m)
            elif not active and phase != 'complete' and key in (ord('r'), ord('R')):
                set_status(m, 'queued', 'Повторяем задание с сохранёнными параметрами.')
                run(['systemctl', 'start', '--no-block', WORKER])
                local_error = ''
            elif not active and phase != 'complete' and key in (ord('c'), ord('C')):
                cancel_before_transfer(m)
        except Exception as error:
            local_error = str(error)


def main():
    if os.geteuid() != 0:
        return 1
    if sys.argv[1:] == ['worker']:
        return worker()
    if sys.argv[1:] == ['screen']:
        run(['chvt', '8'])
        unicode_ready = prepare_console()
        curses.wrapper(screen_view, module(), unicode_ready)
        return 0
    return 2


if __name__ == '__main__':
    sys.exit(main())
