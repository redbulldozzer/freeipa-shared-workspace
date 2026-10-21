#!/usr/bin/python3
"""Installed CLI and constrained polkit RPC entry; secrets never enter argv."""
import argparse
import getpass
import json
import os
from pathlib import Path
import resource
import socket
import struct
import stat
import sys
import tempfile

from transition.core import (ENTRY, STATE, Job, System, TransitionError, json_write,
                             options_from, plan)


def root_required():
    if os.geteuid() != 0:
        raise TransitionError('Нужны права локального администратора.')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)


def dispatch(system, options, secrets, existing=None):
    from transition.engine import validate_secrets
    import fcntl
    planned = Job(system, existing).planned() if existing else plan(system, options)
    validate_secrets(system, planned, secrets)
    root = system.path(STATE)
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    root.chmod(0o755)
    fd = os.open(system.path(STATE+'/transition.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    receiver = None
    sock_path = None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TransitionError('Уже выполняется другое задание перехода.') from None
        jobs = system.path(STATE+'/jobs')
        for candidate in jobs.iterdir() if jobs.exists() else []:
            if candidate.is_dir():
                active = system.run(['systemctl', 'is-active', 'office-local-transition-'+candidate.name], check=False)
                if active.stdout.strip() in ('active', 'activating'):
                    raise TransitionError('Уже выполняется другое задание или ввод учётных данных.')
        job = Job(system, existing) if existing else Job.create(system, planned)
        if existing and job.state()['status'] not in ('blocked', 'prepared', 'interrupted'):
            raise TransitionError('Это задание не нуждается в возобновлении.')
        stale = job.directory/'credentials.sock'
        if stale.exists():
            info = stale.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                raise TransitionError('Неожиданный файл вместо канала учётных данных.')
            stale.unlink()
        receiver = socket.socket(socket.AF_UNIX)
        sock_path = str(stale)
        receiver.bind(sock_path)
        os.chmod(sock_path, 0o600)
        receiver.listen(1)
        receiver.settimeout(20)
        system.run(['systemd-run', '--quiet', '--unit=office-local-transition-'+job.id,
                    '--collect', '--property=Type=exec', '--property=UMask=0077',
                    '--property=LimitCORE=0', '--property=TimeoutStopSec=15',
                    '/usr/bin/python3', ENTRY, 'worker', job.id])
        conn, _ = receiver.accept()
        with conn:
            _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                raise TransitionError('Недопустимый получатель учётных данных.')
            conn.sendall((json.dumps(secrets)+'\n').encode())
            # The receiver waits for EOF before taking this same execution lock.
            os.close(fd)
            fd = None
            conn.shutdown(socket.SHUT_WR)
        return {'id': job.id, 'status': 'dispatched', 'public_status': str(job.public)}
    finally:
        if fd is not None:
            os.close(fd)
        if receiver is not None:
            receiver.close()
        if sock_path is not None:
            Path(sock_path).unlink(missing_ok=True)


def worker(system, job_id):
    from transition.engine import execute
    job = Job(system, job_id)
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(15)
    try:
        client.connect(str(job.directory/'credentials.sock'))
        _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0:
            raise TransitionError('Недопустимый источник учётных данных.')
        data = b''
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 16384:
                raise TransitionError('Превышен размер запроса.')
        execute(job, json.loads(data))
    except Exception as error:
        job.update(status='blocked', error=str(error) if isinstance(error, TransitionError)
                   else 'Не получены учётные данные; нужен повторный безопасный ввод.')
    finally:
        client.close()


def rpc(system):
    for line in sys.stdin:
        try:
            if len(line) > 32768:
                raise TransitionError('Превышен размер запроса.')
            request = json.loads(line)
            action = request.get('action')
            if action == 'inspect':
                result = system.inspect()
            elif action == 'job':
                job = Job(system, request['id'])
                if job.state()['status'] == 'running':
                    active = system.run(['systemctl', 'is-active', 'office-local-transition-'+job.id], check=False)
                    if active.stdout.strip() != 'active':
                        job.update(status='interrupted', error='Выполнение прервано; введи пароли для продолжения.')
                result = {'state': job.state(), 'options': job.planned()['options']}
            elif action == 'plan':
                result = plan(system, request.get('options', {}))
            elif action in ('dispatch', 'resume'):
                result = dispatch(system, request.get('options', {}), request.get('secrets', {}),
                                  request.get('id') if action == 'resume' else None)
            elif action == 'rollback':
                from transition.engine import rollback
                result = rollback(Job(system, request['id']))
            elif action == 'accept':
                from transition.engine import accept
                result = accept(Job(system, request['id']), request.get('applications', False),
                                request.get('reboot', False))
            else:
                raise TransitionError('Неизвестная операция.')
            print(json.dumps({'ok': True, 'result': result}, ensure_ascii=False), flush=True)
        except Exception as error:
            message = str(error) if isinstance(error, TransitionError) else 'Ошибка запроса: '+type(error).__name__
            print(json.dumps({'ok': False, 'error': message}, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser(description='Переход на локальную учётку')
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('inspect', 'rpc', 'keyring-helper'):
        sub.add_parser(action)
    for action in ('worker', 'status', 'rollback', 'resume', 'confirm-admin'):
        sub.add_parser(action).add_argument('id')
    acceptance = sub.add_parser('accept')
    acceptance.add_argument('id')
    acceptance.add_argument('--applications', action='store_true')
    acceptance.add_argument('--reboot', action='store_true')
    for action in ('plan', 'apply'):
        p = sub.add_parser(action)
        p.add_argument('--password-mode', choices=('new', 'local'), default='new')
        p.add_argument('--source-user', default='')
        p.add_argument('--admin-user', default='office-admin')
        p.add_argument('--admin-public-key-file')
        p.add_argument('--close-session', action='store_true')
        p.add_argument('--queue-policy', choices=('archive', 'delete'), default='archive')
    args = parser.parse_args()
    if args.action == 'keyring-helper':
        from transition.keyring import main as helper
        return helper()
    if args.action == 'status':
        if not __import__('re').fullmatch(r'[0-9a-f]{32}', args.id):
            raise TransitionError('Некорректный идентификатор.')
        print(Path(STATE+'/public/'+args.id+'.json').read_text())
        return 0
    root_required()
    system = System()
    if args.action == 'inspect':
        result = system.inspect()
    elif args.action == 'rpc':
        rpc(system)
        return 0
    elif args.action == 'worker':
        worker(system, args.id)
        return 0
    elif args.action == 'confirm-admin':
        job = Job(system, args.id)
        is_ssh = bool(os.environ.get('SSH_CONNECTION'))
        parent = os.getppid()
        for _ in range(12):
            try:
                p = Path('/proc')/str(parent)
                if (p/'comm').read_text().strip().startswith('sshd'):
                    is_ssh = True
                    break
                fields = (p/'stat').read_text().rsplit(')', 1)[1].split()
                parent = int(fields[1])
                if parent <= 1:
                    break
            except (OSError, ValueError):
                break
        if os.environ.get('SUDO_USER') != job.planned()['options']['admin_user'] or not is_ssh:
            raise TransitionError('Подтверждение нужно выполнить из нового SSH-сеанса локального администратора через sudo.')
        json_write(job.directory/'ssh-confirmed', {'user': os.environ['SUDO_USER']})
        result = {'admin_ssh_verified': True, 'id': args.id}
    elif args.action == 'rollback':
        from transition.engine import rollback
        result = rollback(Job(system, args.id))
    elif args.action == 'accept':
        from transition.engine import accept
        result = accept(Job(system, args.id), args.applications, args.reboot)
    else:
        opts = ({k: getattr(args, k) for k in ('password_mode', 'source_user', 'admin_user',
                                             'close_session', 'queue_policy')}
                if args.action in ('plan', 'apply') else Job(system, args.id).planned()['options'])
        if args.action in ('plan', 'apply'):
            opts['admin_public_key'] = Path(args.admin_public_key_file).read_text() if args.admin_public_key_file else ''
        planned = plan(system, opts) if args.action != 'resume' else Job(system, args.id).planned()
        if args.action == 'plan':
            result = planned
        else:
            secret = getpass.getpass('Пароль рабочего входа: ')
            admin = getpass.getpass('Пароль локального администратора (оставь пустым, если уже действует): ')
            result = dispatch(system, opts, {'password': secret, 'admin_password': admin},
                              args.id if args.action == 'resume' else None)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except TransitionError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
