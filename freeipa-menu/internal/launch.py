"""Unprivileged terminal authentication agent and fixed privileged entry point."""
import os
import select
import subprocess
import sys

ENTRY = '/usr/local/share/freeipa-menu/internal/admin-entry'


def main():
    if os.geteuid() == 0:
        return subprocess.call([ENTRY])
    read_fd, write_fd = os.pipe()
    agent = None
    try:
        # Register outside setuid pkexec: its internal agent fails on some Mint builds.
        agent = subprocess.Popen(['/usr/bin/pkttyagent', '--process', str(os.getpid()),
                                  '--notify-fd', str(write_fd)], pass_fds=(write_fd,))
        os.close(write_fd)
        write_fd = -1
        if not select.select([read_fd], [], [], 15)[0]:
            raise RuntimeError('Служба авторизации не ответила. Проверь polkit.')
        os.read(read_fd, 1)
        if agent.poll() is not None:
            raise RuntimeError('Не удалось открыть запрос пароля администратора.')
        return subprocess.call(['/usr/bin/pkexec', '--disable-internal-agent', ENTRY])
    except (OSError, RuntimeError) as error:
        print(error)
        return 1
    finally:
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)
        if agent is not None and agent.poll() is None:
            agent.terminate()
            agent.wait(timeout=5)


if __name__ == '__main__':
    sys.exit(main())
