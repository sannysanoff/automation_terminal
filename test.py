#!/usr/bin/env python3
import os
import pty
import subprocess
import select
import time
import pyte

# Создать псевдотерминал
master_fd, slave_fd = pty.openpty()
env = os.environ.copy()
env.update({
    "TERM": "vt100",
    "COLUMNS": "40",
    "LINES": "25"
})

# Запустить top в PTY
proc = subprocess.Popen(
    ["top"],                  # -b для пакетного режима, чтобы top не ожидал ввода
    stdin=slave_fd,
    stdout=slave_fd,
    stderr=slave_fd,
    env=env,
    close_fds=True
)

screen = pyte.Screen(40, 25)
stream = pyte.Stream(screen)

start = time.time()
next_dump = start + 1

try:
    while True:
        # Читать из PTY
        r, _, _ = select.select([master_fd], [], [], 0.1)
        if master_fd in r:
            data = os.read(master_fd, 4096)
            if not data:
                break
            stream.feed(data.decode('utf-8', 'ignore'))

        now = time.time()
        if now >= next_dump:
            print("=" * 40)
            for line in screen.display:
                print(line)
            next_dump += 1

        if now - start >= 20:
            break
finally:
    proc.terminate()
    os.close(master_fd)
    os.close(slave_fd)
