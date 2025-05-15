#!/usr/bin/env python3
# requires: root or set-uid, psutil installed
#
# usage:
#   sudo ./waittree.py <parent-pid>

import sys
import subprocess
import psutil
import re
from pathlib import Path

# regex of wait-channels that correspond to blocking on terminal input
WAIT_RE = re.compile(r'^(ttread|ttyin|ttywait|ttyin_wait|ttnread|select|poll)$')

def thread_waits(pid: int) -> bool:
    """Return True if any thread of pid is blocked on terminal input."""
    try:
        out = subprocess.check_output(
            ['ps', '-M', '-p', str(pid), '-o', 'state,wchan'],
            text=True,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        return False
    for line in out.splitlines()[1:]:
        state, wchan = (line.strip().split(maxsplit=1) + [''])[:2]
        if WAIT_RE.match(wchan):
            return True
    return False

def annotate(proc: psutil.Process, indent: str = '') -> None:
    waits = 'waits' if proc.terminal() and thread_waits(proc.pid) else 'works'
    print(f'{indent}{proc.pid} {proc.name()} [{waits}]')
    for child in proc.children():
        annotate(child, indent + '  ')

def main():
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        sys.exit('need parent pid')
    root = psutil.Process(int(sys.argv[1]))
    annotate(root)

if __name__ == '__main__':
    main()
