#!/usr/bin/env python3
# requires: root or set-uid, psutil installed
#
# usage:
#   sudo ./input-detect.py -p <parent-pid> [-v]

import sys
import argparse
import subprocess
import psutil
import re
from pathlib import Path

# regex of wait-channels that correspond to blocking on terminal input
WAIT_RE = re.compile(r'^(ttread|ttyin|ttywait|ttyin_wait|ttnread|select|poll)$')

def thread_waits(pid: int, verbose: bool = False) -> bool:
    """Return True if any thread of pid is blocked on terminal input."""
    cmd = ['ps', '-M', '-p', str(pid), '-o', 'state,wchan']
    if verbose:
        print(f"  Running command: {' '.join(cmd)}")
    try:
        out = subprocess.check_output(
            cmd,
            text=True,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        if verbose:
            print(f"  Command failed for PID {pid}")
        return False
    
    if verbose:
        print(f"  Output for PID {pid}:\n{out.strip()}")

    for line in out.splitlines()[1:]: # Skip header line
        parts = line.strip().split()
        if not parts: # Handle empty lines if any
            if verbose:
                print(f"    Skipping empty line: '{line.strip()}'")
            continue

        # On some systems (like macOS observed by user), `ps -o state,wchan`
        # might still print many columns, with the requested ones at the end.
        # We assume 'wchan' is the very last column.
        # 'state' would be second to last, but it's not used by WAIT_RE.
        # Example wide line: "user  pid   ... command S -" (state='S', wchan='-')
        # Example narrow line (often on Linux or direct ps -o state,wchan): "S    ttread" (state='S', wchan='ttread')
        
        wchan = parts[-1]
            
        if verbose:
            # For clarity in logs, show what's being interpreted as state and wchan
            parsed_state_for_log = parts[-2] if len(parts) >= 2 else "N/A"
            print(f"    Checking line (raw): '{line.strip()}'")
            # print(f"    Parsed parts: {parts}") # Can be very verbose
            print(f"    Interpreted state='{parsed_state_for_log}', wchan='{wchan}'")
            
        match = WAIT_RE.match(wchan)
        if match:
            if verbose:
                print(f"      Found matching wchan: '{wchan}' for PID {pid}")
            return True
        elif verbose:
            print(f"      No match for wchan: '{wchan}' (PID {pid})")
    if verbose:
        print(f"  No waiting threads found for PID {pid} (based on wchan values like {WAIT_RE.pattern})")
    return False

def annotate(proc: psutil.Process, indent: str = '', verbose: bool = False) -> None:
    if verbose:
        print(f"{indent}Annotating PID {proc.pid} ({proc.name()})")
        has_terminal = proc.terminal()
        print(f"{indent}  Process has terminal: {has_terminal}")
    else:
        has_terminal = proc.terminal()

    is_waiting = False
    if has_terminal:
        if verbose:
            print(f"{indent}  Checking thread waits for PID {proc.pid}")
        is_waiting = thread_waits(proc.pid, verbose)
        if verbose:
            print(f"{indent}  Thread waits result for PID {proc.pid}: {is_waiting}")
    
    waits_status = 'waits' if has_terminal and is_waiting else 'works'
    print(f'{indent}{proc.pid} {proc.name()} [{waits_status}]')
    
    for child in proc.children():
        annotate(child, indent + '  ', verbose)

def main():
    parser = argparse.ArgumentParser(description="Display a process tree and annotate processes waiting for terminal input.")
    parser.add_argument('-p', '--pid', type=int, required=True, help="Parent Process ID to start the tree from.")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output for debugging.")
    
    args = parser.parse_args()

    try:
        root = psutil.Process(args.pid)
    except psutil.NoSuchProcess:
        sys.exit(f"Error: Process with PID {args.pid} not found.")
    
    if args.verbose:
        print(f"Starting annotation for root PID: {args.pid}")
        
    annotate(root, verbose=args.verbose)

if __name__ == '__main__':
    main()
