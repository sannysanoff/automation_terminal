#!/usr/bin/env python3
import os
import pty
import subprocess
import select
import pyte
from flask import Flask, request, jsonify
import threading
import signal
import sys
import time # Added for sleep
import platform # For OS detection

# --- Global variables ---
# PTY and subprocess related
master_fd, slave_fd = None, None
proc = None
screen = None
stream = None # pyte stream

# Control flag for the PTY reader thread
pty_running = True
# PTY reader thread object
pty_thread = None

# Flask application
app = Flask(__name__)

# Maximum wait time for synchronous keystroke command completion (in seconds)
MAX_SYNC_WAIT_SECONDS = 60

# --- Helper Functions ---
def count_processes_in_pgroup(pgid):
    """Counts the number of processes in a given process group using ps."""
    # Ensure pgid is a positive integer as expected by ps for --pgid
    if not isinstance(pgid, int) or pgid <= 0:
        app.logger.error(f"Invalid PGID for counting: {pgid}")
        return -1 # Indicate an error

    system_os = platform.system()
    if system_os == "Linux":
        command = ["ps", "-o", "pid", "--no-headers", "--pgid", str(pgid)]
    elif system_os == "Darwin": # macOS
        # On macOS, `ps -g <pgid>` lists processes in the group.
        # `-o pid=` prints only the PID without a header.
        command = ["ps", "-o", "pid=", "-g", str(pgid)]
    else:
        app.logger.error(f"Unsupported OS for process counting: {system_os}")
        return -1 # Indicate an error for unsupported OS

    try:
        app.logger.debug(f"Executing process count command: '{" ".join(command)}'")
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            # If ps returns non-zero, it could be that the PGID no longer exists (common).
            # Or, for macOS, if the group is empty, `ps -g` might return 1.
            # We check stderr for specific messages indicating the group doesn't exist or is empty.
            stderr_lower = result.stderr.lower()
            if "does not exist" in stderr_lower or "no such process" in stderr_lower or \
               (system_os == "Darwin" and result.stdout.strip() == "" and result.returncode == 1): # macOS specific for empty group
                app.logger.info(f"Process group {pgid} appears empty or non-existent. Assuming 0 processes. stderr: {result.stderr.strip()}")
                return 0
            else:
                app.logger.warning(f"Command '{" ".join(command)}' failed with rc {result.returncode}, stderr: {result.stderr.strip()}")
                return -1 # Indicate an error

        output_lines = result.stdout.strip().split('\n')
        # Filter out empty lines that might result from split if stdout is empty
        valid_pids = [line for line in output_lines if line.strip()]
        count = len(valid_pids)
        app.logger.debug(f"Processes in PGID {pgid}: {count}. PIDs: {valid_pids}")
        return count
    except FileNotFoundError: # ps command not found
        app.logger.error(f"'ps' command not found. Cannot count processes.")
        return -1 
    except Exception as e:
        app.logger.error(f"Error counting processes in pgroup {pgid} with 'ps': {e}")
        return -1

# --- PTY Reader Thread ---
def pty_reader_thread_function():
    """
    Reads output from the master PTY FD and feeds it to the pyte stream.
    """
    global stream, master_fd, pty_running
    try:
        while pty_running:
            if master_fd is None: # FD might have been closed by cleanup
                break
            # Wait for data to be available for reading
            readable, _, _ = select.select([master_fd], [], [], 0.1)
            if master_fd in readable:
                try:
                    data = os.read(master_fd, 4096)
                    if data: # Ensure data is not empty before decoding
                        decoded_data = data.decode('utf-8', 'ignore')
                        # Log a snippet of the data read, escaping newlines for readability
                        log_snippet = decoded_data[:60].replace('\n', '\\n').replace('\r', '\\r')
                        # Using app.logger for consistency if Flask's logger is configured
                        app.logger.debug(f"PTY Read {len(decoded_data)} chars: '{log_snippet}...'")
                        if stream:
                            stream.feed(decoded_data)
                    else:  # EOF: PTY has been closed (e.g., shell exited)
                        app.logger.info("PTY EOF (empty data read), stopping reader thread.")
                        pty_running = False # Signal to stop, if not already
                        break
                except OSError:  # Happens if FD is closed by another thread
                    print("PTY read error (FD likely closed), stopping reader thread.")
                    pty_running = False
                    break
                except Exception as e:
                    print(f"Error in PTY reader: {e}")
                    pty_running = False
                    break
    finally:
        print("PTY reader thread exited.")

# --- Flask HTTP Endpoints ---
@app.route('/keystroke', methods=['POST'])
def push_keystroke():
    """
    Receives keystrokes and writes them to the PTY.
    Expects form data: {'keys': 'your_command\\n'}
    """
    global master_fd
    app.logger.info(f"Received POST /keystroke. Form data: {request.form}")
    if not master_fd or not pty_running:
        app.logger.warning("PTY not active for /keystroke")
        return jsonify({"error": "PTY not active or not initialized"}), 503
    try:
        keys = request.form.get('keys')
        if keys is None:
            return jsonify({"error": "Missing 'keys' in form data"}), 400
        
        os.write(master_fd, keys.encode('utf-8'))
        return jsonify({"status": "success", "keys_sent": keys})
    except OSError as e: # master_fd might be closed
        return jsonify({"error": f"Error writing to PTY: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

@app.route('/keystroke_sync', methods=['POST'])
def push_keystroke_sync():
    """
    Receives keystrokes, writes them to PTY, and waits for the command to complete.
    Completion is defined as only the initial shell process remaining in its process group.
    Expects form data: {'keys': 'your_command\\n'}
    """
    global master_fd, proc
    app.logger.info(f"Received POST /keystroke_sync. Form data: {request.form}")

    if not master_fd or not pty_running:
        app.logger.warning("PTY not active for /keystroke_sync")
        return jsonify({"error": "PTY not active or not initialized"}), 503
    
    if not proc or proc.poll() is not None:
        app.logger.warning("Shell process not running for /keystroke_sync")
        return jsonify({"error": "Shell process is not running."}), 503

    try:
        keys = request.form.get('keys')
        if keys is None:
            return jsonify({"error": "Missing 'keys' in form data"}), 400
        
        os.write(master_fd, keys.encode('utf-8'))
        app.logger.info(f"Sent keys for sync: '{keys.strip()}'")

        # Initial sleep to allow the command to start
        time.sleep(1.0)

        # Check if shell is still running after sending keys and initial sleep
        if proc.poll() is not None:
            return jsonify({"status": "success", "message": "Shell process exited shortly after command submission."})

        pgid = os.getpgid(proc.pid)
        app.logger.info(f"Waiting for command completion in PGID {pgid} (shell PID: {proc.pid}). Max wait: {MAX_SYNC_WAIT_SECONDS}s.")

        start_time = time.time()
        while time.time() - start_time < MAX_SYNC_WAIT_SECONDS:
            if proc.poll() is not None: # Shell itself exited
                app.logger.info(f"Shell process (PID: {proc.pid}, PGID: {pgid}) exited during wait.")
                return jsonify({"status": "success", "message": "Shell process exited during command execution."})

            current_process_count = count_processes_in_pgroup(pgid)
            app.logger.debug(f"Polling PGID {pgid}: {current_process_count} processes.")

            if current_process_count == 1: # Only the shell itself remains
                app.logger.info(f"Command completed in PGID {pgid}. Only shell process found.")
                return jsonify({"status": "success", "message": "Command completed."})
            elif current_process_count == 0: # PGID became empty (shell exited)
                app.logger.info(f"Process group {pgid} became empty. Shell likely exited.")
                return jsonify({"status": "success", "message": "Shell process group became empty, command considered complete."})
            elif current_process_count < 0: # Error in counting
                app.logger.error(f"Error counting processes for PGID {pgid}.")
                return jsonify({"status": "error", "message": "Failed to count processes in process group."}), 500
            
            time.sleep(0.5) # Polling interval

        app.logger.warning(f"Timeout waiting for command completion in PGID {pgid}.")
        return jsonify({"status": "timeout", "message": f"Command did not complete within {MAX_SYNC_WAIT_SECONDS} seconds."}), 503

    except ProcessLookupError: # os.getpgid(proc.pid) if proc died race condition
        app.logger.error("Shell process disappeared unexpectedly during /keystroke_sync.")
        return jsonify({"status": "error", "message": "Shell process disappeared unexpectedly."}), 500
    except OSError as e: # master_fd might be closed or other OS error
        app.logger.error(f"OSError during /keystroke_sync: {e}")
        return jsonify({"error": f"Error interacting with PTY: {e}"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in /keystroke_sync: {e}", exc_info=True)
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

@app.route('/screen', methods=['GET'])
def get_screen_capture():
    """
    Captures the current content of the virtual screen and returns it.
    """
    global screen
    app.logger.info("Received GET /screen")
    if not screen or not pty_running:
        app.logger.warning("Screen/PTY not active for /screen")
        return jsonify({"error": "Screen not active or not initialized"}), 503
    
    # Accessing screen.display and screen.cursor should be relatively safe.
    # For more complex interactions, a lock might be needed.
    display_data = [line for line in screen.display]
    cursor_data = {
        "x": screen.cursor.x,
        "y": screen.cursor.y,
        "hidden": screen.cursor.hidden
    }
    app.logger.debug(f"Screen data: {display_data}, Cursor: {cursor_data}")
    return jsonify({"screen": display_data, "cursor": cursor_data})

@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 errors by logging and returning a JSON response."""
    app.logger.warning(f"Invalid URL accessed: {request.path} - {e}")
    return jsonify(error=f"Endpoint not found: {request.path}"), 404

# --- Cleanup Function ---
def cleanup_pty_and_process():
    """
    Cleans up the PTY file descriptors and terminates the subprocess.
    """
    global pty_running, proc, master_fd, slave_fd, pty_thread

    print("Initiating cleanup...")
    pty_running = False  # Signal PTY reader thread to stop

    # Wait for PTY reader thread to finish
    if pty_thread and pty_thread.is_alive():
        print("Waiting for PTY reader thread to exit...")
        pty_thread.join(timeout=1.0) # Wait for a short period
        if pty_thread.is_alive():
            print("PTY reader thread did not exit gracefully.")

    # Terminate the subprocess (shell and its children)
    if proc and proc.poll() is None:  # Check if process is still running
        shell_pgid = os.getpgid(proc.pid) # Get PGID before it potentially exits
        print(f"Terminating shell process tree (PGID: {shell_pgid})...")
        try:
            os.killpg(shell_pgid, signal.SIGTERM)  # Send SIGTERM to the process group
            proc.wait(timeout=2)  # Wait for graceful termination
        except ProcessLookupError:
            print(f"Shell process group (PGID: {shell_pgid}) already exited.")
        except subprocess.TimeoutExpired:
            print(f"Shell process tree (PGID: {shell_pgid}) did not terminate gracefully with SIGTERM, sending SIGKILL...")
            try:
                os.killpg(shell_pgid, signal.SIGKILL)  # Force kill
                proc.wait(timeout=2)  # Wait for forced termination
            except ProcessLookupError: # Could have exited between SIGTERM and SIGKILL
                print(f"Shell process group (PGID: {shell_pgid}) already exited before SIGKILL.")
            except Exception as e_kill:
                print(f"Error force killing process group (PGID: {shell_pgid}): {e_kill}")
        except Exception as e_term:
            print(f"Error terminating process group (PGID: {shell_pgid}): {e_term}")
    elif proc:
        print("Shell process already terminated.")
    proc = None # Mark as handled

    # Close PTY file descriptors
    # Make copies and set globals to None first to prevent re-entry issues or use after close
    temp_master_fd = master_fd
    master_fd = None
    if temp_master_fd is not None:
        print("Closing master PTY FD.")
        try:
            os.close(temp_master_fd)
        except OSError as e:
            print(f"Error closing master_fd: {e}")

    temp_slave_fd = slave_fd # slave_fd is the one created by openpty, not used directly after Popen
    slave_fd = None
    if temp_slave_fd is not None:
        print("Closing slave PTY FD (parent's copy).")
        try:
            os.close(temp_slave_fd)
        except OSError as e:
            print(f"Error closing slave_fd: {e}")
    
    print("Cleanup finished.")

# --- Signal Handler for Ctrl+C ---
def sigint_handler(sig, frame):
    """
    Handles SIGINT (Ctrl+C). Initiates process termination and raises KeyboardInterrupt.
    """
    global proc, pty_running
    print("\nCtrl+C received by signal handler. Initiating shutdown sequence.")
    
    pty_running = False # Signal PTY reader thread to stop ASAP

    if proc and proc.poll() is None:
        pgid_to_signal = -1
        try:
            pgid_to_signal = os.getpgid(proc.pid)
            print(f"SIGINT: Terminating shell process tree (PGID: {pgid_to_signal}) immediately...")
            # Send SIGTERM to the entire process group of the shell
            os.killpg(pgid_to_signal, signal.SIGTERM)
        except ProcessLookupError:
             print(f"SIGINT: Shell process (PGID: {pgid_to_signal if pgid_to_signal != -1 else 'unknown'}) already exited.")
        except Exception as e:
            print(f"SIGINT: Error sending SIGTERM to process group (PGID: {pgid_to_signal if pgid_to_signal != -1 else 'unknown'}): {e}")
    
    # Raising KeyboardInterrupt allows Flask to perform its own shutdown,
    # and then the `finally` block in `main()` will execute `cleanup_pty_and_process`.
    raise KeyboardInterrupt

# --- Main Application ---
def main():
    global master_fd, slave_fd, proc, screen, stream, pty_running, pty_thread

    # PTY dimensions and environment variables
    cols, lines = 80, 24  # Standard terminal dimensions
    env = os.environ.copy()
    env.update({
        "TERM": "vt100",  # A simple terminal type
        "COLUMNS": str(cols),
        "LINES": str(lines),
        "PS1": "[PTY]\\$ ",  # A simple, predictable prompt for bash
        "PROMPT_COMMAND": "", # Avoids potential escape codes from default PROMPT_COMMAND
    })

    try:
        # Create a new PTY
        # master_fd is for the parent (this script)
        # slave_fd_temp is for the child process (bash)
        master_fd_temp, slave_fd_temp = pty.openpty()
        
        # Assign to globals *after* successful creation
        master_fd = master_fd_temp
        slave_fd = slave_fd_temp # Store parent's copy of slave FD for cleanup

        # Determine the shell to use
        shell_cmd = os.environ.get("SHELL", "/bin/bash") # Default to /bin/bash if $SHELL is not set
        print(f"Using shell: {shell_cmd}")

        # Start the shell in the PTY.
        # -i for interactive mode (if supported by the shell).
        # preexec_fn=os.setsid makes the shell a new session leader, crucial for os.killpg.
        proc = subprocess.Popen(
            [shell_cmd, "-i"], # Attempt to run in interactive mode
            stdin=slave_fd,  # Use the slave FD for shell's stdio
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True,   # Close other FDs in child, except 0,1,2 which are set by stdin/out/err
            preexec_fn=os.setsid
        )
        print(f"Shell process ({shell_cmd}) started with PID: {proc.pid}, PGID: {os.getpgid(proc.pid)}")

        # After Popen, the child has its stdio connected to its end of the PTY.
        # The parent's copy of slave_fd is not directly used for read/write by the parent,
        # but it needs to be kept open until the child is done, then closed by cleanup.

        # Initialize pyte screen and stream
        screen = pyte.Screen(cols, lines)
        stream = pyte.Stream(screen)
        pty_running = True  # Set flag before starting thread

        # Start the PTY reader thread
        # daemon=True ensures thread exits if main thread exits unexpectedly
        pty_thread = threading.Thread(target=pty_reader_thread_function, daemon=True)
        pty_thread.start()

        # Give bash and pty_reader a moment to initialize and print the first prompt
        print("Waiting a moment for PTY to initialize...")
        time.sleep(0.5) # Increased slightly for more reliability

        # Set up signal handler for Ctrl+C (SIGINT)
        # This should be set up after PTY and process are initialized.
        signal.signal(signal.SIGINT, sigint_handler)

        print(f"Flask server starting on http://127.0.0.1:5399")
        print("Endpoints:")
        print("  POST /keystroke (form data: {'keys': 'your_command\\n'})")
        print("  POST /keystroke_sync (form data: {'keys': 'your_command\\n'})")
        print("  GET  /screen")
        
        # Run Flask web server.
        # use_reloader=False is critical when managing subprocesses and threads.
        # debug=True enables Flask's debugger and more verbose logging.
        app.run(host='127.0.0.1', port=5399, debug=True, use_reloader=False)

    except KeyboardInterrupt:
        print("KeyboardInterrupt caught in main. Shutting down...")
    except Exception as e:
        print(f"An unexpected error occurred in main: {e}")
    finally:
        print("Main finally block: Performing cleanup...")
        cleanup_pty_and_process()
        print("Application finished.")

if __name__ == '__main__':
    main()
