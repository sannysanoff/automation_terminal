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
    Completion is defined as the shell process regaining foreground control of the PTY.
    Expects form data: {'keys': 'your_command\\n'}
    """
    global master_fd, proc, slave_fd # slave_fd is needed for tcgetpgrp
    app.logger.info(f"Received POST /keystroke_sync. Form data: {request.form}")

    if not master_fd or not pty_running or slave_fd is None:
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
            app.logger.info("Shell process exited shortly after command submission and initial sleep.")
            return jsonify({"status": "success", "message": "Shell process exited shortly after command submission."})

        shell_pid = proc.pid
        shell_pgid = os.getpgid(shell_pid) # PGID of the shell process itself
        app.logger.info(f"Waiting for command completion. Shell PID: {shell_pid}, Shell PGID: {shell_pgid}. Max wait: {MAX_SYNC_WAIT_SECONDS}s.")
        app.logger.debug(f"Using slave FD {slave_fd} for tcgetpgrp checks.")

        start_time = time.time()
        while time.time() - start_time < MAX_SYNC_WAIT_SECONDS:
            if proc.poll() is not None: # Shell itself exited
                app.logger.info(f"Shell process (PID: {shell_pid}) exited during wait.")
                return jsonify({"status": "success", "message": "Shell process exited during command execution."})

            try:
                current_foreground_pgid = os.tcgetpgrp(slave_fd)
                app.logger.debug(f"Polling PTY's foreground PGID: {current_foreground_pgid}. Shell's PGID: {shell_pgid}.")
            except OSError as e:
                # This can happen if slave_fd is no longer valid (e.g., PTY closed, shell exited abruptly)
                app.logger.error(f"Error calling tcgetpgrp on slave_fd ({slave_fd}): {e}. Assuming command finished or error.")
                if proc.poll() is not None: # Check again if shell exited
                     return jsonify({"status": "success", "message": "Shell process exited, PTY state uncertain."})
                return jsonify({"status": "error", "message": f"Error checking PTY foreground process group: {e}"}), 500

            if current_foreground_pgid == shell_pgid:
                # The shell's process group is the foreground group on the PTY.
                # This means the shell is at a prompt, ready for new input.
                # Any command it launched in the foreground has completed.
                app.logger.info(f"Shell (PGID {shell_pgid}) is foreground process group on PTY. Command considered complete.")
                return jsonify({"status": "success", "message": "Command completed."})
            
            time.sleep(0.5) # Polling interval

        app.logger.warning(f"Timeout waiting for command completion (Shell PGID: {shell_pgid} did not become foreground).")
        return jsonify({"status": "timeout", "message": f"Command did not complete within {MAX_SYNC_WAIT_SECONDS} seconds."}), 503

    except ProcessLookupError: # os.getpgid(proc.pid) can fail if proc died just before the call
        app.logger.error("Shell process disappeared unexpectedly (ProcessLookupError) during /keystroke_sync.")
        return jsonify({"status": "error", "message": "Shell process disappeared unexpectedly."}), 500
    except OSError as e: # os.write, or other os calls if PTY state is bad
        app.logger.error(f"OSError during /keystroke_sync: {e}")
        # Check if it's an EIO error, which often means the PTY is gone
        if e.errno == 5: # EIO (Input/output error)
            app.logger.warning("OSError EIO, PTY may have been closed. Assuming command/shell exited.")
            return jsonify({"status": "success", "message": "PTY closed, command assumed complete or shell exited."})
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
    global pty_running, proc, master_fd, slave_fd, pty_thread, app

    # Use app.logger if available, otherwise fallback to print
    log_func = app.logger.info if app and hasattr(app, 'logger') else print

    log_func("Initiating cleanup...")
    pty_running = False  # Signal PTY reader thread to stop

    # Wait for PTY reader thread to finish
    if pty_thread and pty_thread.is_alive():
        log_func("Waiting for PTY reader thread to exit...")
        pty_thread.join(timeout=1.0) # Wait for a short period
        if pty_thread.is_alive():
            log_func("PTY reader thread did not exit gracefully.")

    # Terminate the subprocess (shell and its children)
    if proc and proc.poll() is None:  # Check if process is still running
        shell_pgid = -1 # Default value
        try:
            shell_pgid = os.getpgid(proc.pid) # Get PGID before it potentially exits
            log_func(f"Terminating shell process tree (PGID: {shell_pgid})...")
            os.killpg(shell_pgid, signal.SIGTERM)  # Send SIGTERM to the process group
            proc.wait(timeout=2)  # Wait for graceful termination
        except ProcessLookupError:
            log_func(f"Shell process group (PGID: {shell_pgid if shell_pgid != -1 else 'unknown'}) already exited.")
        except subprocess.TimeoutExpired:
            log_func(f"Shell process tree (PGID: {shell_pgid}) did not terminate gracefully with SIGTERM, sending SIGKILL...")
            try:
                os.killpg(shell_pgid, signal.SIGKILL)  # Force kill
                proc.wait(timeout=2)  # Wait for forced termination
            except ProcessLookupError: # Could have exited between SIGTERM and SIGKILL
                log_func(f"Shell process group (PGID: {shell_pgid}) already exited before SIGKILL.")
            except Exception as e_kill:
                log_func(f"Error force killing process group (PGID: {shell_pgid}): {e_kill}")
        except Exception as e_term: # Includes OSError if os.getpgid fails before assignment
            log_func(f"Error terminating process group (PGID: {shell_pgid if shell_pgid != -1 else 'unknown'}): {e_term}")
    elif proc:
        log_func("Shell process already terminated.")
    proc = None # Mark as handled

    # Close PTY file descriptors
    # Make copies and set globals to None first to prevent re-entry issues or use after close
    temp_master_fd = master_fd
    master_fd = None
    if temp_master_fd is not None:
        log_func("Closing master PTY FD.")
        try:
            os.close(temp_master_fd)
        except OSError as e:
            log_func(f"Error closing master_fd: {e}")

    temp_slave_fd = slave_fd # slave_fd is the one created by openpty, not used directly after Popen
    slave_fd = None
    if temp_slave_fd is not None:
        log_func("Closing slave PTY FD (parent's copy).")
        try:
            os.close(temp_slave_fd)
        except OSError as e:
            log_func(f"Error closing slave_fd: {e}")
    
    log_func("Cleanup finished.")

# --- Signal Handler for Ctrl+C ---
def sigint_handler(sig, frame):
    """
    Handles SIGINT (Ctrl+C). Initiates process termination and exits.
    """
    global proc, pty_running, app # Ensure app is accessible for logging

    # Use app.logger if available, otherwise fallback to print
    log_func = app.logger.info if app and hasattr(app, 'logger') else print

    log_func("\nCtrl+C received by signal handler. Initiating shutdown sequence.")
    
    pty_running = False # Signal PTY reader thread to stop ASAP

    if proc and proc.poll() is None:
        pgid_to_signal = -1
        try:
            pgid_to_signal = os.getpgid(proc.pid)
            log_func(f"SIGINT: Terminating shell process tree (PGID: {pgid_to_signal}) immediately...")
            # Send SIGTERM to the entire process group of the shell
            os.killpg(pgid_to_signal, signal.SIGTERM)
        except ProcessLookupError:
             log_func(f"SIGINT: Shell process (PGID: {pgid_to_signal if pgid_to_signal != -1 else 'unknown'}) already exited.")
        except Exception as e:
            log_func(f"SIGINT: Error sending SIGTERM to process group (PGID: {pgid_to_signal if pgid_to_signal != -1 else 'unknown'}): {e}")
    
    # Raising KeyboardInterrupt would normally be caught by main's try/except.
    # However, if Flask/Werkzeug interferes with this, a more direct approach is needed.
    
    log_func("SIGINT handler: Performing direct cleanup and exiting.")
    cleanup_pty_and_process() # Call cleanup directly.
    
    # Exit the entire process.
    # sys.exit(0) attempts a clean exit.
    # os._exit(0) is a more forceful exit that bypasses most cleanup; use if sys.exit hangs.
    sys.exit(0)

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

    except KeyboardInterrupt: # This might not be reached if sigint_handler exits directly
        app.logger.info("KeyboardInterrupt caught in main. Shutting down...")
    except Exception as e:
        app.logger.error(f"An unexpected error occurred in main: {e}", exc_info=True)
    finally:
        # This finally block will run if KeyboardInterrupt is caught by main,
        # or if app.run() exits normally, or if another exception occurs in main's try block.
        # If sigint_handler calls sys.exit(), this finally block in main might not run.
        app.logger.info("Main finally block reached.")
        # cleanup_pty_and_process is now primarily called from sigint_handler for Ctrl+C.
        # Call it here to handle non-Ctrl+C exits or if sigint_handler failed to fully cleanup.
        # cleanup_pty_and_process should be idempotent.
        if pty_running: # If pty_running is still true, sigint_handler might not have run or completed.
            app.logger.info("Main finally block: pty_running is true, ensuring cleanup.")
            cleanup_pty_and_process()
        else:
            # If pty_running is false, cleanup was likely initiated by sigint_handler.
            # A second call to an idempotent cleanup_pty_and_process is generally safe if needed,
            # but we rely on the signal handler's call for Ctrl+C.
            app.logger.info("Main finally block: pty_running is false, cleanup likely handled by sigint_handler or already in progress.")
        app.logger.info("Application finished.")

if __name__ == '__main__':
    main()
