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
                        print(f"PTY Read {len(decoded_data)} chars: '{log_snippet}...'")
                        if stream:
                            stream.feed(decoded_data)
                    else:  # EOF: PTY has been closed (e.g., bash exited)
                        print("PTY EOF (empty data read), stopping reader thread.")
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

    # Terminate the subprocess (bash and its children)
    if proc and proc.poll() is None:  # Check if process is still running
        print(f"Terminating bash process tree (PGID: {os.getpgid(proc.pid)})...")
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)  # Send SIGTERM to the process group
            proc.wait(timeout=2)  # Wait for graceful termination
        except ProcessLookupError:
            print("Bash process group already exited.")
        except subprocess.TimeoutExpired:
            print("Bash process tree did not terminate gracefully with SIGTERM, sending SIGKILL...")
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)  # Force kill
                proc.wait(timeout=2)  # Wait for forced termination
            except Exception as e_kill:
                print(f"Error force killing process group: {e_kill}")
        except Exception as e_term:
            print(f"Error terminating process group: {e_term}")
    elif proc:
        print("Bash process already terminated.")
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
        print("SIGINT: Terminating bash process tree immediately...")
        try:
            # Send SIGTERM to the entire process group of bash
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception as e:
            print(f"SIGINT: Error sending SIGTERM to process group: {e}")
    
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

        # Start bash in the PTY.
        # -i for interactive mode.
        # preexec_fn=os.setsid makes bash a new session leader, crucial for os.killpg.
        proc = subprocess.Popen(
            ["/bin/bash", "-i"],
            stdin=slave_fd,  # Use the slave FD for bash's stdio
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True,   # Close other FDs in child, except 0,1,2 which are set by stdin/out/err
            preexec_fn=os.setsid
        )
        print(f"Bash started with PID: {proc.pid}, PGID: {os.getpgid(proc.pid)}")

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

        print(f"Flask server starting on http://127.0.0.1:5000")
        print("Endpoints:")
        print("  POST /keystroke (form data: {'keys': 'your_command\\n'})")
        print("  GET  /screen")
        
        # Run Flask web server.
        # use_reloader=False is critical when managing subprocesses and threads.
        # debug=True enables Flask's debugger and more verbose logging.
        app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)

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
