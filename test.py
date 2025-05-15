#!/usr/bin/env python3
import os
import pty
import subprocess
import select
import pyte
import unicodedata # Added for character category checking
import argparse # Added for command-line arguments
import logging # Added for setting logger level
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

# --- Global for verbose logging ---
verbose_logging_enabled = False

# --- Globals for capturing terminal output lines ---
# Stores complete lines captured from the PTY stream
pyte_listener_lines = []
# Accumulates characters for the current line being built by LoggingStream
current_line_buffer_for_listener = ""
# Lock to protect access to pyte_listener_lines and current_line_buffer_for_listener
pyte_listener_lock = threading.Lock()

# Flask application
app = Flask(__name__)

# Maximum wait time for synchronous keystroke command completion (in seconds)
MAX_SYNC_WAIT_SECONDS = 60

# --- Custom Listener for Line Capture ---
class LineCaptureListener: # No longer inherits from pyte.Stream
    def __init__(self):
        # This listener uses global variables for line capture:
        # pyte_listener_lines, current_line_buffer_for_listener, pyte_listener_lock
        # No complex initialization needed here.
        # Removed diagnostic prints as they are not relevant for a simple listener.
        pass

    def dispatch(self, event: str, *args, **kwargs) -> None: # pyte listener interface
        # Raw print to stderr to confirm entry, bypassing Flask logger for this specific check.
        # Log event and args for better diagnostics.
        print(f"RAW_DISPATCH_ENTRY (LineCaptureListener): event='{event}', args={args}, kwargs={kwargs}", file=sys.stderr, flush=True)
        
        global current_line_buffer_for_listener, pyte_listener_lines, pyte_listener_lock, verbose_logging_enabled
        # Log entry into dispatch, using event and args.
        app.logger.debug(f"LineCaptureListener.dispatch entered: event='{event}', args={args}, verbose_enabled_in_dispatch={verbose_logging_enabled}")

        # This listener is only interested in "TEXT" events for line capture.
        # It does not call super().dispatch() as it's not part of a complex inheritance chain
        # for dispatching, and it's not a pyte.Stream itself.
        # The pyte.Stream that this listener is attached to will handle dispatching
        # to other listeners (like pyte.Screen).

        if event == "TEXT":
            if not args: # Should not happen for TEXT event, but good to guard
                app.logger.warning("LoggingStream: TEXT event received with no args.")
                return
            
            char = args[0] # For "TEXT" event, the character is the first argument

            # All subsequent character processing logic is now conditional on event == "TEXT"
            # and uses 'char' derived from args[0].
            with pyte_listener_lock:
                if char == "\n":
                    app.logger.debug(f"LoggingStream LF: Appending CBL ('{current_line_buffer_for_listener}') to PLL. Old PLL len: {len(pyte_listener_lines)}")
                    pyte_listener_lines.append(current_line_buffer_for_listener)
                    app.logger.debug(f"LoggingStream LF: CBL ('{current_line_buffer_for_listener}') appended. New PLL len: {len(pyte_listener_lines)}. Clearing CBL.")
                    current_line_buffer_for_listener = ""
                    app.logger.debug(f"LoggingStream LF: CBL cleared. PLL (last 3): {pyte_listener_lines[-3:] if len(pyte_listener_lines) > 3 else pyte_listener_lines}")
                    if verbose_logging_enabled: # Keep verbose for even more detail if needed
                        app.logger.debug(f"Verbose LoggingStream LF: Full context: PLL (len {len(pyte_listener_lines)}) is {pyte_listener_lines[-5:] if len(pyte_listener_lines) > 5 else pyte_listener_lines}, CBL is ('{current_line_buffer_for_listener}')")
                elif char == "\r":
                    app.logger.debug(f"LoggingStream CR: Appending CBL ('{current_line_buffer_for_listener}') to PLL. Old PLL len: {len(pyte_listener_lines)}")
                    pyte_listener_lines.append(current_line_buffer_for_listener) # Always append, even if empty
                    app.logger.debug(f"LoggingStream CR: CBL ('{current_line_buffer_for_listener}') appended. New PLL len: {len(pyte_listener_lines)}. Clearing CBL.")
                    current_line_buffer_for_listener = ""
                    app.logger.debug(f"LoggingStream CR: CBL cleared. PLL (last 3): {pyte_listener_lines[-3:] if len(pyte_listener_lines) > 3 else pyte_listener_lines}")
                    if verbose_logging_enabled: # Keep verbose for even more detail if needed
                        app.logger.debug(f"Verbose LoggingStream CR: Full context: PLL (len {len(pyte_listener_lines)}) is {pyte_listener_lines[-5:] if len(pyte_listener_lines) > 5 else pyte_listener_lines}, CBL is ('{current_line_buffer_for_listener}')")
                elif char == "\x08":  # Backspace
                    if current_line_buffer_for_listener:
                        old_cbl = current_line_buffer_for_listener
                        current_line_buffer_for_listener = current_line_buffer_for_listener[:-1]
                        app.logger.debug(f"LoggingStream BS: CBL was '{old_cbl}', now '{current_line_buffer_for_listener}'")
                    else:
                        app.logger.debug(f"LoggingStream BS: CBL empty, no change.")
                    if verbose_logging_enabled: # Keep verbose for even more detail if needed
                         app.logger.debug(f"Verbose LoggingStream BS: Context: PLL (len {len(pyte_listener_lines)}): {pyte_listener_lines[-3:] if len(pyte_listener_lines) > 3 else pyte_listener_lines}")
                # Check if it's a printable char (not a control character)
                # This check is implicitly handled by pyte parser giving "TEXT" event for printable chars.
                # Non-printable chars that are part of control sequences come as other events (CSI, ESC etc.)
                # So, if event is "TEXT", char is expected to be printable or simple whitespace.
                elif not unicodedata.category(char).startswith('C'): # Keep this check for robustness with TEXT
                    # Unconditional log for character addition
                    app.logger.debug(f"LoggingStream CHAR: Adding char '{char.encode('unicode_escape').decode()}' to CBL. Old CBL: '{current_line_buffer_for_listener}'")
                    current_line_buffer_for_listener += char
                    app.logger.debug(f"LoggingStream CHAR: CBL after adding char: '{current_line_buffer_for_listener}'")
                    if verbose_logging_enabled: # Keep verbose for even more detail if needed
                        app.logger.debug(f"Verbose LoggingStream CHAR: Context: PLL (len {len(pyte_listener_lines)}): {pyte_listener_lines[-3:] if len(pyte_listener_lines) > 3 else pyte_listener_lines}")
        # Else (if event is not "TEXT"): it's a control sequence (like ESC, CSI, etc.) or other event.
        # It was already processed by super().dispatch() for pyte.Screen.
        # We are not logging these non-TEXT events to our custom line buffer.

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
                            app.logger.debug(f"PTY Reader: About to call stream.feed(). stream object type: {type(stream)}, stream object: {stream}")
                            # REMOVED Direct diagnostic call to stream.dispatch()
                            # The following block was for diagnostics and is now removed:
                            # if decoded_data:
                            #     first_char_for_direct_test = decoded_data[0]
                            #     app.logger.debug(f"PTY Reader: Attempting DIRECT call to stream.dispatch() with event='TEXT', char='{first_char_for_direct_test.encode('unicode_escape').decode()}'")
                            #     try:
                            #         stream.dispatch("TEXT", first_char_for_direct_test)
                            #     except Exception as e_direct_dispatch:
                            #         app.logger.error(f"PTY Reader: EXCEPTION during DIRECT call to stream.dispatch('TEXT', char): {e_direct_dispatch}", exc_info=True)
                            
                            app.logger.debug(f"PTY Reader: Now calling stream.feed() with all {len(decoded_data)} chars.")
                            stream.feed(decoded_data)
                        else:
                            app.logger.warning("PTY Reader: stream object is None. Cannot feed data.")
                    else:  # EOF: PTY has been closed (e.g., shell exited)
                        app.logger.info("PTY EOF (empty data read), stopping reader thread.")
                        pty_running = False # Signal to stop, if not already
                        break
                except OSError:  # Happens if FD is closed by another thread
                    app.logger.warning("PTY read error (FD likely closed), stopping reader thread.")
                    pty_running = False
                    break
                except Exception as e:
                    app.logger.error(f"Error in PTY reader: {e}", exc_info=True)
                    pty_running = False
                    break
    finally:
        app.logger.info("PTY reader thread exited.")

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
    global master_fd, proc, slave_fd, pyte_listener_lines, current_line_buffer_for_listener, pyte_listener_lock
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

        # Snapshot captured lines before sending keys and command execution
        with pyte_listener_lock:
            lines_before_command_effect = list(pyte_listener_lines)
            # current_line_buffer_for_listener holds the prompt the user is about to type on,
            # or an empty string if the prompt ended with \n or \r.
            # This initial current line will be merged with the typed keys by LoggingStream.
            app.logger.debug(f"SYNC: lines_before_command_effect: {lines_before_command_effect}")
        
        os.write(master_fd, keys.encode('utf-8'))
        app.logger.info(f"Sent keys for sync: '{keys.strip()}'")

        # Initial sleep to allow the command to start and for its echo to be processed
        time.sleep(1.0) 

        # Check if shell is still running after sending keys and initial sleep
        if proc.poll() is not None:
            app.logger.info("Shell process exited shortly after command submission and initial sleep.")
            # Capture output even if shell exits quickly
            with pyte_listener_lock:
                lines_after_command_effect = list(pyte_listener_lines)
                final_current_line = current_line_buffer_for_listener
                app.logger.debug(f"SYNC (shell exited path): lines_after_command_effect (len {len(lines_after_command_effect)}): {lines_after_command_effect[-5:] if len(lines_after_command_effect) > 5 else lines_after_command_effect}")
                app.logger.debug(f"SYNC (shell exited path): final_current_line: '{final_current_line}'")
                
                output_segment = lines_after_command_effect[len(lines_before_command_effect):]
                if final_current_line: # Add the last incomplete line (new prompt, or partial output)
                    output_segment.append(final_current_line)

                # Reset log for next command - consistent with main path
                current_line_buffer_for_listener = final_current_line
                pyte_listener_lines = []
                app.logger.debug(f"SYNC (shell exited path): Reset CBL to '{current_line_buffer_for_listener}', PLL to empty.")

            app.logger.debug(f"SYNC (shell exited path): Returning output_segment (len {len(output_segment)}): {output_segment[-5:] if len(output_segment) > 5 else output_segment}")
            return jsonify({"status": "success", "message": "Shell process exited shortly after command submission.", "output": output_segment})

        shell_pid = proc.pid
        shell_pgid = os.getpgid(shell_pid) # PGID of the shell process itself
        app.logger.info(f"Waiting for command completion. Shell PID: {shell_pid}, Shell PGID: {shell_pgid}. Max wait: {MAX_SYNC_WAIT_SECONDS}s.")
        
        start_time = time.time()
        command_completed_normally = False
        completion_message = "Command completion status unknown."

        while time.time() - start_time < MAX_SYNC_WAIT_SECONDS:
            if proc.poll() is not None: # Shell itself exited
                app.logger.info(f"Shell process (PID: {shell_pid}) exited during wait.")
                completion_message = "Shell process exited during command execution."
                command_completed_normally = True # Or consider it a form of completion
                break

            # Platform-specific command completion check
            if sys.platform == "darwin": # macOS
                try:
                    pstree_cmd = ["pstree", str(shell_pid)]
                    # Execute pstree and capture its output.
                    result = subprocess.run(pstree_cmd, capture_output=True, text=True, check=False)
                    
                    app.logger.debug(f"pstree for PID {shell_pid} (rc={result.returncode}):\nSTDOUT: {result.stdout.strip()}\nSTDERR: {result.stderr.strip()}")

                    if result.returncode == 0:
                        output_lines = result.stdout.strip().splitlines()
                        # Assumption: 1 line of output from `pstree <pid>` means the process has no children.
                        if len(output_lines) == 1:
                            app.logger.info(f"macOS pstree check: Shell PID {shell_pid} has no children. Command complete.")
                            completion_message = "Command completed (macOS pstree check)."
                            command_completed_normally = True
                            break # Exit the loop, output will be handled below
                        # else: shell has children (pstree output > 1 line), command still running. Loop continues.
                    else:
                        # pstree command failed. Check if the shell process itself has exited.
                        if proc.poll() is not None:
                             app.logger.info(f"Shell process (PID: {shell_pid}) exited (detected after pstree failure).")
                             completion_message = "Shell process exited (detected after pstree failure)."
                             command_completed_normally = True # Consider this a form of completion
                             break # Exit the loop, output will be handled below
                        # Shell is still running, but pstree failed for another reason.
                        app.logger.warning(f"pstree command for PID {shell_pid} failed (rc={result.returncode}, stderr: {result.stderr.strip()}). Assuming command still running or error with pstree.")
                        # Continue loop; will eventually timeout if this state persists.
                
                except FileNotFoundError:
                    app.logger.error("'pstree' command not found. This is required for /keystroke_sync on macOS.")
                    return jsonify({"status": "error", "message": "'pstree' command not found. Required for sync operations on macOS."}), 500
                except Exception as e_pstree:
                    app.logger.error(f"Unexpected error during pstree check for PID {shell_pid}: {e_pstree}", exc_info=True)
                    return jsonify({"status": "error", "message": f"Unexpected error during pstree check: {e_pstree}"}), 500
            
            else: # Not macOS (e.g., Linux), use existing tcgetpgrp logic
                app.logger.debug(f"Using tcgetpgrp on slave FD {slave_fd} for non-macOS platform (Shell PGID: {shell_pgid}).")
                try:
                    sfd_isatty = os.isatty(slave_fd)
                    sfd_name = "N/A"
                    if sfd_isatty:
                        try:
                            sfd_name = os.ttyname(slave_fd)
                        except OSError as e_ttyname:
                            sfd_name = f"Error getting ttyname: {e_ttyname}"
                    app.logger.debug(f"Diagnostics for slave_fd ({slave_fd}): isatty={sfd_isatty}, name='{sfd_name}'")

                    current_foreground_pgid = os.tcgetpgrp(slave_fd)
                    app.logger.debug(f"Polling PTY's foreground PGID: {current_foreground_pgid}. Shell's PGID: {shell_pgid}.")
                except OSError as e:
                    app.logger.error(f"Error calling tcgetpgrp on slave_fd ({slave_fd}): {e} (errno: {e.errno}). Assuming command finished or error.")
                    # If tcgetpgrp fails, check if shell exited. If so, consider command done.
                    if proc.poll() is not None:
                        completion_message = "Shell process exited, PTY state uncertain after tcgetpgrp error."
                        command_completed_normally = True
                        break
                    # If shell still running, this is an error with PTY state.
                    return jsonify({"status": "error", "message": f"Error checking PTY foreground process group: {e}"}), 500

                if current_foreground_pgid == shell_pgid:
                    app.logger.info(f"Shell (PGID {shell_pgid}) is foreground process group on PTY. Command considered complete.")
                    completion_message = "Command completed."
                    command_completed_normally = True
                    break
            
            time.sleep(0.5) # Polling interval
        
        # After loop: either completed, timed out, or shell exited.
        # Add a very short sleep here to allow any final PTY output (e.g., final prompt)
        # to be processed by the pty_reader_thread and LoggingStream before we capture the output.
        # This is especially important if command completion was detected very quickly.
        time.sleep(0.2) # Short final delay for output processing

        if not command_completed_normally and proc.poll() is None: # Timeout
            app.logger.warning(f"Timeout waiting for command completion (Shell PGID: {shell_pgid} did not become foreground).")
            completion_message = f"Command did not complete within {MAX_SYNC_WAIT_SECONDS} seconds."
            status_code = 503 
            result_status = "timeout"
        elif not command_completed_normally and proc.poll() is not None: # Shell exited during loop but not caught as completion
             app.logger.info(f"Shell process (PID: {shell_pid}) exited during wait (final check).")
             completion_message = "Shell process exited during command execution (final check)."
             status_code = 200
             result_status = "success" # Or "shell_exited"
        else: # Command completed normally or shell exited and was marked as completion
            status_code = 200
            result_status = "success"

        # Capture the output lines
        with pyte_listener_lock:
            lines_after_command_effect = list(pyte_listener_lines)
            final_current_line = current_line_buffer_for_listener
            app.logger.debug(f"SYNC: lines_after_command_effect: {lines_after_command_effect}")
            app.logger.debug(f"SYNC: final_current_line: '{final_current_line}'")
            
            # Construct the output segment from the point the command started affecting the log
            output_segment = lines_after_command_effect[len(lines_before_command_effect):]
            if final_current_line: # Add the last incomplete line (new prompt, or partial output)
                output_segment.append(final_current_line)

            # Reset log for the next command: the new prompt (or lack thereof) is in final_current_line.
            # pyte_listener_lines should be empty as all lines up to the new prompt have been consumed.
            # current_line_buffer_for_listener should hold the new prompt.
            current_line_buffer_for_listener = final_current_line
            pyte_listener_lines = []
        
        app.logger.debug(f"SYNC: Returning output_segment: {output_segment}")
        return jsonify({"status": result_status, "message": completion_message, "output": output_segment}), status_code

    except ProcessLookupError: # os.getpgid(proc.pid) can fail if proc died just before the call
        app.logger.error("Shell process disappeared unexpectedly (ProcessLookupError) during /keystroke_sync.")
        # Attempt to capture output anyway
        with pyte_listener_lock:
            lines_after_command_effect = list(pyte_listener_lines)
            final_current_line = current_line_buffer_for_listener
            output_segment = lines_after_command_effect[len(lines_before_command_effect):] # Use previously captured lines_before_command_effect
            if final_current_line: output_segment.append(final_current_line)
            # Reset log consistent with the main path
            current_line_buffer_for_listener = final_current_line
            pyte_listener_lines = []
        return jsonify({"status": "error", "message": "Shell process disappeared unexpectedly.", "output": output_segment}), 500
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
    
    # log_func("SIGINT handler: Performing direct cleanup and exiting.")
    # cleanup_pty_and_process() # Call cleanup directly.
    
    # Re-raise KeyboardInterrupt to allow the main thread's try/except/finally
    # to execute, which includes calling cleanup_pty_and_process.
    # This makes the shutdown flow more standard with Flask/Werkzeug.
    log_func("SIGINT handler: Raising KeyboardInterrupt for main thread shutdown.")
    raise KeyboardInterrupt

# --- Main Application ---
def main():
    global master_fd, slave_fd, proc, screen, stream, pty_running, pty_thread, verbose_logging_enabled

    parser = argparse.ArgumentParser(description="Run a PTY-backed shell with Flask API.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging of PTY stream processing.")
    args = parser.parse_args()

    if args.verbose:
        verbose_logging_enabled = True
        # Set Flask's logger level to DEBUG to see our verbose logs
        app.logger.setLevel(logging.DEBUG)
        app.logger.info("Verbose logging enabled for LoggingStream (app.logger set to DEBUG).")
    else:
        # Default Flask logger level is INFO if not in debug mode.
        # If Flask's debug=True is set, it might default to DEBUG anyway,
        # but explicitly setting INFO here for non-verbose mode is clearer.
        app.logger.setLevel(logging.INFO)


    # PTY dimensions
    cols, lines = 80, 24  # Standard terminal dimensions
    
    # Base environment for the PTY, common to all shells
    env = os.environ.copy()
    env.update({
        "TERM": "vt100",        # A simple terminal type
        "COLUMNS": str(cols),
        "LINES": str(lines),
        # Set a very basic PATH to avoid issues with user's PATH causing unexpected behavior
        # and to ensure common commands are found. Adjust if specific paths are needed.
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",            # Use a simple locale to avoid complex char issues
        "LC_ALL": "C",
    })

    # Determine the shell to use and customize args/env
    shell_path = os.environ.get("SHELL", "/bin/bash") # Default to /bin/bash
    shell_name = os.path.basename(shell_path)
    
    shell_args_for_popen = [shell_path] # The first argument is the shell executable

    # Customize arguments and environment based on the shell type
    # The goal is to get a simple, interactive shell without user-specific rc files.
    if shell_name == "zsh":
        app.logger.info(f"Configuring for zsh: {shell_path}")
        # -f: Start Zsh without sourcing .zshrc or other startup files.
        # -i: Force interactive mode.
        shell_args_for_popen.extend(["-f", "-i"])
        env["PROMPT"] = "[vm:%~] %(#.#.$) " # New zsh prompt
        # Zsh might still try to source global rc files (/etc/zsh*), -f primarily targets user files.
    elif shell_name == "bash":
        app.logger.info(f"Configuring for bash: {shell_path}")
        # --norc: Do not read and execute the personal initialization file ~/.bashrc.
        # --noprofile: Do not read system-wide or personal profile initialization files.
        # -i: Force interactive mode.
        shell_args_for_popen.extend(["--norc", "--noprofile", "-i"])
        env["PS1"] = "[vm:\\w] \\$ " # New bash prompt
        # PROMPT_COMMAND can also affect bash prompts, ensure it's empty.
        env["PROMPT_COMMAND"] = "" 
    else: # For other shells (e.g., sh, dash, ksh)
        app.logger.info(f"Configuring for generic shell ({shell_name}): {shell_path}")
        # Attempt interactive mode. Startup file skipping varies by shell.
        shell_args_for_popen.append("-i") 
        env["PS1"] = f"[vm:\\w] \\$ " # New generic prompt, using bash-like syntax

    app.logger.info(f"Shell command for Popen: {shell_args_for_popen}")
    app.logger.info(f"Shell environment for Popen (selected keys): "
                    f"TERM={env.get('TERM')}, PS1={env.get('PS1')}, PROMPT={env.get('PROMPT')}, "
                    f"PROMPT_COMMAND={env.get('PROMPT_COMMAND')}, LANG={env.get('LANG')}")

    try:
        # Create a new PTY
        master_fd_temp, slave_fd_temp = pty.openpty()
        
        master_fd = master_fd_temp
        slave_fd = slave_fd_temp # Store parent's copy of slave FD for cleanup

        # Start the shell in the PTY.
        # preexec_fn=os.setsid makes the shell a new session leader, crucial for os.killpg.
        proc = subprocess.Popen(
            shell_args_for_popen, # Use the customized arguments
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env, # Use the customized environment
            close_fds=True,
            preexec_fn=os.setsid
        )
        app.logger.info(f"Shell process ({shell_path}) started with PID: {proc.pid}, PGID: {os.getpgid(proc.pid)}")

        # After Popen, the child has its stdio connected to its end of the PTY.
        # The parent's copy of slave_fd is not directly used for read/write by the parent,
        # but it needs to be kept open until the child is done, then closed by cleanup.

        # Initialize pyte screen, our custom line capture listener, and a standard pyte stream
        screen = pyte.Screen(cols, lines)
        line_capturer = LineCaptureListener() # Instantiate our custom listener
        stream = pyte.Stream()                # Instantiate a standard pyte.Stream

        stream.attach(screen)        # Attach the screen to display terminal content
        stream.attach(line_capturer) # Attach our listener to capture lines

        pty_running = True  # Set flag before starting thread

        # Start the PTY reader thread
        # daemon=True ensures thread exits if main thread exits unexpectedly
        pty_thread = threading.Thread(target=pty_reader_thread_function, daemon=True)
        pty_thread.start()

        # Give shell and pty_reader a moment to initialize and print the first prompt
        app.logger.info("Waiting a moment for PTY to initialize...")
        time.sleep(0.5)

        # Set up signal handler for Ctrl+C (SIGINT)
        # This should be set up after PTY and process are initialized.
        signal.signal(signal.SIGINT, sigint_handler)

        app.logger.info(f"Flask server starting on http://127.0.0.1:5399")
        app.logger.info("Endpoints:")
        app.logger.info("  POST /keystroke (form data: {'keys': 'your_command\\n'})")
        app.logger.info("  POST /keystroke_sync (form data: {'keys': 'your_command\\n'})")
        app.logger.info("  GET  /screen")
        
        # Attempt to set the host TTY to a sane state before Flask runs,
        # if we are connected to a TTY. This can help if terminal settings
        # were inadvertently changed.
        if sys.stdin.isatty():
            app.logger.info("Attempting to set host TTY to 'sane' mode.")
            try:
                subprocess.run(["stty", "sane"], check=True)
            except FileNotFoundError:
                app.logger.warning("'stty' command not found. Cannot set TTY to sane mode.")
            except subprocess.CalledProcessError as e:
                app.logger.warning(f"Failed to set TTY to sane mode: {e}")
            except Exception as e:
                app.logger.warning(f"An unexpected error occurred while trying to run 'stty sane': {e}")

        # Run Flask web server.
        # use_reloader=False is critical when managing subprocesses and threads.
        # debug=True enables Flask's debugger and more verbose logging.
        app.run(host='127.0.0.1', port=5399, debug=True, use_reloader=False)

    except KeyboardInterrupt: 
        app.logger.info("KeyboardInterrupt caught in main. Shutting down...")
    except Exception as e:
        app.logger.error(f"An unexpected error occurred in main: {e}", exc_info=True)
    finally:
        # This finally block will run if KeyboardInterrupt is caught by main (now expected due to sigint_handler),
        # or if app.run() exits normally, or if another exception occurs in main's try block.
        app.logger.info("Main finally block reached.")
        # cleanup_pty_and_process is designed to be idempotent and handles all necessary cleanup.
        # It will be called here regardless of how the try block exits.
        app.logger.info("Main finally block: ensuring comprehensive cleanup.")
        cleanup_pty_and_process()
        app.logger.info("Application finished.")

if __name__ == '__main__':
    main()
