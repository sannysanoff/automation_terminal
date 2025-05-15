package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/go-ansiterm"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	// "unicode" // Moved to event_handler.go if still needed there for IsPrint
)

// --- Global variables ---
var (
	// PTY and subprocess related
	ptyMaster            *os.File
	ptySlaveForTcgetpgrp *os.File // Parent's handle to the slave PTY, primarily for tcgetpgrp
	shellCmd             *exec.Cmd
	ansiParser           *ansiterm.AnsiParser
	eventHandler         *TermEventHandler // Our custom ANSI event handler

	// Control flag for the PTY reader goroutine
	ptyRunning    bool
	ptyRunningMu  sync.Mutex
	ptyReaderDone chan struct{} // To signal PTY reader completion

	// For capturing terminal output lines (now managed by eventHandler)
	// capturedLines               []string // Replaced by eventHandler.capturedLinesForSync
	// currentLineBuffer           bytes.Buffer // Replaced by eventHandler.lineBufferForCapture
	// capturedLinesMu             sync.Mutex // Replaced by eventHandler.mu (or could be separate if needed)

	verboseLoggingEnabled bool
	maxSyncWaitSeconds    int = 60 // Maximum wait time for synchronous keystroke command completion
	defaultPtyCols        int = 80 // Changed to int for easier use with TermEventHandler
	defaultPtyLines       int = 25 // Changed to int
)

// --- Structs for HTTP responses ---
type KeystrokeResponse struct {
	Status   string `json:"status"`
	KeysSent string `json:"keys_sent,omitempty"`
	Error    string `json:"error,omitempty"`
}

type KeystrokeSyncResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ScreenResponse struct {
	Screen []string          `json:"screen"`
	Cursor ScreenCursorState `json:"cursor"`
	Error  string            `json:"error,omitempty"`
}

type ScreenCursorState struct {
	X      uint `json:"x"`
	Y      uint `json:"y"`
	Hidden bool `json:"hidden"` // vt100.Canvas doesn't have a hidden cursor flag directly
}

func logInfo(format string, v ...interface{}) {
	log.Printf("INFO: "+format, v...)
}

func logWarn(format string, v ...interface{}) {
	log.Printf("WARN: "+format, v...)
}

func logError(format string, v ...interface{}) {
	log.Printf("ERROR: "+format, v...)
}

func logDebug(format string, v ...interface{}) {
	if verboseLoggingEnabled {
		log.Printf("DEBUG: "+format, v...)
	}
}

// --- PTY and Shell Setup ---
func setupPtyAndShell() error {
	logInfo("Setting up PTY and shell...")

	env := os.Environ()
	envMap := make(map[string]string)
	for _, e := range env {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) == 2 {
			envMap[pair[0]] = pair[1]
		}
	}

	envMap["TERM"] = "vt100" // go-ansiterm can parse vt100 sequences. "ansi" is also an option.
	envMap["COLUMNS"] = fmt.Sprintf("%d", defaultPtyCols)
	envMap["LINES"] = fmt.Sprintf("%d", defaultPtyLines)
	envMap["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" // Basic PATH
	envMap["LANG"] = "C"
	envMap["LC_ALL"] = "C"

	shellPath := os.Getenv("SHELL")
	if shellPath == "" {
		shellPath = "/bin/bash"
	}
	shellName := filepath.Base(shellPath)
	shellArgs := []string{shellPath}

	switch shellName {
	case "zsh":
		logInfo("Configuring for zsh: %s", shellPath)
		shellArgs = append(shellArgs, "-f", "-i")
		envMap["PROMPT"] = "[vm:%~] %(#.#.$) "
	case "bash":
		logInfo("Configuring for bash: %s", shellPath)
		shellArgs = append(shellArgs, "--norc", "--noprofile", "-i")
		envMap["PS1"] = "[vm:\\w] \\$ "
		envMap["PROMPT_COMMAND"] = ""
	case "sh":
		logInfo("Configuring for sh: %s", shellPath)
		// force interactive sh
		shellArgs = append(shellArgs, "-i")
		// PS1 with an incrementing command‐count (\#), literal "vm" and cwd (\w)
		envMap["PS1"] = "[\\#:vm:\\w] \\$ "
		envMap["PROMPT_COMMAND"] = ""
	default:
		logInfo("Configuring for generic shell (%s): %s", shellName, shellPath)
		shellArgs = append(shellArgs, "-i")
		envMap["PS1"] = fmt.Sprintf("[vm:%s] \\$ ", shellName)
	}

	var finalEnv []string
	for k, v := range envMap {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}
	logInfo("Shell command for Popen: %v", shellArgs)
	logInfo("Shell environment (selected keys): TERM=%s, PS1=%s, PROMPT=%s, PROMPT_COMMAND=%s, LANG=%s",
		envMap["TERM"], envMap["PS1"], envMap["PROMPT"], envMap["PROMPT_COMMAND"], envMap["LANG"])

	var err error
	// Use pty.Open() to get both master and slave FDs
	// ptmx is the master, tty is the slave
	ptmx, tty, err := pty.Open()
	if err != nil {
		return fmt.Errorf("failed to open PTY: %w", err)
	}
	ptyMaster = ptmx
	ptySlaveForTcgetpgrp = tty // Keep this for tcgetpgrp

	// Set the PTY size
	ws := &pty.Winsize{
		Rows: uint16(defaultPtyLines), // defaultPtyLines is now int, cast to uint16
		Cols: uint16(defaultPtyCols),  // defaultPtyCols is now int, cast to uint16
	}
	if err := pty.Setsize(ptyMaster, ws); err != nil {
		ptyMaster.Close()
		ptySlaveForTcgetpgrp.Close()
		return fmt.Errorf("failed to set PTY size: %w", err)
	}
	logInfo("PTY size set to %dx%d", defaultPtyCols, defaultPtyLines)

	shellCmd = exec.Command(shellArgs[0], shellArgs[1:]...)
	shellCmd.Env = finalEnv
	shellCmd.Stdin = tty // Use slave PTY for child's stdio
	shellCmd.Stdout = tty
	shellCmd.Stderr = tty

	// Set a new session ID for the shell process. This makes it a process group leader.
	// Important for os.killpg.
	if shellCmd.SysProcAttr == nil {
		shellCmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	shellCmd.SysProcAttr.Setsid = true
	// Setctty is also important for making the PTY its controlling terminal.
	// On Linux, Ctty should be the FD of the slave PTY.
	// When Stdin/Stdout/Stderr are set to the tty, explicitly setting Ctty can cause issues.
	// The kernel should infer the controlling TTY from FD 0 if it's a TTY.
	shellCmd.SysProcAttr.Setctty = true
	// shellCmd.SysProcAttr.Ctty = int(tty.Fd()) // This line is removed.

	err = shellCmd.Start()
	if err != nil {
		ptyMaster.Close()
		ptySlaveForTcgetpgrp.Close()
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// After shellCmd.Start(), the child process has inherited tty.
	// The parent usually closes its copy of tty for Stdin/Stdout/Stderr,
	// but we keep ptySlaveForTcgetpgrp open specifically for tcgetpgrp.
	// It will be closed during cleanup.

	logInfo("Shell process (%s) started with PID: %d, PGID: %d", shellPath, shellCmd.Process.Pid, shellCmd.Process.Pid)

	// Initialize TermEventHandler and AnsiParser
	eventHandler = NewTermEventHandler(defaultPtyLines, defaultPtyCols)
	// The initial state for the parser is "Ground" according to go-ansiterm examples.
	ansiParser = ansiterm.CreateParser("Ground", eventHandler)
	// If verbose logging for ansiterm parser itself is desired:
	// ansiParser = ansiterm.CreateParser("Ground", eventHandler, ansiterm.WithLogf(logDebug))

	ptyRunningMu.Lock()
	ptyRunning = true
	ptyRunningMu.Unlock()
	ptyReaderDone = make(chan struct{})

	return nil
}

// --- PTY Reader Goroutine ---
func ptyReader() {
	defer close(ptyReaderDone)
	logInfo("PTY reader goroutine started.")
	// Buffer for reading from PTY master
	buf := make([]byte, 4096)

	for {
		ptyRunningMu.Lock()
		if !ptyRunning {
			ptyRunningMu.Unlock()
			break
		}
		ptyRunningMu.Unlock()

		// Set a deadline for reading to make the loop check ptyRunning periodically
		// This also prevents Read from blocking indefinitely if ptyRunning is set to false.
		if ptyMaster == nil { // ptyMaster might be closed by cleanup
			logWarn("ptyMaster is nil in ptyReader loop, exiting.")
			break
		}
		ptyMaster.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, err := ptyMaster.Read(buf)
		if err != nil {
			if os.IsTimeout(err) { // Deadline exceeded
				continue // Loop back to check ptyRunning
			}
			// Handle other errors
			if err == io.EOF {
				logInfo("PTY EOF (shell exited), stopping reader goroutine.")
			} else if strings.Contains(err.Error(), "input/output error") || strings.Contains(err.Error(), "file already closed") {
				logWarn("PTY read error (FD likely closed by cleanup), stopping reader goroutine.")
			} else {
				logError("Error reading from PTY: %v", err)
			}
			ptyRunningMu.Lock()
			ptyRunning = false // Signal to stop
			ptyRunningMu.Unlock()
			break
		}

		if n > 0 {
			data := buf[:n]
			logDebug("PTY Read %d bytes: %q", n, string(data)) // Log raw bytes or a snippet

			// Feed data to the AnsiParser
			// The eventHandler (TermEventHandler) will update the screen model
			// and also handle the line capture logic internally via its Print method.
			if ansiParser != nil {
				_, parseErr := ansiParser.Parse(data)
				if parseErr != nil {
					logError("Error parsing ANSI stream: %v", parseErr)
					// Depending on severity, might want to stop or continue
				}
			}
		}
	}
	logInfo("PTY reader goroutine exited.")
}

// --- HTTP Handlers ---
func keystrokeHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received POST /keystroke. Form data: %v", r.Form)
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Failed to parse form data"}`, http.StatusBadRequest)
		return
	}
	keys := r.FormValue("keys")
	if keys == "" {
		http.Error(w, `{"error": "Missing 'keys' in form data"}`, http.StatusBadRequest)
		return
	}

	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if ptyMaster == nil || !active {
		logWarn("PTY not active for /keystroke")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(KeystrokeResponse{Error: "PTY not active or not initialized"})
		return
	}

	_, err := ptyMaster.WriteString(keys)
	if err != nil {
		logError("Error writing to PTY: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(KeystrokeResponse{Error: fmt.Sprintf("Error writing to PTY: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(KeystrokeResponse{Status: "success", KeysSent: keys})
}

func keystrokeSyncHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received POST /keystroke_sync. Form data: %v", r.Form)
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Failed to parse form data"}`, http.StatusBadRequest)
		return
	}
	keys := r.FormValue("keys")
	if keys == "" {
		http.Error(w, `{"error": "Missing 'keys' in form data"}`, http.StatusBadRequest)
		return
	}

	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if ptyMaster == nil || !active || ptySlaveForTcgetpgrp == nil {
		logWarn("PTY not active for /keystroke_sync")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(KeystrokeSyncResponse{Status: "error", Message: "PTY not active or not initialized"})
		return
	}
	if shellCmd == nil || shellCmd.Process == nil || shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logWarn("Shell process not running for /keystroke_sync")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(KeystrokeSyncResponse{Status: "error", Message: "Shell process is not running."})
		return
	}

	// Capture the current prompt line, then clear only previous captures
	linesBeforeCommandEffect, currentBufferBefore := eventHandler.GetCapturedLinesAndCurrentBuffer()
	eventHandler.ResetCapturedLinesAndSetBuffer(currentBufferBefore)
	logDebug("SYNC: lines_before_command_effect (len %d): %v", len(linesBeforeCommandEffect), linesBeforeCommandEffect)
	logDebug("SYNC: currentBufferBefore: '%s'", currentBufferBefore)

	// Write command to PTY
	_, err := ptyMaster.WriteString(keys)
	if err != nil {
		logError("Error writing to PTY for sync: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(KeystrokeSyncResponse{Status: "error", Message: fmt.Sprintf("Error writing to PTY: %v", err)})
		return
	}
	logInfo("Sent keys for sync: '%s'", strings.TrimSpace(keys))

	time.Sleep(1 * time.Second) // Initial sleep for command echo and start

	if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logInfo("Shell process exited shortly after command submission and initial sleep.")

		linesAfter, finalCurrentLine := eventHandler.GetCapturedLinesAndCurrentBuffer()

		outputSegment := linesAfter[len(linesBeforeCommandEffect):]
		if finalCurrentLine != "" {
			outputSegment = append(outputSegment, finalCurrentLine)
		}
		joined := strings.Join(outputSegment, "")
		eventHandler.ResetCapturedLinesAndSetBuffer(finalCurrentLine)
		logDebug("SYNC (shell exited path): Reset eventHandler captured lines. New buffer: '%s'", finalCurrentLine)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(
			KeystrokeSyncResponse{
				Status:  "success",
				Message: "Shell process exited shortly after command submission.",
				Output:  joined,
			},
		)
		return
	}

	shellPID := shellCmd.Process.Pid
	shellPGID, err := unix.Getpgid(shellPID)
	if err != nil {
		logError("Failed to get PGID for shell PID %d: %v", shellPID, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(KeystrokeSyncResponse{Status: "error", Message: fmt.Sprintf("Failed to get shell PGID: %v", err)})
		return
	}
	logInfo("Waiting for command completion. Shell PID: %d, Shell PGID: %d. Max wait: %ds.", shellPID, shellPGID, maxSyncWaitSeconds)

	startTime := time.Now()
	commandCompletedNormally := false
	completionMessage := "Command completion status unknown."

	for time.Since(startTime).Seconds() < float64(maxSyncWaitSeconds) {
		if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
			logInfo("Shell process (PID: %d) exited during wait.", shellPID)
			completionMessage = "Shell process exited during command execution."
			commandCompletedNormally = true
			break
		}

		if runtime.GOOS == "darwin" {
			// macOS: check pstree
			pstreeCmd := exec.Command("pstree", fmt.Sprintf("%d", shellPID))
			pstreeOut, pstreeErr := pstreeCmd.CombinedOutput()
			logDebug("pstree for PID %d: Output:\n%s", shellPID, string(pstreeOut))

			if pstreeErr == nil {
				// Assumption: 1 line of output (the process itself) means no children.
				// pstree might add a header or the output format might vary.
				// A more robust check might be needed, e.g. count lines with "---" or specific process names.
				// For now, simple line count, excluding empty lines.
				lines := strings.Split(strings.TrimSpace(string(pstreeOut)), "\n")
				actualLines := 0
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						actualLines++
					}
				}
				if actualLines == 1 {
					logInfo("macOS pstree check: Shell PID %d has no children. Command complete.", shellPID)
					completionMessage = "Command completed (macOS pstree check)."
					commandCompletedNormally = true
					break
				}
			} else {
				// pstree failed. If shell exited, that's the reason.
				if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
					logInfo("Shell process (PID: %d) exited (detected after pstree failure).", shellPID)
					completionMessage = "Shell process exited (detected after pstree failure)."
					commandCompletedNormally = true
					break
				}
				logWarn("pstree command for PID %d failed: %v. Output: %s. Assuming command still running or error with pstree.", shellPID, pstreeErr, string(pstreeOut))
			}
		} else if runtime.GOOS == "linux" { // Linux specific: check for child processes
			logDebug("Using ps/awk to check for children of shell PID %d on Linux.", shellPID)
			// Command: ps -o pid,ppid,comm -ax | awk '$2 == <shellPID> {print $1}'
			// We need to run this as a shell pipeline or construct it carefully with Go's exec.
			// Using sh -c for simplicity here.
			psCmd := fmt.Sprintf("ps -o pid,ppid,comm -ax | awk '$2 == %d {print $1}'", shellPID)
			cmd := exec.Command("sh", "-c", psCmd)

			output, err := cmd.Output()
			if err != nil {
				// If the command fails (e.g. awk not found, or ps error), check if shell exited.
				if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
					logInfo("Shell process (PID: %d) exited (detected after ps/awk command failure).", shellPID)
					completionMessage = "Shell process exited (detected after ps/awk command failure)."
					commandCompletedNormally = true
					break
				}
				logWarn("ps/awk command for PID %d failed: %v. Output: %s. Assuming command still running or error with command.", shellPID, err, string(output))
				// Unlike tcgetpgrp error which might indicate a PTY issue, this is more likely a tool issue.
				// We could let it timeout, or return an error. For now, let it continue and potentially timeout.
				// If critical, an error response could be sent:
				// w.WriteHeader(http.StatusInternalServerError)
				// json.NewEncoder(w).Encode(KeystrokeSyncResponse{Status: "error", Message: fmt.Sprintf("Error checking child processes: %v", err)})
				// return
			} else {
				trimmedOutput := strings.TrimSpace(string(output))
				logDebug("ps/awk output for children of PID %d: '%s'", shellPID, trimmedOutput)
				if trimmedOutput == "" { // No child PIDs printed
					logInfo("Linux ps/awk check: Shell PID %d has no children. Command complete.", shellPID)
					completionMessage = "Command completed (Linux ps/awk check)."
					commandCompletedNormally = true
					break
				}
				// If there's output, children exist, command is still running.
			}
		} else { // Other Unix-like systems or unsupported
			logWarn("Synchronous keystroke completion check is not implemented for this platform: %s. Assuming command completed.", runtime.GOOS)
			completionMessage = fmt.Sprintf("Command completion check not available for %s.", runtime.GOOS)
			commandCompletedNormally = true // Default to success to avoid blocking
			break
		}
		time.Sleep(500 * time.Millisecond) // Polling interval
	}

	time.Sleep(200 * time.Millisecond) // Short final delay for output processing

	status := "success"
	httpStatusCode := http.StatusOK

	if !commandCompletedNormally {
		if shellCmd.ProcessState == nil || !shellCmd.ProcessState.Exited() { // Timeout
			logWarn("Timeout waiting for command completion (Shell PGID: %d did not become foreground or children did not exit).", shellPGID)
			completionMessage = fmt.Sprintf("Command did not complete within %d seconds.", maxSyncWaitSeconds)
			status = "timeout"
			httpStatusCode = http.StatusServiceUnavailable
		} else { // Shell exited during loop but not caught as completion (should be rare)
			logInfo("Shell process (PID: %d) exited during wait (final check).", shellPID)
			completionMessage = "Shell process exited during command execution (final check)."
		}
	}

	linesAfterCommandEffect, finalCurrentLine := eventHandler.GetCapturedLinesAndCurrentBuffer()
	logDebug("SYNC: lines_after_command_effect (len %d): %v", len(linesAfterCommandEffect), linesAfterCommandEffect)
	logDebug("SYNC: final_current_line: '%s'", finalCurrentLine)

	// Build one string: echo+output + next prompt
	joined := strings.Join(linesAfterCommandEffect, "")
	if finalCurrentLine != "" {
		joined += finalCurrentLine
	}
	// Reset capture for next command (keep only the new prompt)
	eventHandler.ResetCapturedLinesAndSetBuffer(finalCurrentLine)
	logDebug("SYNC: Returning joined output: %q", joined)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(
		KeystrokeSyncResponse{Status: status, Message: completionMessage, Output: joined},
	)
}

func screenHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received GET /screen")
	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if eventHandler == nil || !active {
		logWarn("Screen/PTY not active for /screen (eventHandler nil or PTY not running)")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ScreenResponse{Error: "Screen not active or not initialized"})
		return
	}

	displayData := eventHandler.GetScreenContent()
	cursorX, cursorY, cursorHidden := eventHandler.GetCursorState()

	cursorData := ScreenCursorState{
		X:      uint(cursorX), // Convert int to uint for struct
		Y:      uint(cursorY),
		Hidden: cursorHidden,
	}

	logDebug("Screen data (first 3 lines): %v, Cursor: %+v", displayData[:min(3, len(displayData))], cursorData)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScreenResponse{Screen: displayData, Cursor: cursorData})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- Cleanup Function ---
func cleanup() {
	logInfo("Initiating cleanup...")
	ptyRunningMu.Lock()
	if !ptyRunning { // Already cleaned up or cleaning up
		ptyRunningMu.Unlock()
		logInfo("Cleanup already in progress or completed.")
		return
	}
	ptyRunning = false
	ptyRunningMu.Unlock()

	// Wait for PTY reader goroutine to finish
	if ptyReaderDone != nil {
		logInfo("Waiting for PTY reader goroutine to exit...")
		select {
		case <-ptyReaderDone:
			logInfo("PTY reader goroutine exited gracefully.")
		case <-time.After(1 * time.Second):
			logWarn("PTY reader goroutine did not exit gracefully within timeout.")
		}
	}

	// Terminate the shell process and its children
	if shellCmd != nil && shellCmd.Process != nil {
		pgid, err := unix.Getpgid(shellCmd.Process.Pid)
		if err == nil {
			logInfo("Terminating shell process tree (PGID: %d)...", pgid)
			// Send SIGTERM to the entire process group
			if err := unix.Kill(-pgid, syscall.SIGTERM); err != nil {
				logWarn("Failed to send SIGTERM to process group %d: %v", pgid, err)
			} else {
				// Wait for a short period for graceful termination
				termWaitDone := make(chan error, 1)
				go func() { termWaitDone <- shellCmd.Wait() }()
				select {
				case <-termWaitDone:
					logInfo("Shell process group %d terminated gracefully.", pgid)
				case <-time.After(2 * time.Second):
					logWarn("Shell process group %d did not terminate gracefully with SIGTERM, sending SIGKILL...", pgid)
					if err := unix.Kill(-pgid, syscall.SIGKILL); err != nil {
						logError("Failed to send SIGKILL to process group %d: %v", pgid, err)
					} else {
						logInfo("Sent SIGKILL to process group %d.", pgid)
					}
				}
			}
		} else if shellCmd.ProcessState == nil || !shellCmd.ProcessState.Exited() {
			// If getpgid fails, but process seems alive, try killing the process directly
			logWarn("Failed to get PGID for shell process %d: %v. Attempting to kill process directly.", shellCmd.Process.Pid, err)
			if err := shellCmd.Process.Kill(); err != nil {
				logError("Failed to kill shell process %d: %v", shellCmd.Process.Pid, err)
			}
		} else {
			logInfo("Shell process already exited or PGID not obtainable.")
		}
	} else {
		logInfo("Shell process not running or already cleaned up.")
	}
	shellCmd = nil

	// Close PTY file descriptors
	if ptyMaster != nil {
		logInfo("Closing master PTY FD.")
		if err := ptyMaster.Close(); err != nil {
			logError("Error closing master PTY FD: %v", err)
		}
		ptyMaster = nil
	}
	if ptySlaveForTcgetpgrp != nil {
		logInfo("Closing slave PTY FD (parent's copy).")
		if err := ptySlaveForTcgetpgrp.Close(); err != nil {
			logError("Error closing slave PTY FD: %v", err)
		}
		ptySlaveForTcgetpgrp = nil
	}

	logInfo("Cleanup finished.")
}

// --- Main Application ---
func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose logging of PTY stream processing.")
	flag.Parse()

	verboseLoggingEnabled = *verbose
	if verboseLoggingEnabled {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
		logInfo("Verbose logging enabled.")
	} else {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}

	if err := setupPtyAndShell(); err != nil {
		logError("Failed to setup PTY and shell: %v", err)
		os.Exit(1)
	}

	// Defer cleanup to ensure it runs on exit
	defer cleanup()

	// Start PTY reader goroutine
	go ptyReader()

	// Give shell and pty_reader a moment to initialize and print the first prompt
	logInfo("Waiting a moment for PTY to initialize...")
	time.Sleep(500 * time.Millisecond)

	// Set up signal handler for Ctrl+C (SIGINT) and other termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		logWarn("\nReceived signal: %s. Initiating shutdown sequence.", sig)
		// cleanup() is deferred, so it will run.
		// If server needs explicit shutdown:
		// if httpServer != nil { httpServer.Shutdown(context.Background()) }
		os.Exit(0) // Trigger deferred cleanup
	}()

	// Setup and run Flask-like HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/keystroke", keystrokeHandler)
	mux.HandleFunc("/keystroke_sync", keystrokeSyncHandler)
	mux.HandleFunc("/screen", screenHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			logWarn("Invalid URL accessed: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		// Could serve a simple help page or redirect
		fmt.Fprintln(w, "PTY Automation Server running. Endpoints: /keystroke, /keystroke_sync, /screen")
	})

	// Attempt to set host TTY to a sane state
	if fileInfo, _ := os.Stdin.Stat(); (fileInfo.Mode() & os.ModeCharDevice) != 0 {
		logInfo("Attempting to set host TTY to 'sane' mode.")
		saneCmd := exec.Command("stty", "sane")
		saneCmd.Stdin = os.Stdin // Ensure stty operates on the correct TTY
		if err := saneCmd.Run(); err != nil {
			logWarn("Failed to set TTY to sane mode: %v (stty output: %s)", err, saneCmd.String())
		}
	}

	serverAddr := "127.0.0.1:5399"
	logInfo("Starting HTTP server on %s", serverAddr)
	logInfo("Endpoints:")
	logInfo("  POST /keystroke (form data: {'keys': 'your_command\\n'})")
	logInfo("  POST /keystroke_sync (form data: {'keys': 'your_command\\n'})")
	logInfo("  GET  /screen")

	if err := http.ListenAndServe(serverAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logError("HTTP server ListenAndServe error: %v", err)
		// Cleanup will be called by defer
	}
	logInfo("HTTP server shut down.")
}
