package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Azure/go-ansiterm"
	"github.com/creack/pty"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
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

	// MCP mode configuration
	mcpMode       bool
	mcpServerAddr string   = "http://localhost:5399" // Default server address for MCP client calls
	mcpLogFile    *os.File                           // Log file for MCP mode debug output

	// Docker container management for MCP mode
	dockerContainerID   string
	dockerHostPort      string
	dockerRunning       atomic.Bool
	dockerMutex         sync.Mutex
	dockerCmd           *exec.Cmd
	dockerStdin         io.WriteCloser
	dockerDied          chan struct{} // Signal when Docker container dies
	dockerKeepaliveDone chan struct{} // Signal to stop keepalive handler
	mcpShutdown         chan struct{} // Signal for graceful MCP shutdown

	// CLI mode configuration
	cliMode    bool
	cliHost    string = "localhost"
	cliPort    int    = 5399
	cliCommand string
	cliArgs    []string
	outputJSON bool

	// Keepalive mode configuration
	keepaliveMode bool
)

// --- Structs for HTTP responses ---
type SendkeysNowaitResponse struct {
	Status   string `json:"status"`
	KeysSent string `json:"keys_sent,omitempty"`
	Error    string `json:"error,omitempty"`
}

type SendkeysResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
	Timeout bool   `json:"timeout,omitempty"`
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
		if mcpMode && mcpLogFile != nil {
			// Write to MCP log file with PID prefix
			pid := os.Getpid()
			logLine := fmt.Sprintf("[%d] DEBUG: "+format+"\n", append([]interface{}{pid}, v...)...)
			if _, err := mcpLogFile.WriteString(logLine); err != nil {
				// Log to standard logger if writing to mcpLogFile fails
				log.Printf("ERROR: Failed to write to mcpLogFile: %v", err)
			}
			if err := mcpLogFile.Sync(); err != nil {
				// Log to standard logger if sync fails
                log.Printf("ERROR: Failed to sync mcpLogFile: %v", err)
			}
		}
		// Also log to standard logger if verboseLoggingEnabled (even in MCP mode)
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
	logInfo("PTY_READER: Goroutine started.")
	defer func() {
		close(ptyReaderDone)
		logInfo("PTY_READER: Goroutine finished and ptyReaderDone channel closed.")
	}()

	// Buffer for reading from PTY master
	buf := make([]byte, 4096)

	for {
		ptyRunningMu.Lock()
		currentPtyRunningState := ptyRunning
		ptyRunningMu.Unlock()

		if !currentPtyRunningState {
			logInfo("PTY_READER: ptyRunning is false, breaking loop.")
			break
		}

		// Set a deadline for reading to make the loop check ptyRunning periodically
		// This also prevents Read from blocking indefinitely if ptyRunning is set to false.
		if ptyMaster == nil { // ptyMaster might be closed by cleanup
			logWarn("PTY_READER: ptyMaster is nil in loop, exiting.")
			break
		}
		// logDebug("PTY_READER: Setting read deadline on ptyMaster.") // Too verbose for normal operation
		if err := ptyMaster.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
            logWarn("PTY_READER: Error setting read deadline: %v. Continuing loop.", err)
			// If setting deadline fails, we might get stuck in Read.
			// However, the ptyRunning check should eventually break the loop if cleanup is called.
			// Forcing an exit here might be too aggressive if it's a transient error.
        }


		// logDebug("PTY_READER: Attempting to read from ptyMaster.") // Too verbose
		n, err := ptyMaster.Read(buf)
		if err != nil {
			if os.IsTimeout(err) { // Deadline exceeded
				// logDebug("PTY_READER: Read timeout, continuing loop to check ptyRunning.") // Too verbose
				continue // Loop back to check ptyRunning
			}
			// Handle other errors
			logWarn("PTY_READER: Read error encountered.")
			if errors.Is(err, io.EOF) {
				logInfo("PTY_READER: EOF received (shell likely exited or PTY closed). Stopping reader.")
			} else if strings.Contains(err.Error(), "input/output error") || strings.Contains(err.Error(), "file already closed") || strings.Contains(err.Error(), "bad file descriptor"){
				logWarn("PTY_READER: PTY read error (FD likely closed by cleanup: '%v'). Stopping reader.", err)
			} else {
				logError("PTY_READER: Unhandled error reading from PTY: %v. Stopping reader.", err)
			}

			ptyRunningMu.Lock()
			if ptyRunning { // Only change if it hasn't been changed by cleanup already
				logInfo("PTY_READER: Setting ptyRunning to false due to read error.")
				ptyRunning = false // Signal to stop
			}
			ptyRunningMu.Unlock()
			break // Exit loop on error
		}

		if n > 0 {
			data := buf[:n]
			logDebug("PTY_READER: Read %d bytes: %q", n, string(data)) // Log raw bytes or a snippet

			// Feed data to the AnsiParser
			// The eventHandler (TermEventHandler) will update the screen model
			// and also handle the line capture logic internally via its Print method.
			if ansiParser != nil {
				// logDebug("PTY_READER: Parsing %d bytes with ansiParser.", n) // Too verbose
				_, parseErr := ansiParser.Parse(data)
				if parseErr != nil {
					logError("PTY_READER: Error parsing ANSI stream: %v", parseErr)
					// Depending on severity, might want to stop or continue
				}
			} else {
				logWarn("PTY_READER: ansiParser is nil, cannot parse output.")
			}
		} else {
			// logDebug("PTY_READER: Read 0 bytes, no error. Looping.") // Can happen if deadline hits but no error
		}
	}
	logInfo("PTY_READER: Loop exited. Goroutine preparing to exit.")
}

type ExecRequest struct {
	Args    []string `json:"args"`
	Stdin   string   `json:"stdin,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
}

type ExecResponse struct {
	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	Error            string `json:"error,omitempty"`
	Timeout          bool   `json:"timeout,omitempty"`
	ExitCode         int    `json:"exit_code"`
	WorkingDirectory string `json:"working_directory"`
}

type WorkingDirectoryResponse struct {
	WorkingDirectory string `json:"working_directory"`
	Error            string `json:"error,omitempty"`
}

type WriteFileResponse struct {
	FullPath string `json:"full_path"`
	Size     int64  `json:"size"`
	Error    string `json:"error,omitempty"`
}

type ChangeWorkingDirectoryResponse struct {
	NewWorkingDirectory     string `json:"new_working_directory,omitempty"`
	CurrentWorkingDirectory string `json:"current_working_directory,omitempty"`
	Error                   string `json:"error,omitempty"`
}

type ReadFileResponse struct {
	Content  string `json:"content"`
	FullPath string `json:"full_path"`
	Size     int64  `json:"size"`
	Error    string `json:"error,omitempty"`
}

type ReplaceInFileResponse struct {
	FullPath         string `json:"full_path"`
	WorkingDirectory string `json:"working_directory"`
	Error            string `json:"error,omitempty"`
}

// --- HTTP Handlers ---
func sendkeysNowaitHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received POST /sendkeys_nowait. Form data: %v", r.Form)
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
		logWarn("PTY not active for /sendkeys_nowait")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(SendkeysNowaitResponse{Error: "PTY not active or not initialized"})
		return
	}

	_, err := ptyMaster.WriteString(keys)
	if err != nil {
		logError("Error writing to PTY: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(SendkeysNowaitResponse{Error: fmt.Sprintf("Error writing to PTY: %v", err)})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SendkeysNowaitResponse{Status: "success", KeysSent: keys})
}

func sendkeysHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received POST /sendkeys. Form data: %v", r.Form)
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
		logWarn("PTY not active for /sendkeys")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(SendkeysResponse{Status: "error", Message: "PTY not active or not initialized"})
		return
	}
	if shellCmd == nil || shellCmd.Process == nil || shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logWarn("Shell process not running for /sendkeys")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(SendkeysResponse{Status: "error", Message: "Shell process is not running."})
		return
	}

	// Capture the current prompt line, then clear only previous captures
	_, currentBufferBefore := eventHandler.GetCapturedLinesAndCurrentBuffer()
	eventHandler.ResetCapturedLinesAndSetBuffer(currentBufferBefore)
	logDebug("SYNC: currentBufferBefore: '%s'", currentBufferBefore)

	// Write command to PTY
	_, err := ptyMaster.WriteString(keys)
	if err != nil {
		logError("Error writing to PTY for sync: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(SendkeysResponse{Status: "error", Message: fmt.Sprintf("Error writing to PTY: %v", err)})
		return
	}
	logInfo("Sent keys for sync: '%s'", strings.TrimSpace(keys))

	time.Sleep(1 * time.Second) // Initial sleep for command echo and start

	if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logInfo("Shell process exited shortly after command submission and initial sleep.")

		linesAfter, finalCurrentLine := eventHandler.GetCapturedLinesAndCurrentBuffer()

		joined := strings.Join(linesAfter, "")
		if finalCurrentLine != "" {
			joined += finalCurrentLine
		}
		eventHandler.ResetCapturedLinesAndSetBuffer(finalCurrentLine)
		logDebug("SYNC (shell exited path): Reset eventHandler captured lines. New buffer: '%s'", finalCurrentLine)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(
			SendkeysResponse{
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
		json.NewEncoder(w).Encode(SendkeysResponse{Status: "error", Message: fmt.Sprintf("Failed to get shell PGID: %v", err)})
		return
	}
	// --- Timeout/kill logic additions ---
	const syncTimeoutSeconds = 30
	const sigintWaitSeconds = 5
	timeoutHappened := false

	logInfo("Waiting for command completion. Shell PID: %d, Shell PGID: %d. Max wait: %ds.", shellPID, shellPGID, syncTimeoutSeconds)

	startTime := time.Now()
	commandCompletedNormally := false
	completionMessage := "Command completion status unknown."

	for time.Since(startTime).Seconds() < float64(syncTimeoutSeconds) {
		if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
			logInfo("Shell process (PID: %d) exited during wait.", shellPID)
			completionMessage = "Shell process exited during command execution."
			commandCompletedNormally = true
			break
		}

		completed, err := checkCommandCompletion(shellPID)
		if err != nil {
			if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
				logInfo("Shell process (PID: %d) exited (detected after command completion check failure).", shellPID)
				completionMessage = "Shell process exited (detected after command completion check failure)."
				commandCompletedNormally = true
				break
			}
			logWarn("Command completion check for PID %d failed: %v. Assuming command still running.", shellPID, err)
		} else if completed {
			completionMessage = "Command completed."
			commandCompletedNormally = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// If not completed, send SIGINT/SIGKILL only to non-shell children, not the shell itself
	if !commandCompletedNormally {
		timeoutHappened = true
		logWarn("Timeout waiting for command completion (Shell PGID: %d did not become foreground or children did not exit).", shellPGID)
		completionMessage = fmt.Sprintf("Command did not complete within %d seconds.", syncTimeoutSeconds)

		// Find child PIDs of the shell (not the shell itself)
		childPIDs, err := getChildPIDs(shellPID)
		if err != nil {
			logWarn("Failed to get child PIDs for shell PID %d: %v", shellPID, err)
		}

		// Send SIGINT to each child process (not the shell)
		for _, pid := range childPIDs {
			logWarn("Sending SIGINT to child process %d...", pid)
			_ = unix.Kill(pid, syscall.SIGINT)
		}

		// Wait up to sigintWaitSeconds for children to exit
		sigintStart := time.Now()
		for time.Since(sigintStart).Seconds() < float64(sigintWaitSeconds) {
			// Re-check for children
			stillChildren, err := getChildPIDs(shellPID)
			if err != nil {
				logWarn("Failed to re-check child PIDs for shell PID %d: %v", shellPID, err)
			}
			if len(stillChildren) == 0 {
				logInfo("All child processes (except shell) exited after SIGINT.")
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		// After waiting, check again and send SIGKILL if needed
		stillChildren, err := getChildPIDs(shellPID)
		if err != nil {
			logWarn("Failed to get remaining child PIDs for shell PID %d: %v", shellPID, err)
		}
		if len(stillChildren) > 0 {
			for _, pid := range stillChildren {
				logWarn("Child process still exists after SIGINT, sending SIGKILL to %d...", pid)
				_ = unix.Kill(pid, syscall.SIGKILL)
			}
		}
	}

	time.Sleep(200 * time.Millisecond) // Short final delay for output processing

	// If timeout happened, try to reset the PTY to sane mode
	if timeoutHappened && ptyMaster != nil {
		go func() {
			// Run "stty sane" in the nested PTY, ignore errors and output
			cmd := exec.Command("stty", "sane")
			cmd.Stdin = ptyMaster
			cmd.Stdout = nil
			cmd.Stderr = nil
			_ = cmd.Run()
		}()
	}

	status := "success"
	httpStatusCode := http.StatusOK

	if timeoutHappened {
		status = "timeout"
		httpStatusCode = http.StatusServiceUnavailable
	} else if !commandCompletedNormally {
		if shellCmd.ProcessState == nil || !shellCmd.ProcessState.Exited() {
			status = "timeout"
			httpStatusCode = http.StatusServiceUnavailable
		} else {
			logInfo("Shell process (PID: %d) exited during wait (final check).", shellPID)
			completionMessage = "Shell process exited during command execution (final check)."
		}
	}

	linesAfterCommandEffect, finalCurrentLine := eventHandler.GetCapturedLinesAndCurrentBuffer()
	logDebug("SYNC: lines_after_command_effect (len %d): %v", len(linesAfterCommandEffect), linesAfterCommandEffect)
	logDebug("SYNC: final_current_line: '%s'", finalCurrentLine)

	joined := strings.Join(linesAfterCommandEffect, "")
	if finalCurrentLine != "" {
		joined += finalCurrentLine
	}
	eventHandler.ResetCapturedLinesAndSetBuffer(finalCurrentLine)
	logDebug("SYNC: Returning joined output: %q", joined)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(
		SendkeysResponse{Status: status, Message: completionMessage, Output: joined, Timeout: timeoutHappened},
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

// --- Exec handler ---
func execHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	var req ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Failed to parse JSON request"}`, http.StatusBadRequest)
		return
	}

	if len(req.Args) == 0 {
		http.Error(w, `{"error": "Missing 'args' in request"}`, http.StatusBadRequest)
		return
	}

	// Set default timeout if not specified
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 15
	}
	if timeout > 60 {
		timeout = 60
	}

	// Get shell working directory
	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	var shellWorkingDir string
	if shellCmd != nil && shellCmd.Process != nil && active {
		if shellCmd.ProcessState == nil || !shellCmd.ProcessState.Exited() {
			pid := shellCmd.Process.Pid
			if wd, err := getWorkingDirectory(pid); err == nil {
				shellWorkingDir = wd
			}
		}
	}

	// Save current working directory of main process
	originalWd, err := os.Getwd()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ExecResponse{
			Error:            fmt.Sprintf("Failed to get current working directory: %v", err),
			ExitCode:         -1,
			WorkingDirectory: "",
		})
		return
	}

	// Change to shell working directory if available
	if shellWorkingDir != "" {
		if err := os.Chdir(shellWorkingDir); err != nil {
			logWarn("Failed to change to shell working directory %s: %v", shellWorkingDir, err)
			shellWorkingDir = originalWd
		}
	} else {
		shellWorkingDir = originalWd
	}

	// Restore original working directory when done
	defer func() {
		if err := os.Chdir(originalWd); err != nil {
			logError("Failed to restore original working directory %s: %v", originalWd, err)
		}
	}()

	// Create command with array arguments
	cmd := exec.Command(req.Args[0], req.Args[1:]...)

	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// Set stdin if provided
	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	timeoutDuration := time.Duration(timeout) * time.Second
	var execErr error
	var exitCode int
	var timedOut bool

	select {
	case execErr = <-done:
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		} else {
			exitCode = -1
		}
	case <-time.After(timeoutDuration):
		timedOut = true
		_ = cmd.Process.Kill()
		<-done // Wait for process to exit
		exitCode = -1
	}

	resp := ExecResponse{
		Stdout:           stdoutBuf.String(),
		Stderr:           stderrBuf.String(),
		ExitCode:         exitCode,
		Timeout:          timedOut,
		WorkingDirectory: shellWorkingDir,
	}

	if timedOut {
		resp.Error = "timeout"
	} else if execErr != nil {
		resp.Error = execErr.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- Working Directory Handler ---
func workingDirectoryHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received GET /working_directory")

	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if shellCmd == nil || shellCmd.Process == nil || !active {
		logWarn("Shell process not running for /working_directory")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(WorkingDirectoryResponse{Error: "Shell process is not running"})
		return
	}

	if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logWarn("Shell process has exited for /working_directory")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(WorkingDirectoryResponse{Error: "Shell process has exited"})
		return
	}

	pid := shellCmd.Process.Pid
	logInfo("Getting working directory for shell PID: %d", pid)
	workingDir, err := getWorkingDirectory(pid)
	if err != nil {
		logError("Failed to get working directory for PID %d: %v", pid, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(WorkingDirectoryResponse{Error: fmt.Sprintf("Failed to get working directory: %v", err)})
		return
	}

	logInfo("Working directory for PID %d: '%s'", pid, workingDir)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(WorkingDirectoryResponse{WorkingDirectory: workingDir})
}

// --- Write File Handler ---
func writeFileHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received POST /write_file")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Failed to parse form data"}`, http.StatusBadRequest)
		return
	}

	filename := r.FormValue("filename")
	content := r.FormValue("content")

	if filename == "" {
		http.Error(w, `{"error": "Missing 'filename' in form data"}`, http.StatusBadRequest)
		return
	}

	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if shellCmd == nil || shellCmd.Process == nil || !active {
		logWarn("Shell process not running for /write_file")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(WriteFileResponse{Error: "Shell process is not running"})
		return
	}

	if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logWarn("Shell process has exited for /write_file")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(WriteFileResponse{Error: "Shell process has exited"})
		return
	}

	// Get working directory of shell process
	pid := shellCmd.Process.Pid
	workingDir, err := getWorkingDirectory(pid)
	if err != nil {
		logError("Failed to get working directory for PID %d: %v", pid, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(WriteFileResponse{Error: fmt.Sprintf("Failed to get working directory: %v", err)})
		return
	}

	// Resolve file path (absolute or relative to working directory)
	var fullPath string
	if filepath.IsAbs(filename) {
		fullPath = filename
	} else {
		fullPath = filepath.Join(workingDir, filename)
	}

	// Clean the path to resolve any .. or . components
	fullPath = filepath.Clean(fullPath)

	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logError("Failed to create directory %s: %v", dir, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(WriteFileResponse{Error: fmt.Sprintf("Failed to create directory: %v", err)})
		return
	}

	// Write file
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		logError("Failed to write file %s: %v", fullPath, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(WriteFileResponse{Error: fmt.Sprintf("Failed to write file: %v", err)})
		return
	}

	// Get file size
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		logError("Failed to stat file %s: %v", fullPath, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(WriteFileResponse{Error: fmt.Sprintf("Failed to get file info: %v", err)})
		return
	}

	logInfo("Successfully wrote file: %s (%d bytes)", fullPath, fileInfo.Size())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(WriteFileResponse{
		FullPath: fullPath,
		Size:     fileInfo.Size(),
	})
}

// --- Change Working Directory Handler ---
func changeWorkingDirectoryHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received POST /change_working_directory")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Failed to parse form data"}`, http.StatusBadRequest)
		return
	}

	directory := r.FormValue("directory")
	if directory == "" {
		http.Error(w, `{"error": "Missing 'directory' in form data"}`, http.StatusBadRequest)
		return
	}

	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if shellCmd == nil || shellCmd.Process == nil || !active || ptySlaveForTcgetpgrp == nil {
		logWarn("PTY not active for /change_working_directory")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{Error: "PTY not active or not initialized"})
		return
	}

	if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logWarn("Shell process not running for /change_working_directory")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{Error: "Shell process is not running"})
		return
	}

	// Check if shell has child processes running
	shellPID := shellCmd.Process.Pid
	childPIDs, err := getChildPIDs(shellPID)
	if err != nil {
		logError("Failed to get child PIDs for shell PID %d: %v", shellPID, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{Error: fmt.Sprintf("Failed to check for running processes: %v", err)})
		return
	}

	if len(childPIDs) > 0 {
		logWarn("Shell has running child processes, cannot change directory")
		currentDir, _ := getWorkingDirectory(shellPID)
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{
			Error:                   "Cannot change directory while shell has running processes",
			CurrentWorkingDirectory: currentDir,
		})
		return
	}

	// Get current working directory before change
	currentDir, err := getWorkingDirectory(shellPID)
	if err != nil {
		logError("Failed to get current working directory for PID %d: %v", shellPID, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{Error: fmt.Sprintf("Failed to get current working directory: %v", err)})
		return
	}

	// Normalize the requested directory path
	var targetDir string
	if filepath.IsAbs(directory) {
		targetDir = filepath.Clean(directory)
	} else {
		targetDir = filepath.Clean(filepath.Join(currentDir, directory))
	}

	// Use sendkeys to execute cd command
	cdCommand := fmt.Sprintf("cd %s\n", shellescape(directory))
	logInfo("Executing cd command via sendkeys: %s", strings.TrimSpace(cdCommand))

	// Capture the current prompt line, then clear only previous captures
	_, currentBufferBefore := eventHandler.GetCapturedLinesAndCurrentBuffer()
	eventHandler.ResetCapturedLinesAndSetBuffer(currentBufferBefore)

	// Write cd command to PTY
	_, err = ptyMaster.WriteString(cdCommand)
	if err != nil {
		logError("Error writing cd command to PTY: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{
			Error:                   fmt.Sprintf("Error writing cd command to PTY: %v", err),
			CurrentWorkingDirectory: currentDir,
		})
		return
	}

	// Wait for command completion
	time.Sleep(1 * time.Second)

	// Wait for cd command to complete
	startTime := time.Now()
	const cdTimeoutSeconds = 10
	commandCompleted := false

	for time.Since(startTime).Seconds() < float64(cdTimeoutSeconds) {
		if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
			logInfo("Shell process exited during cd command")
			break
		}

		completed, err := checkCommandCompletion(shellPID)
		if err != nil {
			if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
				logInfo("Shell process exited during cd command (detected after completion check failure)")
				break
			}
			logWarn("Command completion check for cd command failed: %v", err)
		} else if completed {
			commandCompleted = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if !commandCompleted {
		logWarn("cd command did not complete within timeout")
		w.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{
			Error:                   "cd command timed out",
			CurrentWorkingDirectory: currentDir,
		})
		return
	}

	// Short delay for output processing
	time.Sleep(200 * time.Millisecond)

	// Get the new working directory
	newDir, err := getWorkingDirectory(shellPID)
	if err != nil {
		logError("Failed to get new working directory for PID %d: %v", shellPID, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{
			Error:                   fmt.Sprintf("Failed to get new working directory: %v", err),
			CurrentWorkingDirectory: currentDir,
		})
		return
	}

	// Check if the directory change was successful
	if newDir != targetDir {
		logWarn("Directory change failed. Expected: %s, Got: %s", targetDir, newDir)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{
			Error:                   fmt.Sprintf("Directory change failed. Target: %s", targetDir),
			CurrentWorkingDirectory: newDir,
		})
		return
	}

	// Clear captured output from cd command
	eventHandler.ResetCapturedLinesAndSetBuffer("")

	logInfo("Successfully changed working directory from %s to %s", currentDir, newDir)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ChangeWorkingDirectoryResponse{
		NewWorkingDirectory: newDir,
	})
}

// --- Read File Handler ---
func readFileHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received POST /read_file")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Failed to parse form data"}`, http.StatusBadRequest)
		return
	}

	filename := r.FormValue("filename")
	if filename == "" {
		http.Error(w, `{"error": "Missing 'filename' in form data"}`, http.StatusBadRequest)
		return
	}

	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if shellCmd == nil || shellCmd.Process == nil || !active {
		logWarn("Shell process not running for /read_file")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ReadFileResponse{Error: "Shell process is not running"})
		return
	}

	if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logWarn("Shell process has exited for /read_file")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ReadFileResponse{Error: "Shell process has exited"})
		return
	}

	// Get working directory of shell process
	pid := shellCmd.Process.Pid
	workingDir, err := getWorkingDirectory(pid)
	if err != nil {
		logError("Failed to get working directory for PID %d: %v", pid, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ReadFileResponse{Error: fmt.Sprintf("Failed to get working directory: %v", err)})
		return
	}

	// Resolve file path (absolute or relative to working directory)
	var fullPath string
	if filepath.IsAbs(filename) {
		fullPath = filename
	} else {
		fullPath = filepath.Join(workingDir, filename)
	}

	// Clean the path to resolve any .. or . components
	fullPath = filepath.Clean(fullPath)

	// Read file
	content, err := os.ReadFile(fullPath)
	if err != nil {
		logError("Failed to read file %s: %v", fullPath, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ReadFileResponse{Error: fmt.Sprintf("Failed to read file: %v", err)})
		return
	}

	// Get file size
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		logError("Failed to stat file %s: %v", fullPath, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ReadFileResponse{Error: fmt.Sprintf("Failed to get file info: %v", err)})
		return
	}

	logInfo("Successfully read file: %s (%d bytes)", fullPath, fileInfo.Size())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ReadFileResponse{
		Content:  string(content),
		FullPath: fullPath,
		Size:     fileInfo.Size(),
	})
}

// --- Replace In File Handler ---
func replaceInFileHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received POST /replace_in_file")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Failed to parse form data"}`, http.StatusBadRequest)
		return
	}

	filename := r.FormValue("filename")
	searchString := r.FormValue("search_string")
	replacementString := r.FormValue("replacement_string")

	if filename == "" {
		http.Error(w, `{"error": "Missing 'filename' in form data"}`, http.StatusBadRequest)
		return
	}

	if searchString == "" {
		http.Error(w, `{"error": "Missing 'search_string' in form data"}`, http.StatusBadRequest)
		return
	}

	if replacementString == "" {
		http.Error(w, `{"error": "Missing 'replacement_string' in form data"}`, http.StatusBadRequest)
		return
	}

	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if shellCmd == nil || shellCmd.Process == nil || !active {
		logWarn("Shell process not running for /replace_in_file")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ReplaceInFileResponse{Error: "Shell process is not running"})
		return
	}

	if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
		logWarn("Shell process has exited for /replace_in_file")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ReplaceInFileResponse{Error: "Shell process has exited"})
		return
	}

	// Get working directory of shell process
	pid := shellCmd.Process.Pid
	workingDir, err := getWorkingDirectory(pid)
	if err != nil {
		logError("Failed to get working directory for PID %d: %v", pid, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ReplaceInFileResponse{Error: fmt.Sprintf("Failed to get working directory: %v", err)})
		return
	}

	// Resolve file path (absolute or relative to working directory)
	var fullPath string
	if filepath.IsAbs(filename) {
		fullPath = filename
	} else {
		fullPath = filepath.Join(workingDir, filename)
	}

	// Clean the path to resolve any .. or . components
	fullPath = filepath.Clean(fullPath)

	// Read file
	content, err := os.ReadFile(fullPath)
	if err != nil {
		logError("Failed to read file %s: %v", fullPath, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ReplaceInFileResponse{Error: fmt.Sprintf("Failed to read file: %v", err), WorkingDirectory: workingDir})
		return
	}

	contentStr := string(content)

	// Count occurrences of search string - spaces and other characters must match exactly
	occurrences := strings.Count(contentStr, searchString)
	if occurrences == 0 {
		logError("Search string not found in file %s", fullPath)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ReplaceInFileResponse{Error: "Search string not found in file", FullPath: fullPath, WorkingDirectory: workingDir})
		return
	}

	if occurrences > 1 {
		logError("Multiple occurrences (%d) of search string found in file %s", occurrences, fullPath)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ReplaceInFileResponse{Error: fmt.Sprintf("Multiple occurrences (%d) of search string found in file", occurrences), FullPath: fullPath, WorkingDirectory: workingDir})
		return
	}

	// Perform replacement
	newContent := strings.Replace(contentStr, searchString, replacementString, 1)

	// Write file back
	if err := os.WriteFile(fullPath, []byte(newContent), 0644); err != nil {
		logError("Failed to write file %s: %v", fullPath, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ReplaceInFileResponse{Error: fmt.Sprintf("Failed to write file: %v", err), FullPath: fullPath, WorkingDirectory: workingDir})
		return
	}

	logInfo("Successfully replaced text in file: %s", fullPath)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ReplaceInFileResponse{
		FullPath:         fullPath,
		WorkingDirectory: workingDir,
	})
}

// shellescape escapes a string for safe use in shell commands
func shellescape(s string) string {
	// Simple shell escaping - wrap in single quotes and escape any single quotes
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// --- Cleanup Function ---
func cleanup() {
	logInfo("CLEANUP: Initiating cleanup...")
	ptyRunningMu.Lock()
	if !ptyRunning { // Already cleaned up or cleaning up
		ptyRunningMu.Unlock()
		logInfo("CLEANUP: Cleanup already in progress or completed.")
		return
	}
	logInfo("CLEANUP: Setting ptyRunning to false.")
	ptyRunning = false
	ptyRunningMu.Unlock()

	// Wait for PTY reader goroutine to finish
	if ptyReaderDone != nil {
		logInfo("CLEANUP: Waiting for PTY reader goroutine to exit...")
		select {
		case <-ptyReaderDone:
			logInfo("CLEANUP: PTY reader goroutine exited gracefully.")
		case <-time.After(2 * time.Second): // Increased timeout slightly
			logWarn("CLEANUP: PTY reader goroutine did not exit gracefully within 2s timeout.")
		}
	} else {
		logInfo("CLEANUP: ptyReaderDone channel is nil.")
	}

	// Terminate the shell process and its children
	if shellCmd != nil && shellCmd.Process != nil {
		logInfo("CLEANUP: Shell command and process exist. PID: %d", shellCmd.Process.Pid)
		if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
			logInfo("CLEANUP: Shell process PID %d has already exited.", shellCmd.Process.Pid)
		} else {
			pgid, err := unix.Getpgid(shellCmd.Process.Pid)
			if err == nil {
				logInfo("CLEANUP: Terminating shell process tree (PGID: %d)...", pgid)
				// Send SIGTERM to the entire process group
				logInfo("CLEANUP: Sending SIGTERM to PGID: %d", pgid)
				if err := unix.Kill(-pgid, syscall.SIGTERM); err != nil {
					logWarn("CLEANUP: Failed to send SIGTERM to process group %d: %v", pgid, err)
				} else {
					logInfo("CLEANUP: SIGTERM sent to PGID: %d. Waiting for termination...", pgid)
					// Wait for a short period for graceful termination
					termWaitDone := make(chan error, 1)
					go func() {
						logDebug("CLEANUP: Goroutine waiting for shellCmd.Wait() for PGID %d", pgid)
						termWaitDone <- shellCmd.Wait()
						logDebug("CLEANUP: shellCmd.Wait() completed for PGID %d", pgid)
					}()
					select {
					case waitErr := <-termWaitDone:
						if waitErr != nil {
							logWarn("CLEANUP: Shell process group %d terminated with error: %v", pgid, waitErr)
						} else {
							logInfo("CLEANUP: Shell process group %d terminated gracefully after SIGTERM.", pgid)
						}
					case <-time.After(3 * time.Second): // Increased timeout
						logWarn("CLEANUP: Shell process group %d did not terminate gracefully with SIGTERM after 3s, sending SIGKILL...", pgid)
						if killErr := unix.Kill(-pgid, syscall.SIGKILL); killErr != nil {
							logError("CLEANUP: Failed to send SIGKILL to process group %d: %v", pgid, killErr)
						} else {
							logInfo("CLEANUP: Sent SIGKILL to process group %d.", pgid)
							// Optionally wait for SIGKILL to take effect
							// go func() { termWaitDone <- shellCmd.Wait() }() // This might block if already exited
							// select {
							// case <-termWaitDone:
							// 	logInfo("CLEANUP: Shell process group %d terminated after SIGKILL.", pgid)
							// case <-time.After(1 * time.Second):
							//  logWarn("CLEANUP: Shell process group %d did not confirm termination after SIGKILL.", pgid)
							// }
						}
					}
				}
			} else { // getpgid failed
				logWarn("CLEANUP: Failed to get PGID for shell process %d: %v. Attempting to kill process directly.", shellCmd.Process.Pid, err)
				if err := shellCmd.Process.Kill(); err != nil {
					logError("CLEANUP: Failed to kill shell process %d directly: %v", shellCmd.Process.Pid, err)
				} else {
					logInfo("CLEANUP: Shell process %d killed directly.", shellCmd.Process.Pid)
				}
			}
		}
	} else {
		logInfo("CLEANUP: Shell process (shellCmd or shellCmd.Process) is nil or already cleaned up.")
	}
	logInfo("CLEANUP: Setting shellCmd to nil.")
	shellCmd = nil

	// Close PTY file descriptors
	if ptyMaster != nil {
		logInfo("CLEANUP: Closing master PTY FD.")
		if err := ptyMaster.Close(); err != nil {
			logError("CLEANUP: Error closing master PTY FD: %v", err)
		}
		logInfo("CLEANUP: Setting ptyMaster to nil.")
		ptyMaster = nil
	} else {
		logInfo("CLEANUP: ptyMaster is already nil.")
	}

	if ptySlaveForTcgetpgrp != nil {
		logInfo("CLEANUP: Closing slave PTY FD (parent's copy).")
		if err := ptySlaveForTcgetpgrp.Close(); err != nil {
			logError("CLEANUP: Error closing slave PTY FD: %v", err)
		}
		logInfo("CLEANUP: Setting ptySlaveForTcgetpgrp to nil.")
		ptySlaveForTcgetpgrp = nil
	} else {
		logInfo("CLEANUP: ptySlaveForTcgetpgrp is already nil.")
	}

	logInfo("CLEANUP: Cleanup finished.")
}

// --- Main Application ---
func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose logging of PTY stream processing.")
	mcp := flag.Bool("mcp", false, "Run as MCP server instead of HTTP server.")
	serverAddr := flag.String("server", "http://localhost:5399", "Server address for MCP client REST calls.")
	cli := flag.Bool("cli", false, "Run as CLI client to interact with server.")
	host := flag.String("host", "localhost", "Server host for CLI mode.")
	port := flag.Int("port", 5399, "Server port for CLI mode.")
	jsonOutput := flag.Bool("json", false, "Output raw JSON response in CLI mode.")
	keepalive := flag.Bool("keepalive", false, "Run in keepalive mode - send ping every 5 seconds, wait for pong from stdin.")
	flag.Parse()

	verboseLoggingEnabled = *verbose
	mcpMode = *mcp
	mcpServerAddr = *serverAddr
	cliMode = *cli
	cliHost = *host
	cliPort = *port
	outputJSON = *jsonOutput
	keepaliveMode = *keepalive

	// Check environment variable for keepalive mode
	if os.Getenv("KEEPALIVE") == "true" {
		keepaliveMode = true
	}

	if cliMode {
		args := flag.Args()
		if len(args) == 0 {
			printCLIUsage()
			os.Exit(1)
		}
		cliCommand = args[0]
		cliArgs = args[1:]
		runCLIClient()
		return
	}

	if keepaliveMode {
		runKeepaliveMode()
		return
	}

	if verboseLoggingEnabled {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
		logInfo("Verbose logging enabled.")
	} else {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}

	if mcpMode {
		// Always enable verbose logging in MCP mode
		verboseLoggingEnabled = true

		// Open MCP log file for debug output
		var err error
		mcpLogFilePath := "/tmp/linux_terminal_mcp.log"
		logInfo("MAIN: Attempting to open MCP log file: %s", mcpLogFilePath)
		mcpLogFile, err = os.OpenFile(mcpLogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			logError("MAIN: Failed to open MCP log file '%s': %v. MCP debug logs will not be written to this file.", mcpLogFilePath, err)
			// mcpLogFile will be nil, logDebug will handle it.
		} else {
			logInfo("MAIN: Successfully opened MCP log file: %s", mcpLogFilePath)
			// Defer close only if successfully opened.
			// The actual close will happen when main exits.
			// If runMCPServer() is long-lived, this defer is fine.
			defer func() {
				logInfo("MAIN: Closing MCP log file: %s", mcpLogFilePath)
				if err := mcpLogFile.Close(); err != nil {
					logError("MAIN: Error closing MCP log file '%s': %v", mcpLogFilePath, err)
				}
			}()

			// Write startup message with PID
			pid := os.Getpid()
			startupMsg := fmt.Sprintf("[%d] MCP mode started at %s. Log file: %s\n", pid, time.Now().Format(time.RFC3339), mcpLogFilePath)
			if _, writeErr := mcpLogFile.WriteString(startupMsg); writeErr != nil {
				logError("MAIN: Failed to write startup message to MCP log file '%s': %v", mcpLogFilePath, writeErr)
			}
			if syncErr := mcpLogFile.Sync(); syncErr != nil {
				logError("MAIN: Failed to sync MCP log file '%s' after startup message: %v", mcpLogFilePath, syncErr)
			}
		}

		logInfo("MAIN: Starting in MCP server mode, server address for internal HTTP calls: %s", mcpServerAddr)
		runMCPServer() // This function now contains its own lifecycle logging.
		logInfo("MAIN: runMCPServer() has returned. MCP mode is terminating.")
		return
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
		logWarn("SIGNAL_HANDLER: Received signal: %s.", sig)
		logInfo("SIGNAL_HANDLER: Initiating shutdown sequence due to signal %s.", sig)
		// cleanup() is deferred, so it will run when os.Exit() is called.
		// If server needs explicit shutdown:
		// if httpServer != nil {
		//    logInfo("SIGNAL_HANDLER: Shutting down HTTP server explicitly.")
		//    httpServer.Shutdown(context.Background())
		// }
		logInfo("SIGNAL_HANDLER: Calling os.Exit(0) to trigger deferred cleanup and exit.")
		os.Exit(0)
	}()

	// Setup and run Flask-like HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/sendkeys_nowait", sendkeysNowaitHandler)
	mux.HandleFunc("/sendkeys", sendkeysHandler)
	mux.HandleFunc("/screen", screenHandler)
	mux.HandleFunc("/exec", execHandler)
	mux.HandleFunc("/working_directory", workingDirectoryHandler)
	mux.HandleFunc("/write_file", writeFileHandler)
	mux.HandleFunc("/change_working_directory", changeWorkingDirectoryHandler)
	mux.HandleFunc("/read_file", readFileHandler)
	mux.HandleFunc("/replace_in_file", replaceInFileHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			logWarn("Invalid URL accessed: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		// Could serve a simple help page or redirect
		fmt.Fprintln(w, "PTY Automation Server running. Endpoints: /sendkeys_nowait, /sendkeys, /screen, /exec, /working_directory, /write_file, /read_file")
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

	httpServerAddr := ":5399"
	logInfo("Starting HTTP server on %s", httpServerAddr)
	logInfo("Endpoints:")
	logInfo("  POST /sendkeys_nowait (form data: {'keys': 'your_command\\n'})")
	logInfo("  POST /sendkeys (form data: {'keys': 'your_command\\n'})")
	logInfo("  GET  /screen")
	logInfo("  POST /exec (JSON: {'args': ['cmd', 'arg1'], 'stdin': 'optional', 'timeout': 15})")
	logInfo("  GET  /working_directory")
	logInfo("  POST /write_file (form data: {'filename': 'path/to/file', 'content': 'file content'})")
	logInfo("  POST /change_working_directory (form data: {'directory': 'path/to/directory'})")
	logInfo("  POST /read_file (form data: {'filename': 'path/to/file'})")
	logInfo("  POST /replace_in_file (form data: {'filename': 'path/to/file', 'search_string': 'text to find', 'replacement_string': 'replacement text'})")

	if err := http.ListenAndServe(httpServerAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logError("HTTP server ListenAndServe error: %v", err)
		// Cleanup will be called by defer
	}
	logInfo("HTTP server shut down.")
}

// --- MCP Server Implementation ---

func runMCPServer() {
	// Initialize shutdown channels
	mcpShutdown = make(chan struct{})
	dockerDied = make(chan struct{})

	// Set up signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		logWarn("MCP server received signal: %s. Initiating graceful shutdown.", sig)
		close(mcpShutdown)
	}()

	// Monitor for Docker death and exit with error
	go func() {
		logInfo("MCP_DOCKER_MONITOR: Goroutine started to monitor dockerDied channel.")
		select {
		case <-dockerDied:
			logError("MCP_DOCKER_MONITOR: dockerDied channel closed, indicating the managed Docker container died unexpectedly.")
			logWarn("MCP_DOCKER_MONITOR: This process will now exit abruptly with status 1 due to Docker container death.")
			// Note: os.Exit(1) will prevent deferred functions in runMCPServer (like cleanupDockerContainer) from running.
			// If cleanup is essential even in this scenario, this goroutine should instead signal mcpShutdown.
			os.Exit(1)
		case <-mcpShutdown:
			logInfo("MCP_DOCKER_MONITOR: mcpShutdown signaled. Docker monitor goroutine exiting gracefully.")
			// This case ensures the goroutine exits if the server is shutting down normally,
			// preventing it from lingering or incorrectly triggering os.Exit(1) later if dockerDied closes during shutdown.
		}
		logInfo("MCP_DOCKER_MONITOR: Goroutine finished.")
	}()

	// Create a new MCP server
	s := server.NewMCPServer(
		"Terminal Automation Server 🖥️",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	// Add sendkeys_nowait tool
	sendkeysNowaitTool := mcp.NewTool("sendkeys_nowait",
		mcp.WithDescription("Send keystrokes to terminal. Usually used for interactive applications to answer questions. Should be only after sendkeys, if it stuck in interactive input. Use 'screen' tool to get text screenshot to know the question."),
		mcp.WithString("keys",
			mcp.Required(),
			mcp.Description("Keys to send to the terminal"),
		),
	)
	s.AddTool(sendkeysNowaitTool, sendkeysNowaitToolHandler)

	// Add sendkeys tool
	sendkeysTool := mcp.NewTool("sendkeys",
		mcp.WithDescription("Type the keys terminal and wait for completion, assuming shell prompt. Must include newline at the end. Usually will return echoed input and command output. WARNING: don't forget to escape characters if using double quotes for shell argument! WARNING: Always check command output for errors."),
		mcp.WithString("keys",
			mcp.Required(),
			mcp.Description("Keys to send to the terminal"),
		),
	)
	s.AddTool(sendkeysTool, sendkeysToolHandler)

	// Add screen tool
	screenTool := mcp.NewTool("screen",
		mcp.WithDescription("Get current terminal screen content in text mode."),
	)
	s.AddTool(screenTool, screenToolHandler)

	// Add exec tool
	execTool := mcp.NewTool("exec",
		mcp.WithDescription("Execute command non-interactively. Prefer this mode for quick program execution."),
		mcp.WithString("args",
			mcp.Required(),
			mcp.Description("Command arguments as JSON array (e.g., '[\"ls\", \"-la\"]')"),
		),
		mcp.WithString("stdin",
			mcp.Description("Optional stdin input for the command"),
		),
		mcp.WithNumber("timeout",
			mcp.Description("Timeout in seconds (default: 15, max: 60)"),
		),
	)
	s.AddTool(execTool, execToolHandler)

	// Add get_working_directory tool
	getWorkingDirectoryTool := mcp.NewTool("get_working_directory",
		mcp.WithDescription("Get the current working directory of the terminal shell process"),
	)
	s.AddTool(getWorkingDirectoryTool, getWorkingDirectoryToolHandler)

	// Add write_file tool
	writeFileTool := mcp.NewTool("write_file",
		mcp.WithDescription("Write content to a file. Path can be absolute or relative to shell's working directory."),
		mcp.WithString("filename",
			mcp.Required(),
			mcp.Description("File path (absolute or relative to working directory)"),
		),
		mcp.WithString("content",
			mcp.Required(),
			mcp.Description("Content to write to the file"),
		),
	)
	s.AddTool(writeFileTool, writeFileToolHandler)

	// Add change_working_directory tool
	changeWorkingDirectoryTool := mcp.NewTool("change_working_directory",
		mcp.WithDescription("Change the working directory of the terminal shell. Fails if shell has running processes."),
		mcp.WithString("directory",
			mcp.Required(),
			mcp.Description("Directory path (absolute or relative to current working directory)"),
		),
	)
	s.AddTool(changeWorkingDirectoryTool, changeWorkingDirectoryToolHandler)

	// Add read_file tool
	readFileTool := mcp.NewTool("read_file",
		mcp.WithDescription("Read content from a file. Path can be absolute or relative to shell's working directory."),
		mcp.WithString("filename",
			mcp.Required(),
			mcp.Description("File path (absolute or relative to working directory)"),
		),
	)
	s.AddTool(readFileTool, readFileToolHandler)

	// Add replace_in_file tool
	replaceInFileTool := mcp.NewTool("replace_in_file",
		mcp.WithDescription("Replace text in a file. Spaces and other characters from search_string must match exactly. Fails if multiple occurrences found or file not found."),
		mcp.WithString("filename",
			mcp.Required(),
			mcp.Description("File path (absolute or relative to working directory)"),
		),
		mcp.WithString("search_string",
			mcp.Required(),
			mcp.Description("Text to search for (must match exactly including spaces and other characters)"),
		),
		mcp.WithString("replacement_string",
			mcp.Required(),
			mcp.Description("Text to replace with"),
		),
	)
	s.AddTool(replaceInFileTool, replaceInFileToolHandler)

	// Add begin tool
	beginTool := mcp.NewTool("begin",
		mcp.WithDescription("Open new or existing workspace with automation terminal. Must be called before using other terminal tools. "),
		mcp.WithString("workspace_id",
			mcp.Description("Optional existing workspace ID to open (do not invent new), must leave empty for new workspace."),
		),
	)
	s.AddTool(beginTool, beginToolHandler)

	// Add save_work tool
	saveWorkTool := mcp.NewTool("save_work",
		mcp.WithDescription("Commit current workspace state to a new image. Requires 'begin' to be called first."),
		mcp.WithString("comment",
			mcp.Required(),
			mcp.Description("Commit message describing the work done"),
		),
	)
	s.AddTool(saveWorkTool, saveWorkToolHandler)

	// Set up cleanup for Docker container on exit
	defer cleanupDockerContainer()

	logInfo("MCP_SERVER: Starting MCP server using server.ServeStdio.")
	// Start the stdio server in a goroutine
	serverDone := make(chan error, 1)
	go func() {
		logDebug("MCP_SERVER: Goroutine for server.ServeStdio started.")
		err := server.ServeStdio(s)
		logDebug("MCP_SERVER: server.ServeStdio returned an error: %v", err) // Will be nil on clean exit
		serverDone <- err
		logDebug("MCP_SERVER: Error from server.ServeStdio sent to serverDone channel.")
	}()

	logInfo("MCP_SERVER: Waiting for server.ServeStdio to complete or mcpShutdown signal.")
	// Wait for either server completion or shutdown signal
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "file already closed") {
			// io.EOF or "file already closed" on stdin is expected when the client closes the connection or during shutdown.
			logError("MCP_SERVER: Server.ServeStdio exited with error: %v", err)
		} else if err != nil {
			logInfo("MCP_SERVER: Server.ServeStdio exited with expected error (EOF or closed file): %v", err)
		} else {
			logInfo("MCP_SERVER: Server.ServeStdio exited gracefully (nil error).")
		}
	case <-mcpShutdown:
		logInfo("MCP_SERVER: mcpShutdown signal received. Initiating graceful shutdown of MCP server.")
		// At this point, the MCP client (e.g. the host application) should close its stdin to this process.
		// This will cause server.ServeStdio(s) to return, ideally with io.EOF.
		// We wait for serverDone to confirm ServeStdio has exited.
		logInfo("MCP_SERVER: Waiting for server.ServeStdio to exit after mcpShutdown signal...")
		err := <-serverDone // Wait for the server goroutine to finish
		if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "file already closed") {
			logError("MCP_SERVER: Server.ServeStdio exited with error after shutdown signal: %v", err)
		} else if err != nil {
			logInfo("MCP_SERVER: Server.ServeStdio exited as expected after shutdown signal (EOF or closed file): %v", err)
		} else {
			logInfo("MCP_SERVER: Server.ServeStdio exited gracefully after shutdown signal (nil error).")
		}
	}
	logInfo("MCP_SERVER: MCP server lifecycle concluded.")
}

func sendkeysNowaitToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	if !dockerRunning.Load() {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	keys, err := request.RequireString("keys")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Make REST call to /sendkeys_nowait endpoint
	resp, err := makeSendkeysNowaitRequest(keys)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to send keystroke: %v", err)), nil
	}

	if resp.Error != "" {
		return mcp.NewToolResultError(resp.Error), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Successfully sent keys: %s", resp.KeysSent)), nil
}

func sendkeysToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	if !dockerRunning.Load() {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	keys, err := request.RequireString("keys")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Make REST call to /sendkeys endpoint
	resp, err := makeSendkeysRequest(keys)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to send synchronous keystroke: %v", err)), nil
	}

	if resp.Error != "" {
		return mcp.NewToolResultError(resp.Error), nil
	}

	result := fmt.Sprintf("Status: %s\nMessage: %s", resp.Status, resp.Message)
	if resp.Output != "" {
		result += fmt.Sprintf("\nOutput:\n%s", resp.Output)
	}
	if resp.Timeout {
		result += "\nTimeout: true"
	}

	return mcp.NewToolResultText(result), nil
}

func screenToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	if !dockerRunning.Load() {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	// Make REST call to /screen endpoint
	resp, err := makeScreenRequest()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get screen: %v", err)), nil
	}

	if resp.Error != "" {
		return mcp.NewToolResultError(resp.Error), nil
	}

	result := fmt.Sprintf("Cursor: X=%d, Y=%d, Hidden=%t\n\nScreen Content:\n",
		resp.Cursor.X, resp.Cursor.Y, resp.Cursor.Hidden)

	for i, line := range resp.Screen {
		result += fmt.Sprintf("%2d: %s\n", i+1, line)
	}

	return mcp.NewToolResultText(result), nil
}

func execToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	running := dockerRunning.Load()

	if !running {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	argsStr, err := request.RequireString("args")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Parse args JSON array
	var args []string
	if err := json.Unmarshal([]byte(argsStr), &args); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid args JSON: %v", err)), nil
	}

	if len(args) == 0 {
		return mcp.NewToolResultError("args array cannot be empty"), nil
	}

	// Get optional stdin
	stdin := ""
	if args, ok := request.Params.Arguments.(map[string]interface{}); ok {
		if stdinVal, ok := args["stdin"].(string); ok {
			stdin = stdinVal
		}
	}

	// Get optional timeout
	timeout := 15
	if args, ok := request.Params.Arguments.(map[string]interface{}); ok {
		if timeoutVal, ok := args["timeout"].(float64); ok {
			timeout = int(timeoutVal)
		}
	}

	// Make REST call to /exec endpoint
	resp, err := makeExecRequest(args, stdin, timeout)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to execute command: %v", err)), nil
	}

	result := fmt.Sprintf("Exit Code: %d\nWorking Directory: %s", resp.ExitCode, resp.WorkingDirectory)
	if resp.Stdout != "" {
		result += fmt.Sprintf("\nStdout:\n%s", resp.Stdout)
	}
	if resp.Stderr != "" {
		result += fmt.Sprintf("\nStderr:\n%s", resp.Stderr)
	}
	if resp.Error != "" {
		result += fmt.Sprintf("\nError: %s", resp.Error)
	}
	if resp.Timeout {
		result += "\nTimeout: true"
	}

	return mcp.NewToolResultText(result), nil
}

func getWorkingDirectoryToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	if !dockerRunning.Load() {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	// Make REST call to /working_directory endpoint
	resp, err := makeWorkingDirectoryRequest()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get working directory: %v", err)), nil
	}

	if resp.Error != "" {
		return mcp.NewToolResultError(resp.Error), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Working Directory: %s", resp.WorkingDirectory)), nil
}

func writeFileToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	if !dockerRunning.Load() {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	filename, err := request.RequireString("filename")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	content, err := request.RequireString("content")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Make REST call to /write_file endpoint
	resp, err := makeWriteFileRequest(filename, content)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write file: %v", err)), nil
	}

	if resp.Error != "" {
		return mcp.NewToolResultError(resp.Error), nil
	}

	// Get working directory for additional context
	workingDirResp, workingDirErr := makeWorkingDirectoryRequest()
	workingDirInfo := ""
	if workingDirErr == nil && workingDirResp.Error == "" {
		workingDirInfo = fmt.Sprintf("\nWorking Directory: %s", workingDirResp.WorkingDirectory)
	}

	return mcp.NewToolResultText(fmt.Sprintf("File written successfully:\nPath: %s\nSize: %d bytes%s", resp.FullPath, resp.Size, workingDirInfo)), nil
}

func changeWorkingDirectoryToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	running := dockerRunning.Load()

	if !running {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	directory, err := request.RequireString("directory")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Make REST call to /change_working_directory endpoint
	resp, err := makeChangeWorkingDirectoryRequest(directory)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to change working directory: %v", err)), nil
	}

	if resp.Error != "" {
		result := fmt.Sprintf("Failed to change working directory: %s", resp.Error)
		if resp.CurrentWorkingDirectory != "" {
			result += fmt.Sprintf("\nCurrent working directory: %s", resp.CurrentWorkingDirectory)
		}
		return mcp.NewToolResultError(result), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Successfully changed working directory to: %s", resp.NewWorkingDirectory)), nil
}

func readFileToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	if !dockerRunning.Load() {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	filename, err := request.RequireString("filename")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Make REST call to /read_file endpoint
	resp, err := makeReadFileRequest(filename)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read file: %v", err)), nil
	}

	if resp.Error != "" {
		return mcp.NewToolResultError(resp.Error), nil
	}

	// Get working directory for additional context
	workingDirResp, workingDirErr := makeWorkingDirectoryRequest()
	workingDirInfo := ""
	if workingDirErr == nil && workingDirResp.Error == "" {
		workingDirInfo = fmt.Sprintf("\nWorking Directory: %s", workingDirResp.WorkingDirectory)
	}

	result := fmt.Sprintf("File read successfully:\nPath: %s\nSize: %d bytes%s\n\nContent:\n%s", resp.FullPath, resp.Size, workingDirInfo, resp.Content)

	return mcp.NewToolResultText(result), nil
}

func replaceInFileToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	if !dockerRunning.Load() {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	filename, err := request.RequireString("filename")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	searchString, err := request.RequireString("search_string")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	replacementString, err := request.RequireString("replacement_string")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Make REST call to /replace_in_file endpoint
	resp, err := makeReplaceInFileRequest(filename, searchString, replacementString)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to replace in file: %v", err)), nil
	}

	if resp.Error != "" {
		return mcp.NewToolResultError(resp.Error), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Text replaced successfully in file:\nPath: %s\nWorking Directory: %s", resp.FullPath, resp.WorkingDirectory)), nil
}

func beginToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	logInfo("MCP_BEGIN: Tool handler started.")

	// Check if container is running and get cleanup info without holding lock
	logDebug("MCP_BEGIN: Will lock dockerMutex to check container state")
	dockerMutex.Lock()
	logDebug("MCP_BEGIN: Did lock dockerMutex")
	needsCleanup := dockerRunning.Load()
	oldContainerID := dockerContainerID
	oldCmd := dockerCmd
	oldStdin := dockerStdin
	oldKeepaliveDone := dockerKeepaliveDone
	dockerMutex.Unlock()
	logDebug("MCP_BEGIN: Did unlock dockerMutex")

	// If container is already running, clean it up first
	if needsCleanup {
		logInfo("MCP_BEGIN: Existing Docker workspace is running (container ID: %s). Cleaning it up before starting a new one.", oldContainerID)

		// Signal keepalive handler to stop first
		if oldKeepaliveDone != nil {
			logInfo("MCP_BEGIN: Signaling existing keepalive handler to stop.")
			close(oldKeepaliveDone)
		} else {
			logInfo("MCP_BEGIN: No existing keepalive handler to stop (dockerKeepaliveDone is nil).")
		}

		// Close stdin to signal container to exit
		if oldStdin != nil {
			logInfo("MCP_BEGIN: Closing stdin of existing Docker container to signal it to exit.")
			if err := oldStdin.Close(); err != nil {
				logWarn("MCP_BEGIN: Error closing existing Docker stdin: %v", err)
			} else {
				logDebug("MCP_BEGIN: Successfully closed Docker stdin")
			}
		}

		// Wait for container process to exit or kill it
		if oldCmd != nil && oldCmd.Process != nil {
			logInfo("MCP_BEGIN: Waiting for existing Docker container process (PID: %d) to exit.", oldCmd.Process.Pid)
			done := make(chan error, 1)
			go func() {
				logDebug("MCP_BEGIN: Goroutine waiting for dockerCmd.Wait() for PID: %d", oldCmd.Process.Pid)
				done <- oldCmd.Wait()
				logDebug("MCP_BEGIN: dockerCmd.Wait() completed for PID: %d", oldCmd.Process.Pid)
			}()

			select {
			case err := <-done:
				if err != nil {
					logWarn("MCP_BEGIN: Previous Docker container (PID: %d) exited with error: %v", dockerCmd.Process.Pid, err)
				} else {
					logInfo("MCP_BEGIN: Previous Docker container (PID: %d) exited gracefully.", dockerCmd.Process.Pid)
				}
			case <-time.After(5 * time.Second):
				logWarn("MCP_BEGIN: Previous Docker container (PID: %d) did not exit gracefully after 5s, killing process.", oldCmd.Process.Pid)
				if err := oldCmd.Process.Kill(); err != nil {
					logError("MCP_BEGIN: Failed to kill previous Docker process (PID: %d): %v", oldCmd.Process.Pid, err)
				} else {
					logInfo("MCP_BEGIN: Previous Docker process (PID: %d) killed.", oldCmd.Process.Pid)
				}
				<-done // Wait for process to be killed
				logInfo("MCP_BEGIN: Previous Docker process (PID: %d) confirmed killed.", oldCmd.Process.Pid)
			}
		} else {
			logInfo("MCP_BEGIN: No existing Docker command/process to wait for (dockerCmd or dockerCmd.Process is nil).")
		}

		// Stop the container if it's still running
		if oldContainerID != "" {
			logInfo("MCP_BEGIN: Attempting to stop previous Docker container by ID: %s", oldContainerID)
			stopCmdArgs := []string{"docker", "stop", oldContainerID}
			logDebug("MCP_BEGIN: Executing: %v", stopCmdArgs)
			stopCmd := exec.Command(stopCmdArgs[0], stopCmdArgs[1:]...)
			if output, err := stopCmd.CombinedOutput(); err != nil {
				logWarn("MCP_BEGIN: Failed to stop previous Docker container %s: %v. Output: %s", oldContainerID, err, string(output))
			} else {
				logInfo("MCP_BEGIN: Previous Docker container %s stopped successfully. Output: %s", oldContainerID, string(output))
			}
		}

		// Reset state with lock
		logDebug("MCP_BEGIN: Will lock dockerMutex to reset state")
		dockerMutex.Lock()
		logDebug("MCP_BEGIN: Did lock dockerMutex to reset state")
		dockerRunning.Store(false)
		dockerContainerID = ""
		dockerHostPort = ""
		dockerCmd = nil
		dockerStdin = nil
		dockerKeepaliveDone = nil
		dockerMutex.Unlock()
		logDebug("MCP_BEGIN: Did unlock dockerMutex after reset")

		logInfo("MCP_BEGIN: Previous workspace cleanup complete. Proceeding to create new workspace.")
	} else {
		logInfo("MCP_BEGIN: No existing Docker workspace running. Proceeding to create a new one.")
	}

	// Get image ID (optional parameter)
	imageID := "sannysanoff/automation_terminal" // Default image
	if workspaceID, exists := request.Params.Arguments.(map[string]interface{})["workspace_id"]; exists {
		if workspaceIDStr, ok := workspaceID.(string); ok && workspaceIDStr != "" {
			imageID = workspaceIDStr
			logInfo("MCP_BEGIN: Using custom workspace_id as image: %s", imageID)
		} else {
			logInfo("MCP_BEGIN: Using default image: %s (workspace_id is empty)", imageID)
		}
	} else {
		logInfo("MCP_BEGIN: Using default image: %s (workspace_id not provided)", imageID)
	}

	// Create Docker container first to get container ID
	logInfo("MCP_BEGIN: Creating Docker container with image: %s", imageID)
	createCmdArgs := []string{"docker", "create", "-it", "-p", ":5399", "-e", "KEEPALIVE=true", imageID}
	logDebug("MCP_BEGIN: Docker create command: %v", createCmdArgs)
	createCmd := exec.Command(createCmdArgs[0], createCmdArgs[1:]...)

	createOutput, err := createCmd.Output()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to create Docker container with image %s: %v. Output: %s", imageID, err, string(createOutput))
		logError("MCP_BEGIN: %s", errMsg)
		// Attempt to pull the image if create failed, as it might not exist locally
		logInfo("MCP_BEGIN: Attempting to pull Docker image %s as create failed.", imageID)
		pullCmdArgs := []string{"docker", "pull", imageID}
		logDebug("MCP_BEGIN: Docker pull command: %v", pullCmdArgs)
		pullCmd := exec.Command(pullCmdArgs[0], pullCmdArgs[1:]...)
		if pullOutput, pullErr := pullCmd.CombinedOutput(); pullErr != nil {
			logError("MCP_BEGIN: Failed to pull Docker image %s: %v. Output: %s", imageID, pullErr, string(pullOutput))
			// Return original create error
			return mcp.NewToolResultError(errMsg + fmt.Sprintf(" | Pull attempt also failed: %v. Output: %s", pullErr, string(pullOutput))), nil
		}
		logInfo("MCP_BEGIN: Successfully pulled Docker image %s. Retrying create...", imageID)
		// Retry create
		createOutput, err = createCmd.Output() // Re-run the same createCmd
		if err != nil {
			errMsgRetry := fmt.Sprintf("Failed to create Docker container with image %s even after pull: %v. Output: %s", imageID, err, string(createOutput))
			logError("MCP_BEGIN: %s", errMsgRetry)
			return mcp.NewToolResultError(errMsgRetry), nil
		}
		logInfo("MCP_BEGIN: Docker container created successfully after image pull.")
	}

	containerID := strings.TrimSpace(string(createOutput))
	logInfo("MCP_BEGIN: Created Docker container ID: %s", containerID)
	if containerID == "" {
		errMsg := "Docker create command returned empty container ID."
		logError("MCP_BEGIN: %s", errMsg)
		return mcp.NewToolResultError(errMsg), nil
	}

	// Now start the container interactively
	logInfo("MCP_BEGIN: Starting Docker container with ID: %s", containerID)
	startCmdArgs := []string{"docker", "start", "-ai", containerID}
	logDebug("MCP_BEGIN: Docker start command: %v", startCmdArgs)
	cmd := exec.Command(startCmdArgs[0], startCmdArgs[1:]...)

	// Get stdin pipe to send pong responses
	logInfo("MCP_BEGIN: Getting stdin pipe for Docker container %s.", containerID)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get stdin pipe for container %s: %v", containerID, err)
		logError("MCP_BEGIN: %s", errMsg)
		// Clean up the created container as we can't interact with it
		logWarn("MCP_BEGIN: Attempting to remove container %s due to stdin pipe failure.", containerID)
		exec.Command("docker", "rm", "-f", containerID).Run() // Force remove
		return mcp.NewToolResultError(errMsg), nil
	}
	logDebug("MCP_BEGIN: Stdin pipe obtained for %s.", containerID)

	// Get stdout pipe to read ping messages
	logInfo("MCP_BEGIN: Getting stdout pipe for Docker container %s.", containerID)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get stdout pipe for container %s: %v", containerID, err)
		logError("MCP_BEGIN: %s", errMsg)
		stdin.Close() // Close the stdin pipe we got
		logWarn("MCP_BEGIN: Attempting to remove container %s due to stdout pipe failure.", containerID)
		exec.Command("docker", "rm", "-f", containerID).Run() // Force remove
		return mcp.NewToolResultError(errMsg), nil
	}
	logDebug("MCP_BEGIN: Stdout pipe obtained for %s.", containerID)

	// Start the container
	logInfo("MCP_BEGIN: Executing cmd.Start() for container %s.", containerID)
	if err := cmd.Start(); err != nil {
		errMsg := fmt.Sprintf("Failed to start Docker container %s: %v", containerID, err)
		logError("MCP_BEGIN: %s", errMsg)
		stdin.Close()
		stdout.Close() // Should be closed by cmd.Start() failure, but good practice
		logWarn("MCP_BEGIN: Attempting to remove container %s due to start failure.", containerID)
		exec.Command("docker", "rm", "-f", containerID).Run() // Force remove
		return mcp.NewToolResultError(errMsg), nil
	}

	logInfo("MCP_BEGIN: Docker container %s started successfully with PID: %d.", containerID, cmd.Process.Pid)

	// Wait a moment for container to start and initialize its internal server
	logInfo("MCP_BEGIN: Waiting 3 seconds for container %s to initialize...", containerID)
	time.Sleep(3 * time.Second)

	// Get port mapping
	logInfo("MCP_BEGIN: Inspecting container ports for container: %s", containerID)
	inspectCmdArgs := []string{"docker", "inspect", "--format={{json .NetworkSettings.Ports}}", containerID}
	logDebug("MCP_BEGIN: Running command: %v", inspectCmdArgs)
	inspectCmd := exec.Command(inspectCmdArgs[0], inspectCmdArgs[1:]...)
	portOutput, err := inspectCmd.Output() // Using Output to get stdout
	if err != nil {
		errMsg := fmt.Sprintf("Failed to inspect Docker container %s ports: %v. Output: %s", containerID, err, string(portOutput))
		logError("MCP_BEGIN: %s", errMsg)
		cmd.Process.Kill() // Kill the container process
		stdin.Close()
		// stdout is likely closed by process kill
		logWarn("MCP_BEGIN: Attempting to remove container %s due to inspect failure.", containerID)
		exec.Command("docker", "rm", "-f", containerID).Run() // Force remove
		return mcp.NewToolResultError(errMsg), nil
	}

	logDebug("MCP_BEGIN: Port inspection output for %s: %s", containerID, string(portOutput))
	var ports map[string][]map[string]string
	if err := json.Unmarshal(portOutput, &ports); err != nil {
		errMsg := fmt.Sprintf("Failed to parse port mapping JSON for %s: %v. JSON: %s", containerID, err, string(portOutput))
		logError("MCP_BEGIN: %s", errMsg)
		cmd.Process.Kill()
		stdin.Close()
		logWarn("MCP_BEGIN: Attempting to remove container %s due to port JSON parse failure.", containerID)
		exec.Command("docker", "rm", "-f", containerID).Run() // Force remove
		return mcp.NewToolResultError(errMsg), nil
	}

	logDebug("MCP_BEGIN: Parsed ports for %s: %+v", containerID, ports)
	hostPort := ""
	if tcpPorts, exists := ports["5399/tcp"]; exists && len(tcpPorts) > 0 {
		hostPort = tcpPorts[0]["HostPort"]
		logInfo("MCP_BEGIN: Found host port for 5399/tcp on container %s: %s", containerID, hostPort)
	} else {
		logWarn("MCP_BEGIN: No port mapping found for 5399/tcp on container %s.", containerID)
	}

	if hostPort == "" {
		errMsg := fmt.Sprintf("Host port for 5399/tcp is empty for container %s. Killing process.", containerID)
		logError("MCP_BEGIN: %s", errMsg)
		cmd.Process.Kill()
		stdin.Close()
		logWarn("MCP_BEGIN: Attempting to remove container %s due to missing host port.", containerID)
		exec.Command("docker", "rm", "-f", containerID).Run() // Force remove
		return mcp.NewToolResultError(errMsg), nil
	}

	// Update global state with lock
	logInfo("MCP_BEGIN: Updating global Docker state. Container ID: %s, Host Port: %s", containerID, hostPort)
	logDebug("MCP_BEGIN: Will lock dockerMutex to update state")
	dockerMutex.Lock()
	logDebug("MCP_BEGIN: Did lock dockerMutex to update state")
	dockerContainerID = containerID
	dockerHostPort = hostPort
	dockerRunning.Store(true)
	dockerCmd = cmd
	dockerStdin = stdin
	// Initialize keepalive done channel
	dockerKeepaliveDone = make(chan struct{})
	dockerMutex.Unlock()
	logDebug("MCP_BEGIN: Did unlock dockerMutex after update")

	// Update mcpServerAddr to use the new port
	oldServerAddr := mcpServerAddr
	mcpServerAddr = fmt.Sprintf("http://localhost:%s", hostPort)
	logInfo("MCP_BEGIN: Updated internal mcpServerAddr from %s to %s", oldServerAddr, mcpServerAddr)
	// Start goroutine to handle ping/pong communication
	logInfo("MCP_BEGIN: Starting Docker keepalive handler goroutine for container %s.", containerID)
	go handleDockerKeepalive(stdout, stdin) // stdin here is the pipe to the container

	logInfo("MCP_BEGIN: Docker container %s ready. Host port: %s. Workspace setup completed successfully.", containerID, hostPort)

	return mcp.NewToolResultText(fmt.Sprintf("Workspace started successfully! Container ID: %s, Mapped Port: %s", containerID, hostPort)), nil
}

func saveWorkToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	logInfo("MCP_SAVE_WORK: Starting save_work tool handler.")
	logDebug("MCP_SAVE_WORK: Will lock dockerMutex")
	dockerMutex.Lock()
	logDebug("MCP_SAVE_WORK: Did lock dockerMutex")
	defer func() {
		dockerMutex.Unlock()
		logDebug("MCP_SAVE_WORK: Did unlock dockerMutex (deferred)")
	}()

	// Check if container is running
	if !dockerRunning.Load() || dockerContainerID == "" {
		errMsg := fmt.Sprintf("No workspace running (dockerRunning=%t, containerID='%s'). Please call 'begin' tool first.", dockerRunning.Load(), dockerContainerID)
		logWarn("MCP_SAVE_WORK: %s", errMsg)
		return mcp.NewToolResultError(errMsg), nil
	}

	logInfo("MCP_SAVE_WORK: Workspace is running. Container ID: %s", dockerContainerID)

	comment, err := request.RequireString("comment")
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get 'comment' parameter: %v", err)
		logError("MCP_SAVE_WORK: %s", errMsg)
		return mcp.NewToolResultError(errMsg), nil
	}

	logInfo("MCP_SAVE_WORK: Commit comment: '%s'", comment)

	// Commit the container
	logInfo("MCP_SAVE_WORK: Committing Docker container %s with message: \"%s\"", dockerContainerID, comment)
	commitCmdArgs := []string{"docker", "commit", "-m", comment, dockerContainerID}
	logDebug("MCP_SAVE_WORK: Docker commit command: %v", commitCmdArgs)
	commitCmd := exec.Command(commitCmdArgs[0], commitCmdArgs[1:]...)

	output, err := commitCmd.Output() // Using Output to get the image ID
	if err != nil {
		errMsg := fmt.Sprintf("Failed to commit Docker container %s: %v. Output: %s", dockerContainerID, err, string(output))
		logError("MCP_SAVE_WORK: %s", errMsg)
		return mcp.NewToolResultError(errMsg), nil
	}

	imageIDWithPrefix := strings.TrimSpace(string(output))
	logInfo("MCP_SAVE_WORK: Docker commit successful for %s. Raw Image ID from commit: '%s'", dockerContainerID, imageIDWithPrefix)

	if imageIDWithPrefix == "" {
		errMsg := fmt.Sprintf("Docker commit for container %s returned empty image ID.", dockerContainerID)
		logError("MCP_SAVE_WORK: %s", errMsg)
		return mcp.NewToolResultError(errMsg), nil
	}

	// Remove "sha256:" prefix if present
	imageID := imageIDWithPrefix
	if strings.HasPrefix(imageID, "sha256:") {
		imageID = strings.TrimPrefix(imageID, "sha256:")
		logDebug("MCP_SAVE_WORK: Removed 'sha256:' prefix. Image ID now: '%s'", imageID)
	}

	// Shorten hash to first 12 characters for display, but return full ID if needed by platform
	displayImageID := imageID
	if len(displayImageID) > 12 {
		displayImageID = displayImageID[:12]
		logDebug("MCP_SAVE_WORK: Shortened image ID for display to: '%s'", displayImageID)
	}

	logInfo("MCP_SAVE_WORK: Docker container %s committed successfully. New image ID (display): %s, (full from commit): %s", dockerContainerID, displayImageID, imageIDWithPrefix)
	// The platform might expect the full sha256 prefixed ID or just the hash.
	// For now, returning the potentially shortened hash as per previous logic, but logging the full one.
	// Consider what `mcp.CallToolResult` expects for "New Workspace Id".
	// Returning the shortened ID as per the original logic for now.
	return mcp.NewToolResultText(fmt.Sprintf("Work saved, New Workspace Id: %s", displayImageID)), nil
}

func cleanupDockerContainer() {
	logInfo("MCP_CLEANUP_DOCKER: Initiating Docker container cleanup.")
	logDebug("MCP_CLEANUP_DOCKER: Will lock dockerMutex")
	dockerMutex.Lock()
	logDebug("MCP_CLEANUP_DOCKER: Did lock dockerMutex")
	defer func() {
		dockerMutex.Unlock()
		logDebug("MCP_CLEANUP_DOCKER: Did unlock dockerMutex (deferred)")
	}()

	if dockerRunning.Load() {
		logInfo("MCP_CLEANUP_DOCKER: Docker is running. Container ID: %s", dockerContainerID)

		// Signal keepalive handler to stop first
		if dockerKeepaliveDone != nil {
			logInfo("MCP_CLEANUP_DOCKER: Signaling keepalive handler to stop for container %s.", dockerContainerID)
			close(dockerKeepaliveDone)
			dockerKeepaliveDone = nil // Avoid double close
		} else {
			logInfo("MCP_CLEANUP_DOCKER: No keepalive handler to stop (dockerKeepaliveDone is nil) for container %s.", dockerContainerID)
		}

		// Close stdin to signal container to exit
		if dockerStdin != nil {
			logInfo("MCP_CLEANUP_DOCKER: Closing stdin of Docker container %s to signal it to exit.", dockerContainerID)
			if err := dockerStdin.Close(); err != nil {
				logWarn("MCP_CLEANUP_DOCKER: Error closing Docker stdin for container %s: %v", dockerContainerID, err)
			} else {
				logDebug("MCP_CLEANUP_DOCKER: Successfully closed Docker stdin")
			}
			dockerStdin = nil // Prevent reuse
		} else {
			logInfo("MCP_CLEANUP_DOCKER: No Docker stdin to close (dockerStdin is nil) for container %s.", dockerContainerID)
		}

		// Wait for container process to exit or kill it
		if dockerCmd != nil && dockerCmd.Process != nil {
			logInfo("MCP_CLEANUP_DOCKER: Waiting for Docker container process (PID: %d, Container: %s) to exit.", dockerCmd.Process.Pid, dockerContainerID)
			done := make(chan error, 1)
			go func() {
				logDebug("MCP_CLEANUP_DOCKER: Goroutine waiting for dockerCmd.Wait() for PID %d (Container %s)", dockerCmd.Process.Pid, dockerContainerID)
				done <- dockerCmd.Wait()
				logDebug("MCP_CLEANUP_DOCKER: dockerCmd.Wait() completed for PID %d (Container %s)", dockerCmd.Process.Pid, dockerContainerID)
			}()

			select {
			case err := <-done:
				if err != nil {
					logWarn("MCP_CLEANUP_DOCKER: Docker container process (PID: %d, Container: %s) exited with error: %v", dockerCmd.Process.Pid, dockerContainerID, err)
				} else {
					logInfo("MCP_CLEANUP_DOCKER: Docker container process (PID: %d, Container: %s) exited gracefully.", dockerCmd.Process.Pid, dockerContainerID)
				}
			case <-time.After(5 * time.Second):
				logWarn("MCP_CLEANUP_DOCKER: Docker container process (PID: %d, Container: %s) did not exit gracefully after 5s, killing process.", dockerCmd.Process.Pid, dockerContainerID)
				if err := dockerCmd.Process.Kill(); err != nil {
					logError("MCP_CLEANUP_DOCKER: Failed to kill Docker process (PID: %d, Container: %s): %v", dockerCmd.Process.Pid, dockerContainerID, err)
				} else {
					logInfo("MCP_CLEANUP_DOCKER: Docker process (PID: %d, Container: %s) killed.", dockerCmd.Process.Pid, dockerContainerID)
				}
				<-done // Wait for process to be killed
				logInfo("MCP_CLEANUP_DOCKER: Docker process (PID: %d, Container: %s) confirmed killed.", dockerCmd.Process.Pid, dockerContainerID)
			}
			dockerCmd = nil
		} else {
			logInfo("MCP_CLEANUP_DOCKER: No Docker command/process to wait for (dockerCmd or dockerCmd.Process is nil) for container %s.", dockerContainerID)
		}

		// Stop the container if it's still running (e.g., if process exited but container state is still 'running')
		// And remove it
		if dockerContainerID != "" {
			logInfo("MCP_CLEANUP_DOCKER: Attempting to stop and remove Docker container by ID: %s", dockerContainerID)
			// Stop the container first
			stopCmdArgs := []string{"docker", "stop", dockerContainerID}
			logDebug("MCP_CLEANUP_DOCKER: Executing: %v", stopCmdArgs)
			stopCmd := exec.Command(stopCmdArgs[0], stopCmdArgs[1:]...)
			if output, err := stopCmd.CombinedOutput(); err != nil {
				logWarn("MCP_CLEANUP_DOCKER: Failed to stop Docker container %s: %v. Output: %s", dockerContainerID, err, string(output))
			} else {
				logInfo("MCP_CLEANUP_DOCKER: Docker container %s stopped successfully. Output: %s", dockerContainerID, string(output))
			}

			// Remove the container
			rmCmdArgs := []string{"docker", "rm", dockerContainerID}
			logDebug("MCP_CLEANUP_DOCKER: Executing: %v", rmCmdArgs)
			rmCmd := exec.Command(rmCmdArgs[0], rmCmdArgs[1:]...)
			if output, err := rmCmd.CombinedOutput(); err != nil {
				logWarn("MCP_CLEANUP_DOCKER: Failed to remove Docker container %s: %v. Output: %s", dockerContainerID, err, string(output))
			} else {
				logInfo("MCP_CLEANUP_DOCKER: Docker container %s removed successfully. Output: %s", dockerContainerID, string(output))
			}
		}

		logInfo("MCP_CLEANUP_DOCKER: Resetting Docker state variables.")
		dockerRunning.Store(false)
		dockerContainerID = ""
		dockerHostPort = ""
	} else {
		logInfo("MCP_CLEANUP_DOCKER: Docker not running, no container to clean up.")
	}
	logInfo("MCP_CLEANUP_DOCKER: Docker container cleanup finished.")
}

// --- REST Client Functions for MCP Tools ---

func makeSendkeysNowaitRequest(keys string) (*SendkeysNowaitResponse, error) {
	data := url.Values{}
	data.Set("keys", keys)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(mcpServerAddr+"/sendkeys_nowait", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SendkeysNowaitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func makeWorkingDirectoryRequest() (*WorkingDirectoryResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(mcpServerAddr + "/working_directory")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result WorkingDirectoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func makeWriteFileRequest(filename, content string) (*WriteFileResponse, error) {
	data := url.Values{}
	data.Set("filename", filename)
	data.Set("content", content)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(mcpServerAddr+"/write_file", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result WriteFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func makeChangeWorkingDirectoryRequest(directory string) (*ChangeWorkingDirectoryResponse, error) {
	data := url.Values{}
	data.Set("directory", directory)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(mcpServerAddr+"/change_working_directory", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ChangeWorkingDirectoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func makeReadFileRequest(filename string) (*ReadFileResponse, error) {
	data := url.Values{}
	data.Set("filename", filename)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(mcpServerAddr+"/read_file", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ReadFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func makeReplaceInFileRequest(filename, searchString, replacementString string) (*ReplaceInFileResponse, error) {
	data := url.Values{}
	data.Set("filename", filename)
	data.Set("search_string", searchString)
	data.Set("replacement_string", replacementString)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(mcpServerAddr+"/replace_in_file", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ReplaceInFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// --- CLI Client Implementation ---

func printCLIUsage() {
	fmt.Println("PTY Automation Terminal Client")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  test_automation_terminal --cli [options] <command> [args...]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --host string     Server host (default: localhost)")
	fmt.Println("  --port int        Server port (default: 5399)")
	fmt.Println("  --json           Output raw JSON response")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  sendkeys-nowait <keys>    Send keystroke to terminal (async)")
	fmt.Println("  sendkeys <keys>           Send keystroke to terminal and wait for completion (sync)")
	fmt.Println("  screen                    Get current screen content and cursor position")
	fmt.Println("  exec <cmd> [args...]      Execute command out-of-band (outside PTY)")
	fmt.Println("                           Options: --stdin <text> --timeout <seconds>")
	fmt.Println("  get-working-directory      Get current working directory of shell process")
	fmt.Println("  write-file <filename> <content>  Write content to file (relative to working dir or absolute)")
	fmt.Println("  read-file <filename>             Read content from file (relative to working dir or absolute)")
	fmt.Println("  replace-in-file <filename> <search> <replacement>  Replace text in file (exact match required)")
	fmt.Println("  change-working-directory <dir>   Change working directory of shell process")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  test_automation_terminal --cli sendkeys-nowait \"ls -la\\n\"")
	fmt.Println("  test_automation_terminal --cli sendkeys \"echo 'Hello World'\\n\"")
	fmt.Println("  test_automation_terminal --cli screen")
	fmt.Println("  test_automation_terminal --cli exec \"ps\" \"aux\"")
	fmt.Println("  test_automation_terminal --cli exec --stdin \"hello\" \"cat\"")
	fmt.Println("  test_automation_terminal --cli exec --timeout 30 \"sleep\" \"5\"")
	fmt.Println("  test_automation_terminal --cli get-working-directory")
	fmt.Println("  test_automation_terminal --cli write-file \"test.txt\" \"Hello World\"")
	fmt.Println("  test_automation_terminal --cli read-file \"test.txt\"")
	fmt.Println("  test_automation_terminal --cli replace-in-file \"test.txt\" \"Hello\" \"Hi\"")
	fmt.Println("  test_automation_terminal --cli change-working-directory \"/tmp\"")
	fmt.Println("  test_automation_terminal --cli --host 192.168.1.100 --port 5399 screen")
}

func runCLIClient() {
	baseURL := fmt.Sprintf("http://%s:%d", cliHost, cliPort)

	switch cliCommand {
	case "sendkeys-nowait":
		if len(cliArgs) != 1 {
			fmt.Fprintf(os.Stderr, "Error: sendkeys-nowait requires exactly one argument (keys)\n")
			os.Exit(1)
		}
		keys := processEscapeSequences(cliArgs[0])
		resp, err := makeCLISendkeysNowaitRequest(baseURL, keys)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printSendkeysNowaitResponse(resp)
		}

	case "sendkeys":
		if len(cliArgs) != 1 {
			fmt.Fprintf(os.Stderr, "Error: sendkeys requires exactly one argument (keys)\n")
			os.Exit(1)
		}
		keys := processEscapeSequences(cliArgs[0])
		resp, err := makeCLISendkeysRequest(baseURL, keys)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printSendkeysResponse(resp)
		}

	case "screen":
		if len(cliArgs) != 0 {
			fmt.Fprintf(os.Stderr, "Error: screen command takes no arguments\n")
			os.Exit(1)
		}
		resp, err := makeCLIScreenRequest(baseURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printScreenResponse(resp)
		}

	case "exec":
		if len(cliArgs) < 1 {
			fmt.Fprintf(os.Stderr, "Error: exec requires at least one argument (command)\n")
			os.Exit(1)
		}

		// Parse optional flags
		args := cliArgs
		stdin := ""
		timeout := 15

		// Simple flag parsing - look for --stdin and --timeout
		finalArgs := []string{}
		for i := 0; i < len(args); i++ {
			if args[i] == "--stdin" && i+1 < len(args) {
				stdin = processEscapeSequences(args[i+1])
				i++ // skip next arg
			} else if args[i] == "--timeout" && i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					timeout = t
				}
				i++ // skip next arg
			} else {
				finalArgs = append(finalArgs, args[i])
			}
		}

		if len(finalArgs) == 0 {
			fmt.Fprintf(os.Stderr, "Error: exec requires at least one command argument\n")
			os.Exit(1)
		}

		resp, err := makeCLIExecRequest(baseURL, finalArgs, stdin, timeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printExecResponse(resp)
		}

	case "get-working-directory":
		if len(cliArgs) != 0 {
			fmt.Fprintf(os.Stderr, "Error: get-working-directory command takes no arguments\n")
			os.Exit(1)
		}
		resp, err := makeCLIWorkingDirectoryRequest(baseURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printWorkingDirectoryResponse(resp)
		}

	case "write-file":
		if len(cliArgs) != 2 {
			fmt.Fprintf(os.Stderr, "Error: write-file requires exactly two arguments (filename and content)\n")
			os.Exit(1)
		}
		filename := cliArgs[0]
		content := processEscapeSequences(cliArgs[1])
		resp, err := makeCLIWriteFileRequest(baseURL, filename, content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printWriteFileResponse(resp)
		}

	case "change-working-directory":
		if len(cliArgs) != 1 {
			fmt.Fprintf(os.Stderr, "Error: change-working-directory requires exactly one argument (directory)\n")
			os.Exit(1)
		}
		directory := cliArgs[0]
		resp, err := makeCLIChangeWorkingDirectoryRequest(baseURL, directory)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printChangeWorkingDirectoryResponse(resp)
		}

	case "read-file":
		if len(cliArgs) != 1 {
			fmt.Fprintf(os.Stderr, "Error: read-file requires exactly one argument (filename)\n")
			os.Exit(1)
		}
		filename := cliArgs[0]
		resp, err := makeCLIReadFileRequest(baseURL, filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printReadFileResponse(resp)
		}

	case "replace-in-file":
		if len(cliArgs) != 3 {
			fmt.Fprintf(os.Stderr, "Error: replace-in-file requires exactly three arguments (filename, search_string, replacement_string)\n")
			os.Exit(1)
		}
		filename := cliArgs[0]
		searchString := processEscapeSequences(cliArgs[1])
		replacementString := processEscapeSequences(cliArgs[2])
		resp, err := makeCLIReplaceInFileRequest(baseURL, filename, searchString, replacementString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printReplaceInFileResponse(resp)
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command '%s'\n", cliCommand)
		printCLIUsage()
		os.Exit(1)
	}
}

func processEscapeSequences(s string) string {
	// Process common escape sequences
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\t", "\t")
	s = strings.ReplaceAll(s, "\\r", "\r")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}

func printJSON(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func printSendkeysNowaitResponse(resp *SendkeysNowaitResponse) {
	if resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		return
	}

	if resp.Status == "success" {
		fmt.Printf("✅ Keys sent successfully: %q\n", resp.KeysSent)
	} else {
		fmt.Printf("⚠️  Status: %s, Keys: %q\n", resp.Status, resp.KeysSent)
	}
}

func printSendkeysResponse(resp *SendkeysResponse) {
	if resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		return
	}

	switch resp.Status {
	case "success":
		fmt.Println("✅ Command completed successfully")
	case "timeout":
		fmt.Println("⏰ Command timed out")
	default:
		fmt.Printf("⚠️  Status: %s\n", resp.Status)
	}

	if resp.Message != "" {
		fmt.Printf("Message: %s\n", resp.Message)
	}

	if resp.Timeout {
		fmt.Println("⚠️  Operation timed out")
	}

	if resp.Output != "" {
		fmt.Println("\n--- Command Output ---")
		fmt.Print(resp.Output)
		fmt.Println("--- End Output ---")
	}
}

func printScreenResponse(resp *ScreenResponse) {
	if resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		return
	}

	fmt.Println("📺 Current Screen Content:")
	fmt.Println(strings.Repeat("=", 80))

	for i, line := range resp.Screen {
		fmt.Printf("%2d│%s\n", i, line)
	}

	fmt.Println(strings.Repeat("=", 80))

	cursorStatus := "visible"
	if resp.Cursor.Hidden {
		cursorStatus = "hidden"
	}
	fmt.Printf("🖱️  Cursor: (%d, %d) - %s\n", resp.Cursor.X, resp.Cursor.Y, cursorStatus)
}

func printExecResponse(resp *ExecResponse) {
	if resp.Error != "" && resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		return
	}

	if resp.Timeout {
		fmt.Println("⏰ Command timed out")
	} else if resp.ExitCode == 0 {
		fmt.Println("✅ Command executed successfully")
	} else {
		fmt.Printf("❌ Command failed with exit code: %d\n", resp.ExitCode)
	}

	fmt.Printf("📁 Working Directory: %s\n", resp.WorkingDirectory)

	if resp.Stdout != "" {
		fmt.Println("\n--- STDOUT ---")
		fmt.Print(resp.Stdout)
	}

	if resp.Stderr != "" {
		fmt.Println("\n--- STDERR ---")
		fmt.Print(resp.Stderr)
	}

	if resp.Stdout != "" || resp.Stderr != "" {
		fmt.Println("--- End Output ---")
	}
}

func printWorkingDirectoryResponse(resp *WorkingDirectoryResponse) {
	if resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		return
	}

	fmt.Printf("📁 Working Directory: %s\n", resp.WorkingDirectory)
}

func printWriteFileResponse(resp *WriteFileResponse) {
	if resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		return
	}

	fmt.Printf("✅ File written successfully\n")
	fmt.Printf("📄 Path: %s\n", resp.FullPath)
	fmt.Printf("📏 Size: %d bytes\n", resp.Size)
}

func printChangeWorkingDirectoryResponse(resp *ChangeWorkingDirectoryResponse) {
	if resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		if resp.CurrentWorkingDirectory != "" {
			fmt.Printf("📁 Current Directory: %s\n", resp.CurrentWorkingDirectory)
		}
		return
	}

	fmt.Printf("✅ Working directory changed successfully\n")
	fmt.Printf("📁 New Directory: %s\n", resp.NewWorkingDirectory)
}

func printReadFileResponse(resp *ReadFileResponse) {
	if resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		return
	}

	fmt.Printf("✅ File read successfully\n")
	fmt.Printf("📄 Path: %s\n", resp.FullPath)
	fmt.Printf("📏 Size: %d bytes\n", resp.Size)
	fmt.Println("\n--- File Content ---")
	fmt.Print(resp.Content)
	fmt.Println("--- End Content ---")
}

func printReplaceInFileResponse(resp *ReplaceInFileResponse) {
	if resp.Error != "" {
		fmt.Printf("❌ Error: %s\n", resp.Error)
		if resp.WorkingDirectory != "" {
			fmt.Printf("📁 Working Directory: %s\n", resp.WorkingDirectory)
		}
		return
	}

	fmt.Printf("✅ Text replaced successfully in file\n")
	fmt.Printf("📄 Path: %s\n", resp.FullPath)
	fmt.Printf("📁 Working Directory: %s\n", resp.WorkingDirectory)
}

// --- CLI REST Client Functions ---

func makeCLISendkeysNowaitRequest(baseURL, keys string) (*SendkeysNowaitResponse, error) {
	data := url.Values{}
	data.Set("keys", keys)

	resp, err := http.PostForm(baseURL+"/sendkeys_nowait", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &SendkeysNowaitResponse{
			Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	var result SendkeysNowaitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeCLISendkeysRequest(baseURL, keys string) (*SendkeysResponse, error) {
	data := url.Values{}
	data.Set("keys", keys)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.PostForm(baseURL+"/sendkeys", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &SendkeysResponse{
			Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	var result SendkeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeCLIScreenRequest(baseURL string) (*ScreenResponse, error) {
	resp, err := http.Get(baseURL + "/screen")
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &ScreenResponse{
			Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	var result ScreenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeCLIExecRequest(baseURL string, args []string, stdin string, timeout int) (*ExecResponse, error) {
	req := ExecRequest{
		Args:    args,
		Stdin:   stdin,
		Timeout: timeout,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{Timeout: time.Duration(timeout+5) * time.Second}
	resp, err := client.Post(baseURL+"/exec", "application/json", strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &ExecResponse{
			Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	var result ExecResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeSendkeysRequest(keys string) (*SendkeysResponse, error) {
	data := url.Values{}
	data.Set("keys", keys)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.PostForm(mcpServerAddr+"/sendkeys", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SendkeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func makeScreenRequest() (*ScreenResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(mcpServerAddr + "/screen")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ScreenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func makeCLIWorkingDirectoryRequest(baseURL string) (*WorkingDirectoryResponse, error) {
	resp, err := http.Get(baseURL + "/working_directory")
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &WorkingDirectoryResponse{
			Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	var result WorkingDirectoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeCLIWriteFileRequest(baseURL, filename, content string) (*WriteFileResponse, error) {
	data := url.Values{}
	data.Set("filename", filename)
	data.Set("content", content)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(baseURL+"/write_file", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &WriteFileResponse{
			Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	var result WriteFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeCLIChangeWorkingDirectoryRequest(baseURL, directory string) (*ChangeWorkingDirectoryResponse, error) {
	data := url.Values{}
	data.Set("directory", directory)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(baseURL+"/change_working_directory", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code - allow various status codes as they're handled in the response
	var result ChangeWorkingDirectoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeCLIReadFileRequest(baseURL, filename string) (*ReadFileResponse, error) {
	data := url.Values{}
	data.Set("filename", filename)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(baseURL+"/read_file", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &ReadFileResponse{
			Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	var result ReadFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeCLIReplaceInFileRequest(baseURL, filename, searchString, replacementString string) (*ReplaceInFileResponse, error) {
	data := url.Values{}
	data.Set("filename", filename)
	data.Set("search_string", searchString)
	data.Set("replacement_string", replacementString)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(baseURL+"/replace_in_file", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code - allow various status codes as they're handled in the response
	var result ReplaceInFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w (body: %s)", err, string(body))
	}

	return &result, nil
}

func makeExecRequest(args []string, stdin string, timeout int) (*ExecResponse, error) {
	req := ExecRequest{
		Args:    args,
		Stdin:   stdin,
		Timeout: timeout,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: time.Duration(timeout+5) * time.Second}
	resp, err := client.Post(mcpServerAddr+"/exec", "application/json", strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ExecResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// --- Keepalive Mode Implementation ---

func runKeepaliveMode() {
	logInfo("Starting keepalive mode - sending ping every 5 seconds, waiting for pong from stdin")

	// Set up PTY and shell first
	if err := setupPtyAndShell(); err != nil {
		logError("Failed to setup PTY and shell in keepalive mode: %v", err)
		os.Exit(1)
	}

	// Defer cleanup to ensure it runs on exit
	defer cleanup()

	// Start PTY reader goroutine
	go ptyReader()

	// Give shell and pty_reader a moment to initialize
	logInfo("Waiting a moment for PTY to initialize...")
	time.Sleep(500 * time.Millisecond)

	// Set up signal handler for termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		logWarn("Received signal: %s. Initiating shutdown sequence.", sig)
		os.Exit(0) // Trigger deferred cleanup
	}()

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/sendkeys_nowait", sendkeysNowaitHandler)
	mux.HandleFunc("/sendkeys", sendkeysHandler)
	mux.HandleFunc("/screen", screenHandler)
	mux.HandleFunc("/exec", execHandler)
	mux.HandleFunc("/working_directory", workingDirectoryHandler)
	mux.HandleFunc("/write_file", writeFileHandler)
	mux.HandleFunc("/change_working_directory", changeWorkingDirectoryHandler)
	mux.HandleFunc("/read_file", readFileHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			logWarn("Invalid URL accessed: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "PTY Automation Server running in keepalive mode. Endpoints: /sendkeys_nowait, /sendkeys, /screen, /exec, /working_directory, /write_file, /read_file, /change_working_directory")
	})

	// Start HTTP server in background
	httpServerAddr := ":5399"
	server := &http.Server{
		Addr:    httpServerAddr,
		Handler: mux,
	}

	go func() {
		logInfo("Starting HTTP server on %s in keepalive mode", httpServerAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logError("HTTP server ListenAndServe error in keepalive mode: %v", err)
		}
	}()

	// Channel to receive pong responses from stdin
	pongChan := make(chan bool, 1)

	// Start stdin reader goroutine
	go func() {
		logDebug("KEEPALIVE_MODE: Starting stdin reader goroutine")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			logDebug("KEEPALIVE_MODE: Received from stdin: '%s'", line)
			if line == "pong" {
				logDebug("KEEPALIVE_MODE: Received pong from stdin, signaling pong channel")
				select {
				case pongChan <- true:
					logDebug("KEEPALIVE_MODE: Successfully sent pong signal to channel")
				default:
					logDebug("KEEPALIVE_MODE: Pong channel full, ignoring")
				}
			}
		}
		// If stdin closes, exit
		logInfo("KEEPALIVE_MODE: Stdin closed, exiting keepalive mode")
		server.Shutdown(context.Background())
		os.Exit(0)
	}()

	missedPongs := 0
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Send ping
			logDebug("KEEPALIVE_MODE: Sending ping to stdout")
			fmt.Println("ping")
			logDebug("KEEPALIVE_MODE: Sent ping, now expecting pong from stdin")

			// Wait up to 5 seconds for pong
			select {
			case <-pongChan:
				logInfo("KEEPALIVE_MODE: Received pong from stdin, resetting missed count")
				missedPongs = 0
			case <-time.After(5 * time.Second):
				missedPongs++
				logWarn("KEEPALIVE_MODE: Missed pong #%d (no response within 5 seconds)", missedPongs)

				if missedPongs >= 3 {
					logError("KEEPALIVE_MODE: Three pings passed without pong response, terminating")
					server.Shutdown(context.Background())
					os.Exit(1)
				}
			}
		}
	}
}

// --- Docker Keepalive Handler ---

func handleDockerKeepalive(stdout io.Reader, stdin io.Writer) {
	currentContainerID := dockerContainerID // Capture at start for logging clarity
	logInfo("DOCKER_KEEPALIVE: Handler started for container %s.", currentContainerID)
	scanner := bufio.NewScanner(stdout)

	// Create a channel to signal when scanning is done
	scanDone := make(chan struct{})
	var scanErr error // To store scanner error

	// Start scanning in a separate goroutine
	go func() {
		defer func() {
			logDebug("DOCKER_KEEPALIVE: Scanner goroutine for %s is exiting.", currentContainerID)
			close(scanDone)
		}()
		logDebug("DOCKER_KEEPALIVE: Scanner goroutine for %s started.", currentContainerID)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			logDebug("DOCKER_KEEPALIVE (Container: %s) | Docker stdout: %s", currentContainerID, line)

			if line == "ping" {
				logInfo("DOCKER_KEEPALIVE (Container: %s) | Received 'ping' from Docker container.", currentContainerID)

				// Check if we should stop before writing
				select {
				case <-dockerKeepaliveDone:
					logInfo("DOCKER_KEEPALIVE (Container: %s) | Keepalive handler stopping (dockerKeepaliveDone closed), not sending 'pong'.", currentContainerID)
					return // Exit goroutine
				default:
					// Continue
				}

				logInfo("DOCKER_KEEPALIVE (Container: %s) | Sending 'pong' to Docker container.", currentContainerID)
				if _, err := stdin.Write([]byte("pong\n")); err != nil {
					logError("DOCKER_KEEPALIVE (Container: %s) | Failed to send 'pong' to Docker container: %v", currentContainerID, err)
					// This is a critical error, the communication is broken.
					// We should probably signal that the container is unhealthy.
					// For now, just return and let the main select block handle it.
					scanErr = err // Store error
					return        // Exit goroutine
				}
				logDebug("DOCKER_KEEPALIVE (Container: %s) | 'pong' sent successfully.", currentContainerID)
			}
		}
		// After loop, check for scanner error
		if err := scanner.Err(); err != nil {
			logError("DOCKER_KEEPALIVE (Container: %s) | Scanner error after loop: %v", currentContainerID, err)
			scanErr = err // Store error
		} else {
			logInfo("DOCKER_KEEPALIVE (Container: %s) | Scanner finished without error (EOF or closed).", currentContainerID)
		}
	}()

	// Wait for either scan completion or stop signal from dockerKeepaliveDone
	select {
	case <-scanDone:
		logInfo("DOCKER_KEEPALIVE (Container: %s) | ScanDone channel closed.", currentContainerID)
		if scanErr != nil {
			logError("DOCKER_KEEPALIVE (Container: %s) | Exited due to scanner error: %v", currentContainerID, scanErr)
		} else {
			logInfo("DOCKER_KEEPALIVE (Container: %s) | Exited due to stdout stream close/EOF.", currentContainerID)
		}
		// This path means the container's stdout ended (it might have exited or closed stdout).
	case <-dockerKeepaliveDone:
		logInfo("DOCKER_KEEPALIVE (Container: %s) | Exited due to stop signal (dockerKeepaliveDone channel closed).", currentContainerID)
		// This path means cleanupDockerContainer or beginToolHandler (for an old container) initiated the stop.
		// The scanner goroutine should also see dockerKeepaliveDone and exit.
		return // Explicitly return, main logic for dockerDied is below.
	}

	// If we reach here, it means the keepalive handler is exiting primarily because of issues
	// with the Docker container's communication (scanDone closed, possibly with error),
	// NOT because it was explicitly asked to stop via dockerKeepaliveDone for a controlled shutdown.
	logWarn("DOCKER_KEEPALIVE (Container: %s) | Communication with Docker container potentially lost or container exited.", currentContainerID)
	dockerMutex.Lock()
	defer dockerMutex.Unlock()
	// Check if this is still the active container and if it was marked as running.
	// It's possible a new container was started, and this is the keepalive for an old one.
	if dockerRunning.Load() && dockerContainerID == currentContainerID {
		logWarn("DOCKER_KEEPALIVE (Container: %s) | Marking active Docker container as not running due to communication loss/exit.", currentContainerID)
		dockerRunning.Store(false) // Mark as not running. Actual cleanup (stop/rm) happens elsewhere or if begin is called again.

		// Signal that this specific Docker container instance died.
		// This is important for the MCP server to react if its active container dies.
		logInfo("DOCKER_KEEPALIVE (Container: %s) | Closing dockerDied channel to signal container death.", currentContainerID)
		select {
		case <-dockerDied:
			logWarn("DOCKER_KEEPALIVE (Container: %s) | dockerDied channel was already closed.", currentContainerID)
		default:
			close(dockerDied)
			logInfo("DOCKER_KEEPALIVE (Container: %s) | dockerDied channel closed.", currentContainerID)
		}
	} else {
		logInfo("DOCKER_KEEPALIVE (Container: %s) | Docker container was already marked not running or a new container is active (current active: %s). No action taken on dockerDied.", currentContainerID, dockerContainerID)
	}
	logInfo("DOCKER_KEEPALIVE (Container: %s) | Handler finished.", currentContainerID)
}
