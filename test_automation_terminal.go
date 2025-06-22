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
	dockerRunning       bool
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
			mcpLogFile.WriteString(logLine)
			mcpLogFile.Sync() // Ensure it's written immediately
		}
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
		mcpLogFile, err = os.OpenFile("/tmp/linux_terminal_mcp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			logError("Failed to open MCP log file: %v", err)
		} else {
			defer mcpLogFile.Close()
			// Write startup message with PID
			pid := os.Getpid()
			startupMsg := fmt.Sprintf("[%d] MCP mode started at %s\n", pid, time.Now().Format(time.RFC3339))
			mcpLogFile.WriteString(startupMsg)
			mcpLogFile.Sync()
		}

		logInfo("Starting in MCP server mode, server address: %s", mcpServerAddr)
		runMCPServer()
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
		logWarn("\nReceived signal: %s. Initiating shutdown sequence.", sig)
		// cleanup() is deferred, so it will run.
		// If server needs explicit shutdown:
		// if httpServer != nil { httpServer.Shutdown(context.Background()) }
		os.Exit(0) // Trigger deferred cleanup
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
		<-dockerDied
		logError("Docker container died, exiting MCP server with error code")
		os.Exit(1)
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

	// Start the stdio server in a goroutine
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.ServeStdio(s)
	}()

	// Wait for either server completion or shutdown signal
	select {
	case err := <-serverDone:
		if err != nil {
			logError("MCP server error: %v", err)
		}
	case <-mcpShutdown:
		logInfo("MCP server shutting down gracefully")
		// ServeStdio will exit when stdin closes, which happens during cleanup
	}
}

func sendkeysNowaitToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

	if !running {
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
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

	if !running {
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
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

	if !running {
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
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

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
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

	if !running {
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
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

	if !running {
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
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

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
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

	if !running {
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
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()

	if !running {
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
	logDebug("BEGIN: Starting begin tool handler")
	dockerMutex.Lock()
	defer dockerMutex.Unlock()

	// If container is already running, clean it up first
	if dockerRunning {
		logInfo("BEGIN: Existing workspace is running, closing it before starting new one")
		logDebug("BEGIN: Container already running, cleaning up first")

		// Signal keepalive handler to stop first
		if dockerKeepaliveDone != nil {
			logDebug("BEGIN: Signaling keepalive handler to stop")
			close(dockerKeepaliveDone)
			dockerKeepaliveDone = nil
		}

		// Close stdin to signal container to exit
		if dockerStdin != nil {
			logDebug("BEGIN: Closing Docker stdin")
			dockerStdin.Close()
			dockerStdin = nil
		}

		// Wait for container process to exit or kill it
		if dockerCmd != nil && dockerCmd.Process != nil {
			done := make(chan error, 1)
			go func() {
				done <- dockerCmd.Wait()
			}()

			select {
			case err := <-done:
				if err != nil {
					logWarn("BEGIN: Previous Docker container exited with error: %v", err)
				} else {
					logInfo("BEGIN: Previous Docker container exited gracefully")
				}
			case <-time.After(5 * time.Second):
				logWarn("BEGIN: Previous Docker container did not exit gracefully, killing process")
				dockerCmd.Process.Kill()
				<-done // Wait for process to be killed
			}
			dockerCmd = nil
		}

		// Stop the container if it's still running
		if dockerContainerID != "" {
			logInfo("BEGIN: Stopping previous Docker container: %s", dockerContainerID)
			stopCmd := exec.Command("docker", "stop", dockerContainerID)
			if err := stopCmd.Run(); err != nil {
				logWarn("BEGIN: Failed to stop previous Docker container %s: %v", dockerContainerID, err)
			} else {
				logInfo("BEGIN: Previous Docker container %s stopped successfully", dockerContainerID)
			}
		}

		// Reset state
		dockerRunning = false
		dockerContainerID = ""
		dockerHostPort = ""

		logInfo("BEGIN: Previous workspace cleaned up, proceeding with new workspace")
	}

	// Get image ID (optional parameter)
	imageID := "sannysanoff/automation_terminal"
	if id, err := request.RequireString("workspace_id"); err == nil && id != "" {
		imageID = id
		logDebug("BEGIN: Using custom image ID: %s", imageID)
	} else {
		logDebug("BEGIN: Using default image ID: %s", imageID)
	}

	// Create Docker container first to get container ID
	logInfo("Creating Docker container with image: %s", imageID)
	logDebug("BEGIN: Creating docker create command")
	createCmd := exec.Command("docker", "create", "-it", "-p", ":5399", "-e", "KEEPALIVE=true", imageID)
	logDebug("BEGIN: Docker create command: %v", createCmd.Args)

	logDebug("BEGIN: Executing docker create")
	createOutput, err := createCmd.Output()
	if err != nil {
		logDebug("BEGIN: Failed to create Docker container: %v", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create Docker container: %v", err)), nil
	}

	containerID := strings.TrimSpace(string(createOutput))
	logDebug("BEGIN: Created container ID: %s", containerID)
	if containerID == "" {
		logDebug("BEGIN: Docker create returned empty container ID")
		return mcp.NewToolResultError("Docker create command returned empty container ID"), nil
	}

	// Now start the container interactively
	logInfo("Starting Docker container with ID: %s", containerID)
	logDebug("BEGIN: Creating docker start command")
	cmd := exec.Command("docker", "start", "-ai", containerID)
	logDebug("BEGIN: Docker start command: %v", cmd.Args)

	// Get stdin pipe to send pong responses
	logDebug("BEGIN: Getting stdin pipe for Docker container")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		logDebug("BEGIN: Failed to get stdin pipe: %v", err)
		// Clean up the created container
		exec.Command("docker", "rm", containerID).Run()
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get stdin pipe: %v", err)), nil
	}

	// Get stdout pipe to read ping messages
	logDebug("BEGIN: Getting stdout pipe for Docker container")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logDebug("BEGIN: Failed to get stdout pipe: %v", err)
		stdin.Close()
		// Clean up the created container
		exec.Command("docker", "rm", containerID).Run()
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get stdout pipe: %v", err)), nil
	}

	// Start the container
	logDebug("BEGIN: Starting Docker container")
	if err := cmd.Start(); err != nil {
		logDebug("BEGIN: Failed to start Docker container: %v", err)
		stdin.Close()
		// Clean up the created container
		exec.Command("docker", "rm", containerID).Run()
		return mcp.NewToolResultError(fmt.Sprintf("Failed to start Docker container: %v", err)), nil
	}

	logInfo("Docker container started with PID: %d", cmd.Process.Pid)
	logDebug("BEGIN: Docker container started successfully with PID: %d", cmd.Process.Pid)

	// Wait a moment for container to start
	logDebug("BEGIN: Waiting 2 seconds for container to initialize")
	time.Sleep(2 * time.Second)

	// Get port mapping
	logDebug("BEGIN: Inspecting container ports for container: %s", containerID)
	inspectCmd := exec.Command("docker", "inspect", "--format={{json .NetworkSettings.Ports}}", containerID)
	logDebug("BEGIN: Running command: %v", inspectCmd.Args)
	portOutput, err := inspectCmd.Output()
	if err != nil {
		logDebug("BEGIN: Failed to inspect Docker container ports: %v", err)
		cmd.Process.Kill()
		stdin.Close()
		return mcp.NewToolResultError(fmt.Sprintf("Failed to inspect Docker container ports: %v", err)), nil
	}

	logDebug("BEGIN: Port inspection output: %s", string(portOutput))
	// Parse port mapping JSON
	var ports map[string][]map[string]string
	if err := json.Unmarshal(portOutput, &ports); err != nil {
		logDebug("BEGIN: Failed to parse port mapping JSON: %v", err)
		cmd.Process.Kill()
		stdin.Close()
		return mcp.NewToolResultError(fmt.Sprintf("Failed to parse port mapping JSON: %v", err)), nil
	}

	logDebug("BEGIN: Parsed ports: %+v", ports)
	// Extract host port for 5399/tcp
	hostPort := ""
	if tcpPorts, exists := ports["5399/tcp"]; exists && len(tcpPorts) > 0 {
		hostPort = tcpPorts[0]["HostPort"]
		logDebug("BEGIN: Found host port: %s", hostPort)
	} else {
		logDebug("BEGIN: No port mapping found for 5399/tcp")
	}

	if hostPort == "" {
		logDebug("BEGIN: Host port is empty, killing process")
		cmd.Process.Kill()
		stdin.Close()
		return mcp.NewToolResultError("Failed to find host port mapping for 5399/tcp"), nil
	}

	// Update global state
	logDebug("BEGIN: Updating global state")
	dockerContainerID = containerID
	dockerHostPort = hostPort
	dockerRunning = true
	dockerCmd = cmd
	dockerStdin = stdin

	// Update mcpServerAddr to use the new port
	oldServerAddr := mcpServerAddr
	mcpServerAddr = fmt.Sprintf("http://localhost:%s", hostPort)
	logDebug("BEGIN: Updated server address from %s to %s", oldServerAddr, mcpServerAddr)

	// Initialize keepalive done channel
	dockerKeepaliveDone = make(chan struct{})

	// Start goroutine to handle ping/pong communication
	logDebug("BEGIN: Starting Docker keepalive handler goroutine")
	go handleDockerKeepalive(stdout, stdin)

	logInfo("Docker container ready. Host port: %s, Container ID: %s", hostPort, containerID)
	logDebug("BEGIN: Workspace setup completed successfully")

	return mcp.NewToolResultText("Workspace started successfully!"), nil
}

func saveWorkToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	logDebug("SAVE_WORK: Starting save_work tool handler")
	dockerMutex.Lock()
	defer dockerMutex.Unlock()

	// Check if container is running
	if !dockerRunning || dockerContainerID == "" {
		logDebug("SAVE_WORK: No workspace running (dockerRunning=%t, containerID='%s')", dockerRunning, dockerContainerID)
		return mcp.NewToolResultError("No workspace is running. Please call 'begin' tool first."), nil
	}

	logDebug("SAVE_WORK: Workspace is running, container ID: %s", dockerContainerID)

	comment, err := request.RequireString("comment")
	if err != nil {
		logDebug("SAVE_WORK: Failed to get comment parameter: %v", err)
		return mcp.NewToolResultError(err.Error()), nil
	}

	logDebug("SAVE_WORK: Commit comment: '%s'", comment)

	// Commit the container
	logInfo("Committing Docker container %s with message: %s", dockerContainerID, comment)
	logDebug("SAVE_WORK: Creating docker commit command")
	commitCmd := exec.Command("docker", "commit", "-m", comment, dockerContainerID)
	logDebug("SAVE_WORK: Docker commit command: %v", commitCmd.Args)

	logDebug("SAVE_WORK: Executing docker commit")
	output, err := commitCmd.Output()
	if err != nil {
		logDebug("SAVE_WORK: Docker commit failed: %v", err)
		return mcp.NewToolResultError(fmt.Sprintf("Failed to commit Docker container: %v", err)), nil
	}

	logDebug("SAVE_WORK: Docker commit output: '%s'", string(output))
	imageID := strings.TrimSpace(string(output))
	if imageID == "" {
		logDebug("SAVE_WORK: Docker commit returned empty image ID")
		return mcp.NewToolResultError("Docker commit command returned empty image ID"), nil
	}

	// Remove "sha256:" prefix if present
	if strings.HasPrefix(imageID, "sha256:") {
		imageID = strings.TrimPrefix(imageID, "sha256:")
	}

	// Shorten hash to first 12 characters
	if len(imageID) > 12 {
		imageID = imageID[:12]
	}

	logInfo("Docker container committed successfully. New image ID: %s", imageID)
	logDebug("SAVE_WORK: Successfully committed container, new image ID: %s", imageID)

	return mcp.NewToolResultText(fmt.Sprintf("Work saved, New Workspace Id: %s", imageID)), nil
}

func cleanupDockerContainer() {
	dockerMutex.Lock()
	defer dockerMutex.Unlock()

	if dockerRunning {
		logInfo("Cleaning up Docker container: %s", dockerContainerID)

		// Signal keepalive handler to stop first
		if dockerKeepaliveDone != nil {
			logDebug("Signaling keepalive handler to stop")
			close(dockerKeepaliveDone)
			dockerKeepaliveDone = nil
		}

		// Close stdin to signal container to exit
		if dockerStdin != nil {
			logDebug("Closing Docker stdin")
			dockerStdin.Close()
			dockerStdin = nil
		}

		// Wait for container process to exit or kill it
		if dockerCmd != nil && dockerCmd.Process != nil {
			done := make(chan error, 1)
			go func() {
				done <- dockerCmd.Wait()
			}()

			select {
			case err := <-done:
				if err != nil {
					logWarn("Docker container exited with error: %v", err)
				} else {
					logInfo("Docker container exited gracefully")
				}
			case <-time.After(5 * time.Second):
				logWarn("Docker container did not exit gracefully, killing process")
				dockerCmd.Process.Kill()
				<-done // Wait for process to be killed
			}
			dockerCmd = nil
		}

		// Stop the container if it's still running
		if dockerContainerID != "" {
			logInfo("Stopping Docker container: %s", dockerContainerID)
			stopCmd := exec.Command("docker", "stop", dockerContainerID)
			if err := stopCmd.Run(); err != nil {
				logWarn("Failed to stop Docker container %s: %v", dockerContainerID, err)
			} else {
				logInfo("Docker container %s stopped successfully", dockerContainerID)
			}
		}

		dockerRunning = false
		dockerContainerID = ""
		dockerHostPort = ""
	}
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
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "pong" {
				select {
				case pongChan <- true:
				default:
					// Channel full, ignore
				}
			}
		}
		// If stdin closes, exit
		logInfo("Stdin closed, exiting keepalive mode")
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
			fmt.Println("ping")

			// Wait up to 5 seconds for pong
			select {
			case <-pongChan:
				logInfo("Received pong, resetting missed count")
				missedPongs = 0
			case <-time.After(5 * time.Second):
				missedPongs++
				logWarn("Missed pong #%d", missedPongs)

				if missedPongs >= 3 {
					logError("Three pings passed without pong response, terminating")
					server.Shutdown(context.Background())
					os.Exit(1)
				}
			}
		}
	}
}

// --- Docker Keepalive Handler ---

func handleDockerKeepalive(stdout io.Reader, stdin io.Writer) {
	logInfo("Starting Docker keepalive handler")
	scanner := bufio.NewScanner(stdout)

	// Create a channel to signal when scanning is done
	scanDone := make(chan struct{})

	// Start scanning in a separate goroutine
	go func() {
		defer close(scanDone)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			logDebug("Docker stdout: %s", line)

			if line == "ping" {
				logDebug("Received ping from Docker container, sending pong")

				// Check if we should stop before writing
				select {
				case <-dockerKeepaliveDone:
					logDebug("Keepalive handler stopping, not sending pong")
					return
				default:
				}

				if _, err := stdin.Write([]byte("pong\n")); err != nil {
					logError("Failed to send pong to Docker container: %v", err)
					return
				}
			}
		}
	}()

	// Wait for either scan completion or stop signal
	select {
	case <-scanDone:
		if err := scanner.Err(); err != nil {
			logError("Error reading from Docker stdout: %v", err)
		}
		logInfo("Docker keepalive handler exited due to stdout close")
	case <-dockerKeepaliveDone:
		logInfo("Docker keepalive handler exited due to stop signal")
		return
	}

	// If we exit the keepalive handler due to stdout close, the container likely died
	dockerMutex.Lock()
	if dockerRunning {
		logWarn("Docker container communication lost, marking as not running")
		dockerRunning = false
		// Signal that Docker died
		select {
		case <-dockerDied:
			// Already closed
		default:
			close(dockerDied)
		}
	}
	dockerMutex.Unlock()
}
