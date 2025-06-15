package main

import (
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
	"runtime"
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
	mcpServerAddr string = "http://localhost:5399" // Default server address for MCP client calls
	
	// Docker container management for MCP mode
	dockerContainerID string
	dockerHostPort    string
	dockerRunning     bool
	dockerMutex       sync.Mutex
	
	// CLI mode configuration
	cliMode    bool
	cliHost    string = "localhost"
	cliPort    int    = 5399
	cliCommand string
	cliArgs    []string
	outputJSON bool
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

type OOBExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Error    string `json:"error,omitempty"`
	Timeout  bool   `json:"timeout,omitempty"`
	ExitCode int    `json:"exit_code"`
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
	linesBeforeCommandEffect, currentBufferBefore := eventHandler.GetCapturedLinesAndCurrentBuffer()
	eventHandler.ResetCapturedLinesAndSetBuffer(currentBufferBefore)
	logDebug("SYNC: lines_before_command_effect (len %d): %v", len(linesBeforeCommandEffect), linesBeforeCommandEffect)
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

		outputSegment := linesAfter[len(linesBeforeCommandEffect):]
		if finalCurrentLine != "" {
			outputSegment = append(outputSegment, finalCurrentLine)
		}
		joined := strings.Join(outputSegment, "")
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

		if runtime.GOOS == "darwin" {
			// macOS: check pstree
			pstreeCmd := exec.Command("pstree", fmt.Sprintf("%d", shellPID))
			pstreeOut, pstreeErr := pstreeCmd.CombinedOutput()
			logDebug("pstree for PID %d: Output:\n%s", shellPID, string(pstreeOut))

			if pstreeErr == nil {
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
				if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
					logInfo("Shell process (PID: %d) exited (detected after pstree failure).", shellPID)
					completionMessage = "Shell process exited (detected after pstree failure)."
					commandCompletedNormally = true
					break
				}
				logWarn("pstree command for PID %d failed: %v. Output: %s. Assuming command still running or error with pstree.", shellPID, pstreeErr, string(pstreeOut))
			}
		} else if runtime.GOOS == "linux" {
			logDebug("Using ps/awk to check for children of shell PID %d on Linux.", shellPID)
			psCmd := fmt.Sprintf("ps -o pid,ppid,comm -ax | awk '$2 == %d {print $1}'", shellPID)
			cmd := exec.Command("sh", "-c", psCmd)

			output, err := cmd.Output()
			if err != nil {
				if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
					logInfo("Shell process (PID: %d) exited (detected after ps/awk command failure).", shellPID)
					completionMessage = "Shell process exited (detected after ps/awk command failure)."
					commandCompletedNormally = true
					break
				}
				logWarn("ps/awk command for PID %d failed: %v. Output: %s. Assuming command still running or error with command.", shellPID, err, string(output))
			} else {
				trimmedOutput := strings.TrimSpace(string(output))
				logDebug("ps/awk output for children of PID %d: '%s'", shellPID, trimmedOutput)
				if trimmedOutput == "" {
					logInfo("Linux ps/awk check: Shell PID %d has no children. Command complete.", shellPID)
					completionMessage = "Command completed (Linux ps/awk check)."
					commandCompletedNormally = true
					break
				}
			}
		} else {
			logWarn("Synchronous keystroke completion check is not implemented for this platform: %s. Assuming command completed.", runtime.GOOS)
			completionMessage = fmt.Sprintf("Command completion check not available for %s.", runtime.GOOS)
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
		var childPIDs []int
		if runtime.GOOS == "darwin" {
			// Use 'ps -a -o pid,ppid' to get all processes, then recursively find all descendants of shellPID
			psCmd := exec.Command("ps", "-a", "-o", "pid,ppid")
			out, err := psCmd.Output()
			if err == nil {
				type proc struct{ pid, ppid int }
				var procs []proc
				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				for _, line := range lines[1:] { // skip header
					fields := strings.Fields(line)
					if len(fields) != 2 {
						continue
					}
					pid, err1 := strconv.Atoi(fields[0])
					ppid, err2 := strconv.Atoi(fields[1])
					if err1 == nil && err2 == nil {
						procs = append(procs, proc{pid, ppid})
					}
				}
				// Build map: ppid -> []pid
				childrenMap := make(map[int][]int)
				for _, p := range procs {
					childrenMap[p.ppid] = append(childrenMap[p.ppid], p.pid)
				}
				// Recursively collect all descendants of shellPID
				var collect func(int)
				seen := make(map[int]bool)
				collect = func(ppid int) {
					for _, pid := range childrenMap[ppid] {
						if pid == shellPID || seen[pid] {
							continue
						}
						seen[pid] = true
						childPIDs = append(childPIDs, pid)
						collect(pid)
					}
				}
				collect(shellPID)
			}
		} else if runtime.GOOS == "linux" {
			// Use 'ps -o pid= --ppid <shellPID>'
			psCmd := exec.Command("ps", "-o", "pid=", "--ppid", fmt.Sprintf("%d", shellPID))
			out, err := psCmd.Output()
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					if pid, err := strconv.Atoi(line); err == nil && pid != shellPID {
						childPIDs = append(childPIDs, pid)
					}
				}
			}
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
			var stillChildren []int
			if runtime.GOOS == "darwin" {
				psCmd := exec.Command("ps", "-a", "-o", "pid,ppid")
				out, err := psCmd.Output()
				if err == nil {
					type proc struct{ pid, ppid int }
					var procs []proc
					lines := strings.Split(strings.TrimSpace(string(out)), "\n")
					for _, line := range lines[1:] { // skip header
						fields := strings.Fields(line)
						if len(fields) != 2 {
							continue
						}
						pid, err1 := strconv.Atoi(fields[0])
						ppid, err2 := strconv.Atoi(fields[1])
						if err1 == nil && err2 == nil {
							procs = append(procs, proc{pid, ppid})
						}
					}
					childrenMap := make(map[int][]int)
					for _, p := range procs {
						childrenMap[p.ppid] = append(childrenMap[p.ppid], p.pid)
					}
					seen := make(map[int]bool)
					var collect func(int)
					collect = func(ppid int) {
						for _, pid := range childrenMap[ppid] {
							if pid == shellPID || seen[pid] {
								continue
							}
							seen[pid] = true
							stillChildren = append(stillChildren, pid)
							collect(pid)
						}
					}
					collect(shellPID)
				}
			} else if runtime.GOOS == "linux" {
				psCmd := exec.Command("ps", "-o", "pid=", "--ppid", fmt.Sprintf("%d", shellPID))
				out, err := psCmd.Output()
				if err == nil {
					lines := strings.Split(strings.TrimSpace(string(out)), "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						if pid, err := strconv.Atoi(line); err == nil && pid != shellPID {
							stillChildren = append(stillChildren, pid)
						}
					}
				}
			}
			if len(stillChildren) == 0 {
				logInfo("All child processes (except shell) exited after SIGINT.")
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		// After waiting, check again and send SIGKILL if needed
		var stillChildren []int
		if runtime.GOOS == "darwin" {
			psCmd := exec.Command("ps", "-a", "-o", "pid,ppid")
			out, err := psCmd.Output()
			if err == nil {
				type proc struct{ pid, ppid int }
				var procs []proc
				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				for _, line := range lines[1:] { // skip header
					fields := strings.Fields(line)
					if len(fields) != 2 {
						continue
					}
					pid, err1 := strconv.Atoi(fields[0])
					ppid, err2 := strconv.Atoi(fields[1])
					if err1 == nil && err2 == nil {
						procs = append(procs, proc{pid, ppid})
					}
				}
				childrenMap := make(map[int][]int)
				for _, p := range procs {
					childrenMap[p.ppid] = append(childrenMap[p.ppid], p.pid)
				}
				seen := make(map[int]bool)
				var collect func(int)
				collect = func(ppid int) {
					for _, pid := range childrenMap[ppid] {
						if pid == shellPID || seen[pid] {
							continue
						}
						seen[pid] = true
						stillChildren = append(stillChildren, pid)
						collect(pid)
					}
				}
				collect(shellPID)
			}
		} else if runtime.GOOS == "linux" {
			psCmd := exec.Command("ps", "-o", "pid=", "--ppid", fmt.Sprintf("%d", shellPID))
			out, err := psCmd.Output()
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(out)), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					if pid, err := strconv.Atoi(line); err == nil && pid != shellPID {
						stillChildren = append(stillChildren, pid)
					}
				}
			}
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

// --- Out-of-band exec handler ---
func oobExecHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error": "Failed to parse form data"}`, http.StatusBadRequest)
		return
	}
	cmdStr := r.FormValue("cmd")
	if cmdStr == "" {
		http.Error(w, `{"error": "Missing 'cmd' in form data"}`, http.StatusBadRequest)
		return
	}

	// Split command for exec.Command. Use "sh -c" for shell features.
	cmd := exec.Command("sh", "-c", cmdStr)
	// Set working directory to current directory of Go process (default)
	// (No need to set cmd.Dir)

	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	timeout := 10 * time.Second
	var err error
	var exitCode int
	select {
	case err = <-done:
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		} else {
			exitCode = -1
		}
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done // Wait for process to exit
		exitCode = -1
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OOBExecResponse{
			Stdout:   stdoutBuf.String(),
			Stderr:   stderrBuf.String(),
			Error:    "timeout",
			Timeout:  true,
			ExitCode: exitCode,
		})
		return
	}

	resp := OOBExecResponse{
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		ExitCode: exitCode,
	}
	if err != nil {
		resp.Error = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
	flag.Parse()

	verboseLoggingEnabled = *verbose
	mcpMode = *mcp
	mcpServerAddr = *serverAddr
	cliMode = *cli
	cliHost = *host
	cliPort = *port
	outputJSON = *jsonOutput

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

	if verboseLoggingEnabled {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
		logInfo("Verbose logging enabled.")
	} else {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	}

	if mcpMode {
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
	mux.HandleFunc("/oob_exec", oobExecHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			logWarn("Invalid URL accessed: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		// Could serve a simple help page or redirect
		fmt.Fprintln(w, "PTY Automation Server running. Endpoints: /sendkeys_nowait, /sendkeys, /screen, /oob_exec")
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

	if err := http.ListenAndServe(httpServerAddr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logError("HTTP server ListenAndServe error: %v", err)
		// Cleanup will be called by defer
	}
	logInfo("HTTP server shut down.")
}

// --- MCP Server Implementation ---

func runMCPServer() {
	// Create a new MCP server
	s := server.NewMCPServer(
		"Terminal Automation Server 🖥️",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	// Add sendkeys_nowait tool
	sendkeysNowaitTool := mcp.NewTool("sendkeys_nowait",
		mcp.WithDescription("Send keystrokes to terminal. Mostly used for interactive applications."),
		mcp.WithString("keys",
			mcp.Required(),
			mcp.Description("Keys to send to the terminal"),
		),
	)
	s.AddTool(sendkeysNowaitTool, sendkeysNowaitToolHandler)

	// Add sendkeys tool
	sendkeysTool := mcp.NewTool("sendkeys",
		mcp.WithDescription("Send keystrokes to terminal and wait for command completion. Mostly used for shell commands, because it expects the process to launch and complete as result of keystroke, sending output back. Keys (command) must include newline for that."),
		mcp.WithString("keys",
			mcp.Required(),
			mcp.Description("Keys to send to the terminal"),
		),
	)
	s.AddTool(sendkeysTool, sendkeysToolHandler)

	// Add screen tool
	screenTool := mcp.NewTool("screen",
		mcp.WithDescription("Get current terminal screen content"),
	)
	s.AddTool(screenTool, screenToolHandler)

	// Add oob_exec tool
	oobExecTool := mcp.NewTool("oob_exec",
		mcp.WithDescription("Execute command out-of-band (not through terminal). Often used to monitor command execution, and other non-interactive tasks."),
		mcp.WithString("cmd",
			mcp.Required(),
			mcp.Description("Command to execute"),
		),
	)
	s.AddTool(oobExecTool, oobExecToolHandler)

	// Add begin tool
	beginTool := mcp.NewTool("begin",
		mcp.WithDescription("Open new or existing workspace with automation terminal. Must be called before using other terminal tools."),
		mcp.WithString("image_id",
			mcp.Description("Optional existing workspace ID to open, or leave empty for new workspace"),
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

	// Start the stdio server
	if err := server.ServeStdio(s); err != nil {
		logError("MCP server error: %v", err)
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

func oobExecToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Check if Docker container is running
	dockerMutex.Lock()
	running := dockerRunning
	dockerMutex.Unlock()
	
	if !running {
		return mcp.NewToolResultError("Workspace not running. Please call 'begin' tool first."), nil
	}

	cmd, err := request.RequireString("cmd")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Make REST call to /oob_exec endpoint
	resp, err := makeOOBExecRequest(cmd)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to execute command: %v", err)), nil
	}

	result := fmt.Sprintf("Exit Code: %d", resp.ExitCode)
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

func beginToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dockerMutex.Lock()
	defer dockerMutex.Unlock()
	
	// Check if container is already running
	if dockerRunning {
		return mcp.NewToolResultError("Workspace is already running. Use 'save_work' to commit changes or stop the current workspace first."), nil
	}

	// Get image ID (optional parameter)
	imageID := "automation_terminal"
	if id, err := request.RequireString("image_id"); err == nil && id != "" {
		imageID = id
	}

	// Run Docker container
	logInfo("Starting Docker container with image: %s", imageID)
	cmd := exec.Command("docker", "run", "-d", "--rm", "-it", "-p", ":5399", imageID)
	output, err := cmd.Output()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to start Docker container: %v", err)), nil
	}

	containerID := strings.TrimSpace(string(output))
	if containerID == "" {
		return mcp.NewToolResultError("Docker run command returned empty container ID"), nil
	}

	logInfo("Docker container started with ID: %s", containerID)

	// Wait a moment for container to start
	time.Sleep(2 * time.Second)

	// Get port mapping
	inspectCmd := exec.Command("docker", "inspect", "--format={{json .NetworkSettings.Ports}}", containerID)
	portOutput, err := inspectCmd.Output()
	if err != nil {
		// Clean up container on failure
		exec.Command("docker", "stop", containerID).Run()
		return mcp.NewToolResultError(fmt.Sprintf("Failed to inspect Docker container ports: %v", err)), nil
	}

	// Parse port mapping JSON
	var ports map[string][]map[string]string
	if err := json.Unmarshal(portOutput, &ports); err != nil {
		exec.Command("docker", "stop", containerID).Run()
		return mcp.NewToolResultError(fmt.Sprintf("Failed to parse port mapping JSON: %v", err)), nil
	}

	// Extract host port for 5399/tcp
	hostPort := ""
	if tcpPorts, exists := ports["5399/tcp"]; exists && len(tcpPorts) > 0 {
		hostPort = tcpPorts[0]["HostPort"]
	}

	if hostPort == "" {
		exec.Command("docker", "stop", containerID).Run()
		return mcp.NewToolResultError("Failed to find host port mapping for 5399/tcp"), nil
	}

	// Update global state
	dockerContainerID = containerID
	dockerHostPort = hostPort
	dockerRunning = true

	// Update mcpServerAddr to use the new port
	mcpServerAddr = fmt.Sprintf("http://localhost:%s", hostPort)

	logInfo("Docker container ready. Host port: %s, Container ID: %s", hostPort, containerID)

	return mcp.NewToolResultText(fmt.Sprintf("Workspace started successfully!\nWorkspace ID: %s\nHost Port: %s\nServer URL: %s", containerID, hostPort, mcpServerAddr)), nil
}

func saveWorkToolHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dockerMutex.Lock()
	defer dockerMutex.Unlock()
	
	// Check if container is running
	if !dockerRunning || dockerContainerID == "" {
		return mcp.NewToolResultError("No workspace is running. Please call 'begin' tool first."), nil
	}

	comment, err := request.RequireString("comment")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Commit the container
	logInfo("Committing Docker container %s with message: %s", dockerContainerID, comment)
	commitCmd := exec.Command("docker", "commit", "-m", comment, dockerContainerID)
	output, err := commitCmd.Output()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to commit Docker container: %v", err)), nil
	}

	imageID := strings.TrimSpace(string(output))
	if imageID == "" {
		return mcp.NewToolResultError("Docker commit command returned empty image ID"), nil
	}

	logInfo("Docker container committed successfully. New image ID: %s", imageID)

	return mcp.NewToolResultText(fmt.Sprintf("Work saved successfully!\nNew Image ID: %s\nCommit Message: %s\nWorkspace ID: %s", imageID, comment, dockerContainerID)), nil
}

func cleanupDockerContainer() {
	dockerMutex.Lock()
	defer dockerMutex.Unlock()
	
	if dockerRunning && dockerContainerID != "" {
		logInfo("Cleaning up Docker container: %s", dockerContainerID)
		cmd := exec.Command("docker", "stop", dockerContainerID)
		if err := cmd.Run(); err != nil {
			logWarn("Failed to stop Docker container %s: %v", dockerContainerID, err)
		} else {
			logInfo("Docker container %s stopped successfully", dockerContainerID)
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
	fmt.Println("  oob-exec <cmd>            Execute command out-of-band (outside PTY)")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  test_automation_terminal --cli sendkeys-nowait \"ls -la\\n\"")
	fmt.Println("  test_automation_terminal --cli sendkeys \"echo 'Hello World'\\n\"")
	fmt.Println("  test_automation_terminal --cli screen")
	fmt.Println("  test_automation_terminal --cli oob-exec \"ps aux | grep python\"")
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
		
	case "oob-exec":
		if len(cliArgs) != 1 {
			fmt.Fprintf(os.Stderr, "Error: oob-exec requires exactly one argument (command)\n")
			os.Exit(1)
		}
		cmd := cliArgs[0]
		resp, err := makeCLIOOBExecRequest(baseURL, cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if outputJSON {
			printJSON(resp)
		} else {
			printOOBExecResponse(resp)
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

func printOOBExecResponse(resp *OOBExecResponse) {
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

func makeCLIOOBExecRequest(baseURL, cmd string) (*OOBExecResponse, error) {
	data := url.Values{}
	data.Set("cmd", cmd)
	
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(baseURL+"/oob_exec", data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &OOBExecResponse{
			Error: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)),
		}, nil
	}
	
	var result OOBExecResponse
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

func makeOOBExecRequest(cmd string) (*OOBExecResponse, error) {
	data := url.Values{}
	data.Set("cmd", cmd)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(mcpServerAddr+"/oob_exec", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result OOBExecResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
