package main

import (
	"bufio"
	"bytes"
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
	"unicode"

	"github.com/creack/pty"
	"github.com/xyproto/vt100"
	"golang.org/x/sys/unix"
)

// --- Global variables ---
var (
	// PTY and subprocess related
	ptyMaster             *os.File
	ptySlaveForTcgetpgrp  *os.File // Parent's handle to the slave PTY, primarily for tcgetpgrp
	shellCmd              *exec.Cmd
	vtScreen              *vt100.Canvas
	currentScreenCursorMu sync.Mutex
	currentScreenX        uint
	currentScreenY        uint

	// Control flag for the PTY reader goroutine
	ptyRunning    bool
	ptyRunningMu  sync.Mutex
	ptyReaderDone chan struct{} // To signal PTY reader completion

	// For capturing terminal output lines
	// Stores complete lines captured from the PTY stream
	capturedLines               []string
	currentLineBuffer           bytes.Buffer
	capturedLinesMu             sync.Mutex
	verboseLoggingEnabled       bool
	maxSyncWaitSeconds    int = 60 // Maximum wait time for synchronous keystroke command completion
	defaultPtyCols        uint = 80
	defaultPtyLines       uint = 24
)

// --- Structs for HTTP responses ---
type KeystrokeResponse struct {
	Status   string `json:"status"`
	KeysSent string `json:"keys_sent,omitempty"`
	Error    string `json:"error,omitempty"`
}

type KeystrokeSyncResponse struct {
	Status  string   `json:"status"`
	Message string   `json:"message"`
	Output  []string `json:"output,omitempty"`
	Error   string   `json:"error,omitempty"`
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

	envMap["TERM"] = "vt100"
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

	shellCmd = exec.Command(shellArgs[0], shellArgs[1:]...)
	shellCmd.Env = finalEnv
	shellCmd.Stdin = tty    // Use slave PTY for child's stdio
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
	shellCmd.SysProcAttr.Setctty = true
	shellCmd.SysProcAttr.Ctty = int(tty.Fd())


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


	vtScreen = vt100.NewCanvas()
	// Canvas size is determined by vt100.NewCanvas() via MustTermSize().
	// COLUMNS and LINES env vars are set, which MustTermSize may use as a fallback.
	vtScreen.Clear() // Clear with default colors
	vtScreen.SetRunewise(false) // Use faster block drawing if possible

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
	reader := bufio.NewReader(ptyMaster)

	for {
		ptyRunningMu.Lock()
		if !ptyRunning {
			ptyRunningMu.Unlock()
			break
		}
		ptyRunningMu.Unlock()

		// Set a deadline for reading to make the loop check ptyRunning periodically
		// This is a simple way, select on a channel would be more robust for immediate shutdown
		ptyMaster.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		
		r, size, err := reader.ReadRune()
		if err != nil {
			if os.IsTimeout(err) { // ptyMaster.SetReadDeadline caused this
				continue
			}
			if err == io.EOF {
				logInfo("PTY EOF (shell exited), stopping reader goroutine.")
			} else {
				// Check if the error is "read /dev/ptmx: input/output error" which means PTY closed
				if strings.Contains(err.Error(), "input/output error") || strings.Contains(err.Error(), "file already closed") {
					logWarn("PTY read error (FD likely closed by cleanup), stopping reader goroutine.")
				} else {
					logError("Error reading from PTY: %v", err)
				}
			}
			ptyRunningMu.Lock()
			ptyRunning = false // Signal to stop
			ptyRunningMu.Unlock()
			break
		}

		if size > 0 {
			char := r
			logDebug("PTY Read char: '%s' (rune: %U)", string(char), char)

			// Update captured lines (for /keystroke_sync)
			capturedLinesMu.Lock()
			if char == '\n' {
				capturedLines = append(capturedLines, currentLineBuffer.String())
				logDebug("LineCapture LF: Appending CBL ('%s') to PLL. Old PLL len: %d. New PLL len: %d. Clearing CBL.", currentLineBuffer.String(), len(capturedLines)-1, len(capturedLines))
				currentLineBuffer.Reset()
			} else if char == '\r' {
				// Often \r is followed by \n or overwrites current line.
				// For simplicity, treat \r like \n for line capture, or just reset buffer pos.
				// Python version appended and cleared. Let's do the same.
				capturedLines = append(capturedLines, currentLineBuffer.String())
				logDebug("LineCapture CR: Appending CBL ('%s') to PLL. Old PLL len: %d. New PLL len: %d. Clearing CBL.", currentLineBuffer.String(), len(capturedLines)-1, len(capturedLines))
				currentLineBuffer.Reset()
			} else if char == '\b' { // Backspace
				if currentLineBuffer.Len() > 0 {
					oldCBL := currentLineBuffer.String()
					// Truncate last rune. A simple byte-wise trim for now.
					// For robust UTF-8 backspace, proper rune-wise truncation would be needed.
					if currentLineBuffer.Len() > 0 {
						currentLineBuffer.Truncate(currentLineBuffer.Len() - 1)
					}
					logDebug("LineCapture BS: CBL was '%s', now '%s'", oldCBL, currentLineBuffer.String())
				}
			} else if unicode.IsPrint(char) { // Check if the character is printable
				currentLineBuffer.WriteRune(char)
				logDebug("LineCapture CHAR: Adding char '%s' to CBL. CBL now: '%s'", string(char), currentLineBuffer.String())
			}
			capturedLinesMu.Unlock()

			// Update vtScreen (for /screen endpoint) - simplified manual plotting
			currentScreenCursorMu.Lock()
			if vtScreen != nil {
				if char == '\n' {
					currentScreenX = 0
					if currentScreenY < vtScreen.Height()-1 {
						currentScreenY++
					} else {
						// At the bottom line, effectively overwriting or Plot will ignore if y is out of bounds.
						// No direct scroll method available in vt100.Canvas to shift content up.
						logDebug("Screen at bottom, new line will overwrite last line or be ignored by Plot if Y exceeds canvas height.")
					}
				} else if char == '\r' {
					currentScreenX = 0
				} else if char == '\b' {
					if currentScreenX > 0 {
						currentScreenX--
						// Plot a space to erase the character. Ensure Y is within bounds.
						if currentScreenY < vtScreen.Height() {
							vtScreen.Plot(currentScreenX, currentScreenY, ' ') 
						}
					}
				} else if unicode.IsPrint(char) { // Check if the character is printable
					if currentScreenX >= vtScreen.Width() { // Line wrap
						currentScreenX = 0
						if currentScreenY < vtScreen.Height()-1 {
							currentScreenY++
						} else {
							logDebug("Screen at bottom-right, new char on new line will overwrite last line or be ignored.")
						}
					}
					// Ensure X and Y are within bounds for PlotColor
					if currentScreenX < vtScreen.Width() && currentScreenY < vtScreen.Height() {
						vtScreen.PlotColor(currentScreenX, currentScreenY, vt100.Default, char)
					}
					currentScreenX++
				}
			}
			currentScreenCursorMu.Unlock()
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

	var linesBeforeCommandEffect []string
	capturedLinesMu.Lock()
	linesBeforeCommandEffect = make([]string, len(capturedLines))
	copy(linesBeforeCommandEffect, capturedLines)
	// The currentLineBuffer in Python is merged by LoggingStream. Here, it's simpler:
	// the content of currentLineBuffer is partial output of the *previous* command or the prompt.
	// The keys sent will form new content.
	logDebug("SYNC: lines_before_command_effect (len %d): %v", len(linesBeforeCommandEffect), linesBeforeCommandEffect)
	capturedLinesMu.Unlock()

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
		capturedLinesMu.Lock()
		linesAfter := make([]string, len(capturedLines))
		copy(linesAfter, capturedLines)
		finalCurrentLine := currentLineBuffer.String()
		
		outputSegment := linesAfter[len(linesBeforeCommandEffect):]
		if finalCurrentLine != "" { // Add incomplete line
			outputSegment = append(outputSegment, finalCurrentLine)
		}
		// Reset log for next command
		currentLineBuffer.Reset() // The new prompt might be in finalCurrentLine
		currentLineBuffer.WriteString(finalCurrentLine) // Or it might be empty
		capturedLines = capturedLines[:0] // Clear captured lines, effectively
		logDebug("SYNC (shell exited path): Reset CBL to '%s', PLL to empty.", currentLineBuffer.String())
		capturedLinesMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(KeystrokeSyncResponse{Status: "success", Message: "Shell process exited shortly after command submission.", Output: outputSegment})
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
	var outputSegment []string

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
		} else { // Linux and other Unix-like systems
			logDebug("Using tcgetpgrp on slave FD %d for non-macOS platform (Shell PGID: %d).", ptySlaveForTcgetpgrp.Fd(), shellPGID)
			currentForegroundPGID, err := unix.Tcgetpgrp(int(ptySlaveForTcgetpgrp.Fd()))
			if err != nil {
				logError("Error calling tcgetpgrp on slave_fd (%d): %v (errno: %v). Assuming command finished or error.", ptySlaveForTcgetpgrp.Fd(), err, err.(syscall.Errno))
				if shellCmd.ProcessState != nil && shellCmd.ProcessState.Exited() {
					completionMessage = "Shell process exited, PTY state uncertain after tcgetpgrp error."
					commandCompletedNormally = true
					break
				}
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(KeystrokeSyncResponse{Status: "error", Message: fmt.Sprintf("Error checking PTY foreground process group: %v", err)})
				return
			}
			logDebug("Polling PTY's foreground PGID: %d. Shell's PGID: %d.", currentForegroundPGID, shellPGID)
			if currentForegroundPGID == shellPGID {
				logInfo("Shell (PGID %d) is foreground process group on PTY. Command considered complete.", shellPGID)
				completionMessage = "Command completed."
				commandCompletedNormally = true
				break
			}
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
	
	capturedLinesMu.Lock()
	linesAfterCommandEffect := make([]string, len(capturedLines))
	copy(linesAfterCommandEffect, capturedLines)
	finalCurrentLine := currentLineBuffer.String()
	logDebug("SYNC: lines_after_command_effect (len %d): %v", len(linesAfterCommandEffect), linesAfterCommandEffect)
	logDebug("SYNC: final_current_line: '%s'", finalCurrentLine)

	outputSegment = linesAfterCommandEffect[len(linesBeforeCommandEffect):]
	if finalCurrentLine != "" { // Add the last incomplete line (new prompt, or partial output)
		outputSegment = append(outputSegment, finalCurrentLine)
	}
	
	// Reset log for the next command
	currentLineBuffer.Reset()
	currentLineBuffer.WriteString(finalCurrentLine) // The new prompt is now the current buffer
	capturedLines = capturedLines[:0] // Clear all captured lines
	logDebug("SYNC: Reset CBL to '%s', PLL to empty.", currentLineBuffer.String())
	capturedLinesMu.Unlock()

	logDebug("SYNC: Returning output_segment (len %d): %v", len(outputSegment), outputSegment)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(KeystrokeSyncResponse{Status: status, Message: completionMessage, Output: outputSegment})
}

func screenHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("Received GET /screen")
	ptyRunningMu.Lock()
	active := ptyRunning
	ptyRunningMu.Unlock()

	if vtScreen == nil || !active {
		logWarn("Screen/PTY not active for /screen")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(ScreenResponse{Error: "Screen not active or not initialized"})
		return
	}

	currentScreenCursorMu.Lock()
	// vtScreen.String() returns the characters. We might want to format it like pyte's display (list of strings).
	// vtScreen.Display() is not a method. We need to iterate over vtScreen.Chars2() or similar.
	// For simplicity, let's use vtScreen.String() and split by newline.
	// However, vtScreen.String() adds newlines. We want the raw grid.
	
	var displayData []string
	// vtScreen.Lock() // vt100.Canvas has its own mutex, but we are also managing cursor separately
	for y := uint(0); y < vtScreen.Height(); y++ {
		var lineBuilder strings.Builder
		for x := uint(0); x < vtScreen.Width(); x++ {
			// vtScreen.At(x,y) returns rune, error. We need the ColorRune
			// Directly access internal chars array if possible, or use a method that gives char at pos.
			// vtScreen.Get(x,y) is not available. Let's assume direct access or a helper.
			// The `chars` field is lowercase, so not exported.
			// Let's use `vtScreen.Rune(x,y)` if available, or build from `String()`
			// `vtScreen.Cell(x,y)` might be better. Let's check `canvas.go`.
			// `vtScreen.Rune(uint(x), uint(y))` seems to be the way.
			char, _ := vtScreen.At(x,y) // At returns rune, error
			if char == rune(0) {
				lineBuilder.WriteRune(' ')
			} else {
				lineBuilder.WriteRune(char)
			}
		}
		displayData = append(displayData, lineBuilder.String())
	}
	// vtScreen.Unlock()

	cursorData := ScreenCursorState{
		X:      currentScreenX,
		Y:      currentScreenY,
		Hidden: false, // vt100.Canvas doesn't explicitly track cursor visibility in a simple way
	}
	currentScreenCursorMu.Unlock()
	
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
