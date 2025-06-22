//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// getWorkingDirectory gets the working directory of a process by PID on Linux
func getWorkingDirectory(pid int) (string, error) {
	// On Linux, read /proc/<pid>/cwd symlink
	cwdPath := fmt.Sprintf("/proc/%d/cwd", pid)
	workingDir, err := os.Readlink(cwdPath)
	if err != nil {
		return "", fmt.Errorf("failed to read /proc/%d/cwd: %w", pid, err)
	}
	return workingDir, nil
}

// checkCommandCompletion checks if a command has completed by looking for child processes
func checkCommandCompletion(shellPID int) (bool, error) {
	logDebug("Using ps/awk to check for children of shell PID %d on Linux.", shellPID)
	psCmd := fmt.Sprintf("ps -o pid,ppid,comm -ax | awk '$2 == %d {print $1}'", shellPID)
	cmd := exec.Command("sh", "-c", psCmd)

	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("ps/awk command failed: %w", err)
	}
	
	trimmedOutput := strings.TrimSpace(string(output))
	logDebug("ps/awk output for children of PID %d: '%s'", shellPID, trimmedOutput)
	if trimmedOutput == "" {
		logInfo("Linux ps/awk check: Shell PID %d has no children. Command complete.", shellPID)
		return true, nil
	}
	
	return false, nil
}

// getChildPIDs gets all child PIDs of a given PID on Linux
func getChildPIDs(shellPID int) ([]int, error) {
	var childPIDs []int
	
	// Use 'ps -o pid= --ppid <shellPID>'
	psCmd := exec.Command("ps", "-o", "pid=", "--ppid", fmt.Sprintf("%d", shellPID))
	logDebug("Linux getChildPIDs: Executing command: %v", psCmd.Args)
	
	out, err := psCmd.Output()
	logDebug("Linux getChildPIDs: Command output: '%s'", string(out))
	if err != nil {
		logDebug("Linux getChildPIDs: Command failed with error: %v", err)
		return childPIDs, err
	}
	
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	logDebug("Linux getChildPIDs: Split into %d lines: %v", len(lines), lines)
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if pid, err := strconv.Atoi(line); err == nil && pid != shellPID {
			childPIDs = append(childPIDs, pid)
			logDebug("Linux getChildPIDs: Found child PID: %d", pid)
		} else if err != nil {
			logDebug("Linux getChildPIDs: Failed to parse PID from line '%s': %v", line, err)
		}
	}
	
	logDebug("Linux getChildPIDs: Returning %d child PIDs: %v", len(childPIDs), childPIDs)
	return childPIDs, nil
}
