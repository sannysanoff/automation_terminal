//go:build darwin

package main

/*
#include <libproc.h>
*/
import "C"

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
)

// getWorkingDirectory gets the working directory of a process by PID on macOS
func getWorkingDirectory(pid int) (string, error) {
	// Use libproc to get working directory (more reliable than lsof)
	var vnodeInfo C.struct_proc_vnodepathinfo

	logDebug("Getting working directory for PID %d using libproc", pid)
	ret := C.proc_pidinfo(C.int(pid), C.PROC_PIDVNODEPATHINFO, 0,
		unsafe.Pointer(&vnodeInfo), C.int(unsafe.Sizeof(vnodeInfo)))

	if ret <= 0 {
		logError("proc_pidinfo failed for PID %d", pid)
		return "", fmt.Errorf("failed to get proc info for pid %d", pid)
	}

	cwd := C.GoString(&vnodeInfo.pvi_cdir.vip_path[0])
	logDebug("Found working directory for PID %d: %q", pid, cwd)
	return cwd, nil
}

// checkCommandCompletion checks if a command has completed by looking for child processes
func checkCommandCompletion(shellPID int) (bool, error) {
	// Use pstree to check for children
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
			return true, nil
		}
		return false, nil
	}
	
	return false, fmt.Errorf("pstree command failed: %w", pstreeErr)
}

// getChildPIDs gets all child PIDs of a given PID on macOS
func getChildPIDs(shellPID int) ([]int, error) {
	var childPIDs []int
	
	// Use 'ps -a -o pid,ppid' to get all processes, then recursively find all descendants of shellPID
	psCmd := exec.Command("ps", "-a", "-o", "pid,ppid")
	out, err := psCmd.Output()
	if err != nil {
		return childPIDs, err
	}
	
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
	
	return childPIDs, nil
}
