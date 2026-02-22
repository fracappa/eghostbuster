package netns

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"golang.org/x/sys/unix"
)

// HostIno is the inode of the host network namespace
var HostIno uint64

func init() {
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &stat); err == nil {
		HostIno = stat.Ino
	}
}

// GetIno returns the inode of a namespace file
// func GetIno(path string) (uint64, error) {
// 	var stat unix.Stat_t
// 	if err := unix.Stat(path, &stat); err != nil {
// 		return 0, err
// 	}
// 	return stat.Ino, nil
// }

// FindPathByIno searches /proc for a namespace with the given inode
func FindPathByIno(targetIno uint64) (string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		nsPath := filepath.Join("/proc", entry.Name(), "ns/net")

		var stat unix.Stat_t
		if err := unix.Stat(nsPath, &stat); err != nil {
			continue
		}

		if stat.Ino == targetIno {
			return nsPath, nil
		}
	}

	return "", fmt.Errorf("netns with inode %d not found", targetIno)
}

// GetNameByIno returns a human-readable name for the namespace
// Returns "host" for host namespace, PID for process namespaces, or the inode if not found
func GetNameByIno(targetIno uint64) string {
	if IsHost(targetIno) {
		return "host"
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Sprintf("%d", targetIno)
	}

	for _, entry := range entries {
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		nsPath := filepath.Join("/proc", pid, "ns/net")
		var stat unix.Stat_t
		if err := unix.Stat(nsPath, &stat); err != nil {
			continue
		}

		if stat.Ino == targetIno {
			// Try to get process name or container info
			name := getProcessInfo(pid)
			return fmt.Sprintf("%s (pid:%s)", name, pid)
		}
	}

	return fmt.Sprintf("%d (deleted)", targetIno)
}

// getProcessInfo tries to get a meaningful name from /proc/PID/comm or cgroup
func getProcessInfo(pid string) string {
	// Try comm (process name)
	if data, err := os.ReadFile(filepath.Join("/proc", pid, "comm")); err == nil {
		return strings.TrimSpace(string(data))
	}
	return "unknown"
}

// IsHost returns true if the given inode matches the host namespace
func IsHost(ino uint64) bool {
	return ino == HostIno || ino == 0
}

// Do executes a function in the given namespace (by inode)
// If ino matches host namespace, executes directly without switching
func Do(ino uint64, fn func() error) error {
	if IsHost(ino) {
		return fn()
	}

	nsPath, err := FindPathByIno(ino)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(nsPath)
	if err != nil {
		return fmt.Errorf("failed to get ns: %w", err)
	}
	defer netns.Close()

	return netns.Do(func(_ ns.NetNS) error {
		return fn()
	})
}
