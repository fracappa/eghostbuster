package operator

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
	"github.com/eghostbuster/eghostbuster/pkg/bpf"
	"golang.org/x/sys/unix"
)

type Config struct {
	ScanInterval     time.Duration // How often to check the map
	CloseWaitTimeout time.Duration // How long before considering stale
}

func DefaultConfig() Config {
	return Config{
		ScanInterval:     30 * time.Second,
		CloseWaitTimeout: 60 * time.Second,
	}
}

// StartMonitor periodically scans close_wait_tracker for stale sockets
func StartMonitor(ctx context.Context, objs *bpf.EGhostBusterObjects, cfg Config) error {
	log.Printf("CLOSE_WAIT monitor started (interval=%v, timeout=%v)",
		cfg.ScanInterval, cfg.CloseWaitTimeout)

	ticker := time.NewTicker(cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cleanupStaleCloseWait(objs.CloseWaitTracker, cfg.CloseWaitTimeout)
		}
	}
}

// cleanupStaleCloseWait periodically scans the tracker map and delete the sockets that exceed the timeout
func cleanupStaleCloseWait(tracker *ebpf.Map, timeout time.Duration) {
	var key bpf.EGhostBusterConnectionKey
	var info bpf.EGhostBusterCloseWaitInfo

	now := getKtimeNs()
	timeoutNs := uint64(timeout.Nanoseconds())
	var toDelete []bpf.EGhostBusterConnectionKey

	iter := tracker.Iterate()
	for iter.Next(&key, &info) {
		if now-info.EnteredAt > timeoutNs {
			srcIP := formatIP(key.SrcIp)
			dstIP := formatIP(key.DstIp)
			srcPort := key.SrcPort
			dstPort := key.DstPort

			log.Printf("Stale CLOSE_WAIT: %s:%d -> %s:%d (age: %v)",
				srcIP, srcPort, dstIP, dstPort, time.Duration(now-info.EnteredAt))

			if err := killSocket(srcIP, srcPort, dstIP, dstPort); err != nil {
				log.Printf("Failed to kill: %v", err)
			} else {
				toDelete = append(toDelete, key)
			}
		}
	}

	for _, k := range toDelete {
		tracker.Delete(k)
	}
}

func killSocket(srcIP string, srcPort uint16, dstIP string, dstPort uint16) error {
	// Use ss --kill to destroy the socket
	// ss handles namespaces automatically when run with proper privileges
	cmd := exec.Command("ss", "--kill", "state", "close-wait",
		"src", fmt.Sprintf("%s:%d", srcIP, srcPort),
		"dst", fmt.Sprintf("%s:%d", dstIP, dstPort))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ss --kill failed: %v, output: %s", err, output)
	}
	log.Printf("Successfully killed socket %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
	return nil
}

func formatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func getKtimeNs() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
