package operator

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/eghostbuster/eghostbuster/pkg/bpf"
	"github.com/eghostbuster/eghostbuster/pkg/netns"
	"github.com/eghostbuster/eghostbuster/pkg/socket"
	"golang.org/x/sys/unix"
)

type Config struct {
	ScanInterval     time.Duration // How often to check the map
	CloseWaitTimeout time.Duration // How long before considering stale
}

func ParseConfig() Config {
	cfg := defaultConfig()

	envOverrides := map[string]*time.Duration{
		"CLOSE_WAIT_TIMEOUT": &cfg.CloseWaitTimeout,
		"SCAN_INTERVAL":      &cfg.ScanInterval,
	}

	for env, field := range envOverrides {
		if val := os.Getenv(env); val != "" {
			d, err := time.ParseDuration(val)
			if err != nil {
				log.Printf("error parsing %s env var: %v", env, err)
			} else {
				*field = d
			}
		}
	}

	return cfg
}

func defaultConfig() Config {
	return Config{
		ScanInterval:     30 * time.Second,
		CloseWaitTimeout: 60 * time.Second,
	}
}

// StartMonitor periodically scans close_wait_tracker for stale sockets
func StartMonitor(ctx context.Context, objs *bpf.EGhostBusterObjects, cfg Config) error {
	log.Printf("CLOSE_WAIT monitor started (interval=%v, timeout=%v)", cfg.ScanInterval, cfg.CloseWaitTimeout)

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

func cleanupStaleCloseWait(tracker *ebpf.Map, timeout time.Duration) {
	var key bpf.EGhostBusterConnectionKey
	var info bpf.EGhostBusterCloseWaitInfo

	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	nowKtime := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)

	timeoutNs := uint64(timeout.Nanoseconds())
	var toDelete []bpf.EGhostBusterConnectionKey

	iter := tracker.Iterate()
	for iter.Next(&key, &info) {
		age := nowKtime - info.EnteredAt
		if age > timeoutNs {
			srcIP := socket.FormatIP(key.SrcIp)
			dstIP := socket.FormatIP(key.DstIp)
			srcPort := socket.Ntohs(key.SrcPort)
			dstPort := socket.Ntohs(key.DstPort)

			log.Printf("Stale CLOSE_WAIT: %s:%d -> %s:%d (age=%v, netns=%s)",
				srcIP, srcPort, dstIP, dstPort,
				time.Duration(age), netns.GetNameByIno(info.NetnsIno))

			err := socket.DestroySocketNetnsIno(
				info.NetnsIno,
				srcIP, srcPort,
				dstIP, dstPort,
			)
			if err != nil {
				// check if namespace exist
				if strings.Contains(err.Error(), "not found") {
					// namespace cleanded up
					log.Printf("Socker already cleaned up (namespace deleted): %s:%d -> %s:%d",
						srcIP, srcPort, dstIP, dstPort)
					toDelete = append(toDelete, key)
				} else {
					log.Printf("Failed to kill socket: %v", err)
				}
			} else {
				log.Printf("Killed socket %s:%d -> %s:%d",
					srcIP, srcPort, dstIP, dstPort)
				toDelete = append(toDelete, key)
			}
		}
	}

	for _, k := range toDelete {
		tracker.Delete(k)
	}
}
