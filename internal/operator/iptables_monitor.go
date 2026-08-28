package operator

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/fracappa/eghostbuster/pkg/iptables"
	"golang.org/x/sys/unix"
)

type IptablesConfig struct {
	ScanInterval time.Duration
	StaleTimeout time.Duration
	DryRun       bool
}

func ParseIptablesConfig() IptablesConfig {
	cfg := IptablesConfig{
		ScanInterval: 60 * time.Second,
		StaleTimeout: 120 * time.Second,
	}

	envOverrides := map[string]*time.Duration{
		"IPTABLES_SCAN_INTERVAL": &cfg.ScanInterval,
		"IPTABLES_STALE_TIMEOUT": &cfg.StaleTimeout,
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

	if val := os.Getenv("IPTABLES_DRY_RUN"); val == "true" || val == "1" {
		cfg.DryRun = true
	}

	return cfg
}

func StartIptablesMonitor(ctx context.Context, cfg IptablesConfig, conntrackMap *ebpf.Map) error {
	log.Printf("iptables monitor started (interval=%v, timeout=%v, dryRun=%v)",
		cfg.ScanInterval, cfg.StaleTimeout, cfg.DryRun)

	ticker := time.NewTicker(cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cleanupStaleIptablesRules(conntrackMap, cfg)
		}
	}
}

func cleanupStaleIptablesRules(conntrackMap *ebpf.Map, cfg IptablesConfig) {
	endpoints, err := iptables.ListEndpoints()
	if err != nil {
		log.Printf("iptables scan error: %v", err)
		return
	}

	if len(endpoints) == 0 {
		return
	}

	byIP := make(map[string][]iptables.ServiceEndpoint)
	for _, ep := range endpoints {
		byIP[ep.PodIP] = append(byIP[ep.PodIP], ep)
	}

	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	nowKtime := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	timeoutNs := uint64(cfg.StaleTimeout.Nanoseconds())

	for podIP, eps := range byIP {
		ip := net.ParseIP(podIP).To4()
		if ip == nil {
			continue
		}

		ipKey := binary.LittleEndian.Uint32(ip)

		var lastSeenAt uint64
		if err := conntrackMap.Lookup(ipKey, &lastSeenAt); err != nil {
			continue
		}

		age := nowKtime - lastSeenAt
		if age < timeoutNs {
			continue
		}

		for _, ep := range eps {
			if cfg.DryRun {
				log.Printf("[DRY-RUN] would remove stale endpoint: %s (chain=%s, stale for %v)",
					podIP, ep.ChainName, time.Duration(age))
				continue
			}

			log.Printf("removing stale endpoint: %s (chain=%s, stale for %v)",
				podIP, ep.ChainName, time.Duration(age))

			if err := iptables.RemoveEndpoint(ep); err != nil {
				log.Printf("iptables cleanup error for %s: %v", ep.ChainName, err)
				continue
			}
			log.Printf("cleaned up stale chain: %s", ep.ChainName)
		}

		if !cfg.DryRun {
			conntrackMap.Delete(ipKey)
		}
	}
}
