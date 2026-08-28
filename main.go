package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fracappa/eghostbuster/internal/operator"
	"github.com/fracappa/eghostbuster/pkg/bpf"
	"golang.org/x/sync/errgroup"
)

/*
	Usage:

CLI:

	sudo ./eghostbuster --timeout60s --interval30s
	if cli flags are not set, it will fallback to DefaultConfig (60s timeout, 30s interval)

Envs:

	sudo CLOSE_WAIT_TIMEOUT=600s SCAN_INTERVAL=300s ./eghostbuster
*/
var (
	timeout   = flag.Duration("timeout", 0, "CLOSE_WAIT timeout before killing socket (e.g. 60s, 5m)")
	interval  = flag.Duration("interval", 0, "How often to scan for stale CLOSE_WAIT sockets (e.g. 30s, 1m)")
	fileLocks = flag.String("fileLocks", "lock,lck", "file locks extentions")

	iptablesInterval = flag.Duration("iptablesInterval", 0, "How often to scan for stale iptables rules (e.g. 60s)")
	iptablesTimeout  = flag.Duration("iptablesTimeout", 0, "How long before considering an iptables entry stale (e.g. 120s)")
	dryRun           = flag.Bool("dryRun", false, "Log-only mode: detect stale iptables entries without removing them")
)

func main() {
	flag.Parse()

	// remove memlock limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove rlimit: %v", err)
	}

	cfg := operator.ParseConfig()

	// if CLI flags are set, override the defaults
	if *timeout > 0 {
		cfg.CloseWaitTimeout = *timeout
	}
	if *interval > 0 {
		cfg.ScanInterval = *interval
	}

	iptablesCfg := operator.ParseIptablesConfig()
	if *iptablesInterval > 0 {
		iptablesCfg.ScanInterval = *iptablesInterval
	}
	if *iptablesTimeout > 0 {
		iptablesCfg.StaleTimeout = *iptablesTimeout
	}
	if *dryRun {
		iptablesCfg.DryRun = true
	}

	// load BPF maps and programs
	objs, conntrackAvailable := loadBPFObjects()
	defer objs.Close()

	// save custom file lock extensions in BPF map
	exts := strings.Split(*fileLocks, ",")
	for i, ext := range exts {
		key := uint32(i)
		val := bpf.EGhostBusterFileExtension{}
		e := strings.TrimSpace(ext)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&val.Name[0])), len(val.Name)), e)
		val.Len = uint32(len(e))
		if err := objs.FileExtensions.Update(key, val, 0); err != nil {
			log.Fatalf("failed to load extentions in file_extensions BPF map: %v", err)
		}
	}

	// attach tp_btf/inet_sock_set_state (state changes)
	staleSocketTp, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleSetState,
	})
	if err != nil {
		log.Fatalf("failed to attach inet_sock_set_state: %v", err)
	}
	defer staleSocketTp.Close()

	openAtTp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.RegisterOpenat, nil)
	if err != nil {
		log.Fatalf("failed to attach sys_enter_openat: %v", err)
	}
	defer openAtTp.Close()

	openAt2Tp, err := link.Tracepoint("syscalls", "sys_enter_openat2", objs.RegisterOpenat2, nil)
	if err != nil {
		log.Fatalf("failed to attach sys_enter_openat2: %v", err)
	}
	defer openAt2Tp.Close()

	processExitTp, err := link.Tracepoint("sched", "sched_process_exit", objs.ProcessExitNotifier, nil)
	if err != nil {
		log.Fatalf("failed to attach sched_process_exit: %v", err)
	}
	defer processExitTp.Close()

	// Best-effort: attach conntrack tracepoints
	var conntrackCleanup func()
	if conntrackAvailable {
		conntrackCleanup = attachConntrackTracing(objs.HandleConntrackDestroy, objs.HandleConntrackNew)
	}
	if conntrackCleanup != nil {
		defer conntrackCleanup()
	}

	log.Println("eghostbuster started. Waiting for zombie connections...")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return operator.StartStaleSocketMonitor(ctx, objs, cfg)
	})

	g.Go(func() error {
		return operator.StartFileLocksMonitor(ctx, objs)
	})

	if conntrackAvailable && conntrackCleanup != nil {
		g.Go(func() error {
			return operator.StartIptablesMonitor(ctx, iptablesCfg, objs.ConntrackDestroyTracker)
		})
	} else {
		log.Println("iptables monitor disabled (conntrack BPF tracepoints unavailable)")
	}

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("monitor error: %v", err)
	}

	log.Println("Shutting down..")
}

func loadBPFObjects() (*bpf.EGhostBusterObjects, bool) {
	spec, err := bpf.LoadEGhostBuster()
	if err != nil {
		log.Fatalf("failed to load bpf spec: %v", err)
	}

	var objs bpf.EGhostBusterObjects
	loadErr := spec.LoadAndAssign(&objs, nil)
	if loadErr == nil {
		return &objs, true
	}

	// Full load failed (likely missing nf_conntrack BTF). Strip conntrack
	// programs and retry so the core features still work.
	log.Printf("conntrack programs unavailable, loading without iptables support: %v", loadErr)

	spec, err = bpf.LoadEGhostBuster()
	if err != nil {
		log.Fatalf("failed to reload bpf spec: %v", err)
	}
	for _, name := range []string{"handle_conntrack_destroy", "handle_conntrack_new"} {
		delete(spec.Programs, name)
	}
	delete(spec.Maps, "conntrack_destroy_tracker")

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to load core bpf objects: %v", err)
	}

	objs.HandleSetState = coll.Programs["handle_set_state"]
	objs.ProcessExitNotifier = coll.Programs["process_exit_notifier"]
	objs.RegisterOpenat = coll.Programs["register_openat"]
	objs.RegisterOpenat2 = coll.Programs["register_openat2"]
	objs.CloseWaitTracker = coll.Maps["close_wait_tracker"]
	objs.ExitEvents = coll.Maps["exit_events"]
	objs.FileExtensions = coll.Maps["file_extensions"]
	objs.FileInfoScratch = coll.Maps["file_info_scratch"]
	objs.FileProcessMap = coll.Maps["file_process_map"]

	return &objs, false
}

func attachConntrackTracing(destroy, new_ *ebpf.Program) func() {
	tp1, err := link.AttachTracing(link.TracingOptions{Program: destroy})
	if err != nil {
		log.Printf("conntrack destroy tracepoint unavailable: %v", err)
		return nil
	}

	tp2, err := link.AttachTracing(link.TracingOptions{Program: new_})
	if err != nil {
		log.Printf("conntrack new tracepoint unavailable: %v", err)
		tp1.Close()
		return nil
	}

	log.Println("conntrack tracking enabled (BPF)")
	return func() {
		tp1.Close()
		tp2.Close()
	}
}
