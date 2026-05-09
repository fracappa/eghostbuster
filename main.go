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

	// load BPF maps and programs
	var objs bpf.EGhostBusterObjects
	if err := bpf.LoadEGhostBusterObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load bpf objects: %v", err)
	}
	defer objs.Close()

	// save custom file lock extensions in BPF map
	exts := strings.Split(*fileLocks, ",")
	for i, ext := range exts {
		key := uint32(i)
		val := bpf.EGhostBusterFileExtension{}
		e := strings.TrimSpace(ext)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&val.Name[0])), len(val.Name)), e)
		val.Len = uint32(len(e))
		if err := objs.FileExtensions.Update(key, val, ebpf.UpdateAny); err != nil {
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

	log.Println("eghostbuster started. Waiting for zombie connections...")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return operator.StartStaleSocketMonitor(ctx, &objs, cfg)
	})

	g.Go(func() error {
		return operator.StartFileLocksMonitor(ctx, &objs)
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("monitor error: %v", err)
	}

	log.Println("Shutting down..")
}
