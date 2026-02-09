package main

import (
	"context"
	"errors"
	"log"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/eghostbuster/eghostbuster/internal/operator"
	"github.com/eghostbuster/eghostbuster/pkg/bpf"
)

func main() {
	// remove memlock limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove rlimit: %v", err)
	}

	// load BPF maps and programs
	var objs bpf.EGhostBusterObjects
	if err := bpf.LoadEGhostBusterObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load bpf objects: %v", err)
	}

	defer objs.Close()

	// attach fentry
	fentryLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TcpV4Connect,
	})
	if err != nil {
		log.Fatalf("failed to attach fentry/tcp_v4_connect: %v", err)
	}
	defer fentryLink.Close()

	// tp_btf attaches via link.AttachTracing, not link.Tracepoint
	tpSockLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleSetState,
	})
	if err != nil {
		log.Fatalf("failed to attach tp_btf/inet_sock_set_state: %v", err)
	}
	defer tpSockLink.Close()

	// Attattachach tp/sched/sched_process_exit
	tpSchedLink, err := link.Tracepoint("sched", "sched_process_exit", objs.BpfReaper, nil)
	if err != nil {
		log.Fatalf("failed to attach tp/sched/sched_process_exit: %v", err)
	}
	defer tpSchedLink.Close()

	log.Println("eghostbuster started. Waiting for zombie connections...")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// start ring buffer consumer
	if err := operator.StartMonitor(ctx, &objs); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Fatalf("failed to kick off reaper: %v", err)
		}
	}

	log.Println("Shutting down..")
}
