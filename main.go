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

	// attach fentry/tcp_v4_connect (client connections)
	fentryLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TcpV4Connect,
	})
	if err != nil {
		log.Fatalf("failed to attach fentry/tcp_v4_connect: %v", err)
	}
	defer fentryLink.Close()

	// attach fexit/inet_csk_accept (server connections)
	fexistLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.InetCskAcceptExit,
	})
	if err != nil {
		log.Fatalf("failed to attach fexit/inet_csk_accept: %v", err)
	}
	defer fexistLink.Close()

	// attach tp_btf/inet_sock_set_state (state changes)
	tpLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleSetState,
	})
	if err != nil {
		log.Fatalf("failed to attach inet_sock_set_state: %v", err)
	}
	defer tpLink.Close()

	log.Println("eghostbuster started. Waiting for zombie connections...")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg := operator.DefaultConfig()
	// start ring buffer consumer
	if err := operator.StartMonitor(ctx, &objs, cfg); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Fatalf("monitor error: %v", err)
		}
	}

	log.Println("Shutting down..")
}
