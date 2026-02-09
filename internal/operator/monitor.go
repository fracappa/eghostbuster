package operator

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/eghostbuster/eghostbuster/pkg/bpf"
	"github.com/eghostbuster/eghostbuster/pkg/consts"
	"github.com/vishvananda/netlink"
)

func StartMonitor(ctx context.Context, objs *bpf.EGhostBusterObjects) error {
	rd, err := ringbuf.NewReader(objs.ZombieEvents)
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Close reader when context is cancelled
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("ringbuf read error: %v", err)
			continue
		}

		// Parse the connection_info struct from BPF
		event := parseConnectionInfo(record.RawSample)

		log.Printf("Process exited: PID=%d, Comm=%s", event.Pid, event.Comm)

		// Cleanup all sockets belonging to this dead process
		Cleanup(objs.ConnTracker, event.Pid, event.StartTime)
	}
}

// Cleanup find and kills sockets belonging to the dead PID
func Cleanup(connMap *ebpf.Map, deadPID uint32, deadStartTime uint64) {
	var key bpf.EGhostBusterConnectionKey
	var info bpf.EGhostBusterConnectionInfo

	// 1. Iterate through the BPF Map (Go can do this safely)
	iter := connMap.Iterate()
	for iter.Next(&key, &info) {
		// 2. Match the unique PID + StartTime fingerprint
		if info.Pid == deadPID && info.StartTime == deadStartTime {
			log.Printf("Ghost detected! PID: %d, Comm: %s, 5-Tuple: %v",
				info.Pid, string(info.Comm[:]), key)

			// 3. Trigger the Kernel Cleanup
			err := canceleSocket(key)
			if err != nil {
				log.Printf("Failed to kill ghost: %v", err)
				continue
			}

			// 4. Remove from our tracker
			if err := connMap.Delete(key); err != nil {
				log.Printf("Failed to delete map entry: %v", err)
			}
		}
	}
}

func canceleSocket(key bpf.EGhostBusterConnectionKey) error {
	// Convert uint32 IPs to net.IP (little-endian from BPF on x86)
	srcIP := net.IPv4(
		byte(key.SrcIp), byte(key.SrcIp>>8),
		byte(key.SrcIp>>16), byte(key.SrcIp>>24),
	)
	dstIP := net.IPv4(
		byte(key.DstIp), byte(key.DstIp>>8),
		byte(key.DstIp>>16), byte(key.DstIp>>24),
	)

	// Ports: byte-swap to get integer value from big-endian
	srcPort := int(key.SrcPort>>8 | (key.SrcPort&0xFF)<<8)
	dstPort := int(key.DstPort>>8 | (key.DstPort&0xFF)<<8)

	if key.Proto == consts.TCP_PROTOCOL {
		local := &net.TCPAddr{IP: srcIP, Port: srcPort}
		remote := &net.TCPAddr{IP: dstIP, Port: dstPort}
		return netlink.SocketDestroy(local, remote)
	}

	if key.Proto == consts.UDP_PROTOCOL {
		local := &net.UDPAddr{IP: srcIP, Port: srcPort}
		remote := &net.UDPAddr{IP: dstIP, Port: dstPort}
		return netlink.SocketDestroy(local, remote)
	}

	return fmt.Errorf("unsupported protocol: %d", key.Proto)
}

func parseConnectionInfo(data []byte) bpf.EGhostBusterConnectionInfo {
	return bpf.EGhostBusterConnectionInfo{
		Pid: binary.LittleEndian.Uint32(data[0:4]),
		// 4 bytes padding
		StartTime: binary.LittleEndian.Uint64(data[8:16]),
		Comm:      *(*[16]uint8)(data[16:32]),
	}
}
