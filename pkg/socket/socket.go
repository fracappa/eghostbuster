package socket

import (
	"fmt"
	"os/exec"

	"github.com/fracappa/eghostbuster/pkg/consts"
	"github.com/fracappa/eghostbuster/pkg/netns"
)

// Destroy kills a TCP socket in CLOSE_WAIT state using ss
func DestroySocketNetnsIno(netnsIno uint64, proto uint8, srcIP uint32, srcPort uint16, dstIP uint32, dstPort uint16) error {

	return netns.Do(netnsIno, func() error {
		return destroySocket(proto, srcIP, dstIP, srcPort, dstPort)
	})
}

func destroySocket(proto uint8, srcIP, dstIP uint32, srcPort, dstPort uint16) error {
	srcAddr := fmt.Sprintf("%d.%d.%d.%d",
		byte(srcIP), byte(srcIP>>8), byte(srcIP>>16), byte(srcIP>>24))
	dstAddr := fmt.Sprintf("%d.%d.%d.%d",
		byte(dstIP), byte(dstIP>>8), byte(dstIP>>16), byte(dstIP>>24))

	srcP := Ntohs(srcPort)
	dstP := Ntohs(dstPort)

	src := fmt.Sprintf("%s:%d", srcAddr, srcP)
	dst := fmt.Sprintf("%s:%d", dstAddr, dstP)

	// First verify socket exists with ss
	if !socketExists(src, dst) {
		return fmt.Errorf("socket not found")
	}

	// Now destroy it
	if proto == consts.TCP_PROTOCOL {
		return destroyViaSS(src, dst)
	}

	return fmt.Errorf("unsupported protocol: %d", proto)
}

// socketExists checks if a socket exists using ss
func socketExists(src, dst string) bool {
	cmd := exec.Command("ss", "-tn", "state", "close-wait",
		"src", src, "dst", dst)
	output, err := cmd.CombinedOutput()
	// ss returns 0 if socket found, 1 if not found
	return err == nil && len(output) > 0
}

// destroyViaSS destroys socket using ss --kill
// This is a last-resort method since ss doesn't report errors
func destroyViaSS(src, dst string) error {
	cmd := exec.Command("ss", "--kill", "state", "close-wait",
		"src", src, "dst", dst)
	_, _ = cmd.CombinedOutput()
	// ss --kill always returns 0, so just return nil
	// We already verified the socket exists
	return nil
}

// FormatIP converts a uint32 IP to string (little-endian)
func FormatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// Ntohs converts network byte order to host byte order (16-bit)
func Ntohs(n uint16) uint16 {
	return (n>>8)&0xff | (n<<8)&0xff00
}
