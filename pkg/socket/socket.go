package socket

import (
	"fmt"
	"os/exec"

	"github.com/eghostbuster/eghostbuster/pkg/netns"
)

// Destroy kills a TCP socket in CLOSE_WAIT state using ss
func DestroySocketNetnsIno(netnsIno uint64, srcIP string, srcPort uint16, dstIP string, dstPort uint16) error {
	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)

	return netns.Do(netnsIno, func() error {
		return ssKill(src, dst)
	})
}

func ssKill(src, dst string) error {
	cmd := exec.Command("ss", "--kill", "state", "close-wait",
		"src", src, "dst", dst)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ss failed: %v, output: %s", err, output)
	}
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
