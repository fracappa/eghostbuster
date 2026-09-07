package iptables

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type ServiceEndpoint struct {
	ChainName   string // e.g. KUBE-SEP-AAAAA
	PodIP       string // DNAT target IP
	PodPort     string // DNAT target port
	ParentChain string // e.g. KUBE-SVC-XXXXX
}

var (
	dnatRegex = regexp.MustCompile(`--to-destination\s+(\d+\.\d+\.\d+\.\d+):(\d+)`)
	jumpRegex = regexp.MustCompile(`-A\s+(KUBE-SVC-\S+)\s+.*-j\s+(KUBE-SEP-\S+)`)
)

// ListEndpoints parses iptables NAT rules and returns all KUBE-SEP-* service endpoints.
func ListEndpoints() ([]ServiceEndpoint, error) {
	output, err := iptablesSave()
	if err != nil {
		return nil, err
	}
	return parseEndpoints(output), nil
}

func iptablesSave() (string, error) {
	cmd := exec.Command("iptables-save", "-t", "nat")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("iptables-save: %w: %s", err, string(out))
	}
	return string(out), nil
}

func parseEndpoints(rules string) []ServiceEndpoint {
	lines := strings.Split(rules, "\n")

	endpoints := make(map[string]*ServiceEndpoint)
	for _, line := range lines {
		if !strings.HasPrefix(line, "-A KUBE-SEP-") || !strings.Contains(line, "--to-destination") {
			continue
		}
		matches := dnatRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chainName := fields[1]
		endpoints[chainName] = &ServiceEndpoint{
			ChainName: chainName,
			PodIP:     matches[1],
			PodPort:   matches[2],
		}
	}

	for _, line := range lines {
		matches := jumpRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		if ep, ok := endpoints[matches[2]]; ok {
			ep.ParentChain = matches[1]
		}
	}

	result := make([]ServiceEndpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		result = append(result, *ep)
	}
	return result
}

// RemoveEndpoint removes a stale KUBE-SEP-* chain and its jump rule from the parent chain.
func RemoveEndpoint(ep ServiceEndpoint) error {
	if ep.ParentChain != "" {
		if err := deleteJumpRule(ep.ParentChain, ep.ChainName); err != nil {
			return fmt.Errorf("deleting jump rule from %s: %w", ep.ParentChain, err)
		}
	}

	if err := flushChain(ep.ChainName); err != nil {
		return fmt.Errorf("flushing chain %s: %w", ep.ChainName, err)
	}

	if err := deleteChain(ep.ChainName); err != nil {
		return fmt.Errorf("deleting chain %s: %w", ep.ChainName, err)
	}

	return nil
}

func deleteJumpRule(parentChain, targetChain string) error {
	cmd := exec.Command("iptables", "-t", "nat", "--line-numbers", "-nL", parentChain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("listing %s: %w: %s", parentChain, err, string(out))
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == targetChain {
			delCmd := exec.Command("iptables", "-t", "nat", "-D", parentChain, fields[0])
			delOut, err := delCmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w: %s", err, string(delOut))
			}
			return nil
		}
	}

	return fmt.Errorf("jump rule to %s not found in %s", targetChain, parentChain)
}

func flushChain(chain string) error {
	cmd := exec.Command("iptables", "-t", "nat", "-F", chain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

func deleteChain(chain string) error {
	cmd := exec.Command("iptables", "-t", "nat", "-X", chain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}
