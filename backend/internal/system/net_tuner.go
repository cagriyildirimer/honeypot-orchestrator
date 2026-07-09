package system

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"honeypot-orchestrator/backend/internal/logger"
)

type PortProto struct {
	Port  int
	Proto string
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func SetupFirewall(activePorts []PortProto, webPort *int) {
	runCommand("iptables", "-N", "HONEYPOT_INPUT")
	runCommand("iptables", "-N", "HONEYPOT_BLACKLIST")

	runCommand("iptables", "-F", "HONEYPOT_INPUT")

	err := runCommand("iptables", "-C", "INPUT", "-j", "HONEYPOT_INPUT")
	if err != nil {
		runCommand("iptables", "-I", "INPUT", "1", "-j", "HONEYPOT_INPUT")
	}

	runCommand("iptables", "-A", "HONEYPOT_INPUT", "-i", "lo", "-j", "ACCEPT")

	runCommand("iptables", "-A", "HONEYPOT_INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")

	if webPort != nil {
		runCommand("iptables", "-A", "HONEYPOT_INPUT", "-p", "tcp", "--dport", strconv.Itoa(*webPort), "-j", "ACCEPT")
	}

	runCommand("iptables", "-A", "HONEYPOT_INPUT", "-j", "HONEYPOT_BLACKLIST")

	for _, p := range activePorts {
		runCommand("iptables", "-A", "HONEYPOT_INPUT", "-p", p.Proto, "--dport", strconv.Itoa(p.Port), "-j", "ACCEPT")
	}

	runCommand("iptables", "-A", "HONEYPOT_INPUT", "-p", "tcp", "-j", "DROP")
	runCommand("iptables", "-A", "HONEYPOT_INPUT", "-p", "udp", "-j", "DROP")
	runCommand("iptables", "-A", "HONEYPOT_INPUT", "-p", "icmp", "-j", "DROP")
}

func ApplyNFQueueRules(profileName string) {
	runCommand("iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK", "-j", "NFQUEUE", "--queue-num", "1")

	if profileName == "windows_server" {
		runCommand("iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK", "-j", "NFQUEUE", "--queue-num", "1")
		log.Println("NFQUEUE rules applied for windows_server profile.")
	} else {
		log.Println("NFQUEUE rules removed for non-windows profile.")
	}
}

func CleanupFirewall() {
	runCommand("iptables", "-D", "INPUT", "-j", "HONEYPOT_INPUT")
	runCommand("iptables", "-F", "HONEYPOT_INPUT")
	runCommand("iptables", "-X", "HONEYPOT_INPUT")
	runCommand("iptables", "-F", "HONEYPOT_BLACKLIST")
	runCommand("iptables", "-X", "HONEYPOT_BLACKLIST")
	log.Println("Honeypot firewall cleanup completed.")
}

func ApplyProfileNetworkSettings(
	profileName string,
	eventLogger *logger.EventLogger,
	activePorts []PortProto,
	webPort int,
	webEnabled bool,
) {
	isWindows := profileName == "windows_server"
	targetTTL := "64"
	if isWindows {
		targetTTL = "128"
	}
	targetTimestamps := "1"
	if isWindows {
		targetTimestamps = "0"
	}
	targetRmem := "4096 87380 16777216"
	if isWindows {
		targetRmem = "4096 65536 12582912"
	}
	targetWmem := "4096 65536 16777216"
	if isWindows {
		targetWmem = "4096 65536 12582912"
	}
	targetECN := "2"
	if isWindows {
		targetECN = "0"
	}
	targetDSACK := "1"
	if isWindows {
		targetDSACK = "0"
	}
	targetFACK := "1"
	if isWindows {
		targetFACK = "0"
	}

	sysctlPaths := map[string][]string{
		"net.ipv4.ip_default_ttl":     {"/proc/sys/net/ipv4/ip_default_ttl", targetTTL},
		"net.ipv4.tcp_timestamps":     {"/proc/sys/net/ipv4/tcp_timestamps", targetTimestamps},
		"net.ipv4.tcp_window_scaling": {"/proc/sys/net/ipv4/tcp_window_scaling", "1"},
		"net.ipv4.tcp_sack":           {"/proc/sys/net/ipv4/tcp_sack", "1"},
		"net.ipv4.tcp_ecn":            {"/proc/sys/net/ipv4/tcp_ecn", targetECN},
		"net.ipv4.tcp_dsack":          {"/proc/sys/net/ipv4/tcp_dsack", targetDSACK},
		"net.ipv4.tcp_fack":           {"/proc/sys/net/ipv4/tcp_fack", targetFACK},
		"net.ipv4.tcp_rmem":           {"/proc/sys/net/ipv4/tcp_rmem", targetRmem},
		"net.ipv4.tcp_wmem":           {"/proc/sys/net/ipv4/tcp_wmem", targetWmem},
	}

	var modifiedParams []string
	var failedParams []string

	for name, pair := range sysctlPaths {
		path := pair[0]
		val := pair[1]
		err := os.WriteFile(path, []byte(val), 0644)
		if err != nil {
			failedParams = append(failedParams, fmt.Sprintf("%s (%v)", name, err))
		} else {
			modifiedParams = append(modifiedParams, fmt.Sprintf("%s=%s", name, val))
		}
	}

	if len(failedParams) > 0 {
		summary := fmt.Sprintf("Failed to apply some network fingerprint adjustments: %s. Check if container runs as root and has NET_ADMIN capability.", strings.Join(failedParams, ", "))
		log.Println("Warning:", summary)
		eventLogger.Log(map[string]interface{}{
			"service":       "orchestrator",
			"event_type":    "network_tuning_warning",
			"summary":       summary,
			"failed_params": failedParams,
		})
	}

	if len(modifiedParams) > 0 {
		summary := fmt.Sprintf("Applied network fingerprint adjustments: %s.", strings.Join(modifiedParams, ", "))
		log.Println(summary)
		eventLogger.Log(map[string]interface{}{
			"service":         "orchestrator",
			"event_type":      "network_tuning_applied",
			"summary":         summary,
			"profile":         profileName,
			"modified_params": modifiedParams,
		})
	}

	var wPort *int
	if webEnabled {
		wPort = &webPort
	}
	SetupFirewall(activePorts, wPort)
	ApplyNFQueueRules(profileName)
}

func ApplyFirewallRule(ipOrMac string) {
	if net.ParseIP(ipOrMac) != nil {
		runCommand("iptables", "-A", "HONEYPOT_BLACKLIST", "-s", ipOrMac, "-j", "DROP")
	} else if strings.Contains(ipOrMac, ":") {
		runCommand("iptables", "-A", "HONEYPOT_BLACKLIST", "-m", "mac", "--mac-source", ipOrMac, "-j", "DROP")
	} else {
		runCommand("iptables", "-A", "HONEYPOT_BLACKLIST", "-s", ipOrMac, "-j", "DROP")
	}
}

func RemoveFirewallRule(ipOrMac string) {
	if net.ParseIP(ipOrMac) != nil {
		runCommand("iptables", "-D", "HONEYPOT_BLACKLIST", "-s", ipOrMac, "-j", "DROP")
	} else if strings.Contains(ipOrMac, ":") {
		runCommand("iptables", "-D", "HONEYPOT_BLACKLIST", "-m", "mac", "--mac-source", ipOrMac, "-j", "DROP")
	} else {
		runCommand("iptables", "-D", "HONEYPOT_BLACKLIST", "-s", ipOrMac, "-j", "DROP")
	}
}
