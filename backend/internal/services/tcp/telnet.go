package tcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
)

type TelnetHoneypot struct {
	baseService    *services.BaseTCPService
	profile        *profiles.HoneypotProfile
	attempts       map[string]int
	attemptsMu     sync.Mutex
	virtualFiles   map[string]map[string][]byte // maps srcIP -> (filename -> content)
	virtualFilesMu sync.Mutex
}

func NewTelnetHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	initialProfile *profiles.HoneypotProfile,
) *TelnetHoneypot {
	t := &TelnetHoneypot{
		profile:      initialProfile,
		attempts:     make(map[string]int),
		virtualFiles: make(map[string]map[string][]byte),
	}

	t.baseService = services.NewBaseTCPService(name, host, port, el, ds, t.handleClient)
	return t
}

func (t *TelnetHoneypot) addVirtualFile(srcIP string, filename string, content []byte) {
	t.virtualFilesMu.Lock()
	defer t.virtualFilesMu.Unlock()
	if t.virtualFiles[srcIP] == nil {
		t.virtualFiles[srcIP] = make(map[string][]byte)
	}
	t.virtualFiles[srcIP][filename] = content
}

func (t *TelnetHoneypot) getVirtualFileContent(srcIP string, filename string) ([]byte, bool) {
	t.virtualFilesMu.Lock()
	defer t.virtualFilesMu.Unlock()
	if userFiles, ok := t.virtualFiles[srcIP]; ok {
		if content, ok := userFiles[filename]; ok {
			return content, true
		}
	}
	return nil, false
}

func (t *TelnetHoneypot) Name() string {
	return t.baseService.Name()
}

func (t *TelnetHoneypot) Port() int {
	return t.baseService.Port()
}

func (t *TelnetHoneypot) Proto() string {
	return t.baseService.Proto()
}

func (t *TelnetHoneypot) IsRunning() bool {
	return t.baseService.IsRunning()
}

func (t *TelnetHoneypot) Start(ctx context.Context) error {
	return t.baseService.Start(ctx)
}

func (t *TelnetHoneypot) Stop() error {
	return t.baseService.Stop()
}

func (t *TelnetHoneypot) SetProfile(prof *profiles.HoneypotProfile) {
	t.profile = prof
}

func (t *TelnetHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	t.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	reader := bufio.NewReader(conn)
	telnetProf := t.profile.Telnet

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(telnetProf.Banner)); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	usernameLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	username := strings.TrimSpace(usernameLine)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(telnetProf.PasswordPrompt)); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	passwordLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	password := strings.TrimSpace(passwordLine)

	t.attemptsMu.Lock()
	t.attempts[srcIP]++
	count := t.attempts[srcIP]
	t.attemptsMu.Unlock()

	t.baseService.LogEvent("login_attempt", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
		"profile":  t.profile.Name,
		"username": username,
		"password": password,
		"summary":  fmt.Sprintf("Telnet login attempt for %s (attempt %d)", username, count),
	})

	if count >= 2 && len(strings.TrimSpace(username)) > 0 && len(strings.TrimSpace(password)) > 0 {
		t.baseService.LogEvent("login_success", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"profile":  t.profile.Name,
			"username": username,
			"summary":  fmt.Sprintf("Telnet Authentication succeeded for user '%s'", username),
		})

		t.runTelnetShell(conn, reader, username, srcIP, srcPort)
		return nil
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(telnetProf.LoginFailedResponse)); err != nil {
		return err
	}

	return nil
}

func (t *TelnetHoneypot) runTelnetShell(conn net.Conn, reader *bufio.Reader, username string, srcIP string, srcPort int) {
	isWindows := strings.Contains(t.profile.Name, "windows")

	var welcome string
	if isWindows {
		welcome = "\r\nMicrosoft Windows [Version 10.0.17763.379]\r\n(c) 2018 Microsoft Corporation. Tüm hakları saklıdır.\r\n\r\n"
	} else {
		welcome = fmt.Sprintf("\r\nWelcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\nLast login: Wed Jun  3 10:14:22 2026 from %s\r\n", srcIP)
	}

	_, _ = conn.Write([]byte(welcome))

	currentDir := "/root"
	if username != "root" {
		currentDir = "/home/" + username
	}
	if isWindows {
		currentDir = "C:\\Users\\" + username
	}

	for {
		var prompt string
		if isWindows {
			prompt = fmt.Sprintf("%s>", currentDir)
		} else {
			suffix := "$ "
			if username == "root" {
				suffix = "# "
			}
			prompt = fmt.Sprintf("%s@ubuntu-srv:%s%s", username, currentDir, suffix)
		}

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte(prompt))

		conn.SetReadDeadline(time.Now().Add(300 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		cmd := strings.TrimSpace(line)
		if cmd == "" {
			continue
		}

		t.baseService.LogEvent("telnet_command", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"profile":  t.profile.Name,
			"username": username,
			"command":  cmd,
			"summary":  fmt.Sprintf("Telnet command executed by '%s': %s", username, cmd),
		})

		parts := strings.SplitN(cmd, " ", 2)
		baseCmd := strings.ToLower(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		if baseCmd == "exit" || baseCmd == "quit" {
			_, _ = conn.Write([]byte("logout\r\n"))
			break
		}

		response := t.executeMockCommand(conn, baseCmd, arg, username, &currentDir, isWindows, srcIP, srcPort)
		if response != "" {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte(response))
		}
	}
}

func (t *TelnetHoneypot) executeMockCommand(conn net.Conn, baseCmd, arg, username string, currentDir *string, isWindows bool, srcIP string, srcPort int) string {
	if isWindows {
		switch baseCmd {
		case "whoami":
			return fmt.Sprintf("win-srv2019\\%s\r\n", username)
		case "cd":
			if arg == "" {
				return fmt.Sprintf("%s\r\n", *currentDir)
			}
			if strings.ToLower(arg) == "c:" || strings.ToLower(arg) == "c:\\" || strings.ToLower(arg) == "c:/" {
				*currentDir = "C:"
				return ""
			}
			targetDir := resolveWindowsPath(*currentDir, arg)
			*currentDir = targetDir
			return ""
		case "dir", "ls":
			var filesList []string
			filesList = []string{
				"2026-06-03  10:15             120 notes.txt",
				"2026-06-03  10:15             150 todo.txt",
			}
			t.virtualFilesMu.Lock()
			if userFiles, ok := t.virtualFiles[srcIP]; ok {
				for name, content := range userFiles {
					filesList = append(filesList, fmt.Sprintf("2026-07-14  09:15           %5d %s", len(content), name))
				}
			}
			t.virtualFilesMu.Unlock()
			return fmt.Sprintf(" Directory of %s\r\n\r\n%s\r\n               %d File(s)\r\n               0 Dir(s)  42,919,203,840 bytes free\r\n", *currentDir, strings.Join(filesList, "\r\n"), len(filesList))
		case "type", "cat":
			if arg == "" {
				return "The syntax of the command is incorrect.\r\n"
			}
			if content, ok := t.getVirtualFileContent(srcIP, arg); ok {
				return string(content) + "\r\n"
			}
			return getMockFileContent(arg)
		case "ipconfig":
			return "\r\nWindows IP Configuration\r\n\r\nEthernet adapter Ethernet0:\r\n\r\n   Connection-specific DNS Suffix  . : corp.local\r\n   IPv4 Address. . . . . . . . . . . : 192.168.1.240\r\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n   Default Gateway . . . . . . . . . : 192.168.1.1\r\n"
		case "systeminfo":
			return "Host Name:                 WIN-SRV2019\r\nOS Name:                   Microsoft Windows Server 2019 Standard\r\nOS Version:                10.0.17763 N/A Build 17763\r\nOS Manufacturer:           Microsoft Corporation\r\nOS Configuration:          Member Server\r\nOS Build Type:             Multiprocessor Free\r\nSystem Manufacturer:       VMware, Inc.\r\nSystem Model:              VMware Virtual Platform\r\nSystem Type:               x64-based PC\r\nProcessor(s):              1 Processor(s) Installed.\r\nBIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019\r\nWindows Directory:         C:\\Windows\r\nSystem Directory:          C:\\Windows\\system32\r\nBoot Device:               \\Device\\HarddiskVolume1\r\nSystem Locale:             en-us;English (United States)\r\n"
		case "help":
			return "Supported commands: whoami, cd, dir, ls, type, cat, ipconfig, systeminfo, help, exit\r\n"
		default:
			return fmt.Sprintf("'%s' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n", baseCmd)
		}
	} else {
		// Linux
		switch baseCmd {
		case "whoami":
			return fmt.Sprintf("%s\r\n", username)
		case "id":
			if username == "root" {
				return "uid=0(root) gid=0(root) groups=0(root)\r\n"
			}
			return fmt.Sprintf("uid=1000(%s) gid=1000(%s) groups=1000(%s)\r\n", username, username, username)
		case "pwd":
			return fmt.Sprintf("%s\r\n", *currentDir)
		case "cd":
			if arg == "" || arg == "~" {
				if username == "root" {
					*currentDir = "/root"
				} else {
					*currentDir = "/home/" + username
				}
				return ""
			}
			*currentDir = resolveLinuxPath(*currentDir, arg)
			return ""
		case "ls", "dir":
			if strings.Contains(*currentDir, "etc") {
				return "passwd  group  hosts  resolv.conf\r\n"
			}
			filesList := []string{"Desktop", "Documents", "Downloads", "notes.txt"}
			t.virtualFilesMu.Lock()
			if userFiles, ok := t.virtualFiles[srcIP]; ok {
				for name := range userFiles {
					filesList = append(filesList, name)
				}
			}
			t.virtualFilesMu.Unlock()
			return strings.Join(filesList, "  ") + "\r\n"
		case "cat":
			if arg == "" {
				return ""
			}
			if content, ok := t.getVirtualFileContent(srcIP, arg); ok {
				return string(content) + "\r\n"
			}
			return getMockFileContent(arg)
		case "wget", "curl":
			if arg == "" {
				if baseCmd == "wget" {
					return "wget: missing URL\r\n"
				}
				return "curl: no URL specified\r\n"
			}
			rawURL := arg
			if baseCmd == "curl" {
				parts := strings.Fields(arg)
				for _, p := range parts {
					if !strings.HasPrefix(p, "-") {
						rawURL = p
						break
					}
				}
			}
			rawURL = strings.Trim(rawURL, `"'`)

			filename := "index.html"
			u, err := url.Parse(rawURL)
			if err == nil {
				pathParts := strings.Split(u.Path, "/")
				if len(pathParts) > 0 && pathParts[len(pathParts)-1] != "" {
					filename = pathParts[len(pathParts)-1]
				}
			}

			_, _ = conn.Write([]byte(fmt.Sprintf("Connecting to %s... connected.\r\n", rawURL)))
			time.Sleep(400 * time.Millisecond)
			_, _ = conn.Write([]byte("HTTP request sent, awaiting response... 200 OK\r\n"))
			time.Sleep(400 * time.Millisecond)

			var fileBytes []byte
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Get(rawURL)
			if err == nil && resp.StatusCode == http.StatusOK {
				fileBytes, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if len(fileBytes) == 0 {
				fileBytes = []byte("#!/bin/bash\n# Simulated payload downloaded by honeypot attacker\necho \"Executing malware...\"\n")
			}

			captureDir := "/app/logs/captured_malware"
			_ = os.MkdirAll(captureDir, 0755)
			timestamp := time.Now().Format("20060102_150405")
			safeIP := strings.ReplaceAll(srcIP, ":", "_")
			filePath := fmt.Sprintf("%s/%s_%s_%s", captureDir, timestamp, safeIP, filename)
			_ = os.WriteFile(filePath, fileBytes, 0644)

			malwareType, scanDetails := services.AnalyzePayload(filename, fileBytes)

			hasher := sha256.New()
			hasher.Write(fileBytes)
			sha256Sum := hex.EncodeToString(hasher.Sum(nil))

			t.baseService.LogEvent("captured_payload", map[string]interface{}{
				"src_ip":       srcIP,
				"src_port":     srcPort,
				"profile":      t.profile.Name,
				"username":     username,
				"filename":     filename,
				"file_size":    len(fileBytes),
				"sha256":       sha256Sum,
				"malware_type": malwareType,
				"details":      scanDetails,
				"download_url": rawURL,
				"summary":      fmt.Sprintf("Malware payload '%s' captured from %s. Type: %s", filename, srcIP, malwareType),
			})

			t.addVirtualFile(srcIP, filename, fileBytes)

			_, _ = conn.Write([]byte(fmt.Sprintf("Length: %d (application/octet-stream)\r\nSaving to: '%s'\r\n\r\n", len(fileBytes), filename)))
			time.Sleep(400 * time.Millisecond)
			return fmt.Sprintf("100%%[======================================>] %d  --.-KB/s   in 0.1s\r\n", len(fileBytes))
		case "ifconfig", "ip":
			return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 192.168.1.240  netmask 255.255.255.0  broadcast 192.168.1.255\r\n        ether 00:15:5d:00:1a:2b  txqueuelen 1000  (Ethernet)\r\n"
		case "uname":
			if strings.Contains(arg, "-a") {
				return "Linux ubuntu-srv 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"
			}
			return "Linux\r\n"
		case "help":
			return "Supported commands: whoami, id, pwd, cd, ls, cat, wget, curl, ifconfig, ip, uname -a, help, exit\r\n"
		default:
			return fmt.Sprintf("bash: %s: command not found\r\n", baseCmd)
		}
	}
}

func init() {
	services.Registry["telnet"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewTelnetHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *TelnetHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
