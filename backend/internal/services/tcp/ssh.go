package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	"golang.org/x/crypto/ssh"
	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
)

type SSHHoneypot struct {
	baseService    *services.BaseTCPService
	profile        *profiles.HoneypotProfile
	config         *ssh.ServerConfig
	attempts       map[string]int
	attemptsMu     sync.Mutex
	virtualFiles   map[string]map[string][]byte // maps srcIP -> (filename -> content)
	virtualFilesMu sync.Mutex
}

func NewSSHHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	initialProfile *profiles.HoneypotProfile,
) *SSHHoneypot {
	s := &SSHHoneypot{
		profile:      initialProfile,
		attempts:     make(map[string]int),
		virtualFiles: make(map[string]map[string][]byte),
	}

	s.baseService = services.NewBaseTCPService(name, host, port, el, ds, s.handleRawConn)
	return s
}

func (s *SSHHoneypot) addVirtualFile(srcIP string, filename string, content []byte) {
	s.virtualFilesMu.Lock()
	defer s.virtualFilesMu.Unlock()
	if s.virtualFiles[srcIP] == nil {
		s.virtualFiles[srcIP] = make(map[string][]byte)
	}
	s.virtualFiles[srcIP][filename] = content
}

func (s *SSHHoneypot) getVirtualFileContent(srcIP string, filename string) ([]byte, bool) {
	s.virtualFilesMu.Lock()
	defer s.virtualFilesMu.Unlock()
	if userFiles, ok := s.virtualFiles[srcIP]; ok {
		if content, ok := userFiles[filename]; ok {
			return content, true
		}
	}
	return nil, false
}

func (s *SSHHoneypot) Name() string {
	return s.baseService.Name()
}

func (s *SSHHoneypot) Port() int {
	return s.baseService.Port()
}

func (s *SSHHoneypot) IsRunning() bool {
	return s.baseService.IsRunning()
}

func (s *SSHHoneypot) Start(ctx context.Context) error {
	// Dynamically generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}

	bannerStr := s.profile.SSH.Banner
	version := "OpenSSH_8.9p1 Ubuntu-3"
	if strings.HasPrefix(bannerStr, "SSH-2.0-") {
		version = strings.TrimSpace(bannerStr[8:])
	} else {
		version = strings.TrimSpace(bannerStr)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			s.attemptsMu.Lock()
			s.attempts[srcIP]++
			count := s.attempts[srcIP]
			s.attemptsMu.Unlock()

			passStr := string(password)
			s.baseService.LogEvent("login_attempt", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": 0,
				"profile":  s.profile.Name,
				"username": conn.User(),
				"password": passStr,
				"summary":  fmt.Sprintf("SSH Login attempted for username='%s' password='%s' (Access Denied)", conn.User(), passStr),
			})

			// Allow authentication on 2nd attempt if non-empty
			if count >= 2 && len(strings.TrimSpace(conn.User())) > 0 && len(strings.TrimSpace(passStr)) > 0 {
				return nil, nil
			}

			return nil, fmt.Errorf("password rejected")
		},
		ServerVersion: "SSH-2.0-" + version,
	}
	config.AddHostKey(signer)
	s.config = config

	return s.baseService.Start(ctx)
}

func (s *SSHHoneypot) Stop() error {
	return s.baseService.Stop()
}

func (s *SSHHoneypot) Proto() string {
	return s.baseService.Proto()
}

func (s *SSHHoneypot) SetProfile(prof *profiles.HoneypotProfile) {
	s.profile = prof
}

func (s *SSHHoneypot) handleRawConn(ctx context.Context, conn net.Conn) error {
	srcIP, srcPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	var srcPort int
	fmt.Sscanf(srcPortStr, "%d", &srcPort)

	s.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		s.baseService.LogEvent("client_disconnected", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
		})
		return err
	}

	s.baseService.LogEvent("login_success", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
		"profile":  s.profile.Name,
		"username": sshConn.User(),
		"summary":  fmt.Sprintf("SSH Authentication succeeded for user '%s'", sshConn.User()),
	})

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}

		go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
			for req := range reqs {
				ok := false
				switch req.Type {
				case "pty-req", "shell":
					ok = true
				}
				req.Reply(ok, nil)
				if req.Type == "shell" {
					go s.handleSession(ch, sshConn.User(), srcIP, srcPort)
				}
			}
		}(channel, requests)
	}

	return nil
}

func (s *SSHHoneypot) handleSession(channel ssh.Channel, username string, srcIP string, srcPort int) {
	defer channel.Close()

	isWindows := strings.Contains(s.profile.Name, "windows")

	var welcome string
	if isWindows {
		welcome = "\r\nMicrosoft Windows [Version 10.0.17763.379]\r\n(c) 2018 Microsoft Corporation. Tüm hakları saklıdır.\r\n\r\n"
	} else {
		welcome = fmt.Sprintf("\r\nWelcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/advantage\r\n\r\nLast login: Wed Jun  3 10:14:22 2026 from %s\r\n", srcIP)
	}

	_, _ = channel.Write([]byte(welcome))

	currentDir := "/root"
	if username != "root" {
		currentDir = "/home/" + username
	}
	if isWindows {
		currentDir = "C:\\Users\\" + username
	}

	reader := bufio.NewReader(channel)
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

		_, _ = channel.Write([]byte(prompt))

		lineBytes, err := readLine(reader, channel)
		if err != nil {
			break
		}

		cmd := strings.TrimSpace(string(lineBytes))
		if cmd == "" {
			continue
		}

		s.baseService.LogEvent("ssh_command", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"profile":  s.profile.Name,
			"username": username,
			"command":  cmd,
			"summary":  fmt.Sprintf("SSH command executed by '%s': %s", username, cmd),
		})

		parts := strings.SplitN(cmd, " ", 2)
		baseCmd := strings.ToLower(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		if baseCmd == "exit" || baseCmd == "quit" {
			_, _ = channel.Write([]byte("logout\r\n"))
			break
		}

		response := s.executeMockCommand(channel, baseCmd, arg, username, &currentDir, isWindows, srcIP, srcPort)
		if response != "" {
			_, _ = channel.Write([]byte(response))
		}
	}
}

func readLine(reader *bufio.Reader, channel ssh.Channel) ([]byte, error) {
	var line []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '\n' {
			_, _ = channel.Write([]byte{'\r', '\n'})
			break
		}
		if b == '\r' {
			continue
		}
		if b == 127 || b == 8 { // Backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
				_, _ = channel.Write([]byte{8, ' ', 8})
			}
			continue
		}
		line = append(line, b)
		_, _ = channel.Write([]byte{b}) // Echo back
	}
	return line, nil
}

func (s *SSHHoneypot) executeMockCommand(channel ssh.Channel, baseCmd, arg, username string, currentDir *string, isWindows bool, srcIP string, srcPort int) string {
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
			s.virtualFilesMu.Lock()
			if userFiles, ok := s.virtualFiles[srcIP]; ok {
				for name, content := range userFiles {
					filesList = append(filesList, fmt.Sprintf("2026-07-14  09:15           %5d %s", len(content), name))
				}
			}
			s.virtualFilesMu.Unlock()
			return fmt.Sprintf(" Directory of %s\r\n\r\n%s\r\n               %d File(s)\r\n               0 Dir(s)  42,919,203,840 bytes free\r\n", *currentDir, strings.Join(filesList, "\r\n"), len(filesList))
		case "type", "cat":
			if arg == "" {
				return "The syntax of the command is incorrect.\r\n"
			}
			if content, ok := s.getVirtualFileContent(srcIP, arg); ok {
				return string(content) + "\r\n"
			}
			return getMockFileContent(arg)
		case "ipconfig":
			return "\r\nWindows IP Configuration\r\n\r\nEthernet adapter Ethernet0:\r\n\r\n   Connection-specific DNS Suffix  . : corp.local\r\n   IPv4 Address. . . . . . . . . . . : 192.168.1.240\r\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n   Default Gateway . . . . . . . . . : 192.168.1.1\r\n"
		case "systeminfo":
			return "Host Name:                 WIN-SRV2019\r\nOS Name:                   Microsoft Windows Server 2019 Standard\r\nOS Version:                10.0.17763 N/A Build 17763\r\nOS Manufacturer:           Microsoft Corporation\r\nOS Configuration:          Member Server\r\nOS Build Type:             Multiprocessor Free\r\nSystem Manufacturer:       VMware, Inc.\r\nSystem Model:              VMware Virtual Platform\r\nSystem Type:               x64-based PC\r\nProcessor(s):              1 Processor(s) Installed.\r\nBIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019\r\nWindows Directory:         C:\\Windows\r\nSystem Directory:          C:\\Windows\\system32\r\nBoot Device:               \\Device\\HarddiskVolume1\r\nSystem Locale:             en-us;English (United States)\r\n"
		case "net":
			if strings.ToLower(arg) == "user" {
				return fmt.Sprintf("\r\nUser accounts for \\\\WIN-SRV2019\r\n\r\n-------------------------------------------------------------------------------\r\nAdministrator            Guest                    DefaultAccount           \r\nWDAGUtilityAccount       %s               \r\nThe command completed successfully.\r\n", username)
			}
			return "The syntax of this command is:\r\n\r\nNET [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |\r\n      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START | STATISTICS |\r\n      STOP | TIME | USE | USER | VIEW ]\r\n"
		case "netstat":
			return fmt.Sprintf("\r\nActive Connections\r\n\r\n  Proto  Local Address          Foreign Address        State\r\n  TCP    192.168.1.240:22       %s:%d     ESTABLISHED\r\n  TCP    192.168.1.240:3389     0.0.0.0:0              LISTENING\r\n  TCP    192.168.1.240:445      0.0.0.0:0              LISTENING\r\n", srcIP, srcPort)
		case "help":
			return "Supported commands: whoami, cd, dir, ls, type, cat, ipconfig, systeminfo, net user, netstat, help, exit\r\n"
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
			s.virtualFilesMu.Lock()
			if userFiles, ok := s.virtualFiles[srcIP]; ok {
				for name := range userFiles {
					filesList = append(filesList, name)
				}
			}
			s.virtualFilesMu.Unlock()
			return strings.Join(filesList, "  ") + "\r\n"
		case "cat":
			if arg == "" {
				return ""
			}
			if content, ok := s.getVirtualFileContent(srcIP, arg); ok {
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

			_, _ = channel.Write([]byte(fmt.Sprintf("Connecting to %s... connected.\r\n", rawURL)))
			time.Sleep(400 * time.Millisecond)
			_, _ = channel.Write([]byte("HTTP request sent, awaiting response... 200 OK\r\n"))
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

			s.baseService.LogEvent("captured_payload", map[string]interface{}{
				"src_ip":       srcIP,
				"src_port":     srcPort,
				"profile":      s.profile.Name,
				"username":     username,
				"filename":     filename,
				"file_size":    len(fileBytes),
				"sha256":       sha256Sum,
				"malware_type": malwareType,
				"details":      scanDetails,
				"download_url": rawURL,
				"summary":      fmt.Sprintf("Malware payload '%s' captured from %s. Type: %s", filename, srcIP, malwareType),
			})

			s.addVirtualFile(srcIP, filename, fileBytes)

			_, _ = channel.Write([]byte(fmt.Sprintf("Length: %d (application/octet-stream)\r\nSaving to: '%s'\r\n\r\n", len(fileBytes), filename)))
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

func resolveWindowsPath(current, target string) string {
	target = strings.ReplaceAll(target, "/", "\\")
	var parts []string
	if strings.HasPrefix(strings.ToLower(target), "c:\\") {
		parts = strings.Split(target, "\\")
	} else if strings.HasPrefix(target, "\\") {
		parts = append([]string{"C:"}, strings.Split(strings.TrimPrefix(target, "\\"), "\\")...)
	} else {
		parts = append(strings.Split(current, "\\"), strings.Split(target, "\\")...)
	}

	var resolved []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "." || p == "" {
			continue
		}
		if p == ".." {
			if len(resolved) > 1 {
				resolved = resolved[:len(resolved)-1]
			}
		} else {
			resolved = append(resolved, p)
		}
	}

	if len(resolved) > 0 && !strings.HasSuffix(resolved[0], ":") {
		resolved[0] = resolved[0] + ":"
	}
	return strings.Join(resolved, "\\")
}

func resolveLinuxPath(current, target string) string {
	var parts []string
	if strings.HasPrefix(target, "/") {
		parts = strings.Split(target, "/")
	} else {
		parts = append(strings.Split(current, "/"), strings.Split(target, "/")...)
	}

	var resolved []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "." || p == "" {
			continue
		}
		if p == ".." {
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
		} else {
			resolved = append(resolved, p)
		}
	}
	return "/" + strings.Join(resolved, "/")
}

func getMockFileContent(path string) string {
	pathLower := strings.ToLower(path)
	if strings.HasSuffix(pathLower, "notes.txt") {
		return "Tüm servis entegrasyonlarını tamamlayıp güvenlik duvarı kurallarını gözden geçirin.\r\n"
	}
	if strings.HasSuffix(pathLower, "todo.txt") {
		return "1. Web paneli şifrelerini değiştir\r\n2. SQL Server yedeklerini al\r\n3. Gereksiz portları kapat\r\n"
	}
	if strings.HasSuffix(pathLower, "install_log.txt") {
		return "2026-06-01 10:11:05 [INFO] Installer started.\r\n2026-06-01 10:12:10 [INFO] Files copied successfully.\r\n2026-06-01 10:12:15 [INFO] Installation completed.\r\n"
	}
	if strings.HasSuffix(pathLower, "passwd") {
		return "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\r\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n"
	}
	if strings.HasSuffix(pathLower, "hosts") {
		return "127.0.0.1 localhost\r\n192.168.1.240 ubuntu-srv\r\n"
	}
	if strings.HasSuffix(pathLower, "resolv.conf") {
		return "nameserver 1.1.1.1\r\nnameserver 8.8.8.8\r\n"
	}
	return "Erişim reddedildi veya dosya okunamıyor.\r\n"
}

func init() {
	services.Registry["ssh"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewSSHHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *SSHHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
