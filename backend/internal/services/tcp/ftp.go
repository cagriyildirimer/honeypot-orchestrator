package tcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
)

type FTPHoneypot struct {
	baseService *services.BaseTCPService
	profile     *profiles.HoneypotProfile
	attempts    map[string]int
	attemptsMu  sync.Mutex
}

func NewFTPHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	initialProfile *profiles.HoneypotProfile,
) *FTPHoneypot {
	f := &FTPHoneypot{
		profile:  initialProfile,
		attempts: make(map[string]int),
	}

	f.baseService = services.NewBaseTCPService(name, host, port, el, ds, f.handleClient)
	return f
}

func (f *FTPHoneypot) Name() string {
	return f.baseService.Name()
}

func (f *FTPHoneypot) Port() int {
	return f.baseService.Port()
}

func (f *FTPHoneypot) Proto() string {
	return f.baseService.Proto()
}

func (f *FTPHoneypot) IsRunning() bool {
	return f.baseService.IsRunning()
}

func (f *FTPHoneypot) Start(ctx context.Context) error {
	return f.baseService.Start(ctx)
}

func (f *FTPHoneypot) Stop() error {
	return f.baseService.Stop()
}

func (f *FTPHoneypot) SetProfile(prof *profiles.HoneypotProfile) {
	f.profile = prof
}

func (f *FTPHoneypot) getDataConnection(activeAddr string, dataListener net.Listener) (net.Conn, error) {
	if dataListener != nil {
		dataConn, err := dataListener.Accept()
		if err != nil {
			return nil, err
		}
		return dataConn, nil
	}
	if activeAddr != "" {
		dataConn, err := net.DialTimeout("tcp", activeAddr, 3*time.Second)
		if err != nil {
			return nil, err
		}
		return dataConn, nil
	}
	return nil, fmt.Errorf("no passive listener or active address set")
}

func (f *FTPHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	f.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	reader := bufio.NewReader(conn)
	ftpProf := f.profile.FTP

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(ftpProf.Banner)); err != nil {
		return err
	}

	username := ""
	isLoggedIn := false
	var activeAddr string

	var dataListener net.Listener
	defer func() {
		if dataListener != nil {
			dataListener.Close()
		}
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		command := strings.ToUpper(parts[0])
		argument := ""
		if len(parts) == 2 {
			argument = strings.TrimSpace(parts[1])
		}

		f.baseService.LogEvent("ftp_command", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"profile":  f.profile.Name,
			"command":  command,
			"argument": argument,
			"summary":  "FTP " + command,
		})

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

		if command == "USER" {
			username = argument
			if _, err := conn.Write([]byte(ftpProf.UserPromptResponse)); err != nil {
				return err
			}
		} else if command == "PASS" {
			f.attemptsMu.Lock()
			f.attempts[srcIP]++
			count := f.attempts[srcIP]
			f.attemptsMu.Unlock()

			f.baseService.LogEvent("login_attempt", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"profile":  f.profile.Name,
				"username": username,
				"password": argument,
				"summary":  fmt.Sprintf("FTP login attempt for %s (attempt %d)", username, count),
			})

			if count >= 2 && len(strings.TrimSpace(username)) > 0 && len(strings.TrimSpace(argument)) > 0 {
				f.baseService.LogEvent("login_success", map[string]interface{}{
					"src_ip":   srcIP,
					"src_port": srcPort,
					"profile":  f.profile.Name,
					"username": username,
					"summary":  fmt.Sprintf("FTP Authentication succeeded for user '%s'", username),
				})
				isLoggedIn = true
				if _, err := conn.Write([]byte("230 User logged in, proceed.\r\n")); err != nil {
					return err
				}
			} else {
				if _, err := conn.Write([]byte(ftpProf.LoginFailedResponse)); err != nil {
					return err
				}
			}
		} else if command == "QUIT" {
			_, _ = conn.Write([]byte(ftpProf.QuitResponse))
			break
		} else if command == "SYST" {
			_, _ = conn.Write([]byte("215 UNIX Type: L8\r\n"))
		} else if command == "FEAT" {
			var featResponse string
			if strings.Contains(f.profile.Name, "windows") {
				featResponse = "211-Extended features supported:\r\n" +
					" LANG EN*\r\n" +
					" UTF8\r\n" +
					" SIZE\r\n" +
					" MDTM\r\n" +
					" REST STREAM\r\n" +
					"211 End\r\n"
			} else {
				featResponse = "211-Features:\r\n" +
					" MDTM\r\n" +
					" MFMT\r\n" +
					" TVFS\r\n" +
					" UTF8\r\n" +
					" REST STREAM\r\n" +
					" SIZE\r\n" +
					"211 End\r\n"
			}
			_, _ = conn.Write([]byte(featResponse))
		} else if command == "OPTS" {
			_, _ = conn.Write([]byte("200 OPTS UTF8 is set to ON.\r\n"))
		} else if command == "PWD" {
			_, _ = conn.Write([]byte("257 \"/\" is current directory.\r\n"))
		} else if command == "CWD" {
			if !isLoggedIn {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				continue
			}
			_, _ = conn.Write([]byte("250 Directory successfully changed.\r\n"))
		} else if command == "TYPE" {
			_, _ = conn.Write([]byte("200 Type set to I.\r\n"))
		} else if command == "SIZE" {
			if !isLoggedIn {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				continue
			}
			argLower := strings.ToLower(argument)
			if strings.HasSuffix(argLower, "notes.txt") {
				_, _ = conn.Write([]byte("213 120\r\n"))
			} else if strings.HasSuffix(argLower, "todo.txt") {
				_, _ = conn.Write([]byte("213 150\r\n"))
			} else {
				_, _ = conn.Write([]byte("550 File not found.\r\n"))
			}
		} else if command == "MDTM" {
			if !isLoggedIn {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				continue
			}
			argLower := strings.ToLower(argument)
			if strings.HasSuffix(argLower, "notes.txt") || strings.HasSuffix(argLower, "todo.txt") {
				_, _ = conn.Write([]byte("213 20260714091500\r\n"))
			} else {
				_, _ = conn.Write([]byte("550 File not found.\r\n"))
			}
		} else if command == "PORT" {
			if !isLoggedIn {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				continue
			}
			parts := strings.Split(argument, ",")
			if len(parts) != 6 {
				_, _ = conn.Write([]byte("501 Syntax error in parameters.\r\n"))
				continue
			}
			var h1, h2, h3, h4, p1, p2 int
			_, err := fmt.Sscanf(argument, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2)
			if err != nil {
				_, _ = conn.Write([]byte("501 Syntax error in parameters.\r\n"))
				continue
			}
			ip := fmt.Sprintf("%d.%d.%d.%d", h1, h2, h3, h4)
			port := p1*256 + p2
			activeAddr = fmt.Sprintf("%s:%d", ip, port)

			if dataListener != nil {
				dataListener.Close()
				dataListener = nil
			}

			_, _ = conn.Write([]byte("200 PORT command successful.\r\n"))
		} else if command == "PASV" {
			if !isLoggedIn {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				continue
			}
			activeAddr = "" // clear active mode
			localAddr := conn.LocalAddr().String()
			localIP, _, _ := net.SplitHostPort(localAddr)
			ipCommas := strings.ReplaceAll(localIP, ".", ",")
			if ipCommas == "::1" || ipCommas == "localhost" || strings.Contains(ipCommas, ":") {
				ipCommas = "127,0,0,1"
			}

			if dataListener != nil {
				dataListener.Close()
			}

			var err error
			dataListener, err = net.Listen("tcp", fmt.Sprintf("%s:0", localIP))
			if err != nil {
				_, _ = conn.Write([]byte("425 Can't open data connection.\r\n"))
				continue
			}

			_, portStr, _ := net.SplitHostPort(dataListener.Addr().String())
			var dataPort int
			fmt.Sscanf(portStr, "%d", &dataPort)
			p1 := dataPort / 256
			p2 := dataPort % 256

			_, _ = conn.Write([]byte(fmt.Sprintf("227 Entering Passive Mode (%s,%d,%d)\r\n", ipCommas, p1, p2)))
		} else if command == "LIST" {
			if !isLoggedIn {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				continue
			}
			if dataListener == nil && activeAddr == "" {
				_, _ = conn.Write([]byte("425 Use PORT or PASV first.\r\n"))
				continue
			}
			_, _ = conn.Write([]byte("150 Opening ASCII mode data connection for file list.\r\n"))

			dataConn, err := f.getDataConnection(activeAddr, dataListener)
			if err != nil {
				_, _ = conn.Write([]byte("425 Can't open data connection.\r\n"))
				continue
			}

			listContent := "-rw-r--r--   1 owner    group             120 Jul 14 09:15 notes.txt\r\n-rw-r--r--   1 owner    group             150 Jul 14 09:15 todo.txt\r\n"
			_, _ = dataConn.Write([]byte(listContent))
			dataConn.Close()

			if dataListener != nil {
				dataListener.Close()
				dataListener = nil
			}
			activeAddr = "" // clear for next command
			_, _ = conn.Write([]byte("226 Transfer complete.\r\n"))
		} else if command == "RETR" {
			if !isLoggedIn {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				continue
			}
			if argument == "" {
				_, _ = conn.Write([]byte("501 Syntax error in parameters.\r\n"))
				continue
			}
			if dataListener == nil && activeAddr == "" {
				_, _ = conn.Write([]byte("425 Use PORT or PASV first.\r\n"))
				continue
			}

			argLower := strings.ToLower(argument)
			var fileContent string
			if strings.HasSuffix(argLower, "notes.txt") {
				fileContent = "Tüm servis entegrasyonlarını tamamlayıp güvenlik duvarı kurallarını gözden geçirin.\r\n"
			} else if strings.HasSuffix(argLower, "todo.txt") {
				fileContent = "1. Web paneli şifrelerini değiştir\r\n2. SQL Server yedeklerini al\r\n3. Gereksiz portları kapat\r\n"
			} else {
				_, _ = conn.Write([]byte("550 File not found.\r\n"))
				continue
			}

			_, _ = conn.Write([]byte(fmt.Sprintf("150 Opening ASCII mode data connection for %s.\r\n", argument)))

			dataConn, err := f.getDataConnection(activeAddr, dataListener)
			if err != nil {
				_, _ = conn.Write([]byte("425 Can't open data connection.\r\n"))
				continue
			}

			_, _ = dataConn.Write([]byte(fileContent))
			dataConn.Close()

			if dataListener != nil {
				dataListener.Close()
				dataListener = nil
			}
			activeAddr = "" // clear for next command
			_, _ = conn.Write([]byte("226 Transfer complete.\r\n"))
		} else if command == "STOR" {
			if !isLoggedIn {
				_, _ = conn.Write([]byte("530 Please login with USER and PASS.\r\n"))
				continue
			}
			if argument == "" {
				_, _ = conn.Write([]byte("501 Syntax error in parameters or arguments.\r\n"))
				continue
			}
			if dataListener == nil && activeAddr == "" {
				_, _ = conn.Write([]byte("425 Use PORT or PASV first.\r\n"))
				continue
			}

			_, _ = conn.Write([]byte(fmt.Sprintf("150 Opening BINARY mode data connection for %s.\r\n", argument)))

			dataConn, err := f.getDataConnection(activeAddr, dataListener)
			if err != nil {
				_, _ = conn.Write([]byte("425 Can't open data connection.\r\n"))
				continue
			}

			var fileBytes []byte
			buf := make([]byte, 4096)
			for {
				dataConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := dataConn.Read(buf)
				if n > 0 {
					fileBytes = append(fileBytes, buf[:n]...)
				}
				if err != nil {
					break
				}
			}
			dataConn.Close()

			if dataListener != nil {
				dataListener.Close()
				dataListener = nil
			}
			activeAddr = "" // clear for next command

			_, _ = conn.Write([]byte("226 Transfer complete.\r\n"))

			captureDir := "/app/logs/captured_malware"
			_ = os.MkdirAll(captureDir, 0755)
			timestamp := time.Now().Format("20060102_150405")
			safeIP := strings.ReplaceAll(srcIP, ":", "_")
			filePath := fmt.Sprintf("%s/%s_%s_%s", captureDir, timestamp, safeIP, argument)
			_ = os.WriteFile(filePath, fileBytes, 0644)

			malwareType, scanDetails := services.AnalyzePayload(argument, fileBytes)

			hasher := sha256.New()
			hasher.Write(fileBytes)
			sha256Sum := hex.EncodeToString(hasher.Sum(nil))

			f.baseService.LogEvent("captured_payload", map[string]interface{}{
				"src_ip":       srcIP,
				"src_port":     srcPort,
				"profile":      f.profile.Name,
				"username":     username,
				"filename":     argument,
				"file_size":    len(fileBytes),
				"sha256":       sha256Sum,
				"malware_type": malwareType,
				"details":      scanDetails,
				"summary":      fmt.Sprintf("Malware payload '%s' uploaded via FTP from %s. Type: %s", argument, srcIP, malwareType),
			})
		} else {
			if _, err := conn.Write([]byte(ftpProf.FallbackResponse)); err != nil {
				return err
			}
		}
	}

	return nil
}

func init() {
	services.Registry["ftp"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewFTPHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *FTPHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
