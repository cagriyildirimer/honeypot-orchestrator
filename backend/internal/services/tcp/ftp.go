package tcp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
)

type FTPHoneypot struct {
	baseService *services.BaseTCPService
	profile     *profiles.HoneypotProfile
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
		profile: initialProfile,
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

	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
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
			f.baseService.LogEvent("login_attempt", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"profile":  f.profile.Name,
				"username": username,
				"password": argument,
				"summary":  fmt.Sprintf("FTP login attempt for %s", username),
			})

			if _, err := conn.Write([]byte(ftpProf.LoginFailedResponse)); err != nil {
				return err
			}
		} else if command == "QUIT" {
			_, _ = conn.Write([]byte(ftpProf.QuitResponse))
			break
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
