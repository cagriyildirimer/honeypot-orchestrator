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

type TelnetHoneypot struct {
	baseService *services.BaseTCPService
	profile     *profiles.HoneypotProfile
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
		profile: initialProfile,
	}

	t.baseService = services.NewBaseTCPService(name, host, port, el, ds, t.handleClient)
	return t
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

	t.baseService.LogEvent("login_attempt", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
		"profile":  t.profile.Name,
		"username": username,
		"password": password,
		"summary":  fmt.Sprintf("Telnet login attempt for %s", username),
	})

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(telnetProf.LoginFailedResponse)); err != nil {
		return err
	}

	return nil
}

func init() {
	services.Registry["telnet"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewTelnetHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *TelnetHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
