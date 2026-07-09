package tcp

import (
	"honeypot-orchestrator/backend/internal/profiles"
	"context"
	"fmt"
	"net"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
)

type LDAPSHoneypot struct {
	baseService *services.BaseTCPService
}

func NewLDAPSHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
) *LDAPSHoneypot {
	l := &LDAPSHoneypot{}
	l.baseService = services.NewBaseTCPService(name, host, port, el, ds, l.handleClient)
	return l
}

func (l *LDAPSHoneypot) Name() string {
	return l.baseService.Name()
}

func (l *LDAPSHoneypot) Port() int {
	return l.baseService.Port()
}

func (l *LDAPSHoneypot) Proto() string {
	return l.baseService.Proto()
}

func (l *LDAPSHoneypot) IsRunning() bool {
	return l.baseService.IsRunning()
}

func (l *LDAPSHoneypot) Start(ctx context.Context) error {
	return l.baseService.Start(ctx)
}

func (l *LDAPSHoneypot) Stop() error {
	return l.baseService.Stop()
}

func (l *LDAPSHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	l.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	clientHello := make([]byte, 4096)
	n, err := conn.Read(clientHello)
	if err != nil || n == 0 {
		return err
	}

	tlsRecordType := fmt.Sprintf("0x%02x", clientHello[0])
	tlsVersion := tlsVersionName(clientHello[:n])

	l.baseService.LogEvent("ldaps_tls_client_hello", map[string]interface{}{
		"src_ip":          srcIP,
		"src_port":        srcPort,
		"tls_record_type": tlsRecordType,
		"tls_version":     tlsVersion,
		"summary":         "LDAPS TLS client hello captured.",
	})

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
	return err
}

func tlsVersionName(packet []byte) string {
	if len(packet) < 3 {
		return "unknown"
	}
	v1, v2 := packet[1], packet[2]
	switch {
	case v1 == 0x03 && v2 == 0x01:
		return "TLS 1.0"
	case v1 == 0x03 && v2 == 0x02:
		return "TLS 1.1"
	case v1 == 0x03 && v2 == 0x03:
		return "TLS 1.2"
	case v1 == 0x03 && v2 == 0x04:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("%02x%02x", v1, v2)
	}
}

func init() {
	services.Registry["ldaps"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewLDAPSHoneypot(name, host, port, el, ds)
	}
}

func (s *LDAPSHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
