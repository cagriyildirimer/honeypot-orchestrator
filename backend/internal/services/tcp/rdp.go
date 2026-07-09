package tcp

import (
	"honeypot-orchestrator/backend/internal/profiles"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
)

type RDPHoneypot struct {
	baseService *services.BaseTCPService
}

func NewRDPHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
) *RDPHoneypot {
	r := &RDPHoneypot{}
	r.baseService = services.NewBaseTCPService(name, host, port, el, ds, r.handleClient)
	return r
}

func (r *RDPHoneypot) Name() string {
	return r.baseService.Name()
}

func (r *RDPHoneypot) Port() int {
	return r.baseService.Port()
}

func (r *RDPHoneypot) Proto() string {
	return r.baseService.Proto()
}

func (r *RDPHoneypot) IsRunning() bool {
	return r.baseService.IsRunning()
}

func (r *RDPHoneypot) Start(ctx context.Context) error {
	return r.baseService.Start(ctx)
}

func (r *RDPHoneypot) Stop() error {
	return r.baseService.Stop()
}

func (r *RDPHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	r.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	packet, err := readTpktFrame(conn)
	if err != nil {
		return err
	}

	cookie := extractRdpCookie(packet)

	r.baseService.LogEvent("rdp_connection_request", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
		"cookie":   cookie,
		"summary":  "RDP X.224 connection request captured.",
	})

	negotiationFailure := []byte{
		0x03, 0x00, 0x00, 0x13,
		0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(negotiationFailure)
	return err
}

func readTpktFrame(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	totalLength := int(header[2])<<8 | int(header[3])
	if totalLength < 4 {
		return nil, fmt.Errorf("invalid TPKT length: %d", totalLength)
	}

	payload := make([]byte, totalLength-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	return append(header, payload...), nil
}

func extractRdpCookie(packet []byte) string {
	marker := []byte("Cookie: mstshash=")
	start := bytes.Index(packet, marker)
	if start == -1 {
		return ""
	}

	end := bytes.Index(packet[start:], []byte("\r\n"))
	if end == -1 {
		return string(packet[start+len(marker):])
	}

	return string(packet[start+len(marker) : start+end])
}

func init() {
	services.Registry["rdp"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewRDPHoneypot(name, host, port, el, ds)
	}
}

func (s *RDPHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
