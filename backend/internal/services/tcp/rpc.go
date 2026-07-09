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

type RPCHoneypot struct {
	baseService *services.BaseTCPService
}

func NewRPCHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
) *RPCHoneypot {
	r := &RPCHoneypot{}
	r.baseService = services.NewBaseTCPService(name, host, port, el, ds, r.handleClient)
	return r
}

func (r *RPCHoneypot) Name() string {
	return r.baseService.Name()
}

func (r *RPCHoneypot) Port() int {
	return r.baseService.Port()
}

func (r *RPCHoneypot) IsRunning() bool {
	return r.baseService.IsRunning()
}

func (r *RPCHoneypot) Start(ctx context.Context) error {
	return r.baseService.Start(ctx)
}

func (r *RPCHoneypot) Stop() error {
	return r.baseService.Stop()
}

func (r *RPCHoneypot) Proto() string {
	return r.baseService.Proto()
}

func (r *RPCHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	r.baseService.LogEvent("rpc_connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			break
		}

		data := buf[:n]
		var ptype byte = 0
		if len(data) > 2 {
			ptype = data[2]
		}
		callID := []byte{1, 0, 0, 0}
		if len(data) >= 16 {
			callID = data[12:16]
		}

		r.baseService.LogEvent("rpc_request", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"ptype":    ptype,
			"data_hex": fmt.Sprintf("%x", data[:min(len(data), 32)]),
			"summary":  fmt.Sprintf("Received DCERPC request with PTYPE %d", ptype),
		})

		response := []byte{
			0x05, 0x00, 0x0d, 0x03, // Version 5.0, Bind_Nak (0x0D), Flags 3
			0x10, 0x00, 0x00, 0x00, // Little Endian Data Rep
			0x18, 0x00, 0x00, 0x00, // Frag Len 24, Auth Len 0
		}
		response = append(response, callID...)
		response = append(response, []byte{
			0x04, 0x00, // Reject Reason: Local Limit Exceeded
			0x01,       // Num supported versions: 1
			0x05, 0x00, // Supported version: 5.0
			0x00, 0x00, 0x00, // Padding
		}...)

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(response); err != nil {
			return err
		}

		r.baseService.LogEvent("rpc_response", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"summary":  "Sent DCERPC Bind_Nak response",
		})

		time.Sleep(500 * time.Millisecond)
		break
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	services.Registry["rpc"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewRPCHoneypot(name, host, port, el, ds)
	}
}

func (s *RPCHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
