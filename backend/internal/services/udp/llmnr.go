package udp

import (
	"honeypot-orchestrator/backend/internal/profiles"
	"context"
	"fmt"
	"net"
	"strings"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
)

type LLMNRHoneypot struct {
	baseService *services.BaseUDPService
	host        string
}

func NewLLMNRHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
) *LLMNRHoneypot {
	l := &LLMNRHoneypot{host: host}
	l.baseService = services.NewBaseUDPService(name, host, port, el, ds, l.handleDatagram)
	return l
}

func (l *LLMNRHoneypot) Name() string {
	return l.baseService.Name()
}

func (l *LLMNRHoneypot) Port() int {
	return l.baseService.Port()
}

func (l *LLMNRHoneypot) Proto() string {
	return l.baseService.Proto()
}

func (l *LLMNRHoneypot) IsRunning() bool {
	return l.baseService.IsRunning()
}

func (l *LLMNRHoneypot) Start(ctx context.Context) error {
	return l.baseService.Start(ctx)
}

func (l *LLMNRHoneypot) Stop() error {
	return l.baseService.Stop()
}

func (l *LLMNRHoneypot) handleDatagram(ctx context.Context, data []byte, srcAddr *net.UDPAddr) ([]byte, error) {
	srcIP := srcAddr.IP.String()
	srcPort := srcAddr.Port

	queryName := parseLLMNRName(data)
	if queryName == "" {
		return nil, nil
	}

	l.baseService.LogEvent("llmnr_query", map[string]interface{}{
		"src_ip":     srcIP,
		"src_port":   srcPort,
		"query_name": queryName,
		"summary":    fmt.Sprintf("LLMNR query for %s", queryName),
	})

	respIP := "127.0.0.1"
	if l.host != "0.0.0.0" && l.host != "::" && l.host != "" {
		respIP = l.host
	}

	response := buildLLMNRResponse(data, respIP)
	return response, nil
}

func parseLLMNRName(data []byte) string {
	if len(data) < 12 {
		return ""
	}
	offset := 12
	var labels []string
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			break
		}
		offset++
		if offset+length > len(data) {
			return ""
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, ".")
}

func buildLLMNRResponse(queryData []byte, ipAddrStr string) []byte {
	if len(queryData) < 12 {
		return nil
	}
	txID := queryData[0:2]
	offset := 12
	for offset < len(queryData) {
		length := int(queryData[offset])
		if length == 0 {
			offset++
			break
		}
		offset += length + 1
	}
	questionEnd := offset + 4
	if questionEnd > len(queryData) {
		return nil
	}
	questionSec := queryData[12:questionEnd]

	ip := net.ParseIP(ipAddrStr)
	ipBytes := ip.To4()
	if ipBytes == nil {
		ipBytes = []byte{127, 0, 0, 1}
	}

	header := []byte{
		txID[0], txID[1],
		0x80, 0x00, // flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x01, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}

	answer := []byte{
		0xc0, 0x0c, // name pointer to question name
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x1e, // TTL (30)
		0x00, 0x04, // RDLENGTH (4)
	}
	answer = append(answer, ipBytes...)

	resp := append(header, questionSec...)
	resp = append(resp, answer...)
	return resp
}

func init() {
	services.Registry["llmnr"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewLLMNRHoneypot(name, host, port, el, ds)
	}
}

func (s *LLMNRHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
