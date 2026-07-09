package udp

import (
	"context"
	"fmt"
	"net"
	"strings"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
	"honeypot-orchestrator/backend/internal/services"
)

type DNSHoneypot struct {
	baseService *services.BaseUDPService
}

func NewDNSHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
) *DNSHoneypot {
	d := &DNSHoneypot{}
	d.baseService = services.NewBaseUDPService(name, host, port, el, ds, d.handleDatagram)
	return d
}

func (d *DNSHoneypot) Name() string {
	return d.baseService.Name()
}

func (d *DNSHoneypot) Port() int {
	return d.baseService.Port()
}

func (d *DNSHoneypot) Proto() string {
	return d.baseService.Proto()
}

func (d *DNSHoneypot) IsRunning() bool {
	return d.baseService.IsRunning()
}

func (d *DNSHoneypot) Start(ctx context.Context) error {
	return d.baseService.Start(ctx)
}

func (d *DNSHoneypot) Stop() error {
	return d.baseService.Stop()
}

func (d *DNSHoneypot) handleDatagram(ctx context.Context, data []byte, srcAddr *net.UDPAddr) ([]byte, error) {
	srcIP := srcAddr.IP.String()
	srcPort := srcAddr.Port

	query := parseDNSQuery(data)

	d.baseService.LogEvent("dns_query", map[string]interface{}{
		"src_ip":      srcIP,
		"src_port":    srcPort,
		"query_name":  query.Name,
		"query_type":  query.TypeName,
		"query_class": query.ClassName,
		"summary":     fmt.Sprintf("DNS %s %s", query.TypeName, query.Name),
	})

	response := buildDNSResponse(data, 3, true, true)
	return response, nil
}

type dnsQuery struct {
	Name      string
	TypeName  string
	ClassName string
}

func parseDNSQuery(payload []byte) dnsQuery {
	if len(payload) < 12 {
		return dnsQuery{Name: "<malformed>", TypeName: "UNKNOWN", ClassName: "UNKNOWN"}
	}
	index := 12
	var labels []string
	for index < len(payload) {
		length := int(payload[index])
		index++
		if length == 0 {
			break
		}
		if index+length > len(payload) {
			return dnsQuery{Name: "<malformed>", TypeName: "UNKNOWN", ClassName: "UNKNOWN"}
		}
		labels = append(labels, string(payload[index:index+length]))
		index += length
	}

	qtype := 0
	if index+2 <= len(payload) {
		qtype = int(payload[index])<<8 | int(payload[index+1])
	}
	qclass := 0
	if index+4 <= len(payload) {
		qclass = int(payload[index+2])<<8 | int(payload[index+3])
	}

	name := "."
	if len(labels) > 0 {
		name = strings.Join(labels, ".")
	}

	return dnsQuery{
		Name:      name,
		TypeName:  dnsTypeName(qtype),
		ClassName: dnsClassName(qclass),
	}
}

func buildDNSResponse(payload []byte, rcode int, authoritative, recursionAvailable bool) []byte {
	txID := []byte{0, 0}
	if len(payload) >= 2 {
		txID = payload[:2]
	}
	qCount := []byte{0, 0}
	if len(payload) >= 6 {
		qCount = payload[4:6]
	}

	flags := 0x8000 | 0x0100 | (rcode & 0x0F)
	if authoritative {
		flags |= 0x0400
	}
	if recursionAvailable {
		flags |= 0x0080
	}

	var question []byte
	if len(payload) >= 12 {
		index := 12
		for index < len(payload) {
			length := int(payload[index])
			index++
			if length == 0 {
				break
			}
			index += length
		}
		index += 4
		if index <= len(payload) {
			question = payload[12:index]
		}
	}

	resp := make([]byte, 12+len(question))
	copy(resp[0:2], txID)
	resp[2] = byte(flags >> 8)
	resp[3] = byte(flags & 0xFF)
	copy(resp[4:6], qCount)
	copy(resp[12:], question)

	return resp
}

func dnsTypeName(qtype int) string {
	types := map[int]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		12:  "PTR",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		33:  "SRV",
		255: "ANY",
	}
	if name, ok := types[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

func dnsClassName(qclass int) string {
	classes := map[int]string{
		1:   "IN",
		3:   "CH",
		4:   "HS",
		255: "ANY",
	}
	if name, ok := classes[qclass]; ok {
		return name
	}
	return fmt.Sprintf("CLASS%d", qclass)
}

func init() {
	services.Registry["dns"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewDNSHoneypot(name, host, port, el, ds)
	}
}

func (s *DNSHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
