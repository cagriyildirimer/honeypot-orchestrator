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

type NBTNSSHoneypot struct {
	baseService *services.BaseUDPService
	host        string
}

func NewNBTNSSHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
) *NBTNSSHoneypot {
	n := &NBTNSSHoneypot{host: host}
	n.baseService = services.NewBaseUDPService(name, host, port, el, ds, n.handleDatagram)
	return n
}

func (n *NBTNSSHoneypot) Name() string {
	return n.baseService.Name()
}

func (n *NBTNSSHoneypot) Port() int {
	return n.baseService.Port()
}

func (n *NBTNSSHoneypot) IsRunning() bool {
	return n.baseService.IsRunning()
}

func (n *NBTNSSHoneypot) Start(ctx context.Context) error {
	return n.baseService.Start(ctx)
}

func (n *NBTNSSHoneypot) Stop() error {
	return n.baseService.Stop()
}

func (n *NBTNSSHoneypot) Proto() string {
	return n.baseService.Proto()
}

func (n *NBTNSSHoneypot) handleDatagram(ctx context.Context, data []byte, srcAddr *net.UDPAddr) ([]byte, error) {
	srcIP := srcAddr.IP.String()
	srcPort := srcAddr.Port

	if len(data) < 48 {
		return nil, nil
	}

	queryType := data[46:48]
	queryName := parseNetbiosNsName(data)
	if queryName == "" {
		return nil, nil
	}

	if queryType[0] == 0x00 && queryType[1] == 0x21 {
		n.baseService.LogEvent("netbios_ns_node_status_query", map[string]interface{}{
			"src_ip":     srcIP,
			"src_port":   srcPort,
			"query_name": queryName,
			"summary":    fmt.Sprintf("NetBIOS NS Node Status query (NBSTAT) from %s", srcIP),
		})
	} else {
		n.baseService.LogEvent("netbios_ns_query", map[string]interface{}{
			"src_ip":     srcIP,
			"src_port":   srcPort,
			"query_name": queryName,
			"summary":    fmt.Sprintf("NetBIOS NS query for %s", queryName),
		})
	}

	respIP := "127.0.0.1"
	if n.host != "0.0.0.0" && n.host != "::" && n.host != "" {
		respIP = n.host
	}

	var response []byte
	if queryType[0] == 0x00 && queryType[1] == 0x21 {
		response = buildNetbiosNsNodeStatusResponse(data)
	} else {
		response = buildNetbiosNsResponse(data, respIP)
	}

	return response, nil
}

func decodeNetbiosNsName(encoded []byte) string {
	if len(encoded) < 32 {
		return ""
	}
	var decoded []byte
	for i := 0; i < 32; i += 2 {
		high := int(encoded[i]) - 0x41
		low := int(encoded[i+1]) - 0x41
		if high < 0 || low < 0 {
			return "<unknown>"
		}
		decoded = append(decoded, byte((high<<4)|low))
	}
	s := string(decoded)
	return strings.TrimRight(s, " ")
}

func parseNetbiosNsName(data []byte) string {
	if len(data) < 12+33 {
		return ""
	}
	nameLen := data[12]
	if nameLen != 32 {
		return ""
	}
	return decodeNetbiosNsName(data[13 : 13+32])
}

func buildNetbiosNsResponse(queryData []byte, ipAddressStr string) []byte {
	if len(queryData) < 12 {
		return nil
	}
	txID := queryData[0:2]
	nameSec := queryData[12 : 12+34]

	ip := net.ParseIP(ipAddressStr)
	ipBytes := ip.To4()
	if ipBytes == nil {
		ipBytes = []byte{127, 0, 0, 1}
	}

	header := []byte{
		txID[0], txID[1],
		0x85, 0x00,
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
	}

	answer := make([]byte, len(nameSec)+12)
	copy(answer[0:len(nameSec)], nameSec)
	offset := len(nameSec)
	answer[offset] = 0x00
	answer[offset+1] = 0x20
	answer[offset+2] = 0x00
	answer[offset+3] = 0x01
	answer[offset+4] = 0x00
	answer[offset+5] = 0x04
	answer[offset+6] = 0x93
	answer[offset+7] = 0xe0
	answer[offset+8] = 0x00
	answer[offset+9] = 0x06
	answer[offset+10] = 0x00
	answer[offset+11] = 0x00
	answer = append(answer, ipBytes...)

	return append(header, answer...)
}

func buildNetbiosNsNodeStatusResponse(queryData []byte) []byte {
	if len(queryData) < 12 {
		return nil
	}
	txID := queryData[0:2]
	nameSec := queryData[12 : 12+34]

	header := []byte{
		txID[0], txID[1],
		0x84, 0x00,
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
	}

	n1 := padNetbiosName("WIN-SRV2019", 0x00, 0x04, 0x00)
	n2 := padNetbiosName("CORP", 0x00, 0x84, 0x00)
	n3 := padNetbiosName("WIN-SRV2019", 0x20, 0x04, 0x00)
	namesPayload := append(n1, n2...)
	namesPayload = append(namesPayload, n3...)

	macAddr := []byte{0x00, 0x15, 0x5d, 0xa1, 0xb2, 0xc3}
	statsPayload := append(macAddr, make([]byte, 40)...)

	dataPayload := append([]byte{0x03}, namesPayload...)
	dataPayload = append(dataPayload, statsPayload...)
	dataLen := len(dataPayload)

	answer := make([]byte, len(nameSec)+10)
	copy(answer[0:len(nameSec)], nameSec)
	offset := len(nameSec)
	answer[offset] = 0x00
	answer[offset+1] = 0x21
	answer[offset+2] = 0x00
	answer[offset+3] = 0x01
	answer[offset+4] = 0x00
	answer[offset+5] = 0x00
	answer[offset+6] = 0x00
	answer[offset+7] = 0x00
	answer[offset+8] = byte(dataLen >> 8)
	answer[offset+9] = byte(dataLen & 0xFF)
	answer = append(answer, dataPayload...)

	return append(header, answer...)
}

func padNetbiosName(name string, suffix byte, flagsHigh, flagsLow byte) []byte {
	buf := make([]byte, 18)
	copy(buf, []byte(strings.ToUpper(name)))
	for i := len(name); i < 15; i++ {
		buf[i] = 0x20
	}
	buf[15] = suffix
	buf[16] = flagsHigh
	buf[17] = flagsLow
	return buf
}

func init() {
	services.Registry["nbtnns"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewNBTNSSHoneypot(name, host, port, el, ds)
	}
}

func (s *NBTNSSHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
