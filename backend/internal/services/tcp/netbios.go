package tcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
)

type NetBIOSHoneypot struct {
	baseService *services.BaseTCPService
	profile     *profiles.HoneypotProfile
}

func NewNetBIOSHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	initialProfile *profiles.HoneypotProfile,
) *NetBIOSHoneypot {
	n := &NetBIOSHoneypot{profile: initialProfile}
	n.baseService = services.NewBaseTCPService(name, host, port, el, ds, n.handleClient)
	return n
}

func (n *NetBIOSHoneypot) Name() string {
	return n.baseService.Name()
}

func (n *NetBIOSHoneypot) Port() int {
	return n.baseService.Port()
}

func (n *NetBIOSHoneypot) IsRunning() bool {
	return n.baseService.IsRunning()
}

func (n *NetBIOSHoneypot) Start(ctx context.Context) error {
	return n.baseService.Start(ctx)
}

func (n *NetBIOSHoneypot) Stop() error {
	return n.baseService.Stop()
}

func (n *NetBIOSHoneypot) Proto() string {
	return n.baseService.Proto()
}

func (n *NetBIOSHoneypot) SetProfile(prof *profiles.HoneypotProfile) {
	n.profile = prof
}

func (n *NetBIOSHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	n.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		return err
	}

	packetType := header[0]
	payloadLength := int(header[1])<<16 | int(header[2])<<8 | int(header[3])

	// Cap NetBIOS payload length at 65536 bytes (64KB) to prevent resource exhaustion/DoS.
	if payloadLength > 65536 {
		return fmt.Errorf("NetBIOS payload length %d exceeds safety limit", payloadLength)
	}

	payload := make([]byte, payloadLength)
	if payloadLength > 0 {
		if _, err := conn.Read(payload); err != nil {
			return err
		}
	}

	calledName, callingName := parseSessionRequestNames(payload)

	n.baseService.LogEvent("netbios_session_request", map[string]interface{}{
		"src_ip":       srcIP,
		"src_port":     srcPort,
		"packet_type":  fmt.Sprintf("0x%02x", packetType),
		"called_name":  calledName,
		"calling_name": callingName,
		"summary":      fmt.Sprintf("NetBIOS session request for %s", calledName),
	})

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	if packetType == 0x81 {
		if _, err := conn.Write([]byte{0x82, 0x00, 0x00, 0x00}); err != nil {
			return err
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		nextFrame := make([]byte, 1024)
		if nBytes, err := conn.Read(nextFrame); err == nil && nBytes > 0 {
			n.baseService.LogEvent("netbios_followup", map[string]interface{}{
				"src_ip":    srcIP,
				"src_port":  srcPort,
				"signature": fmt.Sprintf("%x", nextFrame[:min(nBytes, 16)]),
				"summary":   "NetBIOS follow-up payload captured.",
			})
		}
	} else if packetType == 0x00 && len(payload) >= 4 && string(payload[:4]) == "\xffSMB" {
		n.baseService.LogEvent("netbios_smb_negotiate", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"summary":  "NetBIOS received direct SMB1 negotiate request.",
		})

		fullPacket := append(header, payload...)
		smb1Request, err := parseSMB1Header(fullPacket)
		if err == nil {
			challenge, _ := hexToBytes(n.profile.SMB.NtlmChallenge)
			if len(challenge) == 0 {
				challenge = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
			}
			smbResp := buildSMB1NegotiateResponse(
				smb1Request.multiplexID,
				smb1Request.processID,
				smb1Request.userID,
				smb1Request.treeID,
				challenge,
				n.profile.SMB.Domain,
			)

			respLen := len(smbResp)
			nbssHeader := []byte{0x00, byte(respLen >> 16 & 0xFF), byte(respLen >> 8 & 0xFF), byte(respLen & 0xFF)}
			_, _ = conn.Write(append(nbssHeader, smbResp...))
		}
	} else {
		_, _ = conn.Write([]byte{0x83, 0x00, 0x00, 0x01, 0x80})
	}

	return nil
}

func parseSessionRequestNames(payload []byte) (string, string) {
	if len(payload) < 68 {
		return "<unknown>", "<unknown>"
	}
	called := decodeNetbiosNsName(payload[1:33])
	calling := decodeNetbiosNsName(payload[35:67])
	return called, calling
}

type smb1Header struct {
	command     byte
	status      uint32
	flags       byte
	flags2      uint16
	treeID      uint16
	processID   uint32
	userID      uint16
	multiplexID uint16
}

func parseSMB1Header(packet []byte) (smb1Header, error) {
	if len(packet) < 32 || string(packet[:4]) != "\xffSMB" {
		return smb1Header{}, fmt.Errorf("invalid SMB1 header")
	}
	return smb1Header{
		command:     packet[4],
		status:      binary.LittleEndian.Uint32(packet[5:9]),
		flags:       packet[9],
		flags2:      binary.LittleEndian.Uint16(packet[10:12]),
		treeID:      binary.LittleEndian.Uint16(packet[24:26]),
		processID:   uint32(binary.LittleEndian.Uint16(packet[12:14]))<<16 | uint32(binary.LittleEndian.Uint16(packet[26:28])),
		userID:      binary.LittleEndian.Uint16(packet[28:30]),
		multiplexID: binary.LittleEndian.Uint16(packet[30:32]),
	}, nil
}

func buildSMB1Header(command byte, status uint32, flags byte, flags2 uint16, treeID uint16, processID uint32, userID uint16, multiplexID uint16) []byte {
	buf := make([]byte, 32)
	copy(buf[0:4], []byte("\xffSMB"))
	buf[4] = command
	binary.LittleEndian.PutUint32(buf[5:9], status)
	buf[9] = flags
	binary.LittleEndian.PutUint16(buf[10:12], flags2)
	binary.LittleEndian.PutUint16(buf[12:14], uint16((processID>>16)&0xFFFF))
	binary.LittleEndian.PutUint16(buf[24:26], treeID)
	binary.LittleEndian.PutUint16(buf[26:28], uint16(processID&0xFFFF))
	binary.LittleEndian.PutUint16(buf[28:30], userID)
	binary.LittleEndian.PutUint16(buf[30:32], multiplexID)
	return buf
}

func buildSMB1NegotiateResponse(multiplexID uint16, processID uint32, userID, treeID uint16, challenge []byte, domain string) []byte {
	securityMode := byte(0x03)
	capabilities := uint32(0x0001E3FD)
	now := filetime()

	domainBytes := []byte(domain)

	body := make([]byte, 37)
	body[0] = 0x11
	binary.LittleEndian.PutUint16(body[1:3], 0)
	body[3] = securityMode
	binary.LittleEndian.PutUint16(body[4:6], 50)
	binary.LittleEndian.PutUint16(body[6:8], 1)
	binary.LittleEndian.PutUint32(body[8:12], 16644)
	binary.LittleEndian.PutUint32(body[12:16], 65536)
	binary.LittleEndian.PutUint32(body[16:20], 0)
	binary.LittleEndian.PutUint32(body[20:24], capabilities)
	binary.LittleEndian.PutUint64(body[24:32], now)
	binary.LittleEndian.PutUint16(body[32:34], 180)
	body[34] = byte(len(challenge))
	binary.LittleEndian.PutUint16(body[35:37], uint16(len(challenge)+len(domainBytes)+1))

	body = append(body, challenge...)
	body = append(body, domainBytes...)
	body = append(body, 0x00)

	header := buildSMB1Header(0x72, 0, 0x88, 0x4001, treeID, processID, userID, multiplexID)
	return append(header, body...)
}

func hexToBytes(h string) ([]byte, error) {
	var res []byte
	h = strings.TrimSpace(h)
	if len(h)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}
	for i := 0; i < len(h); i += 2 {
		var b byte
		fmt.Sscanf(h[i:i+2], "%02x", &b)
		res = append(res, b)
	}
	return res, nil
}

func filetime() uint64 {
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	return uint64(time.Now().UTC().Sub(epoch) / (100 * time.Nanosecond))
}

func init() {
	services.Registry["netbios"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewNetBIOSHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *NetBIOSHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
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
