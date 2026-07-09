package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"honeypot-orchestrator/backend/internal/defense"
	"honeypot-orchestrator/backend/internal/services"
	"honeypot-orchestrator/backend/internal/logger"
	"honeypot-orchestrator/backend/internal/profiles"
)

type SMBHoneypot struct {
	baseService *services.BaseTCPService
	profile     *profiles.HoneypotProfile
}

func NewSMBHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	initialProfile *profiles.HoneypotProfile,
) *SMBHoneypot {
	s := &SMBHoneypot{profile: initialProfile}
	s.baseService = services.NewBaseTCPService(name, host, port, el, ds, s.handleClient)
	return s
}

func (s *SMBHoneypot) Name() string {
	return s.baseService.Name()
}

func (s *SMBHoneypot) Port() int {
	return s.baseService.Port()
}

func (s *SMBHoneypot) IsRunning() bool {
	return s.baseService.IsRunning()
}

func (s *SMBHoneypot) Start(ctx context.Context) error {
	return s.baseService.Start(ctx)
}

func (s *SMBHoneypot) Stop() error {
	return s.baseService.Stop()
}

func (s *SMBHoneypot) Proto() string {
	return s.baseService.Proto()
}

func (s *SMBHoneypot) SetProfile(prof *profiles.HoneypotProfile) {
	s.profile = prof
}

func (s *SMBHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	s.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	sessionID := uint64(0x1000)

	firstPacket, err := readNbssFrame(conn)
	if err != nil {
		return err
	}

	if bytes.HasPrefix(firstPacket, []byte("\xffSMB")) {
		smb1Request, err := parseSMB1Header(firstPacket)
		if err == nil {
			s.baseService.LogEvent("smb1_negotiate", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"summary":  "SMB1 negotiate request captured.",
			})

			challenge, _ := hexToBytes(s.profile.SMB.NtlmChallenge)
			if len(challenge) == 0 {
				challenge = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
			}

			smbResp := buildSMB1NegotiateResponse(
				smb1Request.multiplexID,
				smb1Request.processID,
				smb1Request.userID,
				smb1Request.treeID,
				challenge,
				s.profile.SMB.Domain,
			)

			if err := writeNbssFrame(conn, smbResp); err != nil {
				return err
			}

			sessionSetupPacket, err := readNbssFrame(conn)
			if err != nil {
				return err
			}

			if bytes.HasPrefix(sessionSetupPacket, []byte("\xffSMB")) {
				sessionSetup, err := parseSMB1Header(sessionSetupPacket)
				if err == nil {
					identity := parseSmb1SessionSetupIdentity(sessionSetupPacket)
					s.baseService.LogEvent("login_attempt", map[string]interface{}{
						"src_ip":      srcIP,
						"src_port":    srcPort,
						"username":    identity.username,
						"domain":      identity.domain,
						"workstation": identity.workstation,
						"summary":     fmt.Sprintf("SMB1 login attempt for %s\\%s", identity.domain, identity.username),
					})

					setupResp := buildSmb1SessionSetupResponse(
						sessionSetup.multiplexID,
						sessionSetup.processID,
						sessionSetup.treeID,
						0x0800,
						s.profile.SMB.NativeOS,
						s.profile.SMB.NativeLanman,
						s.profile.SMB.Domain,
					)
					_ = writeNbssFrame(conn, setupResp)
				}
			}
		}
		return nil
	}

	if !bytes.HasPrefix(firstPacket, []byte("\xfeSMB")) {
		s.baseService.LogEvent("smb_unknown_packet", map[string]interface{}{
			"src_ip":    srcIP,
			"src_port":  srcPort,
			"signature": fmt.Sprintf("%x", firstPacket[:min(len(firstPacket), 16)]),
			"summary":   "Unknown SMB payload captured.",
		})
		return nil
	}

	negotiateRequest, err := parseSmb2Header(firstPacket)
	if err != nil {
		return err
	}

	clientDialects := extractSmb2Dialects(firstPacket)
	signingPolicies := map[int]string{0: "disabled", 1: "enabled", 2: "required"}
	signingPolicyStr := signingPolicies[s.profile.SMB.SigningPolicy]
	if signingPolicyStr == "" {
		signingPolicyStr = "enabled"
	}

	s.baseService.LogEvent("smb_negotiate", map[string]interface{}{
		"src_ip":             srcIP,
		"src_port":           srcPort,
		"dialects":           strings.Join(clientDialects, ", "),
		"dialect_negotiated": "SMB 3.1.1",
		"server_guid":        s.profile.SMB.ServerGUID,
		"signing_policy":     signingPolicyStr,
		"native_os":          s.profile.SMB.NativeOS,
		"summary":            "SMB2 negotiate request captured.",
	})

	serverGuidBytes, _ := hexToBytes(s.profile.SMB.ServerGUID)
	if len(serverGuidBytes) == 0 {
		serverGuidBytes = make([]byte, 16)
	}

	negotiateResp := buildSmb2NegotiateResponse(
		negotiateRequest.messageID,
		negotiateRequest.credits,
		serverGuidBytes,
		s.profile.SMB.SigningPolicy,
	)

	if err := writeNbssFrame(conn, negotiateResp); err != nil {
		return err
	}

	sessionSetupPacket, err := readNbssFrame(conn)
	if err != nil {
		return err
	}

	sessionSetupRequest, err := parseSmb2Header(sessionSetupPacket)
	if err != nil {
		return err
	}

	ntlmNegotiate := extractSessionSetupSecurityBlob(sessionSetupPacket)
	s.baseService.LogEvent("smb_session_setup", map[string]interface{}{
		"src_ip":            srcIP,
		"src_port":          srcPort,
		"ntlm_message_type": ntlmMessageType(ntlmNegotiate),
		"ntlm_challenge":    s.profile.SMB.NtlmChallenge,
		"native_os":         s.profile.SMB.NativeOS,
		"signing_policy":    signingPolicyStr,
		"summary":           "SMB session setup negotiate captured.",
	})

	challenge, _ := hexToBytes(s.profile.SMB.NtlmChallenge)
	if len(challenge) == 0 {
		challenge = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	}

	challengeResp := buildSmb2SessionSetupChallenge(
		sessionSetupRequest.messageID,
		sessionSetupRequest.credits,
		sessionID,
		challenge,
		s.profile.SMB.Domain,
		s.profile.SMB.Hostname,
		s.profile.SMB.DNSDomain,
	)

	if err := writeNbssFrame(conn, challengeResp); err != nil {
		return err
	}

	authPacket, err := readNbssFrame(conn)
	if err != nil {
		return err
	}

	authRequest, err := parseSmb2Header(authPacket)
	if err != nil {
		return err
	}

	ntlmAuth := extractSessionSetupSecurityBlob(authPacket)
	domain, username, workstation := parseNtlmAuthenticate(ntlmAuth)

	s.baseService.LogEvent("login_success", map[string]interface{}{
		"src_ip":      srcIP,
		"src_port":    srcPort,
		"username":    username,
		"domain":      domain,
		"workstation": workstation,
		"summary":     fmt.Sprintf("SMB login success for %s\\%s", domain, username),
	})

	successResp := buildSmb2SessionSetupSuccess(
		authRequest.messageID,
		authRequest.credits,
		sessionID,
	)

	if err := writeNbssFrame(conn, successResp); err != nil {
		return err
	}

	// Session commands loop
	for {
		packet, err := readNbssFrame(conn)
		if err != nil {
			break
		}

		if !bytes.HasPrefix(packet, []byte("\xfeSMB")) {
			break
		}

		header, err := parseSmb2Header(packet)
		if err != nil {
			break
		}

		command := header.command
		msgID := header.messageID
		creditReq := header.credits
		treeID := header.treeID

		if command == 0x0003 { // TREE_CONNECT
			sharePath := parseSmb2TreeConnectPath(packet)
			s.baseService.LogEvent("smb_tree_connect", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"path":     sharePath,
				"summary":  fmt.Sprintf("SMB tree connect to %s", sharePath),
			})

			resp := buildSmb2TreeConnectResponse(msgID, creditReq, sessionID, 0x1)
			_ = writeNbssFrame(conn, resp)
		} else if command == 0x0004 { // TREE_DISCONNECT
			resp := buildSmb2GenericSuccess(0x0004, msgID, creditReq, sessionID, treeID)
			_ = writeNbssFrame(conn, resp)
		} else if command == 0x0005 { // CREATE
			filename := parseSmb2CreateFilename(packet)
			s.baseService.LogEvent("smb_create", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"filename": filename,
				"summary":  fmt.Sprintf("SMB open/create request for %s", filename),
			})

			resp := buildSmb2CreateResponse(msgID, creditReq, sessionID, treeID, 0x55aa)
			_ = writeNbssFrame(conn, resp)
		} else if command == 0x0006 { // CLOSE
			resp := buildSmb2GenericSuccess(0x0006, msgID, creditReq, sessionID, treeID)
			_ = writeNbssFrame(conn, resp)
		} else if command == 0x000e { // QUERY_DIRECTORY
			s.baseService.LogEvent("smb_query_directory", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"summary":  "SMB directory listing requested.",
			})

			resp := buildSmb2QueryDirectoryResponse(msgID, creditReq, sessionID, treeID)
			_ = writeNbssFrame(conn, resp)
		} else if command == 0x0008 { // READ
			s.baseService.LogEvent("smb_read_file", map[string]interface{}{
				"src_ip":   srcIP,
				"src_port": srcPort,
				"summary":  "SMB read file request.",
			})

			decoyContent := fmt.Sprintf(
				"[Deployment]\r\nAdminPassword=%s123!\r\nDomainController=%s.%s\r\nSQLServer=SQL-PROD-01.%s\r\n",
				s.profile.SMB.Hostname,
				strings.ToUpper(s.profile.SMB.Hostname),
				s.profile.SMB.DNSDomain,
				s.profile.SMB.DNSDomain,
			)

			resp := buildSmb2ReadResponse(msgID, creditReq, sessionID, treeID, []byte(decoyContent))
			_ = writeNbssFrame(conn, resp)
		} else {
			resp := buildSmb2GenericSuccess(command, msgID, creditReq, sessionID, treeID)
			_ = writeNbssFrame(conn, resp)
		}
	}

	return nil
}

func readNbssFrame(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	// Cap NBSS message length at 65536 bytes (64KB) to prevent resource exhaustion/DoS.
	if length > 65536 {
		return nil, fmt.Errorf("NBSS frame length %d exceeds safety limit", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeNbssFrame(conn net.Conn, payload []byte) error {
	length := len(payload)
	header := []byte{0x00, byte(length >> 16 & 0xFF), byte(length >> 8 & 0xFF), byte(length & 0xFF)}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := conn.Write(append(header, payload...))
	return err
}

type smb2Header struct {
	command   uint16
	messageID uint64
	credits   uint16
	treeID    uint32
	sessionID uint64
}

func parseSmb2Header(packet []byte) (smb2Header, error) {
	if len(packet) < 64 || string(packet[:4]) != "\xfeSMB" {
		return smb2Header{}, fmt.Errorf("invalid SMB2 header")
	}
	return smb2Header{
		command:   binary.LittleEndian.Uint16(packet[12:14]),
		credits:   binary.LittleEndian.Uint16(packet[14:16]),
		messageID: binary.LittleEndian.Uint64(packet[24:32]),
		treeID:    binary.LittleEndian.Uint32(packet[36:40]),
		sessionID: binary.LittleEndian.Uint64(packet[40:48]),
	}, nil
}

func extractSmb2Dialects(packet []byte) []string {
	if len(packet) < 68 {
		return nil
	}
	dialectCount := int(binary.LittleEndian.Uint16(packet[64:66]))
	offset := 64 + 36
	var dialects []string
	for i := 0; i < dialectCount; i++ {
		start := offset + (i * 2)
		end := start + 2
		if end > len(packet) {
			break
		}
		code := binary.LittleEndian.Uint16(packet[start:end])
		dialects = append(dialects, dialectName(code))
	}
	return dialects
}

func dialectName(code uint16) string {
	switch code {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	}
	return fmt.Sprintf("0x%04x", code)
}

func extractSessionSetupSecurityBlob(packet []byte) []byte {
	if len(packet) < 88 {
		return nil
	}
	offset := int(binary.LittleEndian.Uint16(packet[76:78]))
	length := int(binary.LittleEndian.Uint16(packet[78:80]))
	if length <= 0 || offset+length > len(packet) {
		return nil
	}
	return packet[offset : offset+length]
}

func ntlmMessageType(blob []byte) string {
	token := findNtlmsspToken(blob)
	if len(token) < 12 {
		return "unknown"
	}
	msgType := binary.LittleEndian.Uint32(token[8:12])
	switch msgType {
	case 1:
		return "negotiate"
	case 2:
		return "challenge"
	case 3:
		return "authenticate"
	}
	return fmt.Sprintf("%d", msgType)
}

func buildSmb2Header(command uint16, messageID uint64, creditRequest uint16, status uint32, sessionID uint64, treeID uint32, flags uint32) []byte {
	buf := make([]byte, 64)
	copy(buf[0:4], []byte("\xfeSMB"))
	binary.LittleEndian.PutUint16(buf[4:6], 64)
	binary.LittleEndian.PutUint16(buf[6:8], 1)
	binary.LittleEndian.PutUint32(buf[8:12], status)
	binary.LittleEndian.PutUint16(buf[12:14], command)
	credits := creditRequest
	if credits < 1 {
		credits = 1
	}
	binary.LittleEndian.PutUint16(buf[14:16], credits)
	binary.LittleEndian.PutUint32(buf[16:20], flags)
	binary.LittleEndian.PutUint32(buf[20:24], 0)
	binary.LittleEndian.PutUint64(buf[24:32], messageID)
	binary.LittleEndian.PutUint32(buf[32:36], 0)
	binary.LittleEndian.PutUint32(buf[36:40], treeID)
	binary.LittleEndian.PutUint64(buf[40:48], sessionID)
	guid, _ := hexToBytes("9f6e5e13c4b144d7a8ff3fb0c4a07e11")
	copy(buf[48:64], guid)
	return buf
}

func buildSmb2NegotiateResponse(messageID uint64, creditRequest uint16, serverGuid []byte, signingPolicy int) []byte {
	securityBlob := spnegoNegotiateToken()
	securityOffset := uint16(64 + 65)

	now := filetime()

	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(65)) // StructureSize
	binary.Write(body, binary.LittleEndian, uint16(signingPolicy))
	binary.Write(body, binary.LittleEndian, uint16(0x0311)) // DialectRevision
	binary.Write(body, binary.LittleEndian, uint16(1))      // NegotiateContextCount
	body.Write(serverGuid)
	binary.Write(body, binary.LittleEndian, uint32(0x0000007F)) // Capabilities
	binary.Write(body, binary.LittleEndian, uint32(65536))      // MaxTransactSize
	binary.Write(body, binary.LittleEndian, uint32(65536))      // MaxReadSize
	binary.Write(body, binary.LittleEndian, uint32(65536))      // MaxWriteSize
	binary.Write(body, binary.LittleEndian, now)
	binary.Write(body, binary.LittleEndian, now-(86400*10000000*30))
	binary.Write(body, binary.LittleEndian, securityOffset)
	binary.Write(body, binary.LittleEndian, uint16(len(securityBlob)))
	binary.Write(body, binary.LittleEndian, uint32(0))
	body.Write(securityBlob)

	header := buildSmb2Header(0, messageID, creditRequest, 0, 0, 0, 0x00000001)
	return append(header, body.Bytes()...)
}

func buildSmb2SessionSetupChallenge(messageID uint64, creditRequest uint16, sessionID uint64, ntlmChallenge []byte, domain, hostname, dnsDomain string) []byte {
	securityBlob := spnegoChallengeToken(ntlmChallenge, domain, hostname, dnsDomain)
	securityOffset := uint16(64 + 8)

	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(9)) // StructureSize
	binary.Write(body, binary.LittleEndian, uint16(0)) // SessionFlags
	binary.Write(body, binary.LittleEndian, securityOffset)
	binary.Write(body, binary.LittleEndian, uint16(len(securityBlob)))
	body.Write(securityBlob)

	header := buildSmb2Header(1, messageID, creditRequest, 0xC0000016, sessionID, 0, 0x00000001)
	return append(header, body.Bytes()...)
}

func buildSmb2SessionSetupSuccess(messageID uint64, creditRequest uint16, sessionID uint64) []byte {
	body := []byte{
		0x09, 0x00, // StructureSize
		0x00, 0x00, // SessionFlags
		0x48, 0x00, // SecurityBufferOffset
		0x00, 0x00, // SecurityBufferLength
	}
	header := buildSmb2Header(1, messageID, creditRequest, 0, sessionID, 0, 0x00000001)
	return append(header, body...)
}

func parseSmb2TreeConnectPath(packet []byte) string {
	if len(packet) < 64+8 {
		return ""
	}
	pathOffset := int(binary.LittleEndian.Uint16(packet[64+4 : 64+6]))
	pathLength := int(binary.LittleEndian.Uint16(packet[64+6 : 64+8]))
	if pathOffset+pathLength > len(packet) {
		return ""
	}
	return decodeUTF16LE(packet[pathOffset : pathOffset+pathLength])
}

func buildSmb2TreeConnectResponse(messageID uint64, creditRequest uint16, sessionID uint64, treeID uint32) []byte {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(16)) // StructureSize
	body.WriteByte(1)                                   // ShareType = 1 (DISKLIB)
	body.WriteByte(0)
	binary.Write(body, binary.LittleEndian, uint32(0))          // ShareFlags
	binary.Write(body, binary.LittleEndian, uint32(0))          // Capabilities
	binary.Write(body, binary.LittleEndian, uint32(0x001F01FF)) // MaximalAccess

	header := buildSmb2Header(3, messageID, creditRequest, 0, sessionID, treeID, 0x00000001)
	return append(header, body.Bytes()...)
}

func parseSmb2CreateFilename(packet []byte) string {
	if len(packet) < 64+48 {
		return ""
	}
	nameOffset := int(binary.LittleEndian.Uint16(packet[64+44 : 64+46]))
	nameLength := int(binary.LittleEndian.Uint16(packet[64+46 : 64+48]))
	if nameOffset+nameLength > len(packet) {
		return ""
	}
	return decodeUTF16LE(packet[nameOffset : nameOffset+nameLength])
}

func buildSmb2CreateResponse(messageID uint64, creditRequest uint16, sessionID uint64, treeID uint32, fileID uint64) []byte {
	now := filetime()
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(89)) // StructureSize
	body.WriteByte(0)                                   // OplockLevel
	body.WriteByte(0)                                   // Flags
	binary.Write(body, binary.LittleEndian, uint32(1))  // CreateAction
	binary.Write(body, binary.LittleEndian, now)        // CreationTime
	binary.Write(body, binary.LittleEndian, now)        // LastAccessTime
	binary.Write(body, binary.LittleEndian, now)        // LastWriteTime
	binary.Write(body, binary.LittleEndian, now)        // ChangeTime
	binary.Write(body, binary.LittleEndian, uint64(4096))
	binary.Write(body, binary.LittleEndian, uint64(4096))
	binary.Write(body, binary.LittleEndian, uint32(0x20)) // FileAttributes = 0x20 (ARCHIVE)
	binary.Write(body, binary.LittleEndian, uint32(0))    // Reserved
	// FileID (16 bytes)
	binary.Write(body, binary.LittleEndian, fileID)
	body.Write(make([]byte, 8))
	binary.Write(body, binary.LittleEndian, uint32(0))
	binary.Write(body, binary.LittleEndian, uint32(0))

	header := buildSmb2Header(5, messageID, creditRequest, 0, sessionID, treeID, 0x00000001)
	return append(header, body.Bytes()...)
}

func buildSmb2GenericSuccess(command uint16, messageID uint64, creditRequest uint16, sessionID uint64, treeID uint32) []byte {
	body := []byte{0x04, 0x00, 0x00, 0x02} // generic 4 bytes response
	header := buildSmb2Header(command, messageID, creditRequest, 0, sessionID, treeID, 0x00000001)
	return append(header, body...)
}

func buildSmb2QueryDirectoryResponse(messageID uint64, creditRequest uint16, sessionID uint64, treeID uint32) []byte {
	payload := buildDirListingPayload()
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(9)) // StructureSize
	binary.Write(body, binary.LittleEndian, uint16(72))
	binary.Write(body, binary.LittleEndian, uint32(len(payload)))
	body.Write(payload)

	header := buildSmb2Header(14, messageID, creditRequest, 0, sessionID, treeID, 0x00000001)
	return append(header, body.Bytes()...)
}

func buildDirListingPayload() []byte {
	type entry struct {
		name  string
		size  uint64
		isDir bool
	}
	entries := []entry{
		{".", 0, true},
		{"..", 0, true},
		{"unattended.xml", 865, false},
		{"deployment_config.ini", 124, false},
		{"production_db_backup.bak", 1540320, false},
	}

	var payload []byte
	for i, ent := range entries {
		encodedName := encodeUTF16LE(ent.name)
		entrySize := 60 + len(encodedName)
		padding := (8 - (entrySize % 8)) % 8
		nextOffset := uint32(0)
		if i != len(entries)-1 {
			nextOffset = uint32(entrySize + padding)
		}

		entryBytes := buildDirEntry(nextOffset, ent.name, ent.size, ent.isDir)
		payload = append(payload, entryBytes...)
		payload = append(payload, make([]byte, padding)...)
	}
	return payload
}

func buildDirEntry(nextOffset uint32, filename string, fileSize uint64, isDir bool) []byte {
	now := filetime()
	encodedName := encodeUTF16LE(filename)
	attrs := uint32(0x20)
	if isDir {
		attrs = uint32(0x10)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, nextOffset)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, now)
	binary.Write(buf, binary.LittleEndian, now)
	binary.Write(buf, binary.LittleEndian, now)
	binary.Write(buf, binary.LittleEndian, now)
	binary.Write(buf, binary.LittleEndian, fileSize)
	binary.Write(buf, binary.LittleEndian, fileSize)
	binary.Write(buf, binary.LittleEndian, attrs)
	binary.Write(buf, binary.LittleEndian, uint32(len(encodedName)))
	buf.Write(encodedName)

	return buf.Bytes()
}

func buildSmb2ReadResponse(messageID uint64, creditRequest uint16, sessionID uint64, treeID uint32, content []byte) []byte {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(17)) // StructureSize
	body.WriteByte(72)                                  // DataOffset
	body.WriteByte(0)
	binary.Write(body, binary.LittleEndian, uint32(len(content)))
	binary.Write(body, binary.LittleEndian, uint32(0))
	binary.Write(body, binary.LittleEndian, uint32(0))
	body.Write(content)

	header := buildSmb2Header(8, messageID, creditRequest, 0, sessionID, treeID, 0x00000001)
	return append(header, body.Bytes()...)
}

type smb1SessionSetupIdentity struct {
	username    string
	domain      string
	workstation string
}

func parseSmb1SessionSetupIdentity(packet []byte) smb1SessionSetupIdentity {
	var identity smb1SessionSetupIdentity
	if len(packet) < 32 {
		return identity
	}
	header, err := parseSMB1Header(packet)
	if err != nil {
		return identity
	}

	wordCount := int(packet[32])
	dataStart := 33 + wordCount*2
	if dataStart+2 > len(packet) {
		return identity
	}

	oemPasswordLength := int(binary.LittleEndian.Uint16(packet[33+13*2 : 33+13*2+2]))
	unicodePasswordLength := int(binary.LittleEndian.Uint16(packet[33+14*2 : 33+14*2+2]))

	stringsBytes := packet[dataStart+oemPasswordLength+unicodePasswordLength:]
	if header.flags2&0x8000 != 0 {
		absOffset := 32 + dataStart + 2 + oemPasswordLength + unicodePasswordLength
		if absOffset%2 != 0 && len(stringsBytes) > 0 {
			stringsBytes = stringsBytes[1:]
		}
		parsed := splitSmbStrings(stringsBytes, "utf-16le")
		if len(parsed) > 0 {
			identity.username = parsed[0]
		}
		if len(parsed) > 1 {
			identity.domain = parsed[1]
		}
		if len(parsed) > 2 {
			identity.workstation = parsed[2]
		}
	} else {
		parsed := splitSmbStrings(stringsBytes, "ascii")
		if len(parsed) > 0 {
			identity.username = parsed[0]
		}
		if len(parsed) > 1 {
			identity.domain = parsed[1]
		}
		if len(parsed) > 2 {
			identity.workstation = parsed[2]
		}
	}

	return identity
}

func splitSmbStrings(data []byte, encoding string) []string {
	var s string
	if encoding == "utf-16le" {
		s = decodeUTF16LE(data)
	} else {
		s = string(data)
	}
	parts := strings.Split(s, "\x00")
	var res []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			res = append(res, p)
		}
	}
	return res
}

func buildSmb1SessionSetupResponse(multiplexID uint16, processID uint32, treeID, userID uint16, nativeOS, nativeLanman, domain string) []byte {
	osBytes := []byte(nativeOS)
	lanmanBytes := []byte(nativeLanman)
	domainBytes := []byte(domain)

	body := new(bytes.Buffer)
	body.WriteByte(3) // WordCount = 3
	binary.Write(body, binary.LittleEndian, uint16(0xFF))
	binary.Write(body, binary.LittleEndian, uint16(0))
	binary.Write(body, binary.LittleEndian, uint16(0)) // Action = 0
	binary.Write(body, binary.LittleEndian, uint16(len(osBytes)+len(lanmanBytes)+len(domainBytes)+3))

	body.Write(osBytes)
	body.WriteByte(0)
	body.Write(lanmanBytes)
	body.WriteByte(0)
	body.Write(domainBytes)
	body.WriteByte(0)

	header := buildSMB1Header(0x73, 0, 0x88, 0x4001, treeID, uint32(processID), userID, multiplexID)
	return append(header, body.Bytes()...)
}

// SPNEGO / ASN.1 Token Helpers
func spnegoNegotiateToken() []byte {
	mechTypesRaw := append(asn1Oid("1.2.840.113554.1.2.2"), asn1Oid("1.2.840.48018.1.2.2")...)
	mechTypesRaw = append(mechTypesRaw, asn1Oid("1.3.6.1.4.1.311.2.2.10")...)

	mechSequence := append([]byte{0x30}, append(asn1Length(len(mechTypesRaw)), mechTypesRaw...)...)
	mechTypes := append([]byte{0xa0}, append(asn1Length(len(mechSequence)), mechSequence...)...)
	inner := append([]byte{0x30}, append(asn1Length(len(mechTypes)), mechTypes...)...)
	return append([]byte{0x60}, append(asn1Length(len(inner)), inner...)...)
}

func spnegoChallengeToken(ntlmChallenge []byte, domain, hostname, dnsDomain string) []byte {
	fqdn := fmt.Sprintf("%s.%s", strings.ToLower(hostname), dnsDomain)
	ntlmChallengeData := ntlmChallengeMessage(ntlmChallenge, domain, hostname, dnsDomain, fqdn)
	supportedMech := asn1Oid("1.3.6.1.4.1.311.2.2.10")

	negState := append([]byte{0xa0}, append(asn1Length(3), []byte{0x0a, 0x01, 0x01}...)...)
	mech := append([]byte{0xa1}, append(asn1Length(len(supportedMech)), supportedMech...)...)
	responseToken := append([]byte{0xa2}, append(asn1Length(len(ntlmChallengeData)), ntlmChallengeData...)...)

	innerLen := len(negState) + len(mech) + len(responseToken)
	inner := append([]byte{0x30}, append(asn1Length(innerLen), append(append(negState, mech...), responseToken...)...)...)

	return append([]byte{0xa1}, append(asn1Length(len(inner)), inner...)...)
}

func ntlmChallengeMessage(challenge []byte, domain, hostname, dnsDomain, fqdn string) []byte {
	targetName := encodeUTF16LE(domain)
	now := filetime()

	targetInfo := new(bytes.Buffer)
	targetInfo.Write(ntlmAvPair(2, encodeUTF16LE(domain)))
	targetInfo.Write(ntlmAvPair(1, encodeUTF16LE(hostname)))
	targetInfo.Write(ntlmAvPair(4, encodeUTF16LE(dnsDomain)))
	targetInfo.Write(ntlmAvPair(3, encodeUTF16LE(fqdn)))

	nowBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nowBytes, now)
	targetInfo.Write(ntlmAvPair(7, nowBytes))
	targetInfo.Write(ntlmAvPair(9, []byte{0x02, 0x00, 0x00, 0x00}))
	targetInfo.Write(ntlmAvPair(10, make([]byte, 16)))
	targetInfo.Write([]byte{0x00, 0x00, 0x00, 0x00}) // terminator

	targetInfoBytes := targetInfo.Bytes()
	targetNameOffset := uint32(56)
	targetInfoOffset := targetNameOffset + uint32(len(targetName))

	buf := new(bytes.Buffer)
	buf.Write([]byte("NTLMSSP\x00"))
	binary.Write(buf, binary.LittleEndian, uint32(2))
	binary.Write(buf, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(buf, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(buf, binary.LittleEndian, targetNameOffset)
	binary.Write(buf, binary.LittleEndian, uint32(0xE28A8235))
	buf.Write(challenge)
	buf.Write(make([]byte, 8))
	binary.Write(buf, binary.LittleEndian, uint16(len(targetInfoBytes)))
	binary.Write(buf, binary.LittleEndian, uint16(len(targetInfoBytes)))
	binary.Write(buf, binary.LittleEndian, targetInfoOffset)
	buf.Write([]byte{0x0a, 0x00, 0x63, 0x45, 0x00, 0x00, 0x00, 0x0f})
	buf.Write(targetName)
	buf.Write(targetInfoBytes)

	return buf.Bytes()
}

func ntlmAvPair(avID uint16, value []byte) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint16(buf[0:2], avID)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(value)))
	return append(buf, value...)
}

func parseNtlmAuthenticate(blob []byte) (string, string, string) {
	token := findNtlmsspToken(blob)
	if len(token) < 52 || string(token[:8]) != "NTLMSSP\x00" {
		return "", "", ""
	}
	msgType := binary.LittleEndian.Uint32(token[8:12])
	if msgType != 3 {
		return "", "", ""
	}
	domain := readNtlmField(token, 28)
	username := readNtlmField(token, 36)
	workstation := readNtlmField(token, 44)
	return domain, username, workstation
}

func findNtlmsspToken(blob []byte) []byte {
	idx := bytes.Index(blob, []byte("NTLMSSP\x00"))
	if idx == -1 {
		return nil
	}
	return blob[idx:]
}

func readNtlmField(token []byte, offset int) string {
	if offset+8 > len(token) {
		return ""
	}
	length := int(binary.LittleEndian.Uint16(token[offset : offset+2]))
	dataOffset := int(binary.LittleEndian.Uint32(token[offset+4 : offset+8]))
	if length <= 0 || dataOffset+length > len(token) {
		return ""
	}
	return decodeUTF16LE(token[dataOffset : dataOffset+length])
}

func asn1Length(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var encoded []byte
	temp := length
	for temp > 0 {
		encoded = append([]byte{byte(temp & 0xFF)}, encoded...)
		temp = temp >> 8
	}
	return append([]byte{0x80 | byte(len(encoded))}, encoded...)
}

func asn1Oid(oid string) []byte {
	parts := strings.Split(oid, ".")
	var partsInt []int
	for _, p := range parts {
		var val int
		fmt.Sscanf(p, "%d", &val)
		partsInt = append(partsInt, val)
	}

	if len(partsInt) < 2 {
		return nil
	}

	encoded := []byte{byte(partsInt[0]*40 + partsInt[1])}
	for _, part := range partsInt[2:] {
		if part == 0 {
			encoded = append(encoded, 0)
			continue
		}
		var stack []byte
		temp := part
		for temp > 0 {
			stack = append(stack, byte(temp&0x7F))
			temp >>= 7
		}
		for i := len(stack) - 1; i >= 0; i-- {
			b := stack[i]
			if i > 0 {
				b |= 0x80
			}
			encoded = append(encoded, b)
		}
	}

	res := []byte{0x06}
	res = append(res, asn1Length(len(encoded))...)
	return append(res, encoded...)
}

func init() {
	services.Registry["smb"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewSMBHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *SMBHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
