package tcp

import (
	"honeypot-orchestrator/backend/internal/profiles"
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
)

type MSSQLHoneypot struct {
	baseService *services.BaseTCPService
}

func NewMSSQLHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
) *MSSQLHoneypot {
	m := &MSSQLHoneypot{}
	m.baseService = services.NewBaseTCPService(name, host, port, el, ds, m.handleClient)
	return m
}

func (m *MSSQLHoneypot) Name() string {
	return m.baseService.Name()
}

func (m *MSSQLHoneypot) Port() int {
	return m.baseService.Port()
}

func (m *MSSQLHoneypot) IsRunning() bool {
	return m.baseService.IsRunning()
}

func (m *MSSQLHoneypot) Start(ctx context.Context) error {
	return m.baseService.Start(ctx)
}

func (m *MSSQLHoneypot) Stop() error {
	return m.baseService.Stop()
}

func (m *MSSQLHoneypot) Proto() string {
	return m.baseService.Proto()
}

func (m *MSSQLHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
	remoteAddr := conn.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("remote address is not TCP")
	}
	srcIP := tcpAddr.IP.String()
	srcPort := tcpAddr.Port

	m.baseService.LogEvent("connection", map[string]interface{}{
		"src_ip":   srcIP,
		"src_port": srcPort,
	})

	packetType, payload, err := readTdsPacket(conn)
	if err != nil {
		return err
	}

	usesTds72 := false
	var loginPayload []byte

	if packetType == 0x12 { // PRELOGIN
		m.baseService.LogEvent("mssql_prelogin", map[string]interface{}{
			"src_ip":      srcIP,
			"src_port":    srcPort,
			"packet_type": fmt.Sprintf("0x%02x", packetType),
			"summary":     "MSSQL prelogin captured.",
		})

		preloginResp := buildPreloginResponse()
		if err := writeTdsPacket(conn, 0x04, preloginResp); err != nil {
			return err
		}

		loginPacketType, lp, err := readTdsPacket(conn)
		if err != nil {
			return err
		}
		if loginPacketType != 0x10 {
			return fmt.Errorf("expected LOGIN7 packet")
		}
		loginPayload = lp
	} else if packetType == 0x10 { // LOGIN7 direct
		m.baseService.LogEvent("mssql_login_direct", map[string]interface{}{
			"src_ip":      srcIP,
			"src_port":    srcPort,
			"packet_type": fmt.Sprintf("0x%02x", packetType),
			"summary":     "MSSQL direct login (no prelogin) captured.",
		})
		loginPayload = payload
	} else {
		return fmt.Errorf("unsupported first packet type: %02x", packetType)
	}

	login7Payload := skipAllHeaders(loginPayload)
	var tdsVersionBytes []byte
	if len(login7Payload) >= 8 {
		tdsVersionBytes = login7Payload[4:8]
	} else {
		tdsVersionBytes = []byte{0x00, 0x00, 0x00, 0x71}
	}
	usesTds72 = usesTds72Plus(tdsVersionBytes)

	username := extractLogin7String(login7Payload, 40, 42)
	password := extractLogin7Password(login7Payload)
	clientHostname := extractLogin7String(login7Payload, 36, 38)
	appName := extractLogin7String(login7Payload, 48, 50)
	databaseName := extractLogin7String(login7Payload, 68, 70)

	if len(strings.TrimSpace(username)) > 0 {
		m.baseService.LogEvent("login_success", map[string]interface{}{
			"src_ip":          srcIP,
			"src_port":        srcPort,
			"service":         m.Name(),
			"username":        username,
			"password":        password,
			"client_hostname": clientHostname,
			"app_name":        appName,
			"database_name":   databaseName,
			"summary":         fmt.Sprintf("MSSQL successful login for user '%s' (Host: %s, App: %s)", username, clientHostname, appName),
		})

		successResp := buildLoginSuccessResponse(usesTds72)
		if err := writeTdsPacket(conn, 0x04, successResp); err != nil {
			return err
		}

		for {
			cmdType, cmdPayload, err := readTdsPacket(conn)
			if err != nil {
				break
			}

			if cmdType == 0x01 { // SQL Batch
				queryPayload := skipAllHeaders(cmdPayload)
				queryStr := decodeUTF16LE(queryPayload)
				queryStr = cleanGarbage(queryStr)
				queryLower := strings.ToLower(queryStr)

				m.baseService.LogEvent("sql_query", map[string]interface{}{
					"src_ip":   srcIP,
					"src_port": srcPort,
					"service":  m.Name(),
					"username": username,
					"query":    queryStr,
					"summary":  fmt.Sprintf("MSSQL query executed by '%s': %s", username, truncate(queryStr, 100)),
				})

				var respPayload []byte
				if strings.Contains(queryLower, "@@version") {
					versionText := "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) \n\tSep 24 2019 13:48:23 \n\tCopyright (C) 2019 Microsoft Corporation\n\tStandard Edition on Windows Server 2019 Standard 10.0 <X64> (Build 17763: )\n"
					respPayload = buildSqlTextResponse("version", versionText, usesTds72)
				} else if strings.Contains(queryLower, "sys.databases") || strings.Contains(queryLower, "sysdatabases") {
					dbList := []string{"master", "tempdb", "model", "msdb", "prod_customer_db"}
					respPayload = buildSqlListResponse("name", dbList, usesTds72)
				} else if strings.Contains(queryLower, "@@servername") {
					respPayload = buildSqlTextResponse("servername", "WIN-SRV2019", usesTds72)
				} else {
					respPayload = buildSqlEmptyResponse(usesTds72)
				}

				if err := writeTdsPacket(conn, 0x04, respPayload); err != nil {
					return err
				}
			} else if cmdType == 0x0e || cmdType == 0x03 {
				if err := writeTdsPacket(conn, 0x04, buildSqlEmptyResponse(usesTds72)); err != nil {
					return err
				}
			} else {
				break
			}
		}
	} else {
		m.baseService.LogEvent("login_attempt", map[string]interface{}{
			"src_ip":          srcIP,
			"src_port":        srcPort,
			"service":         m.Name(),
			"username":        username,
			"password":        password,
			"client_hostname": clientHostname,
			"app_name":        appName,
			"database_name":   databaseName,
			"summary":         fmt.Sprintf("MSSQL failed login attempt for user '%s' (Host: %s)", username, clientHostname),
		})

		errResp := buildLoginErrorResponse(username, usesTds72)
		_ = writeTdsPacket(conn, 0x04, errResp)
	}

	return nil
}

func readTdsPacket(conn net.Conn) (byte, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}

	packetType := header[0]
	totalLength := int(header[2])<<8 | int(header[3])
	if totalLength < 8 {
		return 0, nil, fmt.Errorf("invalid TDS packet length")
	}

	payload := make([]byte, totalLength-8)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}

	return packetType, payload, nil
}

func writeTdsPacket(conn net.Conn, packetType byte, payload []byte) error {
	totalLen := len(payload) + 8
	header := []byte{
		packetType, 0x01,
		byte(totalLen >> 8), byte(totalLen & 0xFF),
		0x00, 0x00, 0x01, 0x00,
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(append(header, payload...))
	return err
}

func usesTds72Plus(versionBytes []byte) bool {
	if len(versionBytes) < 4 {
		return false
	}
	valLE := binary.LittleEndian.Uint32(versionBytes)
	valBE := binary.BigEndian.Uint32(versionBytes)

	legacyVersions := map[uint32]bool{
		0x00000070: true, 0x07000000: true,
		0x00000071: true, 0x07010000: true, 0x01000071: true,
	}

	knownVersions := map[uint32]bool{
		0x00000070: true, 0x07000000: true,
		0x00000071: true, 0x07010000: true, 0x01000071: true,
		0x02000972: true, 0x03000A73: true, 0x03000B73: true, 0x04000074: true, 0x08000000: true,
	}

	if knownVersions[valLE] {
		return !legacyVersions[valLE]
	}
	if knownVersions[valBE] {
		return !legacyVersions[valBE]
	}

	majorBE := versionBytes[0]
	majorLE := versionBytes[3]

	if majorBE == 0x08 || (0x72 <= majorBE && majorBE <= 0x74) {
		return true
	}
	if majorLE == 0x08 || (0x72 <= majorLE && majorLE <= 0x74) {
		return true
	}

	return false
}

func skipAllHeaders(payload []byte) []byte {
	if len(payload) < 4 {
		return payload
	}
	allHeadersLen := int(binary.LittleEndian.Uint32(payload[0:4]))
	if allHeadersLen >= 4 && allHeadersLen < len(payload) {
		return payload[allHeadersLen:]
	}
	return payload
}

func extractLogin7String(payload []byte, offsetIdx, lengthIdx int) string {
	if len(payload) < lengthIdx+2 {
		return ""
	}
	offset := int(binary.LittleEndian.Uint16(payload[offsetIdx : offsetIdx+2]))
	length := int(binary.LittleEndian.Uint16(payload[lengthIdx : lengthIdx+2]))
	if length <= 0 {
		return ""
	}
	start := offset
	end := start + (length * 2)
	if end > len(payload) {
		return ""
	}
	return decodeUTF16LE(payload[start:end])
}

func extractLogin7Password(payload []byte) string {
	if len(payload) < 48 {
		return ""
	}
	offset := int(binary.LittleEndian.Uint16(payload[44:46]))
	length := int(binary.LittleEndian.Uint16(payload[46:48]))
	if length <= 0 {
		return ""
	}
	start := offset
	end := start + (length * 2)
	if end > len(payload) {
		return ""
	}

	obfuscated := payload[start:end]
	decrypted := make([]byte, len(obfuscated))
	for i, b := range obfuscated {
		xored := b ^ 0xA5
		swapped := ((xored & 0x0F) << 4) | ((xored & 0xF0) >> 4)
		decrypted[i] = swapped
	}
	return decodeUTF16LE(decrypted)
}

func buildPreloginResponse() []byte {
	tableSize := 5 + 5 + 5 + 5 + 1
	versionOffset := uint16(tableSize)
	encryptionOffset := versionOffset + 6
	instanceOffset := encryptionOffset + 1
	threadidOffset := instanceOffset + 1

	sqlServer2019Version := []byte{0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00}

	buf := new(bytes.Buffer)
	buf.WriteByte(0x00)
	binary.Write(buf, binary.BigEndian, versionOffset)
	binary.Write(buf, binary.BigEndian, uint16(6))

	buf.WriteByte(0x01)
	binary.Write(buf, binary.BigEndian, encryptionOffset)
	binary.Write(buf, binary.BigEndian, uint16(1))

	buf.WriteByte(0x02)
	binary.Write(buf, binary.BigEndian, instanceOffset)
	binary.Write(buf, binary.BigEndian, uint16(1))

	buf.WriteByte(0x03)
	binary.Write(buf, binary.BigEndian, threadidOffset)
	binary.Write(buf, binary.BigEndian, uint16(0))

	buf.WriteByte(0xff)
	buf.Write(sqlServer2019Version)
	buf.WriteByte(0x02) // ENCRYPT_NOT_SUP
	buf.WriteByte(0x00) // empty instance name

	return buf.Bytes()
}

func buildLoginSuccessResponse(usesTds72 bool) []byte {
	prognameBytes := encodeUTF16LE("Microsoft SQL Server")
	loginAckLen := uint16(1 + 4 + 1 + len(prognameBytes) + 1 + 1 + 2)

	tdsVersion := []byte{0x71, 0x00, 0x00, 0x01}
	if usesTds72 {
		tdsVersion = []byte{0x74, 0x00, 0x00, 0x04}
	}

	loginAck := new(bytes.Buffer)
	loginAck.WriteByte(0xad)
	binary.Write(loginAck, binary.LittleEndian, loginAckLen)
	loginAck.WriteByte(0x01) // interface LSQL_TS
	loginAck.Write(tdsVersion)
	loginAck.WriteByte(byte(len("Microsoft SQL Server")))
	loginAck.Write(prognameBytes)
	loginAck.WriteByte(0x0f)           // Major 15
	loginAck.WriteByte(0x00)           // Minor 0
	loginAck.Write([]byte{0x07, 0xd0}) // Build 2000

	dbNew := encodeUTF16LE("master")
	envchangeDB := new(bytes.Buffer)
	envchangeDB.WriteByte(0xe3)
	binary.Write(envchangeDB, binary.LittleEndian, uint16(1+1+len(dbNew)+1))
	envchangeDB.WriteByte(0x01) // Type database
	envchangeDB.WriteByte(byte(len("master")))
	envchangeDB.Write(dbNew)
	envchangeDB.WriteByte(0x00)

	pktNew := encodeUTF16LE("4096")
	envchangePkt := new(bytes.Buffer)
	envchangePkt.WriteByte(0xe3)
	binary.Write(envchangePkt, binary.LittleEndian, uint16(1+1+len(pktNew)+1))
	envchangePkt.WriteByte(0x04) // Type packet size
	envchangePkt.WriteByte(byte(len("4096")))
	envchangePkt.Write(pktNew)
	envchangePkt.WriteByte(0x00)

	done := []byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if usesTds72 {
		done = []byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}

	res := append(envchangeDB.Bytes(), envchangePkt.Bytes()...)
	res = append(res, loginAck.Bytes()...)
	res = append(res, done...)
	return res
}

func buildLoginErrorResponse(username string, usesTds72 bool) []byte {
	if username == "" {
		username = "sa"
	}
	errorText := fmt.Sprintf("Login failed for user '%s'.", username)
	serverName := "WIN-SRV2019"
	msgBytes := encodeUTF16LE(errorText)
	serverBytes := encodeUTF16LE(serverName)

	lineNumberLen := 2
	lineNumberBytes := []byte{0x00, 0x00}
	if usesTds72 {
		lineNumberLen = 4
		lineNumberBytes = []byte{0x00, 0x00, 0x00, 0x00}
	}

	remainingLen := uint16(4 + 1 + 1 + 2 + len(msgBytes) + 1 + len(serverBytes) + 1 + lineNumberLen)

	errorToken := new(bytes.Buffer)
	errorToken.WriteByte(0xaa)
	binary.Write(errorToken, binary.LittleEndian, remainingLen)
	binary.Write(errorToken, binary.LittleEndian, uint32(18456))
	errorToken.WriteByte(0x01) // State
	errorToken.WriteByte(0x0e) // Severity 14
	binary.Write(errorToken, binary.LittleEndian, uint16(len(errorText)))
	errorToken.Write(msgBytes)
	errorToken.WriteByte(byte(len(serverName)))
	errorToken.Write(serverBytes)
	errorToken.WriteByte(0x00) // ProcLen
	errorToken.Write(lineNumberBytes)

	doneToken := []byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if usesTds72 {
		doneToken = []byte{0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}

	return append(errorToken.Bytes(), doneToken...)
}

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	runes := make([]rune, len(b)/2)
	for i := 0; i < len(runes); i++ {
		runes[i] = rune(binary.LittleEndian.Uint16(b[i*2 : i*2+2]))
	}
	return string(runes)
}

func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:i*2+2], uint16(r))
	}
	return b
}

func buildSqlTextResponse(colName, rowText string, usesTds72 bool) []byte {
	colNameBytes := encodeUTF16LE(colName)
	rowBytes := encodeUTF16LE(rowText)

	userTypeBytes := []byte{0x00, 0x00}
	if usesTds72 {
		userTypeBytes = []byte{0x00, 0x00, 0x00, 0x00}
	}

	colMetadata := new(bytes.Buffer)
	colMetadata.WriteByte(0x81)
	colMetadata.Write([]byte{0x01, 0x00}) // 1 column
	colMetadata.Write(userTypeBytes)
	colMetadata.Write([]byte{0x09, 0x00}) // flags Nullable
	colMetadata.WriteByte(0xe7)           // type NVARCHAR
	binary.Write(colMetadata, binary.LittleEndian, uint16(500))
	colMetadata.Write([]byte{0x09, 0x04, 0xd0, 0x00, 0x34}) // collation
	colMetadata.WriteByte(byte(len(colName)))
	colMetadata.Write(colNameBytes)

	row := new(bytes.Buffer)
	row.WriteByte(0xd1)
	binary.Write(row, binary.LittleEndian, uint16(len(rowBytes)))
	row.Write(rowBytes)

	done := []byte{0xfd, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	if usesTds72 {
		done = []byte{0xfd, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}

	res := append(colMetadata.Bytes(), row.Bytes()...)
	return append(res, done...)
}

func buildSqlListResponse(colName string, rowsList []string, usesTds72 bool) []byte {
	colNameBytes := encodeUTF16LE(colName)
	userTypeBytes := []byte{0x00, 0x00}
	if usesTds72 {
		userTypeBytes = []byte{0x00, 0x00, 0x00, 0x00}
	}

	colMetadata := new(bytes.Buffer)
	colMetadata.WriteByte(0x81)
	colMetadata.Write([]byte{0x01, 0x00}) // 1 column
	colMetadata.Write(userTypeBytes)
	colMetadata.Write([]byte{0x09, 0x00}) // flags Nullable
	colMetadata.WriteByte(0xe7)           // type NVARCHAR
	binary.Write(colMetadata, binary.LittleEndian, uint16(256))
	colMetadata.Write([]byte{0x09, 0x04, 0xd0, 0x00, 0x34}) // collation
	colMetadata.WriteByte(byte(len(colName)))
	colMetadata.Write(colNameBytes)

	rowsBuf := new(bytes.Buffer)
	for _, item := range rowsList {
		itemBytes := encodeUTF16LE(item)
		rowsBuf.WriteByte(0xd1)
		binary.Write(rowsBuf, binary.LittleEndian, uint16(len(itemBytes)))
		rowsBuf.Write(itemBytes)
	}

	done := new(bytes.Buffer)
	done.WriteByte(0xfd)
	done.Write([]byte{0x10, 0x00})
	done.Write([]byte{0x00, 0x00})
	if usesTds72 {
		binary.Write(done, binary.LittleEndian, uint64(len(rowsList)))
	} else {
		binary.Write(done, binary.LittleEndian, uint32(len(rowsList)))
	}

	res := append(colMetadata.Bytes(), rowsBuf.Bytes()...)
	return append(res, done.Bytes()...)
}

func buildSqlEmptyResponse(usesTds72 bool) []byte {
	done := []byte{0xfd, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if usesTds72 {
		done = []byte{0xfd, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}
	return done
}

func cleanGarbage(s string) string {
	var clean []rune
	for _, r := range s {
		if r >= 32 {
			clean = append(clean, r)
		}
	}
	return string(clean)
}

func truncate(s string, limit int) string {
	if len(s) > limit {
		return s[:limit]
	}
	return s
}

func init() {
	services.Registry["mssql"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewMSSQLHoneypot(name, host, port, el, ds)
	}
}

func (s *MSSQLHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
