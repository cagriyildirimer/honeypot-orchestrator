package tcp

import (
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

type LDAPHoneypot struct {
	baseService *services.BaseTCPService
	profile     *profiles.HoneypotProfile
}

func NewLDAPHoneypot(
	name string,
	host string,
	port int,
	el *logger.EventLogger,
	ds *defense.DefenseSystem,
	initialProfile *profiles.HoneypotProfile,
) *LDAPHoneypot {
	l := &LDAPHoneypot{profile: initialProfile}
	l.baseService = services.NewBaseTCPService(name, host, port, el, ds, l.handleClient)
	return l
}

func (l *LDAPHoneypot) Name() string {
	return l.baseService.Name()
}

func (l *LDAPHoneypot) Port() int {
	return l.baseService.Port()
}

func (l *LDAPHoneypot) IsRunning() bool {
	return l.baseService.IsRunning()
}

func (l *LDAPHoneypot) Start(ctx context.Context) error {
	return l.baseService.Start(ctx)
}

func (l *LDAPHoneypot) Stop() error {
	return l.baseService.Stop()
}

func (l *LDAPHoneypot) Proto() string {
	return l.baseService.Proto()
}

func (l *LDAPHoneypot) SetProfile(prof *profiles.HoneypotProfile) {
	l.profile = prof
}

func (l *LDAPHoneypot) handleClient(ctx context.Context, conn net.Conn) error {
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

	for {
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			break
		}

		packet := buf[:n]
		handled, err := l.handlePacket(conn, packet, srcIP, srcPort)
		if err != nil || !handled {
			break
		}
	}

	return nil
}

func (l *LDAPHoneypot) handlePacket(conn net.Conn, packet []byte, srcIP string, srcPort int) (bool, error) {
	messageID, protocolOp, payload, err := parseLdapMessage(packet)
	if err != nil {
		return false, err
	}

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	if protocolOp == 0x60 { // Bind Request
		username, password := parseBindRequest(payload)
		l.baseService.LogEvent("login_attempt", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"username": username,
			"password": password,
			"summary":  fmt.Sprintf("LDAP bind attempt for %s", username),
		})

		bindResp := buildBindResponsePayload()
		resp := wrapLdapMessage(messageID, append([]byte{0x61}, append(berLength(len(bindResp)), bindResp...)...))
		_, err = conn.Write(resp)
		return true, err
	}

	if protocolOp == 0x63 { // Search Request
		baseDN, scope := parseSearchRequest(payload)
		l.baseService.LogEvent("ldap_search", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"base_dn":  baseDN,
			"scope":    scope,
			"summary":  fmt.Sprintf("LDAP search under %s", baseDN),
		})

		var responses [][]byte
		if baseDN == "" { // rootDSE
			responses = buildRootDSESearchResponse(messageID, l.profile)
		} else {
			mockEntries := buildADMockEntries(l.profile)
			for _, entry := range mockEntries {
				responses = append(responses, buildSearchEntryResponse(messageID, entry.DN, entry.Attributes))
			}
			donePayload := buildGenericResultPayload(0, "")
			searchDone := wrapLdapMessage(messageID, append([]byte{0x65}, append(berLength(len(donePayload)), donePayload...)...))
			responses = append(responses, searchDone)
		}

		for _, respPacket := range responses {
			if _, err := conn.Write(respPacket); err != nil {
				return false, err
			}
		}
		return true, nil
	}

	if protocolOp == 0x42 { // Unbind Request
		l.baseService.LogEvent("ldap_unbind", map[string]interface{}{
			"src_ip":   srcIP,
			"src_port": srcPort,
			"summary":  "LDAP unbind received.",
		})
		return false, nil
	}

	l.baseService.LogEvent("ldap_operation", map[string]interface{}{
		"src_ip":    srcIP,
		"src_port":  srcPort,
		"operation": fmt.Sprintf("0x%02x", protocolOp),
		"summary":   fmt.Sprintf("Unhandled LDAP op 0x%02x", protocolOp),
	})

	errPayload := buildGenericResultPayload(2, "Protocol error")
	resp := wrapLdapMessage(messageID, append([]byte{0x65}, append(berLength(len(errPayload)), errPayload...)...))
	_, _ = conn.Write(resp)
	return false, nil
}

func readTLV(data []byte, offset int) (byte, int, []byte, int, error) {
	if offset >= len(data) {
		return 0, 0, nil, 0, fmt.Errorf("missing BER tag")
	}
	tag := data[offset]
	offset++
	if offset >= len(data) {
		return 0, 0, nil, 0, fmt.Errorf("missing BER length")
	}
	firstLength := data[offset]
	offset++

	var length int
	if firstLength&0x80 != 0 {
		size := int(firstLength & 0x7F)
		if offset+size > len(data) {
			return 0, 0, nil, 0, fmt.Errorf("truncated BER length size")
		}
		val := 0
		for i := 0; i < size; i++ {
			val = (val << 8) | int(data[offset+i])
		}
		length = val
		offset += size
	} else {
		length = int(firstLength)
	}

	end := offset + length
	if end > len(data) {
		return 0, 0, nil, 0, fmt.Errorf("truncated BER payload")
	}

	return tag, length, data[offset:end], end, nil
}

func parseLdapMessage(packet []byte) (int, byte, []byte, error) {
	tag, _, body, _, err := readTLV(packet, 0)
	if err != nil {
		return 0, 0, nil, err
	}
	if tag != 0x30 {
		return 0, 0, nil, fmt.Errorf("LDAP packet is not a sequence")
	}

	idTag, _, idBytes, offset, err := readTLV(body, 0)
	if err != nil || idTag != 0x02 {
		return 0, 0, nil, fmt.Errorf("invalid message ID tag")
	}

	messageID := 0
	for _, b := range idBytes {
		messageID = (messageID << 8) | int(b)
	}

	if offset >= len(body) {
		return 0, 0, nil, fmt.Errorf("missing protocol payload")
	}
	protocolOp := body[offset]
	_, _, protocolPayload, _, err := readTLV(body, offset)
	if err != nil {
		return 0, 0, nil, err
	}

	return messageID, protocolOp, protocolPayload, nil
}

func parseBindRequest(payload []byte) (string, string) {
	versionTag, _, _, offset, err := readTLV(payload, 0)
	if err != nil || versionTag != 0x02 {
		return "", ""
	}
	nameTag, _, nameBytes, offset, err := readTLV(payload, offset)
	if err != nil || nameTag != 0x04 {
		return "", ""
	}
	username := string(nameBytes)
	password := ""

	if offset < len(payload) {
		authTag := payload[offset]
		_, _, authValue, _, err := readTLV(payload, offset)
		if err == nil && authTag == 0x80 {
			password = string(authValue)
		}
	}
	return username, password
}

func parseSearchRequest(payload []byte) (string, string) {
	baseTag, _, baseBytes, offset, err := readTLV(payload, 0)
	if err != nil || baseTag != 0x04 {
		return "", ""
	}
	baseDN := string(baseBytes)

	scopeTag, _, scopeBytes, _, err := readTLV(payload, offset)
	if err != nil || scopeTag != 0x0a {
		return baseDN, "unknown"
	}

	scope := "unknown"
	if len(scopeBytes) == 1 {
		switch scopeBytes[0] {
		case 0x00:
			scope = "baseObject"
		case 0x01:
			scope = "singleLevel"
		case 0x02:
			scope = "wholeSubtree"
		}
	}
	return baseDN, scope
}

func buildBindResponsePayload() []byte {
	return buildGenericResultPayload(49, "80090308: LdapErr: DSID-0C090457, comment: AcceptSecurityContext error, data 52e, v4563")
}

func buildGenericResultPayload(resultCode int, diagMsg string) []byte {
	var payload []byte
	payload = append(payload, berEnumerated(resultCode)...)
	payload = append(payload, berOctetString("")...)
	payload = append(payload, berOctetString(diagMsg)...)
	return payload
}

func buildRootDSESearchResponse(messageID int, profile *profiles.HoneypotProfile) [][]byte {
	currentTime := time.Now().UTC().Format("20060102150405.0Z")
	dnsDomain := profile.SMB.DNSDomain
	var dcParts []string
	for _, part := range strings.Split(dnsDomain, ".") {
		dcParts = append(dcParts, "DC="+part)
	}
	dcSuffix := strings.Join(dcParts, ",")

	attrs := []struct {
		Name   string
		Values []string
	}{
		{"currentTime", []string{currentTime}},
		{"defaultNamingContext", []string{dcSuffix}},
		{"dnsHostName", []string{fmt.Sprintf("%s.%s", strings.ToUpper(profile.SMB.Hostname), dnsDomain)}},
		{"supportedLDAPVersion", []string{"3"}},
	}

	var entryPayload []byte
	entryPayload = append(entryPayload, berOctetString("")...)
	var partials []byte
	for _, attr := range attrs {
		partials = append(partials, buildPartialAttribute(attr.Name, attr.Values)...)
	}
	entryPayload = append(entryPayload, berSequence(partials)...)

	searchEntry := wrapLdapMessage(messageID, append([]byte{0x64}, append(berLength(len(entryPayload)), entryPayload...)...))
	donePayload := buildGenericResultPayload(0, "")
	searchDone := wrapLdapMessage(messageID, append([]byte{0x65}, append(berLength(len(donePayload)), donePayload...)...))

	return [][]byte{searchEntry, searchDone}
}

func buildPartialAttribute(name string, values []string) []byte {
	var valSetBytes []byte
	for _, val := range values {
		valSetBytes = append(valSetBytes, berOctetString(val)...)
	}
	valueSet := append([]byte{0x31}, append(berLength(len(valSetBytes)), valSetBytes...)...)
	return berSequence(append(berOctetString(name), valueSet...))
}

func wrapLdapMessage(messageID int, protocolOp []byte) []byte {
	body := append(berInteger(messageID), protocolOp...)
	return berSequence(body)
}

func berSequence(payload []byte) []byte {
	return append([]byte{0x30}, append(berLength(len(payload)), payload...)...)
}

func berInteger(val int) []byte {
	var encoded []byte
	if val == 0 {
		encoded = []byte{0x00}
	} else {
		temp := val
		for temp > 0 {
			encoded = append([]byte{byte(temp & 0xFF)}, encoded...)
			temp = temp >> 8
		}
		if encoded[0]&0x80 != 0 {
			encoded = append([]byte{0x00}, encoded...)
		}
	}
	return append([]byte{0x02}, append(berLength(len(encoded)), encoded...)...)
}

func berEnumerated(val int) []byte {
	return []byte{0x0A, 0x01, byte(val)}
}

func berOctetString(val string) []byte {
	encoded := []byte(val)
	return append([]byte{0x04}, append(berLength(len(encoded)), encoded...)...)
}

func berLength(length int) []byte {
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

type ldapMockEntry struct {
	DN         string
	Attributes []struct {
		Name   string
		Values []string
	}
}

func buildADMockEntries(profile *profiles.HoneypotProfile) []ldapMockEntry {
	dnsDomain := profile.SMB.DNSDomain
	var dcParts []string
	for _, part := range strings.Split(dnsDomain, ".") {
		dcParts = append(dcParts, "DC="+part)
	}
	dcSuffix := strings.Join(dcParts, ",")

	makeAttr := func(name string, values []string) struct {
		Name   string
		Values []string
	} {
		return struct {
			Name   string
			Values []string
		}{Name: name, Values: values}
	}

	return []ldapMockEntry{
		{
			DN: fmt.Sprintf("CN=Administrator,CN=Users,%s", dcSuffix),
			Attributes: []struct {
				Name   string
				Values []string
			}{
				makeAttr("objectClass", []string{"top", "person", "organizationalPerson", "user"}),
				makeAttr("cn", []string{"Administrator"}),
				makeAttr("sAMAccountName", []string{"Administrator"}),
				makeAttr("userPrincipalName", []string{fmt.Sprintf("Administrator@%s", dnsDomain)}),
				makeAttr("memberOf", []string{fmt.Sprintf("CN=Domain Admins,CN=Users,%s", dcSuffix), fmt.Sprintf("CN=Enterprise Admins,CN=Users,%s", dcSuffix)}),
				makeAttr("pwdLastSet", []string{"132649032000000000"}),
				makeAttr("userAccountControl", []string{"512"}),
			},
		},
		{
			DN: fmt.Sprintf("CN=cagri,CN=Users,%s", dcSuffix),
			Attributes: []struct {
				Name   string
				Values []string
			}{
				makeAttr("objectClass", []string{"top", "person", "organizationalPerson", "user"}),
				makeAttr("cn", []string{"cagri"}),
				makeAttr("sAMAccountName", []string{"cagri"}),
				makeAttr("userPrincipalName", []string{fmt.Sprintf("cagri@%s", dnsDomain)}),
				makeAttr("memberOf", []string{fmt.Sprintf("CN=Domain Users,CN=Users,%s", dcSuffix)}),
				makeAttr("pwdLastSet", []string{"132849032000000000"}),
				makeAttr("userAccountControl", []string{"512"}),
			},
		},
		{
			DN: fmt.Sprintf("CN=sql_service,CN=Users,%s", dcSuffix),
			Attributes: []struct {
				Name   string
				Values []string
			}{
				makeAttr("objectClass", []string{"top", "person", "organizationalPerson", "user"}),
				makeAttr("cn", []string{"sql_service"}),
				makeAttr("sAMAccountName", []string{"sql_service"}),
				makeAttr("userPrincipalName", []string{fmt.Sprintf("sql_service@%s", dnsDomain)}),
				makeAttr("memberOf", []string{fmt.Sprintf("CN=Domain Users,CN=Users,%s", dcSuffix)}),
				makeAttr("pwdLastSet", []string{"132949032000000000"}),
				makeAttr("servicePrincipalName", []string{fmt.Sprintf("MSSQLSvc/%s.%s:1433", strings.ToUpper(profile.SMB.Hostname), dnsDomain)}),
				makeAttr("userAccountControl", []string{"512"}),
			},
		},
		{
			DN: fmt.Sprintf("CN=%s,OU=Domain Controllers,%s", strings.ToUpper(profile.SMB.Hostname), dcSuffix),
			Attributes: []struct {
				Name   string
				Values []string
			}{
				makeAttr("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"}),
				makeAttr("cn", []string{strings.ToUpper(profile.SMB.Hostname)}),
				makeAttr("sAMAccountName", []string{fmt.Sprintf("%s$", strings.ToUpper(profile.SMB.Hostname))}),
				makeAttr("dnsHostName", []string{fmt.Sprintf("%s.%s", strings.ToUpper(profile.SMB.Hostname), dnsDomain)}),
				makeAttr("userAccountControl", []string{"532480"}),
			},
		},
	}
}

func buildSearchEntryResponse(messageID int, dn string, attributes []struct {
	Name   string
	Values []string
}) []byte {
	var partials []byte
	for _, attr := range attributes {
		partials = append(partials, buildPartialAttribute(attr.Name, attr.Values)...)
	}
	entryPayload := append(berOctetString(dn), berSequence(partials)...)
	return wrapLdapMessage(messageID, append([]byte{0x64}, append(berLength(len(entryPayload)), entryPayload...)...))
}

func init() {
	services.Registry["ldap"] = func(name, host string, port int, el *logger.EventLogger, ds *defense.DefenseSystem, prof *profiles.HoneypotProfile) services.HoneypotService {
		return NewLDAPHoneypot(name, host, port, el, ds, prof)
	}
}

func (s *LDAPHoneypot) PortNameHost() string {
	return s.baseService.PortNameHost()
}
