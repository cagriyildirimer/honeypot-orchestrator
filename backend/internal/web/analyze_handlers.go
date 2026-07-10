package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"honeypot-orchestrator/backend/internal/database"
)

// mapEventToMitre maps a honeypot event to a MITRE ATT&CK Technique ID.
// Returns the Technique ID (e.g. "T1110") or empty string if no mapping exists.
func mapEventToMitre(evt database.Event) string {
	service := strings.ToLower(evt.Service)
	eventType := strings.ToLower(evt.EventType)
	summary := ""
	if evt.Summary != nil {
		summary = strings.ToLower(*evt.Summary)
	}

	// Exclude system/orchestrator events and events without a valid source IP
	if evt.SrcIP == nil || *evt.SrcIP == "" {
		return ""
	}

	ip := *evt.SrcIP
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == "unknown" {
		return ""
	}

	if eventType == "service_started" || eventType == "service_stopped" || eventType == "network_tuning_applied" || eventType == "system_tuning" {
		return ""
	}

	// 1. Credential Access / Brute Force
	if eventType == "login_attempt" || eventType == "login_failed" || eventType == "brute_force" {
		return "T1110"
	}

	// 2. Execution / Command Interpreter
	if eventType == "command_execution" || eventType == "command" || eventType == "shell_command" || strings.Contains(summary, "command") || strings.Contains(summary, "exec") {
		return "T1059"
	}

	// 3. Initial Access / Exploit Public-Facing Application
	if eventType == "exploit_attempt" || eventType == "exploit" || eventType == "exploit_failed" || strings.Contains(summary, "exploit") || strings.Contains(summary, "vuln") {
		return "T1190"
	}

	// 4. Lateral Movement / Exploitation of Remote Services
	if (service == "smb_windows" || service == "rdp_windows") && (eventType == "connection_error" || eventType == "exploit_attempt") {
		return "T1210"
	}

	// 5. Discovery / Network Service Discovery (Default fallback for connection events)
	if eventType == "connection" || eventType == "connected" || eventType == "dns_query" || eventType == "query" || eventType == "search" ||
		service == "dns_windows" || service == "llmnr_windows" || service == "nbtnns_windows" || service == "netbios_windows" ||
		service == "ldap_windows" || service == "ldaps_windows" || service == "rpc_windows" {
		return "T1046"
	}

	return ""
}

// HandleAnalyze handles the GET /api/analyze endpoint.
func (s *Server) HandleAnalyze(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Query last 5000 events from the database
	query := `
		SELECT id, timestamp, service, event_type, src_ip, src_port, summary, details 
		FROM events 
		ORDER BY timestamp DESC 
		LIMIT 5000
	`
	rows, err := s.db.Pool.Query(ctx, query)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	var events []database.Event
	for rows.Next() {
		var evt database.Event
		if err := rows.Scan(&evt.ID, &evt.Timestamp, &evt.Service, &evt.EventType, &evt.SrcIP, &evt.SrcPort, &evt.Summary, &evt.Details); err == nil {
			events = append(events, evt)
		}
	}

	// 1. MITRE ATT&CK Matrix Aggregation
	techniquesCounts := map[string]int{
		"T1110": 0,
		"T1190": 0,
		"T1046": 0,
		"T1059": 0,
		"T1210": 0,
	}

	tacticAttackers := map[string]map[string]int{
		"Initial Access":    make(map[string]int),
		"Execution":         make(map[string]int),
		"Credential Access": make(map[string]int),
		"Discovery":         make(map[string]int),
		"Lateral Movement":  make(map[string]int),
	}

	var ips []string
	ipSet := make(map[string]bool)

	for _, evt := range events {
		techID := mapEventToMitre(evt)
		if techID != "" {
			techniquesCounts[techID]++
			tacticName := ""
			switch techID {
			case "T1110":
				tacticName = "Credential Access"
			case "T1190":
				tacticName = "Initial Access"
			case "T1046":
				tacticName = "Discovery"
			case "T1059":
				tacticName = "Execution"
			case "T1210":
				tacticName = "Lateral Movement"
			}

			if tacticName != "" && evt.SrcIP != nil {
				tacticAttackers[tacticName][*evt.SrcIP]++
			}
		}

		if evt.SrcIP != nil && *evt.SrcIP != "" {
			ip := *evt.SrcIP
			if ip != "127.0.0.1" && ip != "::1" && ip != "localhost" && ip != "unknown" {
				ips = append(ips, ip)
				ipSet[ip] = true
			}
		}
	}

	// Bulk GeoIP Lookup
	var uniqueIPs []string
	for ip := range ipSet {
		uniqueIPs = append(uniqueIPs, ip)
	}
	geoData := BulkLookup(uniqueIPs)

	// Country breakdown aggregation
	countryCounts := make(map[string]map[string]interface{})
	for _, ip := range ips {
		info, ok := geoData[ip]
		countryName := "Unknown"
		countryCode := "XX"
		if ok {
			if info.Country != "" {
				countryName = info.Country
			}
			if info.CountryCode != "" {
				countryCode = info.CountryCode
			}
		}
		key := countryName + "_" + countryCode
		if _, exists := countryCounts[key]; !exists {
			countryCounts[key] = map[string]interface{}{
				"country":      countryName,
				"country_code": countryCode,
				"count":        0,
			}
		}
		countryCounts[key]["count"] = countryCounts[key]["count"].(int) + 1
	}

	// Sort country breakdown
	countryList := make([]map[string]interface{}, 0)
	for _, data := range countryCounts {
		countryList = append(countryList, data)
	}
	sort.Slice(countryList, func(i, j int) bool {
		return countryList[i]["count"].(int) > countryList[j]["count"].(int)
	})
	if len(countryList) > 15 {
		countryList = countryList[:15]
	}

	// 3. Threat Timeline (Hourly volumes in the last 24 hours)
	now := time.Now().UTC()
	type TimelineBucket struct {
		Hour      string `json:"hour"`
		DateHour  string `json:"date_hour"`
		Timestamp int64  `json:"timestamp"`
		Count     int    `json:"count"`
	}

	timelineBuckets := make([]TimelineBucket, 24)
	for i := 0; i < 24; i++ {
		t := now.Add(time.Duration(-23+i) * time.Hour)
		timelineBuckets[i] = TimelineBucket{
			Hour:      t.Format("15:00"),
			DateHour:  t.Format("01-02 15:00"),
			Timestamp: t.Truncate(time.Hour).Unix(),
			Count:     0,
		}
	}

	for _, evt := range events {
		diff := now.Sub(evt.Timestamp)
		hoursAgo := int(diff.Hours())
		if hoursAgo >= 0 && hoursAgo < 24 {
			timelineBuckets[23-hoursAgo].Count++
		}
	}

	// Format tactic attackers payload
	type AttackerCount struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}
	tacticAttackersPayload := make(map[string][]AttackerCount)
	for tacticName, counter := range tacticAttackers {
		list := make([]AttackerCount, 0)
		for ip, count := range counter {
			list = append(list, AttackerCount{IP: ip, Count: count})
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Count > list[j].Count
		})
		if len(list) > 5 {
			list = list[:5]
		}
		tacticAttackersPayload[tacticName] = list
	}

	// MITRE tactics & techniques lists
	type TacticInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	tacticsList := []TacticInfo{
		{Name: "Initial Access", Description: "Tactic used by adversaries to gain an initial foothold within a network."},
		{Name: "Execution", Description: "Tactic representing techniques that result in adversary-controlled code running on a local or remote system."},
		{Name: "Credential Access", Description: "Tactic used for stealing credentials like usernames and passwords."},
		{Name: "Discovery", Description: "Tactic representing techniques used to gain knowledge about the system and internal network."},
		{Name: "Lateral Movement", Description: "Tactic representing techniques used to enter and control remote systems on a network."},
	}

	type TechniqueInfo struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Tactic      string `json:"tactic"`
		Description string `json:"description"`
		Count       int    `json:"count"`
	}
	techniquesList := []TechniqueInfo{
		{ID: "T1110", Name: "Brute Force", Tactic: "Credential Access", Description: "Adversaries may use brute force techniques (e.g., login attempts in SSH, FTP, HTTP, Telnet, MSSQL, SMB) to gain access to accounts.", Count: techniquesCounts["T1110"]},
		{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access", Description: "Adversaries may attempt to exploit vulnerabilities in public-facing web or service applications (e.g., exploit payloads in HTTP, HTTP vulnerability scans).", Count: techniquesCounts["T1190"]},
		{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery", Description: "Adversaries may attempt to get a listing of services and open ports (e.g., connections, port scans, DNS/NetBIOS/LLMNR queries, LDAP directory searches).", Count: techniquesCounts["T1046"]},
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", Description: "Adversaries may use command and scripting interpreters to execute commands on the host (e.g., SSH/Telnet shell commands, SQL query execution, script running).", Count: techniquesCounts["T1059"]},
		{ID: "T1210", Name: "Exploitation of Remote Services", Tactic: "Lateral Movement", Description: "Adversaries may exploit remote services to gain unauthorized access (e.g., SMB/RDP remote exploitation attempts, unauthorized remote desktop connections).", Count: techniquesCounts["T1210"]},
	}

	payload := map[string]interface{}{
		"tactics":               tacticsList,
		"techniques":            techniquesList,
		"country_breakdown":     countryList,
		"timeline":              timelineBuckets,
		"tactic_attackers":      tacticAttackersPayload,
		"total_events_analyzed": len(events),
	}

	JSONResponse(w, http.StatusOK, payload)
}
