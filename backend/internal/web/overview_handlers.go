package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"honeypot-orchestrator/backend/internal/database"
	"honeypot-orchestrator/backend/internal/profiles"
	"honeypot-orchestrator/backend/internal/services"
)

type CSRFResponse struct {
	CSRFToken string `json:"csrf_token"`
}

type ProfileDetail struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Services    []string `json:"services"`
}

type ProfileStatus struct {
	Current   ProfileDetail   `json:"current"`
	Available []ProfileDetail `json:"available"`
}

type WebStatus struct {
	Host        string `json:"host"`
	DisplayHost string `json:"display_host"`
	Port        int    `json:"port"`
}

type SystemStatusResponse struct {
	Services []services.WebServiceStatus `json:"services"`
	Profile  ProfileStatus               `json:"profile"`
	LogPath  string                      `json:"log_path"`
	Web      WebStatus                   `json:"web"`
}

func (s *Server) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	JSONResponse(w, http.StatusOK, map[string]interface{}{"ok": true, "service": "web"})
}

func (s *Server) HandleCSRF(w http.ResponseWriter, r *http.Request) {
	token := generateToken(16)
	now := time.Now()

	s.csrfMu.Lock()
	s.csrfTokens[token] = now
	for k, v := range s.csrfTokens {
		if now.Sub(v) > 24*time.Hour {
			delete(s.csrfTokens, k)
		}
	}
	s.csrfMu.Unlock()

	JSONResponse(w, http.StatusOK, CSRFResponse{CSRFToken: token})
}

func getDisplayHost(r *http.Request) string {
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return r.Host
}

func (s *Server) getActiveProfileName(ctx context.Context) string {
	val, err := s.db.GetSystemSetting(ctx, "orchestrator_state")
	if err != nil {
		return s.config.Profile
	}
	var state map[string]interface{}
	if err := json.Unmarshal([]byte(val), &state); err == nil {
		if prof, ok := state["active_profile"].(string); ok {
			return prof
		}
	}
	return s.config.Profile
}

func (s *Server) getRunningServices(ctx context.Context) map[string]bool {
	running := make(map[string]bool)
	val, err := s.db.GetSystemSetting(ctx, "orchestrator_state")
	if err == nil {
		var state map[string]interface{}
		if err := json.Unmarshal([]byte(val), &state); err == nil {
			if list, ok := state["running_services"].([]interface{}); ok {
				for _, item := range list {
					if name, ok := item.(string); ok {
						running[name] = true
					}
				}
			}
		}
	}
	return running
}

func (s *Server) HandleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	displayHost := getDisplayHost(r)
	activeProfileName := s.getActiveProfileName(ctx)
	prof := profiles.GetProfile(activeProfileName)

	var available []ProfileDetail
	for _, p := range profiles.Profiles {
		available = append(available, ProfileDetail{
			Name:        p.Name,
			DisplayName: p.DisplayName,
			Services:    p.Services,
		})
	}

	JSONResponse(w, http.StatusOK, SystemStatusResponse{
		Services: s.orch.GetServicesStatus(displayHost),
		Profile: ProfileStatus{
			Current: ProfileDetail{
				Name:        prof.Name,
				DisplayName: prof.DisplayName,
				Services:    prof.Services,
			},
			Available: available,
		},
		LogPath: s.config.Logging.Path,
		Web: WebStatus{
			Host:        s.config.Web.Host,
			DisplayHost: displayHost,
			Port:        s.config.Web.Port,
		},
	})
}

func safeInt(val string, def, min, max int) int {
	if val == "" {
		return def
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	if i < min {
		return min
	}
	if i > max {
		return max
	}
	return i
}

func buildFilterSQL(queryValues map[string][]string) (string, []interface{}) {
	var conds []string
	var args []interface{}
	argIdx := 1

	serviceFilter := ""
	if vals := queryValues["service"]; len(vals) > 0 {
		serviceFilter = strings.TrimSpace(strings.ToLower(vals[0]))
	}
	eventFilter := ""
	if vals := queryValues["event_type"]; len(vals) > 0 {
		eventFilter = strings.TrimSpace(strings.ToLower(vals[0]))
	}
	excludeSystem := false
	if vals := queryValues["exclude_system"]; len(vals) > 0 {
		excludeSystem = vals[0] == "true"
	}
	searchQuery := ""
	if vals := queryValues["search"]; len(vals) > 0 {
		searchQuery = strings.TrimSpace(strings.ToLower(vals[0]))
	}
	searchField := ""
	if vals := queryValues["search_field"]; len(vals) > 0 {
		searchField = strings.TrimSpace(strings.ToLower(vals[0]))
	}

	if serviceFilter != "" {
		conds = append(conds, fmt.Sprintf("service = $%d", argIdx))
		args = append(args, serviceFilter)
		argIdx++
	}
	if eventFilter != "" {
		conds = append(conds, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, eventFilter)
		argIdx++
	}
	if excludeSystem {
		conds = append(conds, "src_ip IS NOT NULL AND src_ip != '127.0.0.1' AND src_ip != '::1' AND src_ip != 'localhost' AND src_ip != 'unknown'")
	}

	if searchQuery != "" {
		// Only treat as regex if the query contains actual regex special characters
		regexSpecials := strings.ContainsAny(searchQuery, `[]()*+?{}|\^$`)
		isRegex := false
		if regexSpecials {
			if _, err := regexp.Compile(searchQuery); err == nil {
				isRegex = true
			}
		}

		var searchCond string
		if isRegex {
			if searchField == "src_ip" {
				searchCond = fmt.Sprintf("src_ip ~* $%d", argIdx)
			} else if searchField == "summary" {
				searchCond = fmt.Sprintf("summary ~* $%d", argIdx)
			} else if searchField == "service" {
				searchCond = fmt.Sprintf("service ~* $%d", argIdx)
			} else if searchField == "event_type" {
				searchCond = fmt.Sprintf("event_type ~* $%d", argIdx)
			} else if searchField == "profile" {
				searchCond = fmt.Sprintf("details->>'profile' ~* $%d", argIdx)
			} else {
				searchCond = fmt.Sprintf("(summary ~* $%d OR src_ip ~* $%d OR service ~* $%d OR event_type ~* $%d OR details->>'profile' ~* $%d)", argIdx, argIdx, argIdx, argIdx, argIdx)
			}
			args = append(args, searchQuery)
		} else {
			likeVal := "%" + searchQuery + "%"
			if searchField == "src_ip" {
				searchCond = fmt.Sprintf("src_ip ILIKE $%d", argIdx)
			} else if searchField == "summary" {
				searchCond = fmt.Sprintf("summary ILIKE $%d", argIdx)
			} else if searchField == "service" {
				searchCond = fmt.Sprintf("service ILIKE $%d", argIdx)
			} else if searchField == "event_type" {
				searchCond = fmt.Sprintf("event_type ILIKE $%d", argIdx)
			} else if searchField == "profile" {
				searchCond = fmt.Sprintf("details->>'profile' ILIKE $%d", argIdx)
			} else {
				searchCond = fmt.Sprintf("(summary ILIKE $%d OR src_ip ILIKE $%d OR service ILIKE $%d OR event_type ILIKE $%d OR details->>'profile' ILIKE $%d)", argIdx, argIdx, argIdx, argIdx, argIdx)
			}
			args = append(args, likeVal)
		}
		conds = append(conds, searchCond)
		argIdx++
	}

	whereClause := ""
	if len(conds) > 0 {
		whereClause = strings.Join(conds, " AND ")
	}
	return whereClause, args
}

func formatEventMap(evt database.Event) map[string]interface{} {
	eventData := map[string]interface{}{
		"id":         evt.ID,
		"timestamp":  evt.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"),
		"service":    evt.Service,
		"event_type": evt.EventType,
		"src_ip":     evt.SrcIP,
		"src_port":   evt.SrcPort,
		"summary":    evt.Summary,
		"src_mac":    "N/A",
	}
	if evt.SrcIP != nil {
		eventData["src_mac"] = ResolveMAC(*evt.SrcIP)
	}
	if len(evt.Details) > 0 {
		var detailsMap map[string]interface{}
		if err := json.Unmarshal(evt.Details, &detailsMap); err == nil {
			for k, v := range detailsMap {
				if k != "id" && k != "timestamp" && k != "service" && k != "event_type" && k != "src_ip" && k != "src_port" && k != "summary" {
					eventData[k] = v
				}
			}
		}
	}
	return eventData
}

func (s *Server) getCachedStats(ctx context.Context) map[string]interface{} {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	if s.statsCache != nil && time.Since(s.statsLastUpdate) < 10*time.Second {
		return s.statsCache
	}

	var totalRecent int
	_ = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&totalRecent)

	byService := make(map[string]int)
	sRows, err := s.db.Pool.Query(ctx, "SELECT service, COUNT(*) FROM events GROUP BY service")
	if err == nil {
		for sRows.Next() {
			var svc string
			var count int
			if err := sRows.Scan(&svc, &count); err == nil && svc != "" {
				byService[svc] = count
			}
		}
		sRows.Close()
	}

	byType := make(map[string]int)
	tRows, err := s.db.Pool.Query(ctx, "SELECT event_type, COUNT(*) FROM events GROUP BY event_type")
	if err == nil {
		for tRows.Next() {
			var evType string
			var count int
			if err := tRows.Scan(&evType, &count); err == nil && evType != "" {
				byType[evType] = count
			}
		}
		tRows.Close()
	}

	suspWhere := "src_ip IS NOT NULL AND src_ip != '127.0.0.1' AND src_ip != '::1' AND src_ip != 'localhost' AND src_ip != 'unknown'"
	var totalSuspicious int
	_ = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE "+suspWhere).Scan(&totalSuspicious)

	since24h := time.Now().UTC().Add(-24 * time.Hour)
	ipQuery := `
		SELECT src_ip, COUNT(*) FROM events
		WHERE timestamp >= $1
		  AND src_ip IS NOT NULL
		  AND src_ip != '127.0.0.1'
		  AND src_ip != '::1'
		  AND src_ip != 'localhost'
		  AND src_ip != 'unknown'
		GROUP BY src_ip
		ORDER BY COUNT(*) DESC
		LIMIT 200
	`
	ipTotals := make(map[string]int)
	var topIP string
	var maxCount int
	var topIPsList []string

	ipRows, err := s.db.Pool.Query(ctx, ipQuery, since24h)
	if err == nil {
		for ipRows.Next() {
			var ip string
			var count int
			if err := ipRows.Scan(&ip, &count); err == nil && ip != "" {
				ipTotals[ip] = count
				topIPsList = append(topIPsList, ip)
				if count > maxCount {
					maxCount = count
					topIP = ip
				}
			}
		}
		ipRows.Close()
	}

	topMac := "N/A"
	topIPBlocked := false
	if topIP != "" {
		topMac = ResolveMAC(topIP)
		_ = s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM blacklist WHERE ip = $1)", topIP).Scan(&topIPBlocked)
	}

	geoResults := BulkLookup(topIPsList)
	var geoMarkers []map[string]interface{}
	seenCoords := make(map[string]bool)

	for _, ip := range topIPsList {
		info, ok := geoResults[ip]
		if !ok || (info.Lat == 0 && info.Lon == 0) {
			continue
		}
		coordKey := fmt.Sprintf("%.1f,%.1f", info.Lat, info.Lon)
		if seenCoords[coordKey] {
			continue
		}
		seenCoords[coordKey] = true

		geoMarkers = append(geoMarkers, map[string]interface{}{
			"ip":      ip,
			"lat":     info.Lat,
			"lon":     info.Lon,
			"country": info.Country,
			"city":    info.City,
			"count":   ipTotals[ip],
		})
	}

	s.statsCache = map[string]interface{}{
		"total_recent_events":     totalRecent,
		"suspicious_events_count": totalSuspicious,
		"by_service":              byService,
		"by_type":                 byType,
		"top_ip": func() interface{} {
			if topIP == "" {
				return nil
			}
			return topIP
		}(),
		"top_ip_count":   maxCount,
		"top_ip_mac":     topMac,
		"top_ip_blocked": topIPBlocked,
		"geo_markers":    geoMarkers,
	}
	s.statsLastUpdate = time.Now()
	return s.statsCache
}

func (s *Server) HandleEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queryVals := r.URL.Query()

	limitVal := queryVals.Get("limit")
	limit := safeInt(limitVal, 50, 1, 100000)
	if limitVal == "-1" {
		limit = -1
	}
	page := safeInt(queryVals.Get("page"), 1, 1, 10000000)

	whereClause, args := buildFilterSQL(queryVals)

	query := "SELECT id, timestamp, service, event_type, src_ip, src_port, summary, details FROM events"
	if whereClause != "" {
		query += " WHERE " + whereClause
	}
	query += " ORDER BY timestamp DESC"

	if limit != -1 {
		offset := (page - 1) * limit
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var evt database.Event
		if err := rows.Scan(&evt.ID, &evt.Timestamp, &evt.Service, &evt.EventType, &evt.SrcIP, &evt.SrcPort, &evt.Summary, &evt.Details); err != nil {
			log.Println("Error scanning event row:", err)
			continue
		}
		events = append(events, formatEventMap(evt))
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{"events": events})
}

func (s *Server) HandleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var totalRecent int
	err := s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&totalRecent)
	if err != nil {
		JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	byService := make(map[string]int)
	rows, err := s.db.Pool.Query(ctx, "SELECT service, COUNT(*) FROM events GROUP BY service")
	if err == nil {
		for rows.Next() {
			var svc string
			var count int
			if err := rows.Scan(&svc, &count); err == nil && svc != "" {
				byService[svc] = count
			}
		}
		rows.Close()
	}

	byType := make(map[string]int)
	rows, err = s.db.Pool.Query(ctx, "SELECT event_type, COUNT(*) FROM events GROUP BY event_type")
	if err == nil {
		for rows.Next() {
			var evType string
			var count int
			if err := rows.Scan(&evType, &count); err == nil && evType != "" {
				byType[evType] = count
			}
		}
		rows.Close()
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"total_recent_events": totalRecent,
		"by_service":          byService,
		"by_type":             byType,
	})
}

func (s *Server) HandleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	queryVals := r.URL.Query()
	displayHost := getDisplayHost(r)

	activeProfileName := s.getActiveProfileName(ctx)

	limitVal := queryVals.Get("limit")
	limit := safeInt(limitVal, 50, 1, 100000)
	if limitVal == "-1" {
		limit = -1
	}
	page := safeInt(queryVals.Get("page"), 1, 1, 10000000)

	whereClause, args := buildFilterSQL(queryVals)

	var events []map[string]interface{}
	eventsQuery := "SELECT id, timestamp, service, event_type, src_ip, src_port, summary, details FROM events"
	if whereClause != "" {
		eventsQuery += " WHERE " + whereClause
	}
	eventsQuery += " ORDER BY timestamp DESC"
	if limit != -1 {
		offset := (page - 1) * limit
		eventsQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	rows, err := s.db.Pool.Query(ctx, eventsQuery, args...)
	if err == nil {
		for rows.Next() {
			var evt database.Event
			if err := rows.Scan(&evt.ID, &evt.Timestamp, &evt.Service, &evt.EventType, &evt.SrcIP, &evt.SrcPort, &evt.Summary, &evt.Details); err == nil {
				events = append(events, formatEventMap(evt))
			}
		}
		rows.Close()
	}

	var stats map[string]interface{}

	if whereClause == "" {
		// Use cached stats for landing view to bypass expensive analytics queries
		cached := s.getCachedStats(ctx)
		stats = map[string]interface{}{
			"total_recent_events":     cached["total_recent_events"],
			"total_filtered":          cached["total_recent_events"], // no filter, same
			"suspicious_events_count": cached["suspicious_events_count"],
			"by_service":              cached["by_service"],
			"by_type":                 cached["by_type"],
			"top_ip":                  cached["top_ip"],
			"top_ip_count":            cached["top_ip_count"],
			"top_ip_mac":              cached["top_ip_mac"],
			"top_ip_blocked":          cached["top_ip_blocked"],
			"geo_markers":             cached["geo_markers"],
		}
	} else {
		// Dynamic query for filtered views
		var totalUnfiltered int
		_ = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&totalUnfiltered)

		var totalFiltered int
		countQuery := "SELECT COUNT(*) FROM events WHERE " + whereClause
		_ = s.db.Pool.QueryRow(ctx, countQuery, args...).Scan(&totalFiltered)

		byService := make(map[string]int)
		sRows, err := s.db.Pool.Query(ctx, "SELECT service, COUNT(*) FROM events GROUP BY service")
		if err == nil {
			for sRows.Next() {
				var svc string
				var count int
				if err := sRows.Scan(&svc, &count); err == nil && svc != "" {
					byService[svc] = count
				}
			}
			sRows.Close()
		}

		byType := make(map[string]int)
		tRows, err := s.db.Pool.Query(ctx, "SELECT event_type, COUNT(*) FROM events GROUP BY event_type")
		if err == nil {
			for tRows.Next() {
				var evType string
				var count int
				if err := tRows.Scan(&evType, &count); err == nil && evType != "" {
					byType[evType] = count
				}
			}
			tRows.Close()
		}

		suspWhere := "src_ip IS NOT NULL AND src_ip != '127.0.0.1' AND src_ip != '::1' AND src_ip != 'localhost' AND src_ip != 'unknown'"
		suspWhere = suspWhere + " AND " + whereClause
		var totalSuspicious int
		_ = s.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE "+suspWhere, args...).Scan(&totalSuspicious)

		since24h := time.Now().UTC().Add(-24 * time.Hour)
		ipQuery := `
			SELECT src_ip, COUNT(*) FROM events
			WHERE timestamp >= $1
			  AND src_ip IS NOT NULL
			  AND src_ip != '127.0.0.1'
			  AND src_ip != '::1'
			  AND src_ip != 'localhost'
			  AND src_ip != 'unknown'
			GROUP BY src_ip
			ORDER BY COUNT(*) DESC
			LIMIT 200
		`
		ipTotals := make(map[string]int)
		var topIP string
		var maxCount int
		var topIPsList []string

		ipRows, err := s.db.Pool.Query(ctx, ipQuery, since24h)
		if err == nil {
			for ipRows.Next() {
				var ip string
				var count int
				if err := ipRows.Scan(&ip, &count); err == nil && ip != "" {
					ipTotals[ip] = count
					topIPsList = append(topIPsList, ip)
					if count > maxCount {
						maxCount = count
						topIP = ip
					}
				}
			}
			ipRows.Close()
		}

		topMac := "N/A"
		topIPBlocked := false
		if topIP != "" {
			topMac = ResolveMAC(topIP)
			_ = s.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM blacklist WHERE ip = $1)", topIP).Scan(&topIPBlocked)
		}

		geoResults := BulkLookup(topIPsList)
		var geoMarkers []map[string]interface{}
		seenCoords := make(map[string]bool)

		for _, ip := range topIPsList {
			info, ok := geoResults[ip]
			if !ok || (info.Lat == 0 && info.Lon == 0) {
				continue
			}
			coordKey := fmt.Sprintf("%.1f,%.1f", info.Lat, info.Lon)
			if seenCoords[coordKey] {
				continue
			}
			seenCoords[coordKey] = true

			geoMarkers = append(geoMarkers, map[string]interface{}{
				"ip":      ip,
				"lat":     info.Lat,
				"lon":     info.Lon,
				"country": info.Country,
				"city":    info.City,
				"count":   ipTotals[ip],
			})
		}

		stats = map[string]interface{}{
			"total_recent_events":     totalUnfiltered,
			"total_filtered":          totalFiltered,
			"suspicious_events_count": totalSuspicious,
			"by_service":              byService,
			"by_type":                 byType,
			"top_ip": func() interface{} {
				if topIP == "" {
					return nil
				}
				return topIP
			}(),
			"top_ip_count":   maxCount,
			"top_ip_mac":     topMac,
			"top_ip_blocked": topIPBlocked,
			"geo_markers":    geoMarkers,
		}
	}

	prof := profiles.GetProfile(activeProfileName)
	var available []ProfileDetail
	for _, p := range profiles.Profiles {
		available = append(available, ProfileDetail{
			Name:        p.Name,
			DisplayName: p.DisplayName,
			Services:    p.Services,
		})
	}

	JSONResponse(w, http.StatusOK, map[string]interface{}{
		"services": s.orch.GetServicesStatus(displayHost),
		"profile": ProfileStatus{
			Current: ProfileDetail{
				Name:        prof.Name,
				DisplayName: prof.DisplayName,
				Services:    prof.Services,
			},
			Available: available,
		},
		"log_path":     s.config.Logging.Path,
		"generated_at": time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		"web": map[string]interface{}{
			"host":         s.config.Web.Host,
			"display_host": displayHost,
			"port":         s.config.Web.Port,
		},
		"events": events,
		"stats":  stats,
	})
}
