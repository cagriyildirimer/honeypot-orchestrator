package ti

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"honeypot-orchestrator/backend/internal/config"
	"honeypot-orchestrator/backend/internal/database"
)

func StartWorker(ctx context.Context, db *database.DB, cfg *config.AppConfig) {
	log.Println("[TI WORKER] Starting Threat Intelligence background worker...")
	go runTIWorker(ctx, db, cfg)
}

func runTIWorker(ctx context.Context, db *database.DB, cfg *config.AppConfig) {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	// Initial run immediately on start
	analyzeAndEnrich(ctx, db, cfg)

	for {
		select {
		case <-ctx.Done():
			log.Println("[TI WORKER] Stopping background worker...")
			return
		case <-ticker.C:
			analyzeAndEnrich(ctx, db, cfg)
		}
	}
}

func analyzeAndEnrich(ctx context.Context, db *database.DB, cfg *config.AppConfig) {
	dbCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// 1. Get top active IP addresses in the last 24 hours
	cutoff := time.Now().Add(-24 * time.Hour)
	query := `
		SELECT src_ip, COUNT(*) as count 
		FROM events 
		WHERE src_ip IS NOT NULL AND src_ip != '' AND timestamp >= $1 
		GROUP BY src_ip 
		ORDER BY count DESC 
		LIMIT 50
	`

	rows, err := db.Pool.Query(dbCtx, query, cutoff)
	if err != nil {
		log.Printf("[TI WORKER] Error querying top IPs: %v\n", err)
		return
	}
	defer rows.Close()

	var candidateIPs []string
	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err == nil && ip != "" {
			if !IsPrivateIP(ip) {
				candidateIPs = append(candidateIPs, ip)
			}
		}
	}

	if len(candidateIPs) == 0 {
		return
	}

	// 2. Query cache to find which IPs are already cached and fresh
	cachedMap, err := db.GetThreatIntelBulk(dbCtx, candidateIPs)
	if err != nil {
		log.Printf("[TI WORKER] Error reading cache: %v\n", err)
		// Fallback to treat all as cache misses
		cachedMap = make(map[string]string)
	}

	var toEnrich []string
	for _, ip := range candidateIPs {
		if _, exists := cachedMap[ip]; !exists {
			toEnrich = append(toEnrich, ip)
		}
	}

	if len(toEnrich) == 0 {
		return
	}

	log.Printf("[TI WORKER] Enriched cache misses: %d candidate IPs, querying Threat Intel APIs...\n", len(toEnrich))

	// 3. Load AbuseIPDB and GreyNoise keys
	abuseKey := cfg.ThreatIntel.AbuseIPDBKey
	greyKey := cfg.ThreatIntel.GreyNoiseKey

	// Environment variable overrides
	if envAbuse := os.Getenv("HONEYPOT_TI_ABUSEIPDB_KEY"); envAbuse != "" {
		abuseKey = envAbuse
	}
	if envGrey := os.Getenv("HONEYPOT_TI_GREYNOISE_KEY"); envGrey != "" {
		greyKey = envGrey
	}

	// 4. Run enrichment
	enriched := EnrichAttackerIPs(dbCtx, toEnrich, abuseKey, greyKey)

	// 5. Save results back to threat_intel_cache
	for ip, details := range enriched {
		detailsBytes, err := json.Marshal(details)
		if err != nil {
			continue
		}
		if err := db.SaveThreatIntel(dbCtx, ip, string(detailsBytes)); err != nil {
			log.Printf("[TI WORKER] Error saving cache for IP %s: %v\n", ip, err)
		}
	}

	log.Printf("[TI WORKER] Successfully enriched and cached %d IPs.\n", len(enriched))
}
