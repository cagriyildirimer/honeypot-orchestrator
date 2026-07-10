package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"honeypot-orchestrator/backend/internal/config"
	"honeypot-orchestrator/backend/internal/database"
	"honeypot-orchestrator/backend/internal/ti"
)

func main() {
	configPath := flag.String("config", "../../config.yaml", "Path to config.yaml file")
	flag.Parse()

	log.Println("Starting Threat Intelligence Test Utility...")

	appCfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v\n", err)
	}

	db, err := database.Connect(context.Background(), appCfg.DBURL)
	if err != nil {
		log.Fatalf("Database connection failed: %v\n", err)
	}
	defer db.Close()

	// List of test IPs to inject and enrich
	testIPs := map[string]struct {
		service   string
		eventType string
		summary   string
	}{
		"185.220.101.5": {
			service:   "ssh_windows",
			eventType: "login_failed",
			summary:   "Failed login attempt for admin from Tor exit node",
		},
		"45.143.203.14": {
			service:   "mssql_windows",
			eventType: "brute_force",
			summary:   "Brute force SQL login attack",
		},
		"1.1.1.1": {
			service:   "http_windows",
			eventType: "port_scan",
			summary:   "HTTP port scanning activity detected",
		},
	}

	log.Println("\n--- Phase 1: Injecting fake attack logs into database ---")
	for ip, details := range testIPs {
		ipVal := ip
		portVal := 52311
		summaryVal := details.summary
		detailsBytes, _ := json.Marshal(map[string]interface{}{"note": "Test simulated event"})

		evt := &database.Event{
			Timestamp: time.Now().Add(-10 * time.Minute),
			Service:   details.service,
			EventType: details.eventType,
			SrcIP:     &ipVal,
			SrcPort:   &portVal,
			Summary:   &summaryVal,
			Details:   detailsBytes,
		}
		if err := db.InsertEvent(context.Background(), evt); err != nil {
			log.Printf("Failed to insert event for IP %s: %v\n", ip, err)
		} else {
			log.Printf("Inserted simulated attack event: IP=%s, Service=%s\n", ip, details.service)
		}
	}

	log.Println("\n--- Phase 2: Querying TI APIs (AbuseIPDB, GreyNoise, Tor, Cloud) ---")
	ips := []string{"185.220.101.5", "45.143.203.14", "1.1.1.1"}
	
	abuseKey := appCfg.ThreatIntel.AbuseIPDBKey
	greyKey := appCfg.ThreatIntel.GreyNoiseKey

	log.Printf("Loaded Keys: AbuseIPDB=%t (len=%d), GreyNoise=%t (len=%d)\n",
		abuseKey != "", len(abuseKey), greyKey != "", len(greyKey))

	results := ti.EnrichAttackerIPs(context.Background(), ips, abuseKey, greyKey)

	log.Println("\n--- Phase 3: Displaying results and writing to cache ---")
	for ip, details := range results {
		js, _ := json.MarshalIndent(details, "", "  ")
		fmt.Printf("IP: %s\n%s\n\n", ip, string(js))

		// Save directly to Cache DB so UI gets it immediately
		err := db.SaveThreatIntel(context.Background(), ip, string(js))
		if err != nil {
			log.Printf("Failed to cache result for IP %s: %v\n", ip, err)
		} else {
			log.Printf("Saved results for IP %s to database cache.\n", ip)
		}
	}

	log.Println("\nTI Test completed successfully. Open your dashboard in the browser and navigate to the Analyze page to view the threat intelligence panel with live statistics!")
}
