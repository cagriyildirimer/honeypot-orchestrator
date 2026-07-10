package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
)

func main() {
	apiURL := flag.String("url", "http://localhost/api/test/inject-event", "URL of the inject-event endpoint")
	flag.Parse()

	log.Printf("Starting Threat Intelligence Log Injection Utility...")
	log.Printf("Target Endpoint: %s\n", *apiURL)

	// List of test IPs to inject
	testEvents := []map[string]interface{}{
		{
			"service":    "ssh_windows",
			"event_type": "login_failed",
			"src_ip":     "185.220.101.5",
			"src_port":   52311,
			"summary":    "Failed login attempt for admin from Tor exit node",
			"username":   "admin",
		},
		{
			"service":    "mssql_windows",
			"event_type": "brute_force",
			"src_ip":     "45.143.203.14",
			"src_port":   1433,
			"summary":    "Brute force SQL login attack",
			"username":   "sa",
		},
		{
			"service":    "http_windows",
			"event_type": "port_scan",
			"src_ip":     "1.1.1.1",
			"src_port":   80,
			"summary":    "HTTP port scanning activity detected",
			"path":       "/wp-login.php",
		},
	}

	log.Println("\n--- Injecting simulated attacker events via Web API ---")
	client := &http.Client{}

	for _, evt := range testEvents {
		ip := evt["src_ip"].(string)
		service := evt["service"].(string)

		bodyBytes, err := json.Marshal(evt)
		if err != nil {
			log.Printf("Failed to marshal event: %v\n", err)
			continue
		}

		req, err := http.NewRequest("POST", *apiURL, bytes.NewBuffer(bodyBytes))
		if err != nil {
			log.Printf("Failed to create request: %v\n", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "HoneypotTestUtility/1.0")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("HTTP Request failed for IP %s: %v. (Check if backend/nginx is running and accessible)\n", ip, err)
			continue
		}
		defer resp.Body.Close()

		respBytes, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			log.Printf("[SUCCESS] Event logged for IP %s on service %s. API response: %s\n", ip, service, string(respBytes))
		} else {
			log.Printf("[FAILED] Failed to log event for IP %s. Status: %d, Response: %s\n", ip, resp.StatusCode, string(respBytes))
		}
	}

	log.Println("\nInjection process completed.")
	log.Println("1. Open your Web UI Dashboard in the browser.")
	log.Println("2. Look at the live logs/recent events list; the simulated events should appear immediately.")
	log.Println("3. Within 3 minutes, the honeypot-ti container will run its enrichment loop.")
	log.Println("4. Visit the Analyze page to view the enriched Threat Intelligence data!")
}
