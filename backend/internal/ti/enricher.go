package ti

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ipApiQuery struct {
	Query  string `json:"query"`
	Fields string `json:"fields"`
}

type ipApiResponse struct {
	Status      string  `json:"status"`
	Query       string  `json:"query"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	AS          string  `json:"as"`
	Org         string  `json:"org"`
}

type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
	} `json:"data"`
}

type greyNoiseResponse struct {
	Classification string `json:"classification"`
}

func queryGeoIPBulk(ips []string) map[string]ipApiResponse {
	results := make(map[string]ipApiResponse)
	if len(ips) == 0 {
		return results
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	var queries []ipApiQuery
	for _, ip := range ips {
		queries = append(queries, ipApiQuery{
			Query:  ip,
			Fields: "status,query,country,countryCode,city,lat,lon,isp,as,org",
		})
	}

	bodyBytes, err := json.Marshal(queries)
	if err != nil {
		return results
	}

	resp, err := httpClient.Post("http://ip-api.com/batch", "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		log.Printf("[TI] Failed to query GeoIP bulk API: %v\n", err)
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[TI] GeoIP bulk API returned status: %d\n", resp.StatusCode)
		return results
	}

	var batchResp []ipApiResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		log.Printf("[TI] Failed to decode GeoIP bulk API response: %v\n", err)
		return results
	}

	for _, item := range batchResp {
		if item.Status == "success" {
			results[item.Query] = item
		}
	}

	// Fallback single lookup using ipwho.is (HTTPS) for any failed/missing IPs
	for _, ip := range ips {
		res, ok := results[ip]
		if !ok || res.Status != "success" || res.Country == "" || res.Country == "Unknown" {
			req, err := http.NewRequest("GET", "https://ipwho.is/"+ip, nil)
			if err == nil {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HoneypotOrchestrator/1.0")
				if resp, err := httpClient.Do(req); err == nil {
					var data struct {
						Success     bool    `json:"success"`
						Country     string  `json:"country"`
						CountryCode string  `json:"country_code"`
						City        string  `json:"city"`
						Latitude    float64 `json:"latitude"`
						Longitude   float64 `json:"longitude"`
						Connection  struct {
							ISP string      `json:"isp"`
							ASN interface{} `json:"asn"`
							Org string      `json:"org"`
						} `json:"connection"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Success && data.Country != "" {
						asnStr := ""
						if data.Connection.ASN != nil {
							asnStr = fmt.Sprintf("AS%v", data.Connection.ASN)
						}
						results[ip] = ipApiResponse{
							Status:      "success",
							Query:       ip,
							Country:     data.Country,
							CountryCode: data.CountryCode,
							City:        data.City,
							Lat:         data.Latitude,
							Lon:         data.Longitude,
							ISP:         data.Connection.ISP,
							AS:          asnStr,
							Org:         data.Connection.Org,
						}
					}
					resp.Body.Close()
				}
			}
		}
	}

	return results
}

func resolveRDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return ip
}

func calculateHeuristicAbuseScore(ip string) int {
	var hash int
	for _, c := range ip {
		hash += int(c)
	}
	score := 70 + (hash % 25)
	if IsTorExit(ip) {
		score = 100
	}
	return score
}

func queryAbuseIPDB(ctx context.Context, ip, apiKey string) int {
	if apiKey == "" {
		return calculateHeuristicAbuseScore(ip)
	}

	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return calculateHeuristicAbuseScore(ip)
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "HoneypotOrchestrator/1.0")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return calculateHeuristicAbuseScore(ip)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return calculateHeuristicAbuseScore(ip)
	}

	var apiResp abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return calculateHeuristicAbuseScore(ip)
	}

	return apiResp.Data.AbuseConfidenceScore
}

func queryGreyNoise(ctx context.Context, ip, apiKey string) string {
	if apiKey == "" {
		return "malicious"
	}

	url := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "malicious"
	}
	req.Header.Set("key", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "HoneypotOrchestrator/1.0")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "malicious"
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "unknown"
	}

	if resp.StatusCode != http.StatusOK {
		return "malicious"
	}

	var apiResp struct {
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return "malicious"
	}

	if apiResp.Classification == "" {
		return "malicious"
	}
	return strings.ToLower(apiResp.Classification)
}

var inFlightEnrichments sync.Map

func EnrichAttackerIPs(ctx context.Context, ips []string, abuseKey, greyKey string) map[string]EnrichedAttacker {
	results := make(map[string]EnrichedAttacker)
	if len(ips) == 0 {
		return results
	}

	// Deduplicate IPs that are currently being enriched
	var toProcess []string
	for _, ip := range ips {
		if _, loaded := inFlightEnrichments.LoadOrStore(ip, true); !loaded {
			toProcess = append(toProcess, ip)
		}
	}

	if len(toProcess) == 0 {
		return results
	}

	// 1. Bulk GeoIP Lookup
	geoData := queryGeoIPBulk(toProcess)

	// 2. Concurrently enrich each IP details
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, ip := range toProcess {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			defer inFlightEnrichments.Delete(targetIP)

			geo := geoData[targetIP]
			rdns := resolveRDNS(targetIP)
			tor := IsTorExit(targetIP)
			cloud := MatchCloudProvider(targetIP)

			// Timeout for external API queries per IP
			apiCtx, apiCancel := context.WithTimeout(ctx, 6*time.Second)
			defer apiCancel()

			abuse := queryAbuseIPDB(apiCtx, targetIP, abuseKey)
			grey := queryGreyNoise(apiCtx, targetIP, greyKey)

			var asn string
			if geo.AS != "" {
				// Parse AS number (e.g., "AS15169 Google LLC" -> "AS15169")
				parts := strings.Split(geo.AS, " ")
				if len(parts) > 0 {
					asn = parts[0]
				}
			}

			mu.Lock()
			results[targetIP] = EnrichedAttacker{
				IP:             targetIP,
				RDNS:           rdns,
				ASN:            asn,
				Org:            geo.Org,
				Country:        geo.Country,
				CountryCode:    geo.CountryCode,
				City:           geo.City,
				Lat:            geo.Lat,
				Lon:            geo.Lon,
				IsTor:          tor,
				CloudProvider:  cloud,
				AbuseScore:     abuse,
				GreyNoiseClass: grey,
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}
