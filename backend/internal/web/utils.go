package web

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	PBKDF2Iterations = 600000
	SaltLength       = 16
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hashBytes := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, 32, sha256.New)
	saltHex := hex.EncodeToString(salt)
	hashHex := hex.EncodeToString(hashBytes)

	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", PBKDF2Iterations, saltHex, hashHex), nil
}

func VerifyPassword(password, hashed string) bool {
	if !strings.HasPrefix(hashed, "pbkdf2_sha256$") {
		return password == hashed
	}

	parts := strings.Split(hashed, "$")
	if len(parts) != 4 {
		return false
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}

	expectedHash, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}

	actualHash := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}

func JSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func DecodeJSON(r *http.Request, dst interface{}) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

var (
	arpCache    = make(map[string]string)
	arpCacheMu  sync.RWMutex
	lastArpLoad time.Time
)

func loadArpTable() {
	arpCacheMu.Lock()
	defer arpCacheMu.Unlock()

	if time.Since(lastArpLoad) < 10*time.Second {
		return
	}
	lastArpLoad = time.Now()
	arpCache = make(map[string]string)

	var out []byte
	var err error
	if runtime.GOOS == "windows" {
		out, err = exec.Command("arp", "-a").Output()
	} else {
		if data, err := os.ReadFile("/proc/net/arp"); err == nil {
			lines := strings.Split(string(data), "\n")
			if len(lines) > 1 {
				for _, line := range lines[1:] {
					parts := strings.Fields(line)
					if len(parts) >= 4 {
						ip := parts[0]
						mac := strings.ToLower(parts[3])
						if mac != "00:00:00:00:00:00" {
							arpCache[ip] = mac
						}
					}
				}
				return
			}
		}
		out, err = exec.Command("arp", "-n").Output()
	}

	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			ip := parts[0]
			mac := strings.ToLower(parts[1])
			if strings.Count(ip, ".") == 3 {
				mac = strings.ReplaceAll(mac, "-", ":")
				arpCache[ip] = mac
			}
		}
	}
}

func ResolveMAC(ip string) string {
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" || ip == "unknown" || ip == "" {
		return "N/A"
	}
	loadArpTable()

	arpCacheMu.RLock()
	defer arpCacheMu.RUnlock()
	if mac, ok := arpCache[ip]; ok {
		return mac
	}
	return "unknown"
}

type GeoIPInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	ASN         string  `json:"asn"`
	Org         string  `json:"org"`
}

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

var (
	geoCache   = make(map[string]GeoIPInfo)
	geoCacheMu sync.RWMutex
)

func isPrivateIP(ip string) bool {
	privatePrefixes := []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.", "192.168.", "127.", "0.", "::1"}
	for _, p := range privatePrefixes {
		if strings.HasPrefix(ip, p) {
			return true
		}
	}
	return ip == "unknown" || ip == "localhost" || ip == ""
}

func BulkLookup(ips []string) map[string]GeoIPInfo {
	results := make(map[string]GeoIPInfo)
	var toFetch []string

	for _, ip := range ips {
		if isPrivateIP(ip) {
			results[ip] = GeoIPInfo{Country: "Private", CountryCode: "XX"}
			continue
		}

		geoCacheMu.RLock()
		cached, ok := geoCache[ip]
		geoCacheMu.RUnlock()
		if ok && cached.Country != "Unknown" && cached.Country != "" {
			results[ip] = cached
		} else {
			toFetch = append(toFetch, ip)
		}
	}

	if len(toFetch) == 0 {
		return results
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}

	for i := 0; i < len(toFetch); i += 100 {
		end := i + 100
		if end > len(toFetch) {
			end = len(toFetch)
		}
		batch := toFetch[i:end]

		var queries []ipApiQuery
		for _, ip := range batch {
			queries = append(queries, ipApiQuery{
				Query:  ip,
				Fields: "status,query,country,countryCode,city,lat,lon,isp,as,org",
			})
		}

		payload, err := json.Marshal(queries)
		if err != nil {
			continue
		}

		req, err := http.NewRequest("POST", "http://ip-api.com/batch", bytes.NewBuffer(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "HoneypotOrchestrator/1.0")

		resp, err := httpClient.Do(req)
		if err != nil {
			for _, ip := range batch {
				results[ip] = GeoIPInfo{Country: "Unknown", CountryCode: "XX"}
			}
			continue
		}

		var apiResponses []ipApiResponse
		err = json.NewDecoder(resp.Body).Decode(&apiResponses)
		resp.Body.Close()

		if err != nil {
			for _, ip := range batch {
				results[ip] = GeoIPInfo{Country: "Unknown", CountryCode: "XX"}
			}
			continue
		}

		geoCacheMu.Lock()
		for _, entry := range apiResponses {
			ip := entry.Query
			if entry.Status == "success" {
				asnParts := strings.Split(entry.AS, " ")
				asn := ""
				if len(asnParts) > 0 {
					asn = asnParts[0]
				}
				res := GeoIPInfo{
					Country:     entry.Country,
					CountryCode: entry.CountryCode,
					Lat:         entry.Lat,
					Lon:         entry.Lon,
					City:        entry.City,
					ISP:         entry.ISP,
					ASN:         asn,
					Org:         entry.Org,
				}
				results[ip] = res
				if len(geoCache) >= 5000 {
					geoCache = make(map[string]GeoIPInfo)
				}
				geoCache[ip] = res
			} else {
				results[ip] = GeoIPInfo{Country: "Unknown", CountryCode: "XX"}
			}
		}
		geoCacheMu.Unlock()
	}

	// Secondary fallback for any remaining Unresolved/Unknown IPs using ipwho.is
	for _, ip := range toFetch {
		if res, ok := results[ip]; !ok || res.Country == "Unknown" {
			if singleRes, err := singleGeoIPLookup(httpClient, ip); err == nil && singleRes.Country != "" && singleRes.Country != "Unknown" {
				results[ip] = singleRes
				geoCacheMu.Lock()
				if len(geoCache) >= 5000 {
					geoCache = make(map[string]GeoIPInfo)
				}
				geoCache[ip] = singleRes
				geoCacheMu.Unlock()
			}
		}
	}

	return results
}

func singleGeoIPLookup(client *http.Client, ip string) (GeoIPInfo, error) {
	// Primary Fallback: ipwho.is (HTTPS)
	req, err := http.NewRequest("GET", "https://ipwho.is/"+ip, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HoneypotOrchestrator/1.0")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
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
				return GeoIPInfo{
					Country:     data.Country,
					CountryCode: data.CountryCode,
					Lat:         data.Latitude,
					Lon:         data.Longitude,
					City:        data.City,
					ISP:         data.Connection.ISP,
					ASN:         asnStr,
					Org:         data.Connection.Org,
				}, nil
			}
		}
	}

	// Secondary Fallback: ip-api.com (HTTP)
	req2, err := http.NewRequest("GET", "http://ip-api.com/json/"+ip+"?fields=status,country,countryCode,city,lat,lon,isp,as,org", nil)
	if err != nil {
		return GeoIPInfo{Country: "Unknown", CountryCode: "XX"}, err
	}
	req2.Header.Set("User-Agent", "HoneypotOrchestrator/1.0")
	resp2, err := client.Do(req2)
	if err != nil {
		return GeoIPInfo{Country: "Unknown", CountryCode: "XX"}, err
	}
	defer resp2.Body.Close()

	var data2 ipApiResponse
	if err := json.NewDecoder(resp2.Body).Decode(&data2); err != nil || data2.Status != "success" {
		return GeoIPInfo{Country: "Unknown", CountryCode: "XX"}, nil
	}
	asnParts := strings.Split(data2.AS, " ")
	asn := ""
	if len(asnParts) > 0 {
		asn = asnParts[0]
	}
	return GeoIPInfo{
		Country:     data2.Country,
		CountryCode: data2.CountryCode,
		Lat:         data2.Lat,
		Lon:         data2.Lon,
		City:        data2.City,
		ISP:         data2.ISP,
		ASN:         asn,
		Org:         data2.Org,
	}, nil
}

func generateToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
