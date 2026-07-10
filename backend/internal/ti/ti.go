package ti

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type EnrichedAttacker struct {
	IP             string      `json:"ip"`
	RDNS           string      `json:"rdns"`
	ASN            string      `json:"asn"`
	Org            string      `json:"org"`
	Country        string      `json:"country"`
	CountryCode    string      `json:"countryCode"`
	City           string      `json:"city"`
	Lat            float64     `json:"lat"`
	Lon            float64     `json:"lon"`
	IsTor          bool        `json:"is_tor"`
	CloudProvider  string      `json:"cloud_provider"`
	AbuseScore     interface{} `json:"abuse_score"` // int or string ("N/A")
	GreyNoiseClass string      `json:"greynoise_class"`
}

type CloudNetwork struct {
	Provider string
	Network  *net.IPNet
}

var (
	cloudNetworks []CloudNetwork
	cloudOnce     sync.Once
)

var cloudCIDRs = map[string][]string{
	"AWS": {
		"3.0.0.0/8", "13.32.0.0/12", "13.48.0.0/13", "13.56.0.0/14",
		"15.177.0.0/16", "15.230.0.0/16", "18.0.0.0/8", "34.192.0.0/10",
		"35.152.0.0/13", "44.192.0.0/10", "50.16.0.0/14", "52.0.0.0/10",
		"54.64.0.0/10", "54.128.0.0/10", "54.192.0.0/10",
		"99.77.0.0/16", "99.150.0.0/16",
	},
	"GCP": {
		"8.34.208.0/20", "8.35.192.0/20", "23.236.48.0/20", "23.251.128.0/19",
		"34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/14",
		"35.196.0.0/15", "35.198.0.0/16", "35.199.0.0/17",
		"35.200.0.0/13", "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13",
		"104.196.0.0/14", "107.167.160.0/19", "107.178.192.0/18",
		"108.59.80.0/20", "108.170.192.0/18",
		"130.211.0.0/16", "146.148.0.0/17",
	},
	"Azure": {
		"13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14",
		"20.0.0.0/8", "23.96.0.0/13", "40.64.0.0/10",
		"51.104.0.0/14", "51.120.0.0/14", "52.96.0.0/12",
		"52.112.0.0/14", "52.120.0.0/14", "52.136.0.0/13",
		"52.148.0.0/14", "52.152.0.0/13", "52.160.0.0/11",
		"52.224.0.0/11", "65.52.0.0/14", "70.37.0.0/17",
		"104.40.0.0/13", "104.208.0.0/13", "137.116.0.0/15",
		"168.61.0.0/16", "168.62.0.0/15",
	},
	"DigitalOcean": {
		"64.225.0.0/16", "67.205.128.0/17", "68.183.0.0/16",
		"104.131.0.0/16", "104.236.0.0/16", "128.199.0.0/16",
		"134.122.0.0/16", "134.209.0.0/16", "137.184.0.0/16",
		"138.68.0.0/16", "138.197.0.0/16", "139.59.0.0/16",
		"142.93.0.0/16", "143.110.0.0/16", "143.198.0.0/16",
		"146.190.0.0/16", "157.230.0.0/16", "157.245.0.0/16",
		"159.65.0.0/16", "159.89.0.0/16", "159.203.0.0/16",
		"161.35.0.0/16", "162.243.0.0/16", "163.47.8.0/21",
		"164.90.0.0/16", "164.92.0.0/16", "165.22.0.0/16",
		"165.227.0.0/16", "167.71.0.0/16", "167.172.0.0/16",
		"170.64.0.0/16", "174.138.0.0/16", "178.128.0.0/16",
		"178.62.0.0/16", "188.166.0.0/16", "192.241.128.0/17",
		"198.199.64.0/18", "204.48.16.0/20", "206.189.0.0/16",
		"209.97.128.0/17",
	},
	"OVH": {
		"5.39.0.0/17", "5.135.0.0/16", "5.196.0.0/16",
		"37.59.0.0/16", "37.187.0.0/16", "46.105.0.0/16",
		"51.38.0.0/15", "51.68.0.0/15", "51.75.0.0/16",
		"51.77.0.0/16", "51.79.0.0/16", "51.81.0.0/16",
		"51.83.0.0/16", "51.89.0.0/16", "51.91.0.0/16",
		"51.161.0.0/16", "51.178.0.0/16", "51.195.0.0/16",
		"51.210.0.0/16", "51.254.0.0/15", "54.36.0.0/14",
		"91.134.0.0/16", "92.222.0.0/16", "135.125.0.0/16",
		"137.74.0.0/16", "141.94.0.0/16", "141.95.0.0/16",
		"144.217.0.0/16", "145.239.0.0/16", "147.135.0.0/16",
		"149.56.0.0/16", "151.80.0.0/16", "158.69.0.0/16",
		"164.132.0.0/16", "176.31.0.0/16", "178.32.0.0/15",
		"185.12.32.0/22", "188.165.0.0/16", "193.70.0.0/16",
		"198.27.64.0/18", "198.100.144.0/20",
		"213.186.32.0/19", "213.251.128.0/18",
	},
	"Linode": {
		"23.92.16.0/20", "23.239.0.0/18", "45.33.0.0/17",
		"45.56.64.0/18", "45.79.0.0/16", "50.116.0.0/18",
		"66.175.208.0/20", "66.228.32.0/19", "69.164.192.0/19",
		"72.14.176.0/20", "74.207.224.0/19", "85.159.208.0/21",
		"96.126.96.0/19", "97.107.128.0/20",
		"103.3.60.0/22", "109.74.192.0/20",
		"139.144.0.0/16", "139.162.0.0/16", "143.42.0.0/16",
		"172.104.0.0/15", "172.232.0.0/14",
		"173.230.128.0/19", "173.255.192.0/18",
		"178.79.128.0/17", "185.3.92.0/22",
		"192.155.80.0/20", "194.195.208.0/20",
		"198.58.96.0/19", "198.74.48.0/20",
	},
}

func initCloudNetworks() {
	cloudOnce.Do(func() {
		for provider, cidrs := range cloudCIDRs {
			for _, cidr := range cidrs {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err == nil {
					cloudNetworks = append(cloudNetworks, CloudNetwork{
						Provider: provider,
						Network:  ipnet,
					})
				}
			}
		}
	})
}

func MatchCloudProvider(ipStr string) string {
	initCloudNetworks()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for _, cn := range cloudNetworks {
		if cn.Network.Contains(ip) {
			return cn.Provider
		}
	}
	return ""
}

var (
	torExitNodes = make(map[string]bool)
	torLastFetch time.Time
	torMu        sync.RWMutex
)

func refreshTorExitNodes() {
	torMu.Lock()
	defer torMu.Unlock()

	if time.Since(torLastFetch) < 24*time.Hour && len(torExitNodes) > 0 {
		return
	}

	log.Println("[TI] Refreshing Tor Exit Nodes list...")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://check.torproject.org/torbulkexitlist")
	if err != nil {
		log.Printf("[TI] Failed to fetch Tor exit list: %v\n", err)
		if torLastFetch.IsZero() {
			torLastFetch = time.Now().Add(-23 * time.Hour) // Retry sooner (1 hour)
		}
		return
	}
	defer resp.Body.Close()

	newNodes := make(map[string]bool)
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			newNodes[line] = true
		}
		if err == io.EOF {
			break
		}
	}

	torExitNodes = newNodes
	torLastFetch = time.Now()
	log.Printf("[TI] Successfully loaded %d Tor Exit Nodes.\n", len(torExitNodes))
}

func IsTorExit(ipStr string) bool {
	go refreshTorExitNodes() // Trigger background refresh if stale

	torMu.RLock()
	defer torMu.RUnlock()
	return torExitNodes[ipStr]
}

func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127)
	}
	return ip.To16() != nil && (ip.To16()[0] == 0xfc || ip.To16()[0] == 0xfd)
}
