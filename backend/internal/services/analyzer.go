package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type bazaarResponse struct {
	QueryStatus string `json:"query_status"`
	Data        []struct {
		Signature string   `json:"signature"`
		FileType  string   `json:"file_type"`
		Tags      []string `json:"tags"`
	} `json:"data"`
}

// AnalyzePayload performs local signature matching (offline) and MalwareBazaar API lookup (online)
func AnalyzePayload(fileName string, fileData []byte) (string, string) {
	if len(fileData) == 0 {
		return "Clean / Empty File", "No data to analyze."
	}

	// 1. Calculate SHA-256
	hasher := sha256.New()
	hasher.Write(fileData)
	sha256Sum := hex.EncodeToString(hasher.Sum(nil))

	// 2. Offline local signature scan using regex
	malwareType, details := scanLocalSignatures(fileName, fileData)

	// 3. Online lookup using MalwareBazaar API
	bazaarType, bazaarDetails, err := lookupMalwareBazaar(sha256Sum)
	if err == nil && bazaarType != "" {
		return bazaarType + " (MalwareBazaar)", fmt.Sprintf("Hash matched known malware in abuse.ch database. Tag: %s. Details: %s", bazaarType, bazaarDetails)
	}

	return malwareType, details
}

func scanLocalSignatures(fileName string, data []byte) (string, string) {
	content := string(data)
	contentLower := strings.ToLower(content)

	// Check binary headers
	if len(data) >= 4 {
		if string(data[:4]) == "\x7fELF" {
			return "ELF Linux Executable", "Linux compiled binary. Often used in IoT botnets like Mirai or Gafgyt."
		}
		if len(data) >= 2 && string(data[:2]) == "MZ" {
			return "PE Windows Executable", "Windows compiled binary. Often used in Windows trojans or ransomware."
		}
	}

	// Check for common web shell patterns
	phpShellRegex := regexp.MustCompile(`(?i)(eval|shell_exec|system|passthru|exec|fsockopen|pfsockopen)\s*\(\s*(base64_decode|\$_GET|\$_POST|\$_REQUEST)`)
	if phpShellRegex.MatchString(content) {
		return "PHP Webshell / Backdoor", "Detected obfuscated command execution pattern commonly used in PHP web backdoors (e.g. C99, R57)."
	}

	// Check for generic obfuscated eval execution
	evalRegex := regexp.MustCompile(`(?i)(eval|execute)\s*\(.*(base64_decode|frombase64string)`)
	if evalRegex.MatchString(content) {
		return "Obfuscated Script / Dropper", "Detected script utilizing encoding (base64) to hide execution payloads."
	}

	// Check for PowerShell downloaders
	powershellRegex := regexp.MustCompile(`(?i)(powershell|pwsh).*(downloadstring|downloadfile|new-object\s+net\.webclient)`)
	if powershellRegex.MatchString(contentLower) {
		return "PowerShell Downloader Script", "Detected PowerShell script attempting to download and run external payloads."
	}

	// Check for Unix reverse shells
	reverseShellRegex := regexp.MustCompile(`(?i)(bash\s+-i\s*>\s*&\s*/dev/tcp/|nc\s+-e\s+/bin/sh|nc\s+-e\s+/bin/bash)`)
	if reverseShellRegex.MatchString(contentLower) {
		return "Unix Reverse Shell Payload", "Detected network reverse connection command string designed to give shell access."
	}

	// General scripts
	if strings.HasPrefix(content, "#!/") {
		return "Unix Shell Script", "Executable shell script pattern detected."
	}

	return "Suspicious Raw Data", "Unknown file type containing unclassified payload data."
}

func lookupMalwareBazaar(sha256Sum string) (string, string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.PostForm("https://mb-api.abuse.ch/api/v1/", url.Values{
		"query": {"get_info"},
		"hash":  {sha256Sum},
	})
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("malwarebazaar responded with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var bazaar bazaarResponse
	if err := json.Unmarshal(body, &bazaar); err != nil {
		return "", "", err
	}

	if bazaar.QueryStatus == "ok" && len(bazaar.Data) > 0 {
		match := bazaar.Data[0]
		signature := match.Signature
		if signature == "" && len(match.Tags) > 0 {
			signature = match.Tags[0]
		}
		if signature == "" {
			signature = "Known Malware"
		}
		details := fmt.Sprintf("File Type: %s", match.FileType)
		if len(match.Tags) > 0 {
			details += fmt.Sprintf(" | Tags: %s", strings.Join(match.Tags, ", "))
		}
		return signature, details, nil
	}

	return "", "", fmt.Errorf("no match found in MalwareBazaar")
}
