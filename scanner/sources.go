package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Helper to fetch URL content
func fetchURL(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func RunCrtsh(domain, tempDir string, results chan<- string) {
	fmt.Println("[*] Querying crt.sh...")
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	body, err := fetchURL(url)
	if err != nil {
		fmt.Printf("[!] crt.sh error: %v\n", err)
		return
	}

	// Simple regex extract to avoid struct definitions for dynamic JSON
	// The shell script used grep, we can use regex too for robustness against schema changes
	re := regexp.MustCompile(`"name_value":\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	for _, match := range matches {
		if len(match) > 1 {
			// Split explicitly by newline as crt.sh can return multi-line values
			lines := strings.Split(match[1], "\n")
			for _, line := range lines {
				if strings.Contains(line, domain) && !strings.Contains(line, "*") {
					results <- strings.TrimSpace(line)
				}
			}
		}
	}
	fmt.Println(" -> crt.sh done.")
}

func RunHackerTarget(domain, tempDir string, results chan<- string) {
	fmt.Println("[*] Querying HackerTarget...")
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	body, err := fetchURL(url)
	if err != nil {
		fmt.Printf("[!] HackerTarget error: %v\n", err)
		return
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			sub := parts[0]
			if strings.Contains(sub, domain) {
				results <- sub
			}
		}
	}
	fmt.Println(" -> HackerTarget done.")
}

func RunAlienVault(domain, tempDir string, results chan<- string) {
	fmt.Println("[*] Querying AlienVault...")
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	body, err := fetchURL(url)
	if err != nil {
		fmt.Printf("[!] AlienVault error: %v\n", err)
		return
	}

	// Regex for hostname
	re := regexp.MustCompile(`"hostname":\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	for _, match := range matches {
		if len(match) > 1 {
			if strings.Contains(match[1], domain) {
				results <- match[1]
			}
		}
	}
	fmt.Println(" -> AlienVault done.")
}

func RunRapidDNS(domain, tempDir string, results chan<- string) {
	fmt.Println("[*] Querying RapidDNS...")
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
	body, err := fetchURL(url)
	if err != nil {
		fmt.Printf("[!] RapidDNS error: %v\n", err)
		return
	}

	// Extract from table cells
	re := regexp.MustCompile(`<td>\s*([^<]+)\s*</td>`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	for _, match := range matches {
		if len(match) > 1 {
			sub := strings.TrimSpace(match[1])
			if strings.Contains(sub, domain) && !strings.Contains(sub, "*") {
				results <- sub
			}
		}
	}
	fmt.Println(" -> RapidDNS done.")
}

func RunAnubis(domain, tempDir string, results chan<- string) {
    fmt.Println("[*] Querying AnubisDB...")
    url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
    body, err := fetchURL(url)
    if err != nil {
        fmt.Printf("[!] AnubisDB error: %v\n", err)
        return
    }

    var subs []string
    if err := json.Unmarshal(body, &subs); err == nil {
        for _, sub := range subs {
             if strings.Contains(sub, domain) {
                results <- sub
            }
        }
    } else {
        // Fallback regex if array parse fails (Anubis sometimes returns different structures)
        re := regexp.MustCompile(`"([^"]+)"`)
        matches := re.FindAllStringSubmatch(string(body), -1)
        for _, match := range matches {
             if len(match) > 1 {
                 if strings.Contains(match[1], domain) {
                    results <- match[1]
                 }
             }
        }
    }
    fmt.Println(" -> AnubisDB done.")
}

func RunWayback(domain, tempDir string, results chan<- string) {
    fmt.Println("[*] Querying Wayback Machine...")
    url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", domain)
    
    // This can be huge, maybe stream it? For now, fetch all.
    body, err := fetchURL(url)
    if err != nil {
        fmt.Printf("[!] Wayback error: %v\n", err)
        return
    }

    lines := strings.Split(string(body), "\n")
    for _, line := range lines {
        // Extract domain from URL
        // Simple heuristic: split by / and take 3rd part (protocol://domain/...)
        parts := strings.Split(line, "/")
        if len(parts) >= 3 {
            sub := parts[2]
            // Remove port if present
            sub = strings.Split(sub, ":")[0]
             if strings.Contains(sub, domain) {
                results <- sub
            }
        }
    }
     fmt.Println(" -> Wayback Machine done.")
}

func RunGithub(domain, token string, results chan<- string) {
      fmt.Println("[*] Querying GitHub API...")
      // Basic implementation - requires pagination for real usage, but keeping it simple as per shell script
      url := fmt.Sprintf("https://api.github.com/search/code?q=%s", domain)
      req, _ := http.NewRequest("GET", url, nil)
      req.Header.Set("Authorization", "token "+token)
      
      client := &http.Client{}
      resp, err := client.Do(req)
      if err != nil {
          return
      }
      defer resp.Body.Close()
      
      body, _ := io.ReadAll(resp.Body)
      
      // Regex search in JSON
      re := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain))
      matches := re.FindAllString(string(body), -1)
      
      for _, match := range matches {
          results <- match
      }
      fmt.Println(" -> GitHub API done.")
}
