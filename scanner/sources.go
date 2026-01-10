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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func RunCrtsh(domain, tempDir string, results chan<- string) {
	fmt.Println("[*] Querying crt.sh...")
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	body, err := fetchURL(url)
	if err != nil {
		return
	}

	re := regexp.MustCompile(`"name_value":\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	for _, match := range matches {
		if len(match) > 1 {
			lines := strings.Split(match[1], "\n")
			for _, line := range lines {
                line = strings.TrimPrefix(line, "*.") // Clean wildcards
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
		return
	}

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
		return
	}

	// More specific regex for RapidDNS table cells containing the domain
    re := regexp.MustCompile(`<td>\s*([a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain) + `)\s*</td>`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	for _, match := range matches {
		if len(match) > 1 {
			sub := strings.TrimSpace(match[1])
			if !strings.Contains(sub, "*") {
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

func RunThreatMiner(domain, tempDir string, results chan<- string) {
    fmt.Println("[*] Querying ThreatMiner...")
    url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", domain)
    body, err := fetchURL(url)
    if err != nil {
        return
    }

    re := regexp.MustCompile(`"results":\s*\[([^\]]+)\]`)
    match := re.FindStringSubmatch(string(body))
    if len(match) > 1 {
        // Extract individual results
        subRe := regexp.MustCompile(`"([^"]+)"`)
        subMatches := subRe.FindAllStringSubmatch(match[1], -1)
        for _, subMatch := range subMatches {
            if len(subMatch) > 1 {
                if strings.Contains(subMatch[1], domain) {
                    results <- subMatch[1]
                }
            }
        }
    }
    fmt.Println(" -> ThreatMiner done.")
}

func RunWayback(domain, tempDir string, results chan<- string) {
    fmt.Println("[*] Querying Wayback Machine...")
    url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", domain)
    
    body, err := fetchURL(url)
    if err != nil {
        return
    }

    // Improved regex to extract domain from various URL formats
    re := regexp.MustCompile(`(?i)https?://([^/:]+)`)
    matches := re.FindAllStringSubmatch(string(body), -1)
    
    for _, match := range matches {
        if len(match) > 1 {
            sub := strings.ToLower(match[1])
            if strings.Contains(sub, domain) {
                results <- sub
            }
        }
    }
     fmt.Println(" -> Wayback Machine done.")
}

func RunGithub(domain, token string, results chan<- string) {
      fmt.Println("[*] Querying GitHub API...")
      url := fmt.Sprintf("https://api.github.com/search/code?q=%s", domain)
      req, _ := http.NewRequest("GET", url, nil)
      req.Header.Set("Authorization", "token "+token)
      
      client := &http.Client{}
      resp, err := client.Do(req)
      if err != nil {
          return
      }
      defer resp.Body.Close()
      
      if resp.StatusCode != http.StatusOK {
          return
      }

      body, _ := io.ReadAll(resp.Body)
      
      re := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain))
      matches := re.FindAllString(string(body), -1)
      
      for _, match := range matches {
          results <- strings.ToLower(match)
      }
      fmt.Println(" -> GitHub API done.")
}

