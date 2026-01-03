package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

func ScanDomain(domain string, config Config) {
	fmt.Printf("[+] Starting subdomain enumeration for: %s\n", domain)
	
	// Create directory
	safeDomain := domain // In real app, sanitization needed
	if err := os.MkdirAll(safeDomain, 0755); err != nil {
		fmt.Printf("[!] Error creating directory: %v\n", err)
		return
	}

	tempDir := filepath.Join(safeDomain, "temp_subs")
	os.MkdirAll(tempDir, 0755)
	defer os.RemoveAll(tempDir) // Cleanup on exit

	var wg sync.WaitGroup
	resultsChan := make(chan string, 1000)

	// List of runner functions
	runners := []func(string, string, chan<- string){
		RunCrtsh,
		RunHackerTarget,
		RunAlienVault,
		RunRapidDNS,
		RunAnubis,
		RunWayback, // Note: Wayback implementation needs care for large outputs
	}

	// We'll wrap external tool runners separately or here
	// External tools usually write to file or stdout.
	// For this plan, let's keep it simple: API sources stream to channel.
	
	for _, runner := range runners {
		wg.Add(1)
		go func(r func(string, string, chan<- string)) {
			defer wg.Done()
			r(domain, tempDir, resultsChan)
		}(runner)
	}

	// External Tools needing exec
	wg.Add(1)
	go func() {
		defer wg.Done()
		RunSubfinder(domain, resultsChan)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		RunAssetfinder(domain, resultsChan)
	}()
    
    // Amass is slow, maybe run parallel too
    wg.Add(1)
    go func() {
        defer wg.Done()
        RunAmass(domain, resultsChan)
    }()

    // Puredns
    wg.Add(1)
    go func() {
        defer wg.Done()
        RunPuredns(domain, resultsChan)
    }()

    // Ffuf
    wg.Add(1)
    go func() {
        defer wg.Done()
        RunFfuf(domain, resultsChan)
    }()

    // GitHub
	if config.GithubToken != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RunGithub(domain, config.GithubToken, resultsChan)
		}()
	}


	// Collector routine
	outputFile := filepath.Join(safeDomain, domain+"_sub.txt")
	
	// We need to wait for writers to finish before closing channel
	// We'll do that in a separate goroutine
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect unique subdomains
	uniqueSubs := make(map[string]bool)
	for sub := range resultsChan {
		if sub != "" {
			uniqueSubs[sub] = true
		}
	}

	// Write to file
	f, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("[!] Error creating output file: %v\n", err)
		return
	}
	defer f.Close()

	for sub := range uniqueSubs {
		f.WriteString(sub + "\n")
	}

	fmt.Printf("\n[+] Total unique subdomains found: %d\n", len(uniqueSubs))
	fmt.Printf("[+] Results saved to %s\n", outputFile)

    // Alive Probing
    RunHttpx(outputFile, filepath.Join(safeDomain, domain+"_alive_sub.txt"))
}

func ScanFile(filename string, config Config) {
    // Read file and loop ScanDomain
    // Implementation needed
    fmt.Println("[*] Scanning from file is not fully implemented yet in this step.")
}
