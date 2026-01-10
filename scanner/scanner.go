package scanner

import (
	"bufio"
	"fmt"
	"os"

	"strings"
	"sync"
)

func ScanDomain(domain string, config Config) {
	fmt.Printf("[+] Starting subdomain enumeration for: %s\n", domain)
	
	// Create system temp directory for interim results
	tempDir, err := os.MkdirTemp("", "subhunter-" + domain + "-*")
	if err != nil {
		fmt.Printf("[!] Error creating temp directory: %v\n", err)
		return
	}
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
		RunWayback, 
		RunThreatMiner,
	}
	
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
    
    wg.Add(1)
    go func() {
        defer wg.Done()
        RunAmass(domain, resultsChan)
    }()

    wg.Add(1)
    go func() {
        defer wg.Done()
        RunPuredns(domain, resultsChan)
    }()

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
	outputFile := "sub-" + domain + ".txt"
	
	// We need to wait for writers to finish before closing channel
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
    aliveOutputFile := "alive-sub-" + domain + ".txt"
    RunHttpx(outputFile, aliveOutputFile)
}

func ScanFile(filename string, config Config) {
    file, err := os.Open(filename)
    if err != nil {
        fmt.Printf("[!] Error opening file: %v\n", err)
        return
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        domain := strings.TrimSpace(scanner.Text())
        if domain != "" {
            ScanDomain(domain, config)
        }
    }

    if err := scanner.Err(); err != nil {
        fmt.Printf("[!] Error reading file: %v\n", err)
    }
}
