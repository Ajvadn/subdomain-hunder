package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func runToolSimple(name string, args []string, results chan<- string) {
	cmd := exec.Command(name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Printf("[!] %s not found or failed to start: %v\n", name, err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			results <- line
		}
	}
	cmd.Wait()
}

func RunSubfinder(domain string, results chan<- string) {
	fmt.Println("[*] Running Subfinder...")
    // -silent to output only domains
	runToolSimple("subfinder", []string{"-d", domain, "-silent"}, results)
    fmt.Println(" -> Subfinder done.")
}

func RunAmass(domain string, results chan<- string) {
    fmt.Println("[*] Running Amass (Passive)...")
    // Amass writes to stdout with -o ? No, we want stdout for pipe.
    // amass enum -passive -d domain
    runToolSimple("amass", []string{"enum", "-passive", "-d", domain, "-timeout", "10"}, results)
     fmt.Println(" -> Amass done.")
}

func RunAssetfinder(domain string, results chan<- string) {
    fmt.Println("[*] Running Assetfinder...")
    runToolSimple("assetfinder", []string{"--subs-only", domain}, results)
     fmt.Println(" -> Assetfinder done.")
}

func RunHttpx(inputFile, outputFile string) {
    fmt.Println("[*] Starting Alive Probing (httpx)...")
    // httpx -l input -o output -silent
    cmd := exec.Command("httpx", "-l", inputFile, "-o", outputFile, "-silent")
    if err := cmd.Run(); err != nil {
        fmt.Printf("[!] httpx failed: %v\n", err)
    } else {
        fmt.Printf("[+] Alive subdomains saved to %s\n", outputFile)
    }
}

func RunPuredns(domain string, results chan<- string) {
    // Check for wordlist
    wordlist := "subdomains.txt"
    if _, err := os.Stat(wordlist); os.IsNotExist(err) {
        // Try searching common locations or download
        common := "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if _, err := os.Stat(common); err == nil {
            wordlist = common
        } else {
            // Download logic could go here, but for now we warn
            fmt.Println("[!] Wordlist not found for puredns. Skipping.")
            return
        }
    }
    
    fmt.Println("[*] Running Puredns...")
    // puredns bruteforce wordlist domain -r resolvers.txt --write output
    // We need resolvers.txt too.
    resolvers := "resolvers.txt"
    if _, err := os.Stat(resolvers); os.IsNotExist(err) {
         fmt.Println("[!] resolvers.txt not found. Skipping puredns.")
         return
    }

    // We use a temp file for puredns output as it writes to file
    outFile := "puredns_temp.txt"
    cmd := exec.Command("puredns", "bruteforce", wordlist, domain, "-r", resolvers, "--write", outFile)
    if err := cmd.Run(); err != nil {
         fmt.Printf("[!] puredns failed: %v\n", err)
         return
    }
    
    // Read user results
    file, err := os.Open(outFile)
    if err != nil {
        return
    }
    defer file.Close()
    defer os.Remove(outFile)
    
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        results <- scanner.Text()
    }
    fmt.Println(" -> Puredns done.")
}

func RunFfuf(domain string, results chan<- string) {
    // Basic VHost discovery
    // wordlist := "subdomains.txt" // Simplify assumption
    fmt.Println("[*] Running ffuf (VHost)...")
    
    // ffuf -w wordlist -u http://domain -H "Host: FUZZ.domain" ...
    // This is complex to parse via pipe generally, but we can try json.
    // For this implementation, let's skip complex parsing and just alert it's running.
    // Real implementation requires parsing JSON output.
    fmt.Println("[!] Ffuf implementation placeholder. Real ffuf requires JSON parsing.")
}
