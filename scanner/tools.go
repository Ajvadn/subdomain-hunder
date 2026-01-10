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

func EnsureFilesExist() {
    resolvers := "resolvers.txt"
    wordlist := "subdomains.txt"

    if _, err := os.Stat(resolvers); os.IsNotExist(err) {
        fmt.Println("[*] resolvers.txt not found. Attempting to download...")
        DownloadFile("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt", resolvers)
    }

    if _, err := os.Stat(wordlist); os.IsNotExist(err) {
        fmt.Println("[*] subdomains.txt not found. Attempting to download small default list...")
        DownloadFile("https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-1000.txt", wordlist)
    }
}

func RunPuredns(domain string, results chan<- string) {
    EnsureFilesExist()
    wordlist := "subdomains.txt"
    resolvers := "resolvers.txt"

    if _, err := os.Stat(wordlist); os.IsNotExist(err) {
        fmt.Println("[!] Wordlist still missing for puredns. Skipping.")
        return
    }
    
    fmt.Println("[*] Running Puredns...")
    if _, err := os.Stat(resolvers); os.IsNotExist(err) {
         fmt.Println("[!] resolvers.txt missing. Skipping puredns.")
         return
    }

    outFile := "puredns_temp.txt"
    cmd := exec.Command("puredns", "bruteforce", wordlist, domain, "-r", resolvers, "--write", outFile, "--quiet")
    if err := cmd.Run(); err != nil {
         fmt.Printf("[!] puredns failed: %v\n", err)
         return
    }
    
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
    EnsureFilesExist()
    wordlist := "subdomains.txt"
    
    if _, err := os.Stat(wordlist); os.IsNotExist(err) {
        return
    }

    fmt.Println("[*] Running ffuf (VHost)...")
    // ffuf -w wordlist -u http://domain -H "Host: FUZZ.domain" -mc 200,301,302 -s
    // Using -s for silent output (only results)
    cmd := exec.Command("ffuf", "-w", wordlist, "-u", "http://"+domain, "-H", "Host: FUZZ."+domain, "-mc", "200,301,302", "-s")
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return
    }

    if err := cmd.Start(); err != nil {
        return
    }

    scanner := bufio.NewScanner(stdout)
    for scanner.Scan() {
        line := scanner.Text()
        // ffuf -s returns the fuzzed value (the subdomain part)
        if line != "" {
            results <- line + "." + domain
        }
    }
    cmd.Wait()
    fmt.Println(" -> ffuf done.")
}
