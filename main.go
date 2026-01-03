package main

import (
	"flag"
	"fmt"
	"os"
	"subdomain-hunter/scanner"
)

func main() {
	// Parse Flags
	domainPtr := flag.String("d", "", "Target domain (single)")
	filePtr := flag.String("f", "", "File containing list of domains")
	githubTokenPtr := flag.String("g", "", "GitHub API Token (optional)")
	updatePtr := flag.Bool("u", false, "Update tools")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -d <domain> | -f <file> [-g <github_token>] [-u]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	// Show Banner
	printBanner()

	if *updatePtr {
		scanner.UpdateTools()
		if *domainPtr == "" && *filePtr == "" {
			return
		}
	}

	if *domainPtr == "" && *filePtr == "" {
		flag.Usage()
		os.Exit(1)
	}

	config := scanner.Config{
		GithubToken: *githubTokenPtr,
	}

	if *domainPtr != "" {
		scanner.ScanDomain(*domainPtr, config)
	} else if *filePtr != "" {
		scanner.ScanFile(*filePtr, config)
	}
}

func printBanner() {
	// Simple one-line banner without italics as requested
	fmt.Println("Subdomain Hunter by Ajvad-N")
	fmt.Println("===========================")
}
