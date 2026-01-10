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

	// Automatically update/check tools before running
	scanner.UpdateTools()

	if *domainPtr == "" && *filePtr == "" {
		if *updatePtr {
			// If user only wanted update, we can stop here
			return
		}
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
	// ANSI Color Codes
	const (
		Reset  = "\033[0m"
		Cyan   = "\033[36m"
		Yellow = "\033[33m"
		Bold   = "\033[1m"
	)

	fmt.Printf("%s%sSubdomain Hunter by Ajvad-N%s\n", Bold, Cyan, Reset)
	fmt.Printf("%s===========================%s\n", Yellow, Reset)
}
