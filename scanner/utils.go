package scanner

import (
	"fmt"
	"os"
	"os/exec"
)

// Config holds the configuration for the scan
type Config struct {
	GithubToken string
}

// UpdateTools runs the update commands for the supported tools
func UpdateTools() {
	fmt.Println("[*] Updating tools...")
	// We'll implement the actual update logic here
	// This mirrors the shell script updates
	
	// Example: subfinder -up
	if _, err := exec.LookPath("subfinder"); err == nil {
		fmt.Println(" -> Updating Subfinder...")
		runCmd("subfinder", "-up")
	}

	// Go install updates (requires go)
	if _, err := exec.LookPath("go"); err == nil {
		fmt.Println(" -> Updating Amass...")
		runCmd("go", "install", "-v", "github.com/owasp-amass/amass/v4/cmd/amass@latest")
		
		fmt.Println(" -> Updating Assetfinder...")
		runCmd("go", "install", "github.com/tomnomnom/assetfinder@latest")
	} else {
		fmt.Println("[!] Go not found, skipping Go-based updates.")
	}
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
