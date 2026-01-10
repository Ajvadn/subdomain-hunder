package scanner

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// Config holds the configuration for the scan
type Config struct {
	GithubToken string
}

// DownloadFile downloads a file from a URL to a local path
func DownloadFile(url string, filepath string) error {
	fmt.Printf("[*] Downloading %s...\n", filepath)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// UpdateTools runs the update commands for the supported tools
func UpdateTools() {
	fmt.Println("[*] Updating tools...")
	
	if _, err := exec.LookPath("subfinder"); err == nil {
		fmt.Println(" -> Updating Subfinder...")
		runCmd("subfinder", "-up")
	}

	if _, err := exec.LookPath("go"); err == nil {
		fmt.Println(" -> Updating Amass...")
		runCmd("go", "install", "-v", "github.com/owasp-amass/amass/v4/cmd/amass@latest")
		
		fmt.Println(" -> Updating Assetfinder...")
		runCmd("go", "install", "github.com/tomnomnom/assetfinder@latest")
	} else {
		fmt.Println("[!] Go not found, skipping Go-based updates.")
	}
}
