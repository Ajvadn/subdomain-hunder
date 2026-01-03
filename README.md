# Subdomain Hunter (Go Version)

A powerful, fast, and comprehensive subdomain enumeration tool rewritten in Go. It combines passive reconnaissance sources with active brute-forcing and permutation scanning to discover subdomains for a target.

## Features

-   **Parallel Execution**: Runs all sources simultaneously for maximum speed.
-   **Passive Reconnaissance**:
    -   `crt.sh` (Certificate Transparency)
    -   `HackerTarget`
    -   `AlienVault OTX`
    -   `RapidDNS`
    -   `Wayback Machine` (Web Archives)
    -   `AnubisDB`
    -   `Subfinder` (Integration)
    -   `Amass` (Passive Mode)
    -   `Assetfinder`
    -   `GitHub Code Search` (Native API support)
-   **Active Enumeration**:
    -   **DNS Brute Forcing**: Uses `puredns`.
    -   **VHost Discovery**: Placeholder for `ffuf`.
    -   **Alive Probing**: checks with `httpx`.
-   **Smart & Clean**:
    -   Auto-installs missing dependencies.
    -   Normalizes and deduplicates results strictly.
    -   Saves final unique list to `<domain>_sub.txt`.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/subdomain-hunter.git
    cd subdomain-hunter
    ```

2.  **Build:**
    ```bash
    go build -o subdomain-hunter .
    ```
    
    *Requires Go 1.21+*

3.  **Dependencies**:
    The tool relies on `subfinder`, `amass`, `assetfinder`, `puredns`, and `httpx` being in your PATH. It can attempt to update/install them via `-u` flag.

## Usage

### Basic Usage (Single Domain)
```bash
./subdomain-hunter -d example.com
```

### Multi–Domain Input
Scan multiple domains from a file:
```bash
./subdomain-hunter -f domains.txt
```

### With GitHub API
Find subdomains leaked in code commits:
```bash
./subdomain-hunter -d example.com -g <YOUR_GITHUB_TOKEN>
```

### Update Tools
Update the internal tools:
```bash
./subdomain-hunter -u
```

## Output

-   **`<domain>/<domain>_sub.txt`**: The final, unique list of found subdomains.
-   **`<domain>/<domain>_alive_sub.txt`**: List of subdomains that are currently reachable.

## Disclaimer
This tool is for educational and security testing purposes only. Usage against targets without prior consent is illegal. The author is not responsible for any misuse.
