# Subdomain Hunter

A powerful, fast, and comprehensive subdomain enumeration tool written in Bash. It combines passive reconnaissance sources with active brute-forcing and permutation scanning to discover subdomains for a target.

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
    -   `GitHub Code Search` (Native API support)
-   **Active Enumeration**:
    -   **DNS Brute Forcing**: Uses `puredns` with smart wordlist detection (Kali Linux/SecLists support).
    -   **VHost Discovery**: fuzzed with `ffuf`.
    -   **Alive Probing**: checks with `httpx`.
-   **Smart & Clean**:
    -   Auto-installs missing dependencies (Go-based tools).
    -   Normalizes and deduplicates results strictly.
    -   Saves final unique list to `sub.txt`.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/subdomain-hunter.git
    cd subdomain-hunter
    ```

2.  **Make executable:**
    ```bash
    chmod +x subdomain_hunter.sh
    ```

3.  **Dependencies**:
    The script will automatically check for and offer to install missing Go tools (`subfinder`, `puredns`, `httpx`, `ffuf`).
    *   Ensure you have `curl`, `jq`, and `go` installed on your system.
    *   For Kali Linux, wordlists are auto-detected.

## Usage

### Basic Usage (Passive + Active)
```bash
./subdomain_hunter.sh -d example.com
```

### With GitHub API (Recommended for deep dive)
Find subdomains leaked in code commits:
```bash
./subdomain_hunter.sh -d example.com -g <YOUR_GITHUB_TOKEN>
```

### Update Tools
Update the internal tools (like subfinder):
```bash
./subdomain_hunter.sh -u
```

## Output

-   **`sub.txt`**: The final, unique list of found subdomains.
-   **`<domain>_alive.txt`**: List of subdomains that are currently reachable (HTTP/HTTPS).

## Disclaimer
This tool is for educational and security testing purposes only. Usage against targets without prior consent is illegal. The author is not responsible for any misuse.
