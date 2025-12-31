#!/bin/bash

# Subdomain Hunter - Bash Version
# Usage: ./subdomain_hunter.sh -d <domain> [-u]

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
RESET='\033[0m'
BOLD='\033[1m'

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "   _____       __         __                      _        "
    echo "  / ___/__  __/ /_  _____/ /___  ____ ___  ____ _(_)___    "
    echo "  \__ \/ / / / __ \/ ___/ / __ \/ __ \`__ \/ __ \` / / __ \   "
    echo " ___/ / /_/ / /_/ / /__/ / /_/ / / / / / / /_/ / / / / /   "
    echo "/____/\__,_/_.___/\___/_/\____/_/ /_/ /_/\__,_/_/_/ /_/    "
    echo "    __  __            __                                   "
    echo "   / / / /_  ______  / /____  _____                        "
    echo "  / /_/ / / / / __ \/ __/ _ \/ ___/                        "
    echo " / __  / /_/ / / / / /_/  __/ /                            "
    echo "/_/ /_/\__,_/_/ /_/\__/\___/_/                             "
    echo "                                                           "
    echo -e "             ${MAGENTA}by Ajvad-N${RESET}"
    echo -e "${BLUE}=======================================================${RESET}"
    echo ""
}

# Show banner immediately
print_banner

show_usage() {
    echo "Usage: $0 -d <domain> | -f <file> [-g <github_token>] [-u]"
    echo "  -d  Target domain (single)"
    echo "  -f  File containing list of domains"
    echo "  -g  GitHub API Token (optional, for code search)"
    echo "  -u  Update tools"
    exit 1
}

# Function to check and install dependencies
check_dependencies() {
    # 1. Subfinder
    if ! command -v subfinder &> /dev/null; then
        echo -e "${RED}[!] Subfinder is missing.${RESET}"
        read -p "Do you want to install it? (y/N) " choice
        case "$choice" in 
            y|Y ) 
                if command -v go &> /dev/null; then
                    echo "[*] Installing Subfinder..."
                    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                    export PATH=$PATH:$(go env GOPATH)/bin
                else
                    echo "[!] Go not found."
                fi
                ;;
        esac
    fi

    # Amass
    if ! command -v amass &> /dev/null; then
        echo -e "${RED}[!] Amass is missing.${RESET}"
        read -p "Do you want to install it? (y/N) " choice
        case "$choice" in 
            y|Y ) 
                if command -v go &> /dev/null; then
                    echo -e "${BLUE}[*] Installing Amass...${RESET}"
                    go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest
                    export PATH=$PATH:$(go env GOPATH)/bin
                else
                    echo "[!] Go not found."
                fi
                ;;
        esac
    fi

    # Assetfinder
    if ! command -v assetfinder &> /dev/null; then
        echo -e "${RED}[!] Assetfinder is missing.${RESET}"
        read -p "Do you want to install it? (y/N) " choice
        case "$choice" in 
            y|Y ) 
                if command -v go &> /dev/null; then
                    echo -e "${BLUE}[*] Installing Assetfinder...${RESET}"
                    go install github.com/tomnomnom/assetfinder@latest
                    export PATH=$PATH:$(go env GOPATH)/bin
                else
                    echo "[!] Go not found."
                fi
                ;;
        esac
    fi

    # 2. Active Tools
    # Puredns
    if ! command -v puredns &> /dev/null; then
        echo -e "${RED}[!] puredns (Active DNS) is missing.${RESET}"
        read -p "Do you want to install it? (y/N) " choice
        case "$choice" in
            y|Y )
                    if command -v go &> /dev/null; then
                        echo -e "${BLUE}[*] Installing puredns...${RESET}"
                        go install github.com/d3mondev/puredns/v2@latest
                        export PATH=$PATH:$(go env GOPATH)/bin
                    else
                        echo -e "${RED}[!] Go not found.${RESET}"
                    fi
                    ;;
        esac
    fi

    # Httpx
    if ! command -v httpx &> /dev/null; then
        echo -e "${RED}[!] httpx (Alive Probe) is missing.${RESET}"
        read -p "Do you want to install it? (y/N) " choice
        case "$choice" in
            y|Y )
                    if command -v go &> /dev/null; then
                        echo -e "${BLUE}[*] Installing httpx...${RESET}"
                        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
                        export PATH=$PATH:$(go env GOPATH)/bin
                    else
                        echo -e "${RED}[!] Go not found.${RESET}"
                    fi
                    ;;
        esac
    fi
 
    # FFUF
    if ! command -v ffuf &> /dev/null; then
        echo -e "${RED}[!] ffuf (VHost Fuzzer) is missing.${RESET}"
        read -p "Do you want to install it? (y/N) " choice
        case "$choice" in
            y|Y )
                    if command -v go &> /dev/null; then
                        echo -e "${BLUE}[*] Installing ffuf...${RESET}"
                        go install github.com/ffuf/ffuf/v2@latest
                        export PATH=$PATH:$(go env GOPATH)/bin
                    else
                        echo -e "${RED}[!] Go not found.${RESET}"
                    fi
                    ;;
        esac
    fi
   
    # Massdns
    if ! command -v massdns &> /dev/null; then
            echo -e "${YELLOW}[!] Warning: massdns might be required for puredns but installing it via script is complex (requires make).${RESET}"
            echo -e "${YELLOW}    Please install massdns manually if puredns fails.${RESET}"
    fi
}


DOMAIN=""
DOMAIN_FILE=""
GITHUB_TOKEN=""
UPDATE=false


# Parse arguments
while getopts "d:f:g:u" opt; do
    case $opt in
        d)
            DOMAIN="$OPTARG"
            ;;
        f)
            DOMAIN_FILE="$OPTARG"
            ;;
        g)
            GITHUB_TOKEN="$OPTARG"
            export GITHUB_TOKEN  # Export for subfinder/others
            ;;
        u)
            UPDATE=true
            ;;
        \?)
            show_usage
            ;;
    esac
done

# Check dependencies
check_dependencies

# Perform Update if requested
if [ "$UPDATE" = true ]; then
    echo -e "${BLUE}[*] Updating tools...${RESET}"
    if command -v subfinder &> /dev/null; then
        echo -e "${CYAN} -> Updating Subfinder...${RESET}"
        subfinder -up
    else
        echo -e "${RED}[!] Subfinder not found. Skipping update.${RESET}"
    fi

    if command -v amass &> /dev/null; then
        echo " -> Updating Amass..."
        go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest
    fi

    if command -v assetfinder &> /dev/null; then
        echo " -> Updating Assetfinder..."
        go install github.com/tomnomnom/assetfinder@latest
    fi
    echo "[+] Update complete."
    # If no domain provided, exit after update
    if [ -z "$DOMAIN" ]; then
        exit 0
    fi
fi

# --- Core Scanning Logic ---

scan_domain_worker() {
    local TARGET_DOMAIN=$1
    # Update global DOMAIN variable for worker functions
    DOMAIN=$TARGET_DOMAIN
    
    # Sanitize domain for filename usage (basic)
    local SAFE_DOMAIN=$(echo "$DOMAIN" | tr -cd '[:alnum:]._-')
    
    # Create directory for the domain
    if [ ! -d "$SAFE_DOMAIN" ]; then
        echo -e "${BLUE}[*] Creating directory: ${BOLD}$SAFE_DOMAIN${RESET}"
        mkdir -p "$SAFE_DOMAIN"
    fi
    
    OUTPUT_FILE="${SAFE_DOMAIN}/${DOMAIN}_sub.txt"
    # Update TEMP_BASE to include domain directory to avoid collisions
    TEMP_BASE="${SAFE_DOMAIN}/.temp_subs_${SAFE_DOMAIN}_$$"
    
    # Ensure parallel execution doesn't mix files
    # (TEMP_BASE includes PID ($$) and now domain, so safe for sequential, 
    # but for true parallel runs of multiple domains we rely on different PIDs or this unique naming)
    
    echo -e "${BLUE}=======================================================${RESET}"
    echo -e "${GREEN}[+] Starting subdomain enumeration for: ${BOLD}$DOMAIN${RESET}"
    echo -e "${BLUE}=======================================================${RESET}"

    # Launch Jobs
    run_crtsh &
    run_hackertarget &
    run_alienvault &
    run_rapiddns &
    run_subfinder &
    run_amass &
    run_assetfinder &
    run_github &
    run_wayback &
    run_anubis &
    run_puredns &
    run_ffuf &
    
    wait

    # Aggregation
    echo -e "${BLUE}[*] Aggregating results...${RESET}"
    # Concatenate, Normalize (Lower case, remove protocol), Sort, Unique
    cat ${TEMP_BASE}_*.txt 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's|^https\?://||' | sort -u > $OUTPUT_FILE
    rm ${TEMP_BASE}_*.txt 2>/dev/null

    COUNT=$(wc -l < $OUTPUT_FILE 2>/dev/null || echo 0)

    echo ""
    echo -e "${GREEN}[+] Total unique subdomains found: ${BOLD}$COUNT${RESET}"
    echo -e "${GREEN}[+] Results saved to ${BOLD}$OUTPUT_FILE${RESET}"

    # Alive Probing
    echo -e "${BLUE}[*] Starting Alive Probing (httpx)...${RESET}"
    ALIVE_FILE="${SAFE_DOMAIN}/${DOMAIN}_alive_sub.txt"
    if command -v httpx &> /dev/null; then
        httpx -l "$OUTPUT_FILE" -silent -o "$ALIVE_FILE"
        ALIVE_COUNT=$(wc -l < "$ALIVE_FILE" 2>/dev/null || echo 0)
        echo -e "${GREEN}[+] Alive subdomains saved to ${BOLD}$ALIVE_FILE${RESET} (Count: $ALIVE_COUNT)"
    else
        echo -e "${YELLOW}[!] httpx not found. Skipping probing.${RESET}"
    fi
    echo ""
}



run_crtsh() {
    echo -e "${BLUE}[*] Querying crt.sh...${RESET}"
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | grep -oP '"name_value":\s*"\K[^"]+' | sed 's/\\n/\n/g' | grep -v '*' | grep "$DOMAIN" > "${TEMP_BASE}_crtsh.txt"
    echo -e "${CYAN} -> crt.sh done.${RESET}"
}

run_hackertarget() {
    echo -e "${BLUE}[*] Querying HackerTarget...${RESET}"
    curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" | cut -d, -f1 | grep "$DOMAIN" > "${TEMP_BASE}_ht.txt"
    echo -e "${CYAN} -> HackerTarget done.${RESET}"
}

run_alienvault() {
    echo -e "${BLUE}[*] Querying AlienVault...${RESET}"
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" | grep -oP '"hostname":\s*"\K[^"]+' | grep "$DOMAIN" > "${TEMP_BASE}_av.txt"
    echo -e "${CYAN} -> AlienVault done.${RESET}"
}

run_rapiddns() {
    echo -e "${BLUE}[*] Querying RapidDNS...${RESET}"
    curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1" | grep -oP '<td>\s*\K[^<]+' | grep "$DOMAIN" | grep -v '*' > "${TEMP_BASE}_rdns.txt"
    echo -e "${CYAN} -> RapidDNS done.${RESET}"
}

run_subfinder() {
    if command -v subfinder &> /dev/null; then
        echo -e "${BLUE}[*] Running Subfinder...${RESET}"
        # Pass token if available (env var already set)
        subfinder -d "$DOMAIN" -silent > "${TEMP_BASE}_subfinder.txt"
        echo -e "${CYAN} -> Subfinder done.${RESET}"
    fi
}

run_amass() {
    if command -v amass &> /dev/null; then
        echo -e "${BLUE}[*] Running Amass (Passive)...${RESET}"
        # Amass passive enumeration
        # Note: Amass can be verbose and slow. We capture output to file.
        amass enum -passive -d "$DOMAIN" -timeout 10 -o "${TEMP_BASE}_amass.txt" > /dev/null 2>&1
        echo -e "${CYAN} -> Amass done.${RESET}"
    else
        echo -e "${YELLOW}[!] Amass not found, skipping.${RESET}"
    fi
}

run_assetfinder() {
    if command -v assetfinder &> /dev/null; then
        echo -e "${BLUE}[*] Running Assetfinder...${RESET}"
        assetfinder --subs-only "$DOMAIN" > "${TEMP_BASE}_assetfinder.txt"
        echo -e "${CYAN} -> Assetfinder done.${RESET}"
    else
        echo -e "${YELLOW}[!] Assetfinder not found, skipping.${RESET}"
    fi
}

run_github() {
    if [ -n "$GITHUB_TOKEN" ]; then
        echo -e "${BLUE}[*] Querying GitHub API...${RESET}"
        # Search for code containing the domain
        # Note: GitHub API has rate limits and pagination. We grab top results.
        curl -s -H "Authorization: token $GITHUB_TOKEN" "https://api.github.com/search/code?q=$DOMAIN" > "${TEMP_BASE}_github.json"
        
        # Parse output for domain matches
        if command -v jq &> /dev/null; then
            # We look for 'name' or 'path' or content snippet? Search API returns items.
            # Usually better to grep the raw JSON for the domain pattern.
            grep -oP '[a-zA-Z0-9._-]+\.'$DOMAIN "${TEMP_BASE}_github.json" | sort -u > "${TEMP_BASE}_github.txt"
        else
             grep -oP '[a-zA-Z0-9._-]+\.'$DOMAIN "${TEMP_BASE}_github.json" | sort -u > "${TEMP_BASE}_github.txt"
        fi
        rm "${TEMP_BASE}_github.json" 2>/dev/null
        echo -e "${CYAN} -> GitHub API done.${RESET}"
    else
        echo -e "${YELLOW}[*] No GitHub token provided, skipping GitHub search.${RESET}"
    fi
}

run_wayback() {
    echo -e "${BLUE}[*] Querying Wayback Machine...${RESET}"
    # Fetch archived URLs, extract subdomains
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=txt&fl=original&collapse=urlkey" \
    | awk -F/ '{print $3}' \
    | grep "$DOMAIN" \
    | sort -u > "${TEMP_BASE}_wayback.txt"
    echo -e "${CYAN} -> Wayback Machine done.${RESET}"
}

run_anubis() {
    echo -e "${BLUE}[*] Querying AnubisDB...${RESET}"
    # Returns JSON array ["sub1.domain.com", "sub2.domain.com"]
    curl -s "https://jldc.me/anubis/subdomains/$DOMAIN" \
    | grep -oP '\"(.*?)\"' \
    | tr -d '"' \
    | grep "$DOMAIN" \
    | sort -u > "${TEMP_BASE}_anubis.txt"
    echo -e "${CYAN} -> AnubisDB done.${RESET}"
}


run_puredns() {
    echo -e "${BLUE}[*] Starting Active DNS Brute Forcing...${RESET}"
    
    # Smart Wordlist Detection (Kali Linux / SecLists)
    WORDLIST=""
    if [ -f "subdomains.txt" ]; then
        WORDLIST="subdomains.txt"
    elif [ -f "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt" ]; then
        WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        echo -e "${CYAN}[*] Using detected SecLists wordlist (Top 110k).${RESET}"
    elif [ -f "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" ]; then
        WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        echo -e "${CYAN}[*] Using detected SecLists wordlist (Top 5000).${RESET}"
    elif [ -f "/usr/share/wordlists/dnsmap.txt" ]; then
        WORDLIST="/usr/share/wordlists/dnsmap.txt"
        echo -e "${CYAN}[*] Using detected dnsmap wordlist.${RESET}"
    else
        # Fallback to download
        WORDLIST="subdomains.txt"
        echo -e "${YELLOW}[*] No local wordlist found. Downloading default (Top 5000)...${RESET}"
        curl -s -L "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o "$WORDLIST"
    fi

    if command -v puredns &> /dev/null; then
        echo -e "${BLUE}[*] Running Puredns...${RESET}"
        puredns bruteforce "$WORDLIST" "$DOMAIN" -r "resolvers.txt" --write "${TEMP_BASE}_puredns.txt" &> /dev/null
        echo -e "${CYAN} -> Puredns done.${RESET}"
    else
        echo -e "${RED}[!] puredns not found, skipping brute force.${RESET}"
    fi
}

run_ffuf() {
    echo -e "${BLUE}[*] Starting VHost Discovery (ffuf)...${RESET}"
    if command -v ffuf &> /dev/null; then
        # Use the same wordlist as puredns if possible, but let's re-detect or pass it?
        # For simplicity, we'll re-run basic detection or assume download. 
        # Actually, let's just assume subdomains.txt if available, or the detected logic.
        # Repeating logic briefly:
        WORDLIST_FFUF="subdomains.txt"
        if [ -f "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" ]; then
             WORDLIST_FFUF="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        fi
        
        ffuf -w "$WORDLIST_FFUF" -u "http://$DOMAIN" -H "Host: FUZZ.$DOMAIN" -ac -mc 200,301,302,403 -s -json > "${TEMP_BASE}_ffuf_raw.json"
        
        if command -v jq &> /dev/null; then
            cat "${TEMP_BASE}_ffuf_raw.json" | jq -r '.results[] | .input.FUZZ + ".'$DOMAIN'"' > "${TEMP_BASE}_ffuf.txt" 2>/dev/null
        else
            grep -oP '"input":{"FUZZ":"\K[^"]+' "${TEMP_BASE}_ffuf_raw.json" | awk -v d="$DOMAIN" '{print $0"."d}' > "${TEMP_BASE}_ffuf.txt"
        fi
        rm "${TEMP_BASE}_ffuf_raw.json" 2>/dev/null
        echo -e "${CYAN} -> ffuf done.${RESET}"
    else
        echo -e "${RED}[!] ffuf not found. Skipping VHost discovery.${RESET}"
    fi
}

# --- Execution Flow ---

if [ -n "$DOMAIN_FILE" ]; then
    if [ -f "$DOMAIN_FILE" ]; then
        echo -e "${BLUE}[*] Loading domains from file: ${BOLD}$DOMAIN_FILE${RESET}"
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Trim whitespace
            line=$(echo "$line" | xargs)
            # Skip empty lines
            [[ -z "$line" ]] && continue
            scan_domain_worker "$line"
        done < "$DOMAIN_FILE"
    else
        echo -e "${RED}[!] File not found: $DOMAIN_FILE${RESET}"
        exit 1
    fi
elif [ -n "$DOMAIN" ]; then
    scan_domain_worker "$DOMAIN"
else
    show_usage
fi
