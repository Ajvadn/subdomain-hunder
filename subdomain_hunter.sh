#!/bin/bash

# Subdomain Hunter - Bash Version
# Usage: ./subdomain_hunter.sh -d <domain> [-u]

print_banner() {
    echo "   _____       __       __                          _       "
    echo "  / ___/__  __/ /_  ___/ /___  ____ ___  ____ _    (_)___   "
    echo "  \__ \/ / / / __ \/ __  / __ \/ __ \`__ \/ __ \` /   / / __ \  "
    echo " ___/ / /_/ / /_/ / /_/ / /_/ / / / / / / /_/ /   / / / / /  "
    echo "/____/\__,_/_.___/\__,_/\____/_/ /_/ /_/\__,_(_)_/ /_/ /_/   "
    echo "                                              /___/          "
    echo "    __  __            __                       "
    echo "   / / / /_  ______  / /____  _____            "
    echo "  / /_/ / / / / __ \/ __/ _ \/ ___/            "
    echo " / __  / /_/ / / / / /_/  __/ /                "
    echo "/_/ /_/\__,_/_/ /_/\__/\___/_/                 "
    echo ""
    echo "             by Ajvad-N"
    echo "======================================================="
    echo ""
}

# Show banner immediately
print_banner

show_usage() {
    echo "Usage: $0 -d <domain> [-g <github_token>] [-u]"
    echo "  -d  Target domain to enumerate (Passive + Active)"
    echo "  -g  GitHub API Token (optional, for code search)"
    echo "  -u  Update tools"
    exit 1
}

# Function to check and install dependencies
check_dependencies() {
    # 1. Subfinder
    if ! command -v subfinder &> /dev/null; then
        echo "[!] Subfinder is missing."
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

    # 2. Active Tools
    # Puredns
    if ! command -v puredns &> /dev/null; then
        echo "[!] puredns (Active DNS) is missing."
        read -p "Do you want to install it? (y/N) " choice
        case "$choice" in
            y|Y )
                    if command -v go &> /dev/null; then
                        echo "[*] Installing puredns..."
                        go install github.com/d3mondev/puredns/v2@latest
                        export PATH=$PATH:$(go env GOPATH)/bin
                    else
                        echo "[!] Go not found."
                    fi
                    ;;
        esac
    fi

    # Httpx
    if ! command -v httpx &> /dev/null; then
        echo "[!] httpx (Alive Probe) is missing."
        read -p "Do you want to install it? (y/N) " choice
            case "$choice" in
            y|Y )
                    if command -v go &> /dev/null; then
                        echo "[*] Installing httpx..."
                        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
                        export PATH=$PATH:$(go env GOPATH)/bin
                    else
                        echo "[!] Go not found."
                    fi
                    ;;
        esac
    fi
 
    # FFUF
    if ! command -v ffuf &> /dev/null; then
        echo "[!] ffuf (VHost Fuzzer) is missing."
        read -p "Do you want to install it? (y/N) " choice
        case "$choice" in
            y|Y )
                    if command -v go &> /dev/null; then
                        echo "[*] Installing ffuf..."
                        go install github.com/ffuf/ffuf/v2@latest
                        export PATH=$PATH:$(go env GOPATH)/bin
                    else
                        echo "[!] Go not found."
                    fi
                    ;;
        esac
    fi
   
    # Massdns
    if ! command -v massdns &> /dev/null; then
            echo "[!] Warning: massdns might be required for puredns but installing it via script is complex (requires make)."
            echo "    Please install massdns manually if puredns fails."
    fi
}


DOMAIN=""
GITHUB_TOKEN=""
UPDATE=false


# Parse arguments
while getopts "d:g:u" opt; do
    case $opt in
        d)
            DOMAIN="$OPTARG"
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
    echo "[*] Updating tools..."
    if command -v subfinder &> /dev/null; then
        echo " -> Updating Subfinder..."
        subfinder -up
    else
        echo "[!] Subfinder not found. Skipping update."
    fi
    echo "[+] Update complete."
    # If no domain provided, exit after update
    if [ -z "$DOMAIN" ]; then
        exit 0
    fi
fi

# Check for Domain
if [ -z "$DOMAIN" ]; then
    show_usage
fi

OUTPUT_FILE="sub.txt"
TEMP_BASE=".temp_subs_$$"
touch "${TEMP_BASE}_all.txt"

echo "[+] Starting subdomain enumeration for: $DOMAIN"

# --- Worker Functions ---

run_crtsh() {
    echo "[*] Querying crt.sh..."
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | grep -oP '"name_value":\s*"\K[^"]+' | sed 's/\\n/\n/g' | grep -v '*' | grep "$DOMAIN" > "${TEMP_BASE}_crtsh.txt"
    echo " -> crt.sh done."
}

run_hackertarget() {
    echo "[*] Querying HackerTarget..."
    curl -s "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" | cut -d, -f1 | grep "$DOMAIN" > "${TEMP_BASE}_ht.txt"
    echo " -> HackerTarget done."
}

run_alienvault() {
    echo "[*] Querying AlienVault..."
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/passive_dns" | grep -oP '"hostname":\s*"\K[^"]+' | grep "$DOMAIN" > "${TEMP_BASE}_av.txt"
    echo " -> AlienVault done."
}

run_rapiddns() {
    echo "[*] Querying RapidDNS..."
    curl -s "https://rapiddns.io/subdomain/$DOMAIN?full=1" | grep -oP '<td>\s*\K[^<]+' | grep "$DOMAIN" | grep -v '*' > "${TEMP_BASE}_rdns.txt"
    echo " -> RapidDNS done."
}

run_subfinder() {
    if command -v subfinder &> /dev/null; then
        echo "[*] Running Subfinder..."
        # Pass token if available (env var already set)
        subfinder -d "$DOMAIN" -silent > "${TEMP_BASE}_subfinder.txt"
        echo " -> Subfinder done."
    fi
}

run_github() {
    if [ -n "$GITHUB_TOKEN" ]; then
        echo "[*] Querying GitHub API..."
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
        echo " -> GitHub API done."
    else
        echo "[*] No GitHub token provided, skipping GitHub search."
    fi
}

run_wayback() {
    echo "[*] Querying Wayback Machine..."
    # Fetch archived URLs, extract subdomains
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=txt&fl=original&collapse=urlkey" \
    | awk -F/ '{print $3}' \
    | grep "$DOMAIN" \
    | sort -u > "${TEMP_BASE}_wayback.txt"
    echo " -> Wayback Machine done."
}

run_anubis() {
    echo "[*] Querying AnubisDB..."
    # Returns JSON array ["sub1.domain.com", "sub2.domain.com"]
    curl -s "https://jldc.me/anubis/subdomains/$DOMAIN" \
    | grep -oP '\"(.*?)\"' \
    | tr -d '"' \
    | grep "$DOMAIN" \
    | sort -u > "${TEMP_BASE}_anubis.txt"
    echo " -> AnubisDB done."
}


run_puredns() {
    echo "[*] Starting Active DNS Brute Forcing..."
    
    # Smart Wordlist Detection (Kali Linux / SecLists)
    WORDLIST=""
    if [ -f "subdomains.txt" ]; then
        WORDLIST="subdomains.txt"
    elif [ -f "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt" ]; then
        WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
        echo "[*] Using detected SecLists wordlist (Top 110k)."
    elif [ -f "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" ]; then
        WORDLIST="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        echo "[*] Using detected SecLists wordlist (Top 5000)."
    elif [ -f "/usr/share/wordlists/dnsmap.txt" ]; then
        WORDLIST="/usr/share/wordlists/dnsmap.txt"
        echo "[*] Using detected dnsmap wordlist."
    else
        # Fallback to download
        WORDLIST="subdomains.txt"
        echo "[*] No local wordlist found. Downloading default (Top 5000)..."
        curl -s -L "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" -o "$WORDLIST"
    fi

    if command -v puredns &> /dev/null; then
        echo "[*] Running Puredns..."
        puredns bruteforce "$WORDLIST" "$DOMAIN" -r "resolvers.txt" --write "${TEMP_BASE}_puredns.txt" &> /dev/null
        echo " -> Puredns done."
    else
        echo "[!] puredns not found, skipping brute force."
    fi
}

run_ffuf() {
    echo "[*] Starting VHost Discovery (ffuf)..."
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
        echo " -> ffuf done."
    else
        echo "[!] ffuf not found. Skipping VHost discovery."
    fi
}

# --- Launch Jobs ---

run_crtsh &
run_hackertarget &
run_alienvault &
run_rapiddns &
run_subfinder &
run_github &
run_wayback &
run_anubis &
run_puredns &
run_ffuf &

wait

# --- Aggregation ---
echo "[*] Aggregating results..."
# Concatenate, Normalize (Lower case, remove protocol), Sort, Unique
cat ${TEMP_BASE}_*.txt 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's|^https\?://||' | sort -u > $OUTPUT_FILE
rm ${TEMP_BASE}_*.txt 2>/dev/null

COUNT=$(wc -l < $OUTPUT_FILE)

echo ""
echo "[+] Total unique subdomains found: $COUNT"
echo "[+] Results saved to $OUTPUT_FILE"

# --- Alive Probing (Sequential) ---
echo "[*] Starting Alive Probing (httpx)..."
ALIVE_FILE="${DOMAIN}_alive.txt"
if command -v httpx &> /dev/null; then
    httpx -l "$OUTPUT_FILE" -silent -o "$ALIVE_FILE"
    ALIVE_COUNT=$(wc -l < "$ALIVE_FILE" 2>/dev/null || echo 0)
    echo "[+] Alive subdomains saved to $ALIVE_FILE (Count: $ALIVE_COUNT)"
else
    echo "[!] httpx not found. Skipping probing."
fi
