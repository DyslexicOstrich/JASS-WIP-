#!/bin/bash

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to parse and display open ports with color coding
parse_nmap_results() {
    local nmap_file="$1"
    echo -e "\n[*] Open Ports Found:"
    echo "--------------------------"
    while read -r line; do
        port=$(echo "$line" | awk '{print $1}')
        service=$(echo "$line" | awk '{print $3}')
	version=$(echo "$line" | awk '{print $4}')

        # Color-code specific ports
        case "$port" in
            "21/tcp")
                color=$RED
                ;;
            "22/tcp")
                color=$YELLOW
                ;;
            "80/tcp" | "443/tcp" | "8080/tcp" | "8443/tcp")
                color=$GREEN
                ;;
            *)
                color=$BLUE
                ;;
        esac

        # Print the colored output
        echo -e "${color}Port: $port, Service: $service${NC}, Version: $version${NC}"
    done < <(grep 'open' "$nmap_file" | grep -v '^PORT')
    echo "--------------------------"
}

# Function to check for specific web ports
check_web_ports() {
    local nmap_file="$1"
    if grep -qE '(^|\s)(80/tcp|443/tcp|8080/tcp|8443/tcp)\s+open' "$nmap_file"; then
        return 0  # True (web ports found)
    else
        return 1  # False (no web ports found)
    fi
}

# Prompt for the target IP or domain
read -p "Enter the target IP or domain: " TARGET

# Validate the input
if [ -z "$TARGET" ]; then
    echo "No target provided. Exiting..."
    exit 1
fi

DATE=$(date +%Y-%m-%d_%H-%M-%S)
OUTPUT_DIR="./results_${TARGET}_${DATE}"

# Create a directory to store the results
mkdir -p "$OUTPUT_DIR"

# Step 1: Nmap Scan
echo "[*] Starting Nmap scan on $TARGET..."
nmap -sC -sV -oN "$OUTPUT_DIR/nmap_scan.txt" "$TARGET"

# Parse and display open ports
parse_nmap_results "$OUTPUT_DIR/nmap_scan.txt"

# Step 2: Check for web ports
if check_web_ports "$OUTPUT_DIR/nmap_scan.txt"; then
    read -p "Web ports (80, 443, 8080, 8443) detected. Do you want to proceed with further enumeration? (y/n): " CONTINUE
    if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
        echo "Exiting the script as requested."
        exit 0
    fi
else
    echo "No ports detected"
    read -p "Continue? (y/n):" CONTINUE_2
    if [[ "$CONTINUE_2" != "y" && "$CONTINUE_2" != "Y" ]]; then
	echo"Exitiing..."
	exit 0
    else
	echo "[*] Running additional Nmap scan..."
	nmap -p- -sC -sV -oN "$OUTPUT_DIR/nmap_full_scan.txt" "$TARGET"
	echo "[*] Additional Nmap scan completed."
	parse_nmap_results "$OUTPUT_DIR/nmap_full_scan.txt"
    fi
fi

read -p "Input the URL: " URL

# Step 3: Choose Gobuster or Gospider
echo -e "\nSelect the tool for enumeration:"
echo "1) Gobuster (Directory enumeration)"
echo "2) Gobuster (Subdomain enumeration)"
echo "3) Gospider (Web crawling)"
read -p "Enter the number of your choice: " TOOL_CHOICE

# Execute the selected tool
case $TOOL_CHOICE in
    1)
        echo "[*] Running Gobuster for directory enumeration on $TARGET..."
        gobuster dir -u "http://$URL" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o "$OUTPUT_DIR/gobuster_dirs.txt"
        ;;
    2)
        echo "[*] Running Gobuster for subdomain enumeration on $TARGET..."
        gobuster dns -d "$URL" -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o "$OUTPUT_DIR/gobuster_subdomains.txt"
        ;;
    3)
        echo "[*] Running Gospider for web crawling on $URL..."
        gospider -s "http://$TARGET" -o "$OUTPUT_DIR/gospider_results.txt"
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac

echo -e "\n[*] Scanning completed. Results are saved in the $OUTPUT_DIR directory."
