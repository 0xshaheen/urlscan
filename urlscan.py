import requests
import json
import re
import time
import sys
import os

# Banner
def print_banner():
    banner = """
    ============================================
          UrlScan Subdomain Finder
    ============================================
    Author: 0xShaheen
    Facebook: https://facebook.com/0xshaheen
    Twitter:  https://x.com/0xshaheen
    Github:   https://github.com/0xshaheen
    LinkedIn: https://www.linkedin.com/in/0xshaheen
    Medium:   https://medium.com/@0xshaheen
    ============================================
    """
    print(banner)

# Function to fetch subdomains
def fetch_urlscan_subdomains(domain):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
    headers = {"User-Agent": "Mozilla/5.0"}
    subdomains = set()

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 429:
            print(f"[!] Rate limit hit for {domain}. Retrying in 60 seconds...")
            time.sleep(60)
            return fetch_urlscan_subdomains(domain)

        response.raise_for_status()

        try:
            data = response.json()
        except json.JSONDecodeError:
            print(f"[ERROR] Failed to parse JSON response for {domain}.")
            return

        # Extract subdomains that match *.domain.com
        subdomain_pattern = re.compile(rf"^[a-zA-Z0-9.-]+\.{re.escape(domain)}$")
        for entry in data.get("results", []):
            page_info = entry.get("page", {})
            found_domain = page_info.get("domain", "")
            if subdomain_pattern.match(found_domain):
                subdomains.add(found_domain)

        if subdomains:
            output_file = f"urlscan_subs_{domain}.txt"
            with open(output_file, "w") as f:
                f.write("\n".join(sorted(subdomains)))
            print(f"[+] {len(subdomains)} subdomains for {domain} saved to {output_file}")
        else:
            print(f"[!] No matching subdomains found for {domain}.")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch data for {domain}: {e}")

# Main function
def main():
    print_banner()

    if len(sys.argv) < 2:
        domain_or_file = input("Enter a domain (e.g., domain.com) or a file containing domains: ").strip()
    else:
        domain_or_file = sys.argv[1].strip()

    # Check if input is a file
    if os.path.isfile(domain_or_file):
        with open(domain_or_file, "r") as file:
            domains = [line.strip() for line in file if line.strip()]
        
        print(f"[+] Found {len(domains)} domains in {domain_or_file}. Fetching subdomains...\n")
        for domain in domains:
            fetch_urlscan_subdomains(domain)
    else:
        fetch_urlscan_subdomains(domain_or_file)

if __name__ == "__main__":
    main()
