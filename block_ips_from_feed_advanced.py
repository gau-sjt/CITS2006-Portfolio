import os
import platform
import requests
from datetime import datetime
""" IP blocking for Windows and Linux. Adds a firewall rule to block a given IP. 
A log of blocked addresses is created."""

#FireHOL feed containing a list of bad IPs.
FEED_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
WHITELIST = {"1.1.1.1", "8.8.8.8", "127.0.0.1"}
LOG_FILE = "blocked_ips_log.txt"

def get_bad_ips():
    print("Fetching IPs from FireHOL feed...")
    try:
        response = requests.get(FEED_URL)
        response.raise_for_status()
        ip_list = [line.strip() for line in response.text.splitlines() if line and not line.startswith("#")]
        return ip_list[:10]  # Limited for demo.
    except Exception as e:
        print(f"Failed to fetch IPs: {e}")
        return []

def block_ip_windows(ip):
    rule_name = f"Block {ip}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    os.system(command)

def block_ip_linux(ip):
    command = f'sudo iptables -A INPUT -s {ip} -j DROP'
    os.system(command)

def block_ip(ip):
    os_type = platform.system()
    if os_type == "Windows":
        block_ip_windows(ip)
    elif os_type in ("Linux", "Darwin"):
        block_ip_linux(ip)
    else:
        print(f"Unsupported OS: {os_type}")

def log_block(ip):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - Blocked: {ip}\n")

def main():
    bad_ips = get_bad_ips()
    if not bad_ips:
        print("No IPs to block. Exiting.")
        return

    print("Blocking malicious IPs...")
    for ip in bad_ips:
        if ip in WHITELIST:
            print(f"Skipping whitelisted IP: {ip}")
            continue

        confirm = input(f"Block {ip}? [y/N]: ").strip().lower()
        if confirm == 'y':
            block_ip(ip)
            log_block(ip)
            print(f"Blocked: {ip}")
        else:
            print(f"Skipped: {ip}")

    print("Finished blocking.")

if __name__ == "__main__":
    main()
