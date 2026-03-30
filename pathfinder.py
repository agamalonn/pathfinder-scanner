import nmap
import socket
import json
from datetime import datetime

# ANSI Color Codes for terminal
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

class PathFinderPro:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def fetch_cve_details(self, product, version):
        if not product or not version:
            return None
        # Mock logic: if it's a known service, flag it
        return f"Vulnerability Check: {product} {version} may be exposed to known exploits."

    def run_scan(self):
        print(f"\n{BLUE}{BOLD}[*] PathFinder: Starting Analysis on {self.target}...{RESET}")
        print(f"{BLUE}-----------------------------------------------------------{RESET}")
        try:
            # Scanning common ports with version detection
            self.scanner.scan(self.target, '21,22,80,443,445,3389,8080', '-sV')
        except Exception as e:
            print(f"{RED}[!] Scan Error: {e}{RESET}")
            return []

        report = []
        for host in self.scanner.all_hosts():
            print(f"{GREEN}[+] Host Found: {host} ({self.scanner[host].state()}){RESET}")
            host_data = {"ip": host, "services": []}
            
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    svc = self.scanner[host][proto][port]
                    product = svc['product']
                    version = svc['version']
                    
                    print(f"    {CYAN}Port {port}:{RESET} {svc['name']} {YELLOW}({product} {version}){RESET}")
                    
                    vuln_info = self.fetch_cve_details(product, version)
                    if vuln_info:
                        print(f"    {RED}{BOLD}    [!] ALERT: {vuln_info}{RESET}")
                    
                    host_data["services"].append({
                        "port": port,
                        "service": svc['name'],
                        "product": product,
                        "version": version,
                        "security_note": vuln_info
                    })
            report.append(host_data)
        return report

    def save_report(self, data):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"attack_surface_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"\n{GREEN}{BOLD}[V] Professional JSON report generated: {filename}{RESET}\n")

if __name__ == "__main__":
    # ASCII Art Header
    print(f"{CYAN}{BOLD}")
    print("  _____       _   _      ______ _           _Z")
    print(" |  __ \     | | | |    |  ____(_)         | |")
    print(" | |__) |__ _| |_| |__  | |__   _ _ __   __| | ___ _ __")
    print(" |  ___/ _` | __| '_ \ |  __| | | '_ \ / _` |/ _ \ '__|")
    print(" | |  | (_| | |_| | | || |    | | | | | (_| |  __/ |")
    print(" |_|   \__,_|\__|_| |_||_|    |_|_| |_|\__,_|\___|_|")
    print(f"                                       (By Agam){RESET}")

    # Identify target (local IP)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except:
        local_ip = '127.0.0.1'
    finally:
        s.close()

    scanner = PathFinderPro(local_ip)
    results = scanner.run_scan()
    scanner.save_report(results)
