import nmap
import socket
import json
from datetime import datetime

# ANSI Color Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

class PathFinderPro:
    def __init__(self, target_range):
        self.target_range = target_range
        self.scanner = nmap.PortScanner()

    def fetch_cve_details(self, product, version):
        if not product or not version:
            return None
        # Logic: Flagging specific common vulnerable services
        return f"Risk Analysis: {product} version {version} might contain known vulnerabilities. Manual verify recommended."

    def run_scan(self):
        print(f"\n{BLUE}{BOLD}[*] PathFinder: Scanning Entire Subnet: {self.target_range}{RESET}")
        print(f"{BLUE}-----------------------------------------------------------{RESET}")
        
        try:
            # -F (Fast scan): Scans top 100 ports to save time on a whole subnet
            # -sV: Version detection
            self.scanner.scan(hosts=self.target_range, arguments='-F -sV')
        except Exception as e:
            print(f"{RED}[!] Scan Error: {e}{RESET}")
            return []

        report = []
        for host in self.scanner.all_hosts():
            host_state = self.scanner[host].state()
            if host_state == "up":
                print(f"{GREEN}[+] Host Found: {host}{RESET}")
                host_data = {"ip": host, "services": []}
                
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    for port in ports:
                        svc = self.scanner[host][proto][port]
                        product = svc.get('product', '')
                        version = svc.get('version', '')
                        
                        print(f"    {CYAN}Port {port}:{RESET} {svc['name']} {YELLOW}({product} {version}){RESET}")
                        
                        vuln = self.fetch_cve_details(product, version)
                        if vuln:
                            print(f"    {RED}    [!] {vuln}{RESET}")
                        
                        host_data["services"].append({
                            "port": port,
                            "service": svc['name'],
                            "product": product,
                            "version": version
                        })
                report.append(host_data)
        return report

    def save_report(self, data):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"network_attack_surface_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"\n{GREEN}{BOLD}[V] Full Network Report Generated: {filename}{RESET}\n")

if __name__ == "__main__":
    print(f"{CYAN}{BOLD}")
    print("  _____       _   _      ______ _           _ ")
    print(" |  __ \     | | | |    |  ____(_)         | |")
    print(" | |__) |__ _| |_| |__  | |__   _ _ __   __| | ___ _ __")
    print(" |  ___/ _` | __| '_ \ |  __| | | '_ \ / _` |/ _ \ '__|")
    print(" | |  | (_| | |_| | | || |    | | | | | (_| |  __/ |")
    print(" |_|   \__,_|\__|_| |_||_|    |_|_| |_|\__,_|\___|_|")
    print(f"                                       (Network Edition){RESET}")

    # Step 1: Find Local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except:
        local_ip = '127.0.0.1'
    finally:
        s.close()

    # Step 2: Convert IP to Subnet Range (e.g., 192.168.0.201 -> 192.168.0.0/24)
    network_base = ".".join(local_ip.split(".")[:-1]) + ".0/24"
    
    # Step 3: Run
    scanner = PathFinderPro(network_base)
    results = scanner.run_scan()
    scanner.save_report(results)
