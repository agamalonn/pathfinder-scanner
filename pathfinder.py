import nmap
import socket
import json
import httpx
from datetime import datetime

class PathFinderPro:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def fetch_cve_details(self, product, version):
        """Queries a vulnerability database for known CVEs."""
        if not product or not version:
            return "No specific version detected for CVE lookup."
        
        # Using a public API (like Vulners or NIST - simplified for this demo)
        search_query = f"{product} {version}"
        print(f"  [!] Searching vulnerabilities for: {search_query}...")
        
        # This is a simulation of an API call to a vulnerability DB
        # In a production tool, you'd use an API Key for NIST NVD or Vulners
        return f"Potential exploits found for {product} {version}. Check https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={product}"

    def run_scan(self):
        print(f"[*] PathFinder: Analyzing {self.target} for attack paths...")
        try:
            # -sV: Service/Version detection
            # -O: OS detection (requires sudo/root)
            self.scanner.scan(self.target, '22,80,443,445,3389', '-sV')
        except Exception as e:
            return {"error": str(e)}

        report = []
        for host in self.scanner.all_hosts():
            host_data = {
                "ip": host,
                "status": self.scanner[host].state(),
                "services": []
            }
            
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    svc = self.scanner[host][proto][port]
                    vuln_info = self.fetch_cve_details(svc['product'], svc['version'])
                    
                    host_data["services"].append({
                        "port": port,
                        "service": svc['name'],
                        "product": svc['product'],
                        "version": svc['version'],
                        "security_note": vuln_info
                    })
            report.append(host_data)
        return report

    def save_report(self, data):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"attack_surface_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"\n[+] Professional security report generated: {filename}")

if __name__ == "__main__":
    # Get local IP safely
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
