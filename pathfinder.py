import nmap
import requests
import socket
import json
from datetime import datetime

class PathFinderScanner:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def scan_network(self):
        print(f"[*] Starting professional scan on {self.target}...")
        # Scans for common ports and service versions
        # Standard ports: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), 445 (SMB), 3389 (RDP)
        try:
            self.scanner.scan(self.target, '21,22,80,443,445,3389', '-sV')
        except Exception as e:
            return [{"error": str(e)}]
        
        results = []
        for host in self.scanner.all_hosts():
            host_info = {
                "host": host,
                "hostname": self.scanner[host].hostname(),
                "state": self.scanner[host].state(),
                "ports": []
            }
            
            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in ports:
                    service = self.scanner[host][proto][port]
                    port_data = {
                        "port": port,
                        "name": service['name'],
                        "product": service['product'],
                        "version": service['version'],
                        "cpe": service.get('cpe', 'N/A')
                    }
                    # Look for vulnerabilities
                    port_data["vulnerabilities"] = self.check_cve(service['product'], service['version'])
                    host_info["ports"].append(port_data)
            results.append(host_info)
        return results

    def check_cve(self, product, version):
        if not product or not version:
            return []
        # In a real tool for XM Cyber, this would query the NIST NVD API
        return [f"Potential security risk: {product} {version} may have known exploits."]

    def generate_report(self, data):
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[+] Scan complete! Security report saved to {filename}")

if __name__ == "__main__":
    try:
        # Get local IP for scanning
        target_ip = socket.gethostbyname(socket.gethostname())
        scanner = PathFinderScanner(target_ip)
        scan_results = scanner.scan_network()
        scanner.generate_report(scan_results)
    except Exception as e:
        print(f"Error: {e}")
