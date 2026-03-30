import nmap
import socket
import json
import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime

# --- Colors for Terminal UI ---
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
BOLD = '\033[1m'
RESET = '\033[0m'

class PathFinderPro:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()

    def run_scan(self):
        print(f"{CYAN}[*] PathFinder: Scanning {self.target}...{RESET}")
        print("-" * 59)
        # Fast scan for common ports
        self.nm.scan(hosts=self.target, arguments='-F --open') 
        
        results = []
        for host in self.nm.all_hosts():
            host_info = {
                "ip": host,
                "status": self.nm[host].state(),
                "services": []
            }
            print(f"{GREEN}[+] Host Found: {host}{RESET}")
            
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    svc = self.nm[host][proto][port]
                    print(f"    Port {port}: {svc['name']} ({svc.get('product', '')})")
                    
                    # Logic layer for "Risk Analysis" (XM Cyber style)
                    risk = ""
                    if svc.get('version') or svc.get('product'):
                        risk = f"Potential CVE check recommended for {svc['product']}"
                        print(f"        {YELLOW}[!] Risk: {risk}{RESET}")

                    host_info["services"].append({
                        "port": port,
                        "name": svc['name'],
                        "risk": risk
                    })
            results.append(host_info)
        return results

class PathfinderVisualizer:
    def __init__(self, scan_data):
        self.data = scan_data
        self.G = nx.Graph()

    def draw(self):
        print(f"\n{CYAN}[*] Generating Risk-Based Attack Surface...{RESET}")
        center = "Gateway"
        self.G.add_node(center, color='gray', size=1200)

        for host in self.data:
            ip = host['ip']
            # חישוב ציון סיכון בסיסי
            risk_score = len(host['services']) * 2
            
            # קביעת צבע לפי סיכון
            node_color = 'green'
            if risk_score > 5: node_color = 'orange'
            if risk_score > 10: node_color = 'red'
            
            self.G.add_node(ip, color=node_color, size=1000)
            self.G.add_edge(center, ip)
            
            for svc in host['services']:
                svc_label = f"{ip}:{svc['port']}"
                self.G.add_node(svc_label, color='lightgray', size=300)
                self.G.add_edge(ip, svc_label)

        plt.figure(figsize=(12, 10))
        pos = nx.spring_layout(self.G, k=0.5)
        
        colors = [self.G.nodes[n]['color'] for n in self.G.nodes()]
        sizes = [self.G.nodes[n]['size'] for n in self.G.nodes()]
        
        nx.draw(self.G, pos, with_labels=True, node_color=colors, 
                node_size=sizes, font_size=8, edge_color='silver', alpha=0.8)
        
        plt.title("PathFinder: Network Risk Map (Red = High Attack Surface)")
        plt.show()

def print_banner():
    print(f"{CYAN}{BOLD}")
    print("  _____       _   _      ______ _           _Z")
    print(" |  __ \     | | | |    |  ____(_)         | |")
    print(" | |__) |__ _| |_| |__  | |__   _ _ __   __| | ___ _ __")
    print(" |  ___/ _` | __| '_ \ |  __| | | '_ \ / _` |/ _ \ '__|")
    print(" | |  | (_| | |_| | | || |    | | | | | (_| |  __/ |")
    print(" |_|   \__,_|\__|_| |_||_|    |_|_| |_|\__,_|\___|_|")
    print(f"                                       (By Agam){RESET}")

if __name__ == "__main__":
    print_banner()

    # Step 1: Network Range Discovery
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        network_base = ".".join(local_ip.split(".")[:-1]) + ".0/24"
    except:
        network_base = '127.0.0.1'
    finally:
        s.close()

    # Step 2: Run Scan
    scanner = PathFinderPro(network_base)
    scan_results = scanner.run_scan()

    # Step 3: Show Map
    if scan_results:
        viz = PathfinderVisualizer(scan_results)
        viz.draw()
    else:
        print(f"{RED}[!] No hosts found to visualize.{RESET}")