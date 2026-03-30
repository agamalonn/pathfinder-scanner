# Pathfinder Scanner 🔍

**Pathfinder Scanner** is a specialized network security tool developed in Python, designed to automate the discovery of services and map them to potential attack vectors. It bridges the gap between raw network scanning and vulnerability intelligence.

## 🎯 Project Goals
The core mission of this project is to simulate the initial phase of **Attack Path Management (APM)**:
1. **Asset Discovery:** Identifying active nodes in the network.
2. **Service Fingerprinting:** Deep analysis of running services and their specific versions.
3. **Vulnerability Mapping:** Associating identified versions with known security risks (CVEs).

## 🚀 Key Features
* **Intelligent Enumeration:** Utilizes `nmap` for high-performance port and service discovery.
* **Version Detection Logic:** Specifically extracts product names and versions to facilitate vulnerability lookups.
* **Automated Reporting:** Generates a structured `JSON` report (Attack Surface Report) for seamless integration with SOC or SIEM workflows.
* **Scalable Architecture:** Built with clean, Object-Oriented Python for future extensions.

## 🛠️ Technical Stack
* **Language:** Python 3.11+
* **Core Libraries:** `python-nmap`, `socket`, `json`, `httpx`
* **Engine:** Nmap (Network Mapper)

## 📋 How It Works
The scanner performs a non-intrusive analysis of the target's attack surface:
1. **Network Sync:** Dynamically identifies the local network context.
2. **Deep Scan:** Probes critical ports (22, 80, 443, etc.) for service details.
3. **Security Analysis:** Matches findings against a logic layer that suggests potential CVE paths.

## 📈 Future Roadmap
- [ ] **Live NIST NVD API Integration:** Directly fetching CVE descriptions and CVSS scores.
- [ ] **Visual Attack Graphs:** Generating DOT/Graphviz files to visualize movement between nodes.
- [ ] **Credential Check:** Implementing basic SSH/Telnet security checks for default credentials.

---
*Developed as a demonstration of Cybersecurity Infrastructure and Risk Assessment concepts.*
