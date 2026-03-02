<div align="center">

<img src="docs/logo.svg" alt="NmapViz Logo" width="120" height="120"/>

# NmapViz

**A BloodHound-style graphical visualizer for nmap scan results**

[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://hub.docker.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Port](https://img.shields.io/badge/Port-12221-58A6FF)](#)

Drop your nmap XML files in. Instantly see your network as an interactive node graph with automatic vulnerability detection, subnet clustering, and exportable reports.

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Node graph visualisation** | Interactive graph with draggable nodes |
| **Subnet clustering** | Hosts are automatically grouped by /24 subnet, keeps large networks manageable. Double-click any cluster to expand it |
| **Multi-file import & merge** | Drop multiple XML files at once. NmapViz merges them intelligently, deduplicating hosts and combining port data |
| **Port classification** | Every open port is classified as **critical** 🔴, **interesting** 🟠, or normal 🟢 with explanations |
| **Vulnerability detection** | Analyses service versions and NSE script output to flag EternalBlue, Heartbleed, SMB issues, default credentials, and more |
| **Version-scan awareness** | Clearly indicates when a scan lacks `-sV` and what information is missing |
| **Scan history** | Every uploaded scan is saved automatically. Browse, reload, and compare past scans at any time |
| **Export reports** | Download results as **JSON**, **HTML** (standalone, dark theme), or **Markdown** |
| **Help & reference** | Built-in nmap command reference with flags, examples, and large-network strategies |

---

## 📸 Screenshots

> Add screenshots to `docs/screenshots/` after running the app.

### Upload Screen
![Upload screen](docs/screenshots/01_upload.png)
*Multi-file drag-and-drop upload. Supports merging multiple XML files from different scans or subnets.*

### Interactive Graph
![Graph view](docs/screenshots/02_graph.png)
*BloodHound-style node graph. Nodes are colour-coded by risk level. Subnet clusters collapse large networks into manageable groups — double-click to expand.*

### Port Details
![Port details sidebar](docs/screenshots/03_ports.png)
*Left sidebar showing all open ports for a selected host, sorted by severity. Critical and interesting ports are highlighted with explanations.*

### Vulnerability Panel
![Vulnerability panel](docs/screenshots/04_vulns.png)
*Detected vulnerabilities sorted by severity (CRITICAL → HIGH → MEDIUM → LOW). Includes CVE references and the detection source (NSE script or version analysis).*

### Scan History & Export
![History and export](docs/screenshots/05_history.png)
*Persistent scan history with one-click reload. Export any scan as JSON, HTML report, or Markdown for pentest documentation.*

---

## 🚀 Quick Start (Docker — Recommended)

### Requirements
- [Docker Desktop](https://docs.docker.com/get-docker/) installed and running
- That's it. No Python, no dependencies.

### Run in 3 commands

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/nmap-visualizer.git
cd nmap-visualizer

# 2. Build and start
docker compose up --build -d

# 3. Open in browser
open http://localhost:12221   # macOS
# or just navigate to http://localhost:12221
```

### Useful Docker commands

```bash
# View logs
docker compose logs -f

# Stop
docker compose down

# Stop and delete all data (including scan history)
docker compose down -v

# Rebuild after code changes
docker compose up --build -d
```

---

## 🐍 Manual Installation (Python)

If you prefer not to use Docker:

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/nmap-visualizer.git
cd nmap-visualizer

# 2. Create virtual environment
python3 -m venv venv

# Activate — Linux/macOS:
source venv/bin/activate
# Activate — Windows:
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py
```

Open http://localhost:12221

---

## 📡 Generating nmap XML Files

NmapViz reads the standard nmap XML output format (`-oX`). Here are the most useful commands:

### Basic — just find open ports
```bash
nmap -oX output.xml 192.168.1.0/24
```

### Recommended — with version detection
```bash
nmap -sV -oX output.xml 192.168.1.0/24
```
Detects service versions, enabling vulnerability matching.

### Full — OS detection, scripts, versions
```bash
nmap -A -oX output.xml 192.168.1.0/24
```

### Maximum coverage — with vulnerability scripts
```bash
nmap -sV --script vuln -oX output.xml 192.168.1.0/24
nmap -A --script vuln -oX output.xml 192.168.1.0/24
```
Detects EternalBlue, Heartbleed, SMB signing issues, FTP anonymous access, and many more.

### Large network — fast and focused
```bash
# Scan top 150 ports at aggressive timing (great for /16 or larger)
nmap -sV --top-ports 150 -T4 -n --open -oX fast.xml 10.0.0.0/16

# Merge multiple subnet scans in NmapViz:
nmap -sV -oX scan_192.xml 192.168.1.0/24
nmap -sV -oX scan_10.xml  10.0.0.0/24
# → drop both files into NmapViz at once
```

---

## 🔴 What Gets Flagged

### Critical Ports (should never be exposed)
Telnet (23), FTP (21), TFTP (69), rsh/rexec/rlogin (512-514), Finger (79), NetBIOS (137/138), SNMP (161), common backdoor ports (4444, 6666, 6667)

### Interesting Ports (require attention)
SSH (22), RDP (3389), SMB (445/139), WinRM (5985/5986), VNC (5900), all databases (MySQL, MSSQL, PostgreSQL, MongoDB, Redis, Elasticsearch), LDAP/Kerberos, DNS, Docker/Kubernetes APIs, and more

### Vulnerability Detection (from NSE scripts + version analysis)
- **EternalBlue / MS17-010** (CVE-2017-0144)
- **SMB Signing disabled** — NTLM Relay attacks
- **SMBv1 enabled** — WannaCry vector
- **Heartbleed** (CVE-2014-0160)
- **POODLE / SSLv3** (CVE-2014-3566)
- **DROWN** (CVE-2016-0800)
- **FTP anonymous access**
- **Redis without authentication**
- **SSH password authentication enabled**
- **Outdated OpenSSH, Apache, PHP, IIS versions**
- **RDP without NLA**
- **HTTP default credentials**
- **Shellshock** (CVE-2014-6271)
- …and more

---

## 📁 Project Structure

```
nmap-visualizer/
├── app.py                  # Flask backend — parsing, history, reports
├── templates/
│   └── index.html          # Full frontend (single file)
├── history/                # Saved scan results (auto-created)
├── docs/
│   ├── logo.svg
│   └── screenshots/        # Add your screenshots here
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .gitignore
└── README.md
```

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit: `git commit -m 'feat: add my feature'`
4. Push: `git push origin feat/my-feature`
5. Open a pull request

---

## ⚠️ Disclaimer

NmapViz is intended for **authorised security assessments only**. Always obtain written permission before scanning any network you do not own. The authors accept no responsibility for misuse.

---

## 📄 Licence

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">
Made with ❤️ for security professionals and network engineers
</div>