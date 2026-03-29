# ⚡ AKT-Recon

<div align="center">

![AKT-Recon Banner](https://img.shields.io/badge/AKT--Recon-v2.0-red?style=for-the-badge&logo=kali-linux&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**Bug Bounty Automation Tool — BRUTAL EDITION**

*By Adarsh Kumar Tiwari | First Year B.Tech CSE | Centurion University*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Screenshots](#screenshots) • [Legal](#legal)

</div>

---

## 🎯 What is AKT-Recon?

AKT-Recon is a **professional-grade bug bounty automation tool** built entirely in Python. It automates the entire reconnaissance and vulnerability discovery process used by real penetration testers and bug bounty hunters.

Built from scratch by a first-year cybersecurity student — no frameworks, no shortcuts, pure Python.

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔍 DNS Recon | A, AAAA, MX, NS, TXT, SOA, CAA records + WHOIS + Zone Transfer |
| 🌐 Subdomain Enum | 80+ wordlist with multithreading + Takeover detection |
| 🚪 Port Scanning | 70+ ports with banner grabbing + risk rating |
| 🔐 SSL/TLS Analysis | Certificate info, weak ciphers, deprecated versions |
| 🛡️ WAF Detection | Cloudflare, Akamai, AWS WAF, Imperva, ModSecurity + 8 more |
| 🕷️ Web Fingerprint | CMS detection, security headers, tech stack |
| 🌍 CORS Testing | Wildcard, origin reflection, credentials bypass |
| 📁 Dir Brute Force | 100+ paths including .env, .git, backup files |
| ⚡ Vuln Detection | SQLi, XSS, LFI, SSRF, Open Redirect, SSTI, JWT |
| 📡 API Discovery | REST, GraphQL, Swagger, OpenAPI endpoints |
| 💀 Secret Scanning | AWS keys, JWT tokens, API keys in JS files |
| 📊 Triple Reports | HTML (beautiful) + JSON (parseable) + TXT (clean) |

---

## 🚀 Installation

### Requirements
- Python 3.8+
- Linux (Kali Linux recommended)
- Root or sudo access (for some modules)

### Quick Install

```bash
# Clone the repo
git clone https://github.com/adarsh-kumar-lab/AKT-Recon.git
cd AKT-Recon

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x akt_recon_v2.py

# Run
python3 akt_recon_v2.py --help
```

### Install System Dependencies

```bash
# Kali Linux / Debian
sudo apt update
sudo apt install -y dnsutils whois nmap python3-pip

# Python packages
pip install -r requirements.txt
```

---

## 📖 Usage

### Basic Scan
```bash
python3 akt_recon_v2.py testphp.vulnweb.com
```

### Full Brutal Scan
```bash
python3 akt_recon_v2.py target.com -t 100
```

### Skip Heavy Modules
```bash
python3 akt_recon_v2.py target.com --skip-subs --skip-dirs
```

### Quick Scan
```bash
python3 akt_recon_v2.py target.com --quick
```

### Port Scan Only
```bash
python3 akt_recon_v2.py target.com --skip-subs --skip-dirs --skip-vuln --skip-api
```

### Custom Output Directory
```bash
python3 akt_recon_v2.py target.com -o /home/kali/results
```

---

## ⚙️ Options

```
usage: akt_recon_v2.py [-h] [-o OUTPUT] [-t THREADS]
                        [--skip-subs] [--skip-ports] [--skip-ssl]
                        [--skip-dirs] [--skip-vuln] [--skip-api] [--quick]
                        target

positional arguments:
  target                Target domain (e.g. testphp.vulnweb.com)

optional arguments:
  -h, --help            Show help message
  -o, --output OUTPUT   Output directory (default: akt_results)
  -t, --threads INT     Number of threads (default: 60)
  --skip-subs           Skip subdomain enumeration
  --skip-ports          Skip port scanning
  --skip-ssl            Skip SSL/TLS analysis
  --skip-dirs           Skip directory brute force
  --skip-vuln           Skip vulnerability detection
  --skip-api            Skip API discovery
  --quick               Quick scan (skips heavy modules)
```

---

## 📊 Output

AKT-Recon generates **3 report formats** automatically:

```
akt_results/
└── target.com/
    └── 20260320_174523/
        ├── report.html    ← Beautiful dashboard
        ├── report.json    ← Machine-readable data
        └── report.txt     ← Clean text summary
```

### HTML Report includes:
- Risk severity dashboard (CRITICAL / HIGH / MEDIUM / LOW)
- All vulnerability findings with details
- Open ports with risk rating
- Subdomains with takeover status
- SSL/TLS certificate info
- WAF detection result
- API endpoints discovered
- Secrets found in JS files
- CORS misconfiguration results

---

## 🎯 Legal Practice Targets

These are **officially authorized** practice targets — safe and legal to test:

| Target | Type | Notes |
|--------|------|-------|
| `testphp.vulnweb.com` | Web App | Acunetix official target |
| `testasp.vulnweb.com` | ASP.NET | Acunetix official target |
| `testhtml5.vulnweb.com` | HTML5 | Acunetix official target |
| `hack.me` | Platform | Legal CTF practice |
| `tryhackme.com` | Platform | Guided rooms |

---

## 🔬 Vulnerabilities Detected

- **SQL Injection** — Error-based, Union-based, Blind, Time-based
- **Cross-Site Scripting (XSS)** — Reflected, Stored
- **Local File Inclusion (LFI)** — Path traversal, null byte
- **Server-Side Request Forgery (SSRF)** — AWS metadata, localhost
- **Open Redirect** — Multiple bypass techniques
- **Server-Side Template Injection (SSTI)** — Jinja2, Twig, Freemarker
- **JWT Vulnerabilities** — None algorithm, weak secrets
- **CORS Misconfiguration** — Wildcard, credential bypass
- **Subdomain Takeover** — GitHub, Heroku, AWS S3, Azure + 6 more
- **DNS Zone Transfer** — AXFR attempt on all nameservers
- **Missing Security Headers** — HSTS, CSP, X-Frame-Options + 4 more
- **Information Disclosure** — Server headers, tech stack exposure
- **Sensitive Files** — .env, .git, backup files, SSH keys

---

## 📁 Project Structure

```
AKT-Recon/
├── akt_recon_v2.py      ← Main tool
├── requirements.txt     ← Python dependencies
├── README.md            ← This file
├── LICENSE              ← MIT License
├── how to install.txt   ← Quick setup guide
└── examples/
    └── sample_report.html  ← Example output
```

---

## 🛠️ Tech Stack

- **Language:** Python 3.8+ (zero external dependencies for core)
- **Threading:** `concurrent.futures.ThreadPoolExecutor`
- **Networking:** `socket`, `urllib`, `ssl`, `http.client`
- **System:** `subprocess` for dig, whois, nmap
- **Reports:** Pure HTML/CSS/JS (no libraries needed)

---

## 🗺️ Roadmap

- [ ] Shodan API integration
- [ ] CVE matching by service version
- [ ] Nuclei template support
- [ ] Automated screenshot capture
- [ ] Slack/Discord webhook notifications
- [ ] Docker container
- [ ] GUI version

---

## ⚖️ Legal Disclaimer

> **AKT-Recon is for authorized security testing and educational purposes ONLY.**
>
> - ✅ Use on systems you OWN
> - ✅ Use on Bug Bounty targets within defined SCOPE
> - ✅ Use in CTF competitions
> - ❌ NEVER scan systems without written permission
> - ❌ Unauthorized scanning is ILLEGAL in every country
>
> The author takes NO responsibility for misuse of this tool.
> By using AKT-Recon, you agree to use it legally and ethically.

---

## 👨‍💻 Author

**Adarsh Kumar Tiwari**
- 🎓 B.Tech CSE — Centurion University, Bhubaneswar
- 🔗 LinkedIn: [linkedin.com/in/adarsh-kumar-tiwari-376a0b386](https://linkedin.com/in/adarsh-kumar-tiwari-376a0b386)
- 🐙 GitHub: [github.com/adarsh-kumar-lab](https://github.com/adarsh-kumar-lab)
- 🎯 TryHackMe: [Add your username]
- 📧 Email: 250301120292@centurionuniv.edu.in

---

## 📄 License

MIT License — Free to use, modify, and distribute with attribution.

---

<div align="center">

**⭐ Star this repo if it helped you!**

*Made with ❤️ and lots of coffee by Adarsh Kumar Tiwari*

</div>
