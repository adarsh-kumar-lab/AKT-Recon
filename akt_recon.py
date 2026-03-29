#!/usr/bin/env python3
# ============================================================
#   AKT-Recon v1.0 — Bug Bounty Automation Tool
#   Author  : Adarsh Kumar Tiwari
#   GitHub  : github.com/adarsh-kumar-lab
#   Purpose : Educational & Authorized Testing Only
# ============================================================

import os, sys, json, socket, subprocess, argparse, datetime, threading, time
import urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colour helpers ───────────────────────────────────────────
class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    BLUE   = "\033[94m"; CYAN   = "\033[96m"; WHITE  = "\033[97m"
    BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
 █████╗ ██╗  ██╗████████╗      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██║ ██╔╝╚══██╔══╝      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║█████╔╝    ██║   █████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║██╔═██╗    ██║   ╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║██║  ██╗   ██║         ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝         ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.RESET}
{C.YELLOW}        Bug Bounty Automation Tool v1.0  |  by Adarsh Kumar Tiwari{C.RESET}
{C.DIM}        For authorized testing only. Unauthorized use is illegal.{C.RESET}
    """)

def log(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": C.CYAN, "OK": C.GREEN, "WARN": C.YELLOW,
              "VULN": C.RED, "SKIP": C.DIM, "STEP": C.BLUE + C.BOLD}
    icons  = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]",
              "VULN": "[VULN]", "SKIP": "[-]", "STEP": "[>>]"}
    c = colors.get(level, C.WHITE)
    i = icons.get(level, "[?]")
    print(f"{C.DIM}{ts}{C.RESET} {c}{i} {msg}{C.RESET}")

def step_banner(n, title):
    print(f"\n{C.BLUE}{C.BOLD}{'='*60}")
    print(f"  STEP {n}: {title}")
    print(f"{'='*60}{C.RESET}")

# ── Results container ────────────────────────────────────────
class Results:
    def __init__(self, target):
        self.target      = target
        self.timestamp   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.subdomains  = []
        self.dns         = {}
        self.ports       = []
        self.web_info    = {}
        self.directories = []
        self.vulns       = []
        self.headers     = {}
        self.techs       = []

R = None  # global results

# ── STEP 1: DNS Reconnaissance ───────────────────────────────
def step_dns(target):
    step_banner(1, "DNS Reconnaissance")
    results = {}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for rtype in record_types:
        try:
            out = subprocess.check_output(
                ["dig", "+short", rtype, target],
                stderr=subprocess.DEVNULL, timeout=10
            ).decode().strip()
            if out:
                results[rtype] = out.split("\n")
                log(f"{rtype} records: {out[:80]}", "OK")
            else:
                log(f"No {rtype} records found", "SKIP")
        except Exception:
            log(f"{rtype} lookup failed", "SKIP")

    # WHOIS
    try:
        whois = subprocess.check_output(
            ["whois", target], stderr=subprocess.DEVNULL, timeout=15
        ).decode()
        for line in whois.split("\n"):
            if any(k in line.lower() for k in ["registrar:", "creation", "expir", "org:"]):
                log(f"WHOIS: {line.strip()}", "INFO")
        results["whois_snippet"] = [l.strip() for l in whois.split("\n")
                                     if any(k in l.lower() for k in
                                            ["registrar","creation","expir","org"]) and l.strip()][:8]
    except Exception:
        log("WHOIS lookup failed", "SKIP")

    R.dns = results
    return results

# ── STEP 2: Subdomain Enumeration ───────────────────────────
SUBDOMAINS_WORDLIST = [
    "www","mail","ftp","admin","api","dev","staging","test","blog","shop",
    "portal","vpn","remote","ns1","ns2","smtp","pop","imap","webmail",
    "mx","cdn","static","assets","app","mobile","m","beta","secure",
    "login","dashboard","panel","cpanel","whm","webdisk","autodiscover",
    "autoconfig","git","svn","jenkins","jira","wiki","docs","support",
    "help","status","monitor","grafana","kibana","elastic","db","mysql",
    "redis","s3","backup","old","new","v1","v2","internal","intranet",
    "cloud","office","meeting","conference","video","media","images","img",
]

def check_subdomain(sub, target):
    fqdn = f"{sub}.{target}"
    try:
        ip = socket.gethostbyname(fqdn)
        return (fqdn, ip)
    except Exception:
        return None

def step_subdomains(target, threads=50):
    step_banner(2, "Subdomain Enumeration")
    log(f"Testing {len(SUBDOMAINS_WORDLIST)} subdomains with {threads} threads...", "INFO")
    found = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_subdomain, s, target): s for s in SUBDOMAINS_WORDLIST}
        for f in as_completed(futures):
            res = f.result()
            if res:
                found.append(res)
                log(f"Found: {res[0]}  →  {res[1]}", "OK")
    if not found:
        log("No subdomains discovered", "SKIP")
    R.subdomains = found
    return found

# ── STEP 3: Port Scanning ────────────────────────────────────
TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,161,
             443,445,465,587,993,995,1433,1521,2181,3000,
             3306,3389,4444,5000,5432,5900,6379,7001,7443,
             8000,8008,8080,8443,8888,9000,9090,9200,27017]

def scan_port(host, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except Exception:
                service = "unknown"
            return (port, service)
    except Exception:
        pass
    return None

SERVICE_BANNERS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3000: "Dev Server",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

def step_ports(target, threads=100):
    step_banner(3, "Port Scanning")
    try:
        ip = socket.gethostbyname(target)
        log(f"Target IP: {ip}", "INFO")
    except Exception:
        ip = target

    log(f"Scanning {len(TOP_PORTS)} common ports...", "INFO")
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in TOP_PORTS}
        for f in as_completed(futures):
            res = f.result()
            if res:
                port, svc = res
                friendly = SERVICE_BANNERS.get(port, svc)
                open_ports.append({"port": port, "service": friendly})
                risk = "HIGH" if port in [21,23,445,3389,5900,27017] else "MEDIUM" if port in [22,25,80,443,3306] else "LOW"
                color = C.RED if risk=="HIGH" else C.YELLOW if risk=="MEDIUM" else C.GREEN
                log(f"Port {port:5d}/tcp  OPEN  {friendly:15s}  {color}[{risk}]{C.RESET}", "OK")

    open_ports.sort(key=lambda x: x["port"])
    if not open_ports:
        log("No open ports found", "SKIP")
    R.ports = open_ports
    return open_ports

# ── STEP 4: Web Fingerprinting ───────────────────────────────
def step_web_fingerprint(target):
    step_banner(4, "Web Fingerprinting & Header Analysis")
    info = {}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AKT-Recon/1.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            headers = dict(resp.headers)
            info["url"]        = url
            info["status"]     = resp.status
            info["headers"]    = headers
            R.headers          = headers

            log(f"Web server reachable: {url} [{resp.status}]", "OK")

            # Tech detection
            server = headers.get("Server", "")
            powered = headers.get("X-Powered-By", "")
            techs = []
            if server:  techs.append(f"Server: {server}")
            if powered: techs.append(f"X-Powered-By: {powered}")
            if "wp-content" in str(resp.read(2000)): techs.append("WordPress")
            R.techs = techs
            for t in techs: log(f"Technology: {t}", "INFO")

            # Security headers check
            sec_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy":   "CSP",
                "X-Frame-Options":           "Clickjacking Protection",
                "X-Content-Type-Options":    "MIME Sniffing Protection",
                "Referrer-Policy":           "Referrer Policy",
                "Permissions-Policy":        "Permissions Policy",
            }
            for h, name in sec_headers.items():
                if h in headers:
                    log(f"Header present: {name}", "OK")
                else:
                    log(f"Missing security header: {name}", "WARN")
                    R.vulns.append({
                        "type": "Missing Security Header",
                        "detail": f"{h} header not set",
                        "severity": "LOW",
                        "url": url
                    })
            break
        except Exception as e:
            log(f"{scheme} failed: {e}", "SKIP")

    R.web_info = info
    return info

# ── STEP 5: Directory Brute Force ────────────────────────────
DIR_WORDLIST = [
    "admin","login","dashboard","api","api/v1","api/v2","backup","config",
    "wp-admin","wp-login.php","phpmyadmin","phpinfo.php","info.php",
    ".git","/.git/config",".env","robots.txt","sitemap.xml","crossdomain.xml",
    "uploads","files","images","static","assets","js","css",
    "users","profile","settings","password","forgot","reset",
    "register","signup","logout","auth","oauth","token",
    "test","dev","old","new","temp","tmp","debug","logs","log",
    "server-status","server-info","nginx_status","health","status",
    "swagger","swagger-ui","swagger.json","openapi.json","api-docs",
    "graphql","graphiql",".htaccess","web.config","package.json",
]

def check_dir(base_url, path):
    url = f"{base_url}/{path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AKT-Recon/1.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        if resp.status in [200, 201, 204, 301, 302, 403]:
            return (url, resp.status)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return (url, 403)
    except Exception:
        pass
    return None

def step_dirbrute(target, threads=30):
    step_banner(5, "Directory & File Brute Force")
    base = R.web_info.get("url", f"http://{target}")
    log(f"Testing {len(DIR_WORDLIST)} paths on {base}", "INFO")
    found = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_dir, base, p): p for p in DIR_WORDLIST}
        for f in as_completed(futures):
            res = f.result()
            if res:
                url, code = res
                color = C.GREEN if code==200 else C.YELLOW if code==403 else C.CYAN
                log(f"{color}[{code}]{C.RESET}  {url}", "OK")
                found.append({"url": url, "status": code})
                if any(s in url for s in [".env",".git","backup","config","phpinfo","debug"]):
                    R.vulns.append({
                        "type": "Sensitive File Exposed",
                        "detail": f"Accessible: {url}",
                        "severity": "HIGH",
                        "url": url
                    })
    if not found:
        log("No directories found", "SKIP")
    R.directories = found
    return found

# ── STEP 6: Vulnerability Detection ─────────────────────────
SQLI_PAYLOADS = ["'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1"]
XSS_PAYLOADS  = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                 "'\"><script>alert(1)</script>"]
OPEN_REDIRECT  = ["//evil.com", "https://evil.com", "//evil.com/%2F.."]

def test_get_param(base_url, param, payload, vuln_type):
    url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AKT-Recon/1.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        body = resp.read(4000).decode(errors="ignore")
        if vuln_type == "SQLi" and any(e in body.lower() for e in
                ["sql syntax","mysql","sqlite","pg:","ora-","odbc","warning: mysql"]):
            return True, body[:200]
        if vuln_type == "XSS" and payload.lower() in body.lower():
            return True, body[:200]
    except Exception:
        pass
    return False, ""

def step_vuln_scan(target):
    step_banner(6, "Vulnerability Detection")
    base = R.web_info.get("url", f"http://{target}")
    common_params = ["id","q","search","query","page","cat","user","name","url","redirect","next","ref"]

    log("Testing SQL Injection...", "INFO")
    for param in common_params[:5]:
        for payload in SQLI_PAYLOADS[:3]:
            found, snippet = test_get_param(base, param, payload, "SQLi")
            if found:
                log(f"POSSIBLE SQLi — param={param} payload={payload}", "VULN")
                R.vulns.append({"type":"SQL Injection","detail":f"param={param} payload={payload}","severity":"CRITICAL","url":base})
                break

    log("Testing XSS...", "INFO")
    for param in common_params[:5]:
        for payload in XSS_PAYLOADS[:2]:
            found, snippet = test_get_param(base, param, payload, "XSS")
            if found:
                log(f"POSSIBLE XSS — param={param}", "VULN")
                R.vulns.append({"type":"Cross-Site Scripting (XSS)","detail":f"param={param}","severity":"HIGH","url":base})
                break

    log("Checking for Open Redirect...", "INFO")
    for param in ["redirect","next","url","return","returnUrl","goto","dest"]:
        for payload in OPEN_REDIRECT:
            url = f"{base}?{param}={urllib.parse.quote(payload)}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"AKT-Recon/1.0"})
                resp = urllib.request.urlopen(req, timeout=8)
                final = resp.geturl()
                if "evil.com" in final:
                    log(f"OPEN REDIRECT — param={param}", "VULN")
                    R.vulns.append({"type":"Open Redirect","detail":f"param={param}","severity":"MEDIUM","url":url})
            except Exception:
                pass

    if not R.vulns:
        log("No obvious vulnerabilities detected (manual testing still needed)", "OK")
    else:
        log(f"{len(R.vulns)} potential issues found!", "WARN")

# ── STEP 7: Report Generation ────────────────────────────────
SEVERITY_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
SEVERITY_COLOR = {"CRITICAL":"#c0392b","HIGH":"#e67e22","MEDIUM":"#f1c40f","LOW":"#27ae60","INFO":"#2980b9"}

def generate_html_report(outdir):
    path = os.path.join(outdir, "report.html")
    vuln_rows = ""
    for v in sorted(R.vulns, key=lambda x: SEVERITY_ORDER.get(x["severity"],9)):
        col = SEVERITY_COLOR.get(v["severity"],"#888")
        vuln_rows += f"""<tr>
          <td><span class="badge" style="background:{col}">{v['severity']}</span></td>
          <td>{v['type']}</td>
          <td>{v['detail']}</td>
          <td><a href="{v['url']}" target="_blank">{v['url'][:60]}</a></td>
        </tr>"""

    port_rows = "".join(f"<tr><td>{p['port']}</td><td>{p['service']}</td></tr>" for p in R.ports)
    sub_rows  = "".join(f"<tr><td>{s[0]}</td><td>{s[1]}</td></tr>" for s in R.subdomains)
    dir_rows  = "".join(f"<tr><td>{d['url']}</td><td>{d['status']}</td></tr>" for d in R.directories[:30])

    dns_html = ""
    for rtype, vals in R.dns.items():
        if isinstance(vals, list):
            dns_html += f"<tr><td>{rtype}</td><td>{'<br>'.join(vals)}</td></tr>"

    total_vulns = len(R.vulns)
    critical = sum(1 for v in R.vulns if v["severity"]=="CRITICAL")
    high     = sum(1 for v in R.vulns if v["severity"]=="HIGH")
    medium   = sum(1 for v in R.vulns if v["severity"]=="MEDIUM")
    low      = sum(1 for v in R.vulns if v["severity"]=="LOW")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AKT-Recon Report — {R.target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }}
  .header {{ background: linear-gradient(135deg, #161b22, #1f2937); padding: 40px; border-bottom: 2px solid #30363d; }}
  .header h1 {{ color: #58a6ff; font-size: 2.4em; letter-spacing: 2px; }}
  .header p {{ color: #8b949e; margin-top: 8px; font-size: 1em; }}
  .header .target {{ color: #f0883e; font-size: 1.3em; font-weight: bold; margin-top: 10px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr)); gap: 16px; margin: 24px 0; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; text-align: center; }}
  .stat-card .num {{ font-size: 2.2em; font-weight: bold; }}
  .stat-card .label {{ color: #8b949e; font-size: 0.85em; margin-top: 4px; }}
  .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; margin: 20px 0; overflow: hidden; }}
  .section-title {{ background: #21262d; padding: 14px 20px; font-size: 1.05em; font-weight: bold; color: #58a6ff; border-bottom: 1px solid #30363d; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #21262d; color: #8b949e; padding: 10px 14px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #21262d; font-size: 0.92em; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 20px; color: white; font-size: 0.78em; font-weight: bold; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .footer {{ text-align: center; padding: 30px; color: #484f58; font-size: 0.85em; border-top: 1px solid #21262d; margin-top: 40px; }}
  .warning {{ background: #2d1b00; border: 1px solid #f0883e; border-radius: 8px; padding: 14px 20px; margin: 20px 0; color: #f0883e; font-size: 0.9em; }}
  .empty {{ color: #484f58; padding: 20px; text-align: center; font-style: italic; }}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ AKT-Recon</h1>
  <p>Bug Bounty Automation Tool  |  by Adarsh Kumar Tiwari</p>
  <div class="target">Target: {R.target}</div>
  <p style="margin-top:6px;color:#8b949e;">Scan completed: {R.timestamp}</p>
</div>

<div class="container">
  <div class="warning">⚠️ This report is for authorized security testing only. Unauthorized use is illegal and unethical.</div>

  <div class="stats">
    <div class="stat-card"><div class="num" style="color:#c0392b">{critical}</div><div class="label">CRITICAL</div></div>
    <div class="stat-card"><div class="num" style="color:#e67e22">{high}</div><div class="label">HIGH</div></div>
    <div class="stat-card"><div class="num" style="color:#f1c40f">{medium}</div><div class="label">MEDIUM</div></div>
    <div class="stat-card"><div class="num" style="color:#27ae60">{low}</div><div class="label">LOW</div></div>
    <div class="stat-card"><div class="num" style="color:#58a6ff">{len(R.ports)}</div><div class="label">OPEN PORTS</div></div>
    <div class="stat-card"><div class="num" style="color:#a371f7">{len(R.subdomains)}</div><div class="label">SUBDOMAINS</div></div>
    <div class="stat-card"><div class="num" style="color:#3fb950">{len(R.directories)}</div><div class="label">DIRECTORIES</div></div>
    <div class="stat-card"><div class="num" style="color:#58a6ff">{total_vulns}</div><div class="label">TOTAL FINDINGS</div></div>
  </div>

  <div class="section">
    <div class="section-title">🎯 Vulnerability Findings</div>
    {"<table><tr><th>Severity</th><th>Type</th><th>Detail</th><th>URL</th></tr>" + vuln_rows + "</table>" if vuln_rows else '<div class="empty">No vulnerabilities detected</div>'}
  </div>

  <div class="section">
    <div class="section-title">🚪 Open Ports</div>
    {"<table><tr><th>Port</th><th>Service</th></tr>" + port_rows + "</table>" if port_rows else '<div class="empty">No open ports found</div>'}
  </div>

  <div class="section">
    <div class="section-title">🌐 Subdomains</div>
    {"<table><tr><th>Subdomain</th><th>IP Address</th></tr>" + sub_rows + "</table>" if sub_rows else '<div class="empty">No subdomains found</div>'}
  </div>

  <div class="section">
    <div class="section-title">📁 Directories & Files</div>
    {"<table><tr><th>URL</th><th>Status</th></tr>" + dir_rows + "</table>" if dir_rows else '<div class="empty">No directories found</div>'}
  </div>

  <div class="section">
    <div class="section-title">🔍 DNS Records</div>
    {"<table><tr><th>Type</th><th>Value</th></tr>" + dns_html + "</table>" if dns_html else '<div class="empty">No DNS records found</div>'}
  </div>

  <div class="section">
    <div class="section-title">🛡️ Security Headers</div>
    <table><tr><th>Header</th><th>Value</th></tr>
    {"".join(f"<tr><td>{k}</td><td>{str(v)[:100]}</td></tr>" for k,v in R.headers.items())}
    </table>
  </div>
</div>

<div class="footer">
  Generated by AKT-Recon v1.0 — Adarsh Kumar Tiwari<br>
  github.com/adarsh-kumar-lab  |  For authorized testing only
</div>
</body></html>"""

    with open(path, "w") as f:
        f.write(html)
    log(f"HTML report saved: {path}", "OK")
    return path

def generate_json_report(outdir):
    path = os.path.join(outdir, "report.json")
    data = {
        "tool":       "AKT-Recon v1.0",
        "author":     "Adarsh Kumar Tiwari",
        "target":     R.target,
        "timestamp":  R.timestamp,
        "summary": {
            "open_ports":   len(R.ports),
            "subdomains":   len(R.subdomains),
            "directories":  len(R.directories),
            "vulns":        len(R.vulns),
        },
        "dns":         R.dns,
        "ports":       R.ports,
        "subdomains":  [{"fqdn": s[0], "ip": s[1]} for s in R.subdomains],
        "directories": R.directories,
        "vulns":       R.vulns,
        "headers":     R.headers,
        "technologies":R.techs,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    log(f"JSON report saved: {path}", "OK")
    return path

def generate_txt_report(outdir):
    path = os.path.join(outdir, "report.txt")
    lines = [
        "=" * 60,
        "  AKT-Recon v1.0 — Bug Bounty Report",
        "  Author   : Adarsh Kumar Tiwari",
        f"  Target   : {R.target}",
        f"  Scanned  : {R.timestamp}",
        "=" * 60, "",
        "[ VULNERABILITY FINDINGS ]",
    ]
    if R.vulns:
        for v in sorted(R.vulns, key=lambda x: SEVERITY_ORDER.get(x["severity"],9)):
            lines.append(f"  [{v['severity']}] {v['type']}")
            lines.append(f"    Detail : {v['detail']}")
            lines.append(f"    URL    : {v['url']}")
            lines.append("")
    else:
        lines.append("  No vulnerabilities detected.")
    lines += ["", "[ OPEN PORTS ]"]
    for p in R.ports:
        lines.append(f"  {p['port']:5d}/tcp  {p['service']}")
    lines += ["", "[ SUBDOMAINS ]"]
    for s in R.subdomains:
        lines.append(f"  {s[0]}  ->  {s[1]}")
    lines += ["", "[ DIRECTORIES ]"]
    for d in R.directories[:20]:
        lines.append(f"  [{d['status']}]  {d['url']}")
    lines += ["", "[ DNS RECORDS ]"]
    for rtype, vals in R.dns.items():
        if isinstance(vals, list):
            lines.append(f"  {rtype}: {', '.join(vals)}")
    lines += ["", "=" * 60,
              "  For authorized testing only.",
              "  github.com/adarsh-kumar-lab",
              "=" * 60]
    with open(path, "w") as f:
        f.write("\n".join(lines))
    log(f"TXT report saved: {path}", "OK")
    return path

def step_reports(target, outdir):
    step_banner(7, "Generating Reports")
    os.makedirs(outdir, exist_ok=True)
    html = generate_html_report(outdir)
    json_r = generate_json_report(outdir)
    txt  = generate_txt_report(outdir)
    print(f"\n{C.GREEN}{C.BOLD}{'='*60}")
    print(f"  SCAN COMPLETE — {R.target}")
    print(f"{'='*60}{C.RESET}")
    print(f"  {C.CYAN}HTML Report : {html}{C.RESET}")
    print(f"  {C.CYAN}JSON Report : {json_r}{C.RESET}")
    print(f"  {C.CYAN}TXT  Report : {txt}{C.RESET}")
    print(f"\n  {C.YELLOW}Findings   : {len(R.vulns)} issues{C.RESET}")
    print(f"  {C.YELLOW}Open Ports : {len(R.ports)}{C.RESET}")
    print(f"  {C.YELLOW}Subdomains : {len(R.subdomains)}{C.RESET}")
    print(f"  {C.YELLOW}Directories: {len(R.directories)}{C.RESET}")
    print(f"\n{C.DIM}  Tip: Open report.html in browser for best view{C.RESET}\n")

# ── Main ─────────────────────────────────────────────────────
def main():
    global R
    parser = argparse.ArgumentParser(
        description="AKT-Recon v1.0 — Bug Bounty Automation Tool by Adarsh Kumar Tiwari",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target",           help="Target domain (e.g. example.com)")
    parser.add_argument("-o","--output",    default="akt_results", help="Output directory (default: akt_results)")
    parser.add_argument("--skip-subs",      action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--skip-ports",     action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-dirs",      action="store_true", help="Skip directory brute force")
    parser.add_argument("--skip-vuln",      action="store_true", help="Skip vulnerability detection")
    parser.add_argument("--threads",        type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--ports-only",     action="store_true", help="Run only port scan")
    args = parser.parse_args()

    banner()
    print(f"{C.YELLOW}  Target  : {args.target}{C.RESET}")
    print(f"{C.YELLOW}  Output  : {args.output}/{C.RESET}")
    print(f"{C.YELLOW}  Threads : {args.threads}{C.RESET}")
    print(f"\n{C.RED}  [!] Only scan targets you have explicit written permission to test!{C.RESET}\n")
    time.sleep(1)

    target = args.target.replace("http://","").replace("https://","").rstrip("/")
    outdir = os.path.join(args.output, target, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    R = Results(target)

    start = time.time()

    if args.ports_only:
        step_ports(target, args.threads)
    else:
        step_dns(target)
        if not args.skip_subs:  step_subdomains(target, args.threads)
        if not args.skip_ports: step_ports(target, args.threads)
        step_web_fingerprint(target)
        if not args.skip_dirs:  step_dirbrute(target, min(args.threads, 30))
        if not args.skip_vuln:  step_vuln_scan(target)

    step_reports(target, outdir)
    elapsed = round(time.time() - start, 1)
    print(f"{C.DIM}  Total scan time: {elapsed}s{C.RESET}\n")

if __name__ == "__main__":
    main()
