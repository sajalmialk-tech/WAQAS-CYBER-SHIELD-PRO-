#!/usr/bin/env python3
# WAQAS CYBER SHIELD PRO
# Defensive, permission-based security checks. Use only on systems you own or are authorized to test.

import os
import re
import ssl
import json
import time
import socket
import shutil
import platform
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen

try:
    import requests
except ImportError:
    requests = None

APP_NAME = "WAQAS CYBER SHIELD PRO"
VERSION = "1.0"
REPORT_DIR = "reports"
LAST_RESULTS = []

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print("\033[96m")
    print("╔══════════════════════════════════════════════╗")
    print("║          WAQAS CYBER SHIELD PRO               ║")
    print("║       DEFENSIVE SECURITY TOOLKIT              ║")
    print("╚══════════════════════════════════════════════╝")
    print("\033[0m")

def pause():
    input("\nEnter دبائیں واپس جانے کے لیے...")

def record(title, data):
    global LAST_RESULTS
    item = {"tool": title, "time": datetime.now(timezone.utc).isoformat(), "result": data}
    LAST_RESULTS.append(item)
    return data

def ask_url():
    raw = input("Website URL (مثلاً https://example.com): ").strip()
    if not raw:
        raise ValueError("URL خالی ہے۔")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("درست HTTP/HTTPS URL درج کریں۔")
    return raw

def host_from_input():
    host = input("Domain یا IP درج کریں: ").strip()
    if not host or any(c in host for c in "/?# "):
        raise ValueError("صرف hostname یا IP درج کریں۔")
    return host

def get_response(url, timeout=8):
    if requests:
        return requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "WaqasCyberShield/1.0"})
    req = Request(url, headers={"User-Agent": "WaqasCyberShield/1.0"})
    return urlopen(req, timeout=timeout)

def show(title, data):
    record(title, data)
    print(f"\n--- {title} ---")
    if isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        print(data)

# 01 - Wi-Fi scan (Android + Termux:API)
def wifi_scan():
    if not shutil.which("termux-wifi-scaninfo"):
        return show("Wi-Fi Scanner", {
            "status": "Unavailable",
            "hint": "Android پر Termux:API app اور termux-api package انسٹال کریں؛ پھر termux-wifi-scaninfo چلائیں۔"
        })
    try:
        out = subprocess.check_output(["termux-wifi-scaninfo"], text=True, timeout=12)
        data = json.loads(out)
        safe = []
        for ap in data:
            safe.append({
                "ssid": ap.get("ssid", ""),
                "bssid": ap.get("bssid", ""),
                "frequency_mhz": ap.get("frequency_mhz"),
                "rssi_dbm": ap.get("rssi"),
                "capabilities": ap.get("capabilities", "Not reported"),
                "note": "Signal/capabilities only; Android may hide details without permissions."
            })
        show("Wi-Fi Scanner", safe)
    except Exception as e:
        show("Wi-Fi Scanner", {"error": str(e), "hint": "Termux:API permissions اور Location/Nearby devices settings چیک کریں۔"})

# 02 - Wi-Fi security analyzer, based only on scan-advertised capabilities
def wifi_security():
    if not shutil.which("termux-wifi-scaninfo"):
        return show("Wi-Fi Security Analyzer", "Termux:API دستیاب نہیں۔")
    try:
        aps = json.loads(subprocess.check_output(["termux-wifi-scaninfo"], text=True, timeout=12))
        results = []
        for ap in aps:
            caps = str(ap.get("capabilities", "")).upper()
            if "WPA3" in caps:
                level = "Strong advertised encryption (WPA3)"
            elif "WPA2" in caps:
                level = "Generally acceptable advertised encryption (WPA2)"
            elif "WPA" in caps:
                level = "Older WPA; consider upgrading"
            elif "WEP" in caps:
                level = "Weak legacy encryption; replace with WPA2-AES/WPA3"
            elif "ESS" in caps or caps == "":
                level = "Open/unknown from scan; verify router settings"
            else:
                level = "Could not determine"
            results.append({"ssid": ap.get("ssid", ""), "capabilities": caps, "assessment": level})
        show("Wi-Fi Security Analyzer", results)
    except Exception as e:
        show("Wi-Fi Security Analyzer", {"error": str(e)})

# 03 - Website security overview
def website_scan():
    url = ask_url()
    try:
        r = get_response(url)
        headers = dict(r.headers.items())
        data = {
            "final_url": getattr(r, "url", url),
            "status_code": getattr(r, "status_code", getattr(r, "status", "unknown")),
            "server_header": headers.get("Server", "Not disclosed"),
            "content_type": headers.get("Content-Type", "Unknown"),
            "https": urlparse(getattr(r, "url", url)).scheme == "https",
            "security_headers_present": [h for h in (
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Content-Type-Options", "X-Frame-Options",
                "Referrer-Policy", "Permissions-Policy") if h in headers]
        }
        show("Website Security Scanner", data)
    except Exception as e:
        show("Website Security Scanner", {"error": str(e)})

# 04 - TLS certificate inspection
def ssl_checker():
    host = host_from_input()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                data = {
                    "hostname": host,
                    "tls_version": ssock.version(),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName", [])[:12],
                    "certificate_validation": "Passed system trust validation"
                }
        show("SSL/TLS Checker", data)
    except Exception as e:
        show("SSL/TLS Checker", {"hostname": host, "error": str(e)})

# 05 - Security headers
def headers_analyzer():
    url = ask_url()
    try:
        r = get_response(url)
        h = r.headers
        checks = {
            "Strict-Transport-Security": "Important for HTTPS sites",
            "Content-Security-Policy": "Helps reduce content injection risk",
            "X-Content-Type-Options": "Should usually be nosniff",
            "X-Frame-Options": "Helps control framing",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Controls browser feature access"
        }
        result = {name: {"present": name in h, "value": h.get(name), "purpose": purpose}
                  for name, purpose in checks.items()}
        show("Security Headers Analyzer", result)
    except Exception as e:
        show("Security Headers Analyzer", {"error": str(e)})

# 06 - DNS records via system resolver
def dns_analyzer():
    host = host_from_input()
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({x[4][0] for x in infos})
        data = {"hostname": host, "resolved_addresses": ips,
                "note": "This basic resolver check does not enumerate every DNS record type."}
        show("DNS Analyzer", data)
    except Exception as e:
        show("DNS Analyzer", {"error": str(e)})

# 07 - HTTP status
def http_status():
    url = ask_url()
    try:
        r = get_response(url)
        show("HTTP Status Checker", {"url": getattr(r, "url", url),
                                     "status": getattr(r, "status_code", getattr(r, "status", "unknown")),
                                     "reason": getattr(r, "reason", "unknown")})
    except Exception as e:
        show("HTTP Status Checker", {"error": str(e)})

# 08 - Cookie flags
def cookie_analyzer():
    url = ask_url()
    try:
        r = get_response(url)
        raw = []
        if requests and hasattr(r, "raw"):
            raw = r.raw.headers.getlist("Set-Cookie")
        else:
            sc = r.headers.get("Set-Cookie")
            raw = [sc] if sc else []
        findings = []
        for c in raw:
            findings.append({
                "cookie_preview": c.split("=", 1)[0],
                "Secure": "secure" in c.lower(),
                "HttpOnly": "httponly" in c.lower(),
                "SameSite": "samesite=" in c.lower()
            })
        show("Cookie Security Analyzer", findings or {"message": "No Set-Cookie header observed."})
    except Exception as e:
        show("Cookie Security Analyzer", {"error": str(e)})

# 09 - HTTPS redirect check
def https_checker():
    raw = input("Domain درج کریں (مثلاً example.com): ").strip()
    if not raw:
        return show("HTTPS Checker", "Domain خالی ہے۔")
    try:
        http_url = "http://" + raw
        r = get_response(http_url)
        final = getattr(r, "url", http_url)
        is_https = urlparse(final).scheme == "https"
        show("HTTPS Checker", {"initial_url": http_url, "final_url": final,
                               "redirected_to_https": is_https,
                               "recommendation": "HTTPS redirect موجود ہے" if is_https else "HTTP سے HTTPS redirect نظر نہیں آیا"})
    except Exception as e:
        show("HTTPS Checker", {"error": str(e)})

# 10 - Save report
def report_generator():
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, "security-report-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"app": APP_NAME, "version": VERSION, "generated": datetime.now(timezone.utc).isoformat(),
                   "results": LAST_RESULTS}, f, indent=2, ensure_ascii=False, default=str)
    print(f"Report saved: {path}")
    pause()

# 11 - Port scan: small, common-port list; explicit authorization confirmation
def port_scanner():
    host = host_from_input()
    confirm = input("کیا یہ آپ کا اپنا/اجازت یافتہ سسٹم ہے؟ (yes لکھیں): ").strip().lower()
    if confirm != "yes":
        return show("Port Scanner", "منسوخ: اجازت کی تصدیق نہیں ہوئی۔")
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 8080]
    results = []
    for port in ports:
        s = socket.socket()
        s.settimeout(0.6)
        try:
            s.connect((host, port))
            results.append({"port": port, "state": "open"})
        except (socket.timeout, OSError):
            results.append({"port": port, "state": "closed_or_filtered"})
        finally:
            s.close()
    show("Limited Port Check", {"host": host, "ports_checked": ports, "results": results,
                                "note": "صرف محدود common ports چیک کیے گئے؛ یہ مکمل audit نہیں۔"})

# 12 - Subdomain discovery from public certificate transparency endpoint
def subdomain_finder():
    domain = host_from_input().lower().strip(".")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain):
        return show("Subdomain Finder", "درست domain درج کریں۔")
    try:
        url = "https://crt.sh/?q=%25." + domain + "&output=json"
        r = get_response(url, timeout=12)
        raw = r.json() if hasattr(r, "json") else json.loads(r.read().decode())
        names = sorted({n.strip().lower() for row in raw for n in row.get("name_value", "").splitlines()
                        if n.strip().lower().endswith("." + domain) or n.strip().lower() == domain})
        show("Passive Subdomain Finder", {"domain": domain, "subdomains": names[:100],
                                          "source": "Public certificate-transparency data",
                                          "note": "Passive discovery only; results may be stale."})
    except Exception as e:
        show("Passive Subdomain Finder", {"error": str(e)})

# 13 - WHOIS using system command if installed
def whois_lookup():
    domain = host_from_input()
    if not shutil.which("whois"):
        return show("WHOIS Lookup", "whois command نہیں ملا۔ Termux میں: pkg install whois")
    try:
        out = subprocess.check_output(["whois", domain], text=True, stderr=subprocess.STDOUT, timeout=15)
        show("WHOIS Lookup", out[:7000])
    except Exception as e:
        show("WHOIS Lookup", {"error": str(e)})

# 14 - IP info, no precise geolocation
def ip_information():
    value = host_from_input()
    try:
        ip = socket.gethostbyname(value)
        show("IP Information", {"input": value, "resolved_ipv4": ip,
                                "address_type": "private" if ipaddress_is_private(ip) else "public",
                                "note": "No person/location tracking is performed."})
    except Exception as e:
        show("IP Information", {"error": str(e)})

def ipaddress_is_private(ip):
    import ipaddress
    return ipaddress.ip_address(ip).is_private

# 15 - Traceroute
def traceroute():
    host = host_from_input()
    if platform.system().lower() == "windows":
        cmd = ["tracert", "-h", "12", "-w", "1000", host]
    elif shutil.which("traceroute"):
        cmd = ["traceroute", "-m", "12", "-w", "1", host]
    elif shutil.which("tracepath"):
        cmd = ["tracepath", "-m", "12", host]
    else:
        return show("Traceroute", "traceroute/tracepath دستیاب نہیں۔ Termux میں pkg install traceroute آزمائیں۔")
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=25)
        show("Traceroute Analyzer", out[:7000])
    except Exception as e:
        show("Traceroute Analyzer", {"error": str(e)})

# 16 - URL reputation via local heuristic only (no external submission)
def malware_url_checker():
    url = ask_url()
    p = urlparse(url)
    flags = []
    if p.scheme != "https": flags.append("HTTPS استعمال نہیں ہو رہا")
    if len(url) > 180: flags.append("URL غیر معمولی طور پر طویل ہے")
    if "@" in p.netloc: flags.append("URL میں @ موجود ہے")
    if p.hostname and p.hostname.replace(".", "").isdigit(): flags.append("IP address بطور hostname استعمال ہوا ہے")
    if p.hostname and p.hostname.count("-") >= 3: flags.append("Hostname میں کئی hyphens ہیں")
    show("Suspicious URL Heuristic", {"url": url, "flags": flags,
                                      "assessment": "Review recommended" if flags else "No basic heuristic warning",
                                      "warning": "یہ malware database scan نہیں؛ صرف مقامی heuristic ہے۔"})

# 17 - phishing indicators
def phishing_detector():
    url = ask_url()
    p = urlparse(url)
    host = p.hostname or ""
    suspicious_terms = ["login", "verify", "secure", "account", "update", "wallet", "password"]
    found = [w for w in suspicious_terms if w in (host + p.path).lower()]
    flags = []
    if p.scheme != "https": flags.append("HTTPS نہیں")
    if "@" in p.netloc: flags.append("@ character")
    if host.startswith("xn--") or ".xn--" in host: flags.append("Punycode domain")
    if len(found) >= 2: flags.append("Multiple sensitive keywords in URL")
    if len(host.split(".")) > 5: flags.append("Unusually many subdomain levels")
    show("Phishing URL Detector", {"url": url, "indicators": flags,
                                   "keywords_found": found,
                                   "note": "صرف indicators ہیں؛ فیصلہ کرنے سے پہلے domain الگ سے verify کریں۔"})

# 18 - robots.txt
def robots_analyzer():
    url = ask_url()
    p = urlparse(url)
    robots = f"{p.scheme}://{p.netloc}/robots.txt"
    try:
        r = get_response(robots)
        body = getattr(r, "text", None)
        if body is None: body = r.read().decode("utf-8", "replace")
        show("Robots.txt Analyzer", {"url": robots, "status": getattr(r, "status_code", getattr(r, "status", "unknown")),
                                     "content_preview": body[:5000],
                                     "note": "robots.txt رسائی کی اجازت یا سیکیورٹی کنٹرول نہیں ہوتا۔"})
    except Exception as e:
        show("Robots.txt Analyzer", {"error": str(e)})

# 19 - basic technology hints from headers and HTML
def technology_detector():
    url = ask_url()
    try:
        r = get_response(url)
        headers = dict(r.headers.items())
        body = getattr(r, "text", "")
        hints = []
        for key in ("Server", "X-Powered-By", "X-Generator"):
            if headers.get(key): hints.append(f"{key}: {headers[key]}")
        for token in ("wp-content", "Drupal.settings", " Joomla!", "Shopify", " Next.js", "__NEXT_DATA__"):
            if token.lower() in body[:200000].lower(): hints.append(f"HTML hint: {token.strip()}")
        show("Technology Detector", {"url": getattr(r, "url", url), "hints": hints,
                                     "note": "صرف public headers/HTML hints؛ شناخت مکمل یا یقینی نہیں۔"})
    except Exception as e:
        show("Technology Detector", {"error": str(e)})

# 20 - password strength locally; never stores or transmits input
def password_analyzer():
    pw = input("اپنا test password درج کریں (یہ کہیں بھی send/save نہیں ہوگا): ")
    score = 0
    checks = {
        "length_12_plus": len(pw) >= 12,
        "lowercase": bool(re.search(r"[a-z]", pw)),
        "uppercase": bool(re.search(r"[A-Z]", pw)),
        "number": bool(re.search(r"\d", pw)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", pw))
    }
    score = sum(checks.values())
    if len(pw) < 8: rating = "Weak"
    elif score >= 5 and len(pw) >= 12: rating = "Stronger"
    elif score >= 4: rating = "Moderate"
    else: rating = "Weak"
    show("Password Strength Analyzer", {"rating": rating, "checks": checks,
                                        "advice": "ہر اکاؤنٹ کے لیے منفرد لمبا passphrase استعمال کریں؛ password reuse نہ کریں۔"})
    del pw

TOOLS = {
    "1": ("Wi-Fi Scanner", wifi_scan),
    "2": ("Wi-Fi Security Analyzer", wifi_security),
    "3": ("Website Security Scanner", website_scan),
    "4": ("SSL/TLS Checker", ssl_checker),
    "5": ("Security Headers Analyzer", headers_analyzer),
    "6": ("DNS Analyzer", dns_analyzer),
    "7": ("HTTP Status Checker", http_status),
    "8": ("Cookie Security Analyzer", cookie_analyzer),
    "9": ("HTTPS Checker", https_checker),
    "10": ("Security Report Generator", report_generator),
    "11": ("Limited Port Scanner", port_scanner),
    "12": ("Passive Subdomain Finder", subdomain_finder),
    "13": ("WHOIS Lookup", whois_lookup),
    "14": ("IP Information", ip_information),
    "15": ("Traceroute Analyzer", traceroute),
    "16": ("Suspicious URL Heuristic", malware_url_checker),
    "17": ("Phishing URL Detector", phishing_detector),
    "18": ("Robots.txt Analyzer", robots_analyzer),
    "19": ("Technology Detector", technology_detector),
    "20": ("Password Strength Analyzer", password_analyzer),
}

def main():
    os.makedirs(REPORT_DIR, exist_ok=True)
    while True:
        clear()
        banner()
        print(" [01-10] CORE TOOLS")
        print(" [11-20] ADVANCED TOOLS\n")
        for key, (name, _) in TOOLS.items():
            print(f" [{int(key):02d}] {name}")
        print("\n [00] Exit")
        choice = input("\nSelect tool: ").strip()
        if choice in ("0", "00"):
            print("Stay safe. Only test systems with permission.")
            break
        if choice in TOOLS:
            try:
                TOOLS[choice][1]()
                if choice != "10":
                    pause()
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                pause()
            except Exception as e:
                print(f"\nError: {e}")
                pause()
        else:
            print("Invalid option.")
            time.sleep(1)

if __name__ == "__main__":
    main()
