# WAQAS CYBER SHIELD PRO

A defensive Python security toolkit for Termux, Android (with Termux:API), and Linux.

## Files
- `main.py` — all 20 tools and menu
- `requirements.txt` — Python dependency
- `reports/` — JSON reports are saved here

## Termux installation

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pkg install termux-api whois traceroute -y
pip install -r requirements.txt
python main.py
```

Install the separate **Termux:API Android app** from a trusted source and grant the Android permissions needed for Wi-Fi scan results. Availability depends on Android version/device restrictions.

## GitHub setup

Upload this folder to a repository. Then on Termux:

```bash
git clone https://github.com/YOUR-USERNAME/WAQAS-CYBER-SHIELD-PRO.git
cd WAQAS-CYBER-SHIELD-PRO
pip install -r requirements.txt
python main.py
```

Replace the clone URL with your actual repository URL.

## Included tools

1. Wi-Fi Scanner
2. Wi-Fi Security Analyzer
3. Website Security Scanner
4. SSL/TLS Checker
5. Security Headers Analyzer
6. DNS Analyzer
7. HTTP Status Checker
8. Cookie Security Analyzer
9. HTTPS Checker
10. JSON Security Report Generator
11. Limited Port Scanner (10 common ports; explicit authorization confirmation)
12. Passive Subdomain Finder (public certificate-transparency data)
13. WHOIS Lookup
14. IP Information
15. Traceroute Analyzer
16. Suspicious URL Heuristic
17. Phishing URL Detector
18. Robots.txt Analyzer
19. Technology Detector
20. Local Password Strength Analyzer

## Important limitations

- Use only on networks, websites, and systems you own or have explicit permission to assess.
- The port checker is intentionally limited and is not a full vulnerability scanner.
- Wi-Fi encryption assessment uses only capabilities exposed by Android; it cannot inspect router configuration or guarantee a security score.
- URL checks are heuristics, not a malware/phishing reputation database.
- DNS lookup uses the operating system resolver and does not enumerate every DNS record.
- Public technology fingerprints can be incomplete or misleading.
- Never enter a real account password into a tool. Use a test password for the local strength checker.
- No tool attempts exploitation, password guessing, deauthentication, stealth, or access bypass.

## Compatibility

Python 3.9+. Some Termux:API features may be unavailable on certain Android versions/devices.
