# 🛡️ Python-Based Web Vulnerability Scanner

A lightweight, beginner-friendly Python tool that detects basic web vulnerabilities like missing security headers, open redirect parameters, and reflected XSS. It generates a professional PDF report summarizing the results.

---

## 🚀 Features

- ✅ Scans for common missing security headers:
  - `X-Frame-Options`
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Content-Type-Options`
- 🔀 Detects suspicious redirect parameters (e.g., `?url=`, `?redirect=`)
- ⚠️ Tests for reflected Cross-Site Scripting (XSS) with safe payloads
- 🧾 Exports findings to a clean PDF report using `fpdf`
- 🔧 Built with `requests`, `BeautifulSoup`, and `urllib`

---

## 📦 Installation

Make sure you have Python 3 installed.

Install required libraries:

```bash
pip install requests beautifulsoup4 fpdf
```

## Usage 
Run the script:
```bash
python web_scanner.py
```
You will be prompted to enter a full URL to scan, for example:
```bash
Enter a full URL (e.g. https://example.com/page?param=value):
```
Once the scan is complete, a report will be generated as vuln_report.pdf in the current directory.


## Legal Disclaimer

This tool is intended for educational purposes only.
Do not scan websites you do not own or have explicit permission to test.

Safe targets for learning include:

https://httpbin.org/

https://xss-game.appspot.com/

https://testphp.vulnweb.com/

https://web-security-academy.portswigger.net/

## Technologies Used
Python 3

requests

fpdf

BeautifulSoup

urllib.parse


