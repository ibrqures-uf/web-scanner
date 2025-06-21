import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from fpdf import FPDF
import unicodedata

# stores scan results to write into the PDF
report_lines = []

def log(line):
    print(line)
    report_lines.append(line)

# common security headers
def check_headers(url):
    log(f"\n[+] Checking security headers for: {url}")
    headers_to_check = [
        'X-Frame-Options',
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Content-Type-Options'
    ]

    try:
        response = requests.get(url, timeout=5)
        for header in headers_to_check:
            if header in response.headers:
                log(f"[OK] {header} found: {response.headers[header]}")
            else:
                log(f"[MISSING] {header} is missing!")
    except requests.RequestException as e:
        log(f"[!] Request failed: {e}")

# check for suspicious redirect parameters
def check_open_redirect(url):
    log("\n[+] Checking for potential open redirect...")
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    suspicious_keys = ['next', 'url', 'redirect', 'return']

    found = False
    for key in params:
        if key.lower() in suspicious_keys:
            log(f"[WARNING] Suspicious parameter found: {key}={params[key]}")
            log("          → Might be vulnerable to open redirect!")
            found = True

    if not found:
        log("[OK] No obvious open redirect parameters found.")

# check for basic reflected XSS
def check_xss(url):
    log("\n[+] Checking for basic reflected XSS...")
    xss_payload = "<script>alert(1)</script>"

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        log("[!] No parameters to test for XSS.")
        return

    for key in params:
        test_params = params.copy()
        test_params[key] = [xss_payload]
        query_string = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
        test_url = parsed._replace(query=query_string).geturl()

        try:
            response = requests.get(test_url, timeout=5)
            if xss_payload in response.text:
                log(f"[VULNERABLE] Reflected XSS possible with parameter: {key}")
            else:
                log(f"[OK] No reflection detected for: {key}")
        except Exception as e:
            log(f"[!] Request failed for XSS test on parameter '{key}': {e}")

# sanitize text for PDF encoding
def sanitize_text(text):
    return unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii')

# create PDF report
def generate_pdf_report(filename="vuln_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_title("Web Vulnerability Scan Report")

    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "Simple Web Vulnerability Report", ln=True, align='C')

    pdf.set_font("Arial", size=12)
    pdf.ln(10)  # Add spacing

    for line in report_lines:
        cleaned = sanitize_text(line.replace("\n", ""))
        pdf.multi_cell(0, 10, cleaned)

    pdf.output(filename)
    print(f"\n[OK] PDF report generated: {filename}")

# main scanner flow
def main():
    print("=== Simple Web Vulnerability Scanner ===")
    target_url = input("Enter a full URL ").strip()

    if not target_url.startswith("http"):
        print("[!] URL must start with http:// or https://")
        return

    report_lines.clear()
    log(f"Target URL: {target_url}")
    check_headers(target_url)
    check_open_redirect(target_url)
    check_xss(target_url)
    log("\n[✓] Scan completed.")

    generate_pdf_report()

if __name__ == "__main__":
    main()
