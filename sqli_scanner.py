import requests
import sys
import time

# ANSI colors for pretty output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def load_payloads(file_path):
    """Load payloads from a text file"""
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def is_vulnerable(response_text, original_response_text):
    """Check if response suggests SQL injection based on error messages or differences"""
    # Common database error messages
    error_signatures = [
        "sql syntax",
        "mysql_fetch",
        "oracle.jdbc",
        "postgresql error",
        "unclosed quotation mark",
        "you have an error in your sql syntax",
        "warning: mysql",
        "odbc driver",
        "microsoft ole db",
        "sqlite3",
        "sql server",
    ]
    
    # Check for error messages
    for sig in error_signatures:
        if sig.lower() in response_text.lower():
            return True
    
    # If response length is very different and not a simple error page, might be boolean-based
    if len(response_text) != len(original_response_text):
        # Avoid false positives – could be a 404 or other error
        if "not found" not in response_text.lower() and "error" not in response_text.lower():
            return True
    
    return False

def scan_url(url, param, payloads):
    """Test a single URL parameter with all payloads"""
    print(f"\n{YELLOW}[*] Testing parameter: {param}{RESET}")
    vulnerable_payloads = []
    
    # First, get original response as baseline
    try:
        original_response = requests.get(url, timeout=5)
        original_text = original_response.text
    except Exception as e:
        print(f"{RED}[-] Failed to reach URL: {e}{RESET}")
        return []
    
    for payload in payloads:
        # Construct test URL
        test_url = url.replace(f"{param}=", f"{param}={payload}")
        try:
            response = requests.get(test_url, timeout=5)
            if is_vulnerable(response.text, original_text):
                print(f"{GREEN}[+] Potential SQLi with payload: {payload}{RESET}")
                vulnerable_payloads.append(payload)
            else:
                print(f"[-] No detection with: {payload}")
            time.sleep(0.5)  # be nice to the server
        except Exception as e:
            print(f"{RED}[-] Request error with payload {payload}: {e}{RESET}")
    
    return vulnerable_payloads

def main():
    if len(sys.argv) < 2:
        print(f"{YELLOW}Usage: python sqli_scanner.py <url>{RESET}")
        print(f"{YELLOW}Example: python sqli_scanner.py 'http://testphp.vulnweb.com/artists.php?artist=1'{RESET}")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Parse URL to extract parameters
    if '?' not in target_url:
        print(f"{RED}[-] URL must contain a query parameter (e.g., ?id=1){RESET}")
        sys.exit(1)
    
    base_url, query = target_url.split('?', 1)
    params = {}
    for pair in query.split('&'):
        if '=' in pair:
            key, val = pair.split('=', 1)
            params[key] = val
    
    if not params:
        print(f"{RED}[-] No parameters found in URL{RESET}")
        sys.exit(1)
    
    # Load payloads
    payloads = load_payloads("payloads.txt")
    print(f"{GREEN}[+] Loaded {len(payloads)} payloads{RESET}")
    
    # Test each parameter
    all_vulnerable = {}
    for param, value in params.items():
        # Reconstruct URL for this parameter
        url_with_param = f"{base_url}?{param}={value}"
        vulnerable = scan_url(url_with_param, param, payloads)
        if vulnerable:
            all_vulnerable[param] = vulnerable
    
    # Summary
    print(f"\n{GREEN}========== SCAN SUMMARY =========={RESET}")
    if all_vulnerable:
        for param, vuln_payloads in all_vulnerable.items():
            print(f"{GREEN}[+] Parameter '{param}' appears vulnerable with {len(vuln_payloads)} payloads{RESET}")
    else:
        print(f"{RED}[-] No SQL injection detected with the provided payloads{RESET}")
        print(f"{YELLOW}[!] This does not guarantee the site is secure – try more advanced payloads or manual testing.{RESET}")

if __name__ == "__main__":
    main()