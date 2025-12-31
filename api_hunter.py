import requests
import re
import sys
import argparse
import time
import random
import json
import threading
import subprocess
import signal
import os
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import dns.resolver

# --- GRACEFUL SHUTDOWN ---
SHUTDOWN = False

def signal_handler(sig, frame):
    global SHUTDOWN
    print("\n\n[!] Ctrl+C terdeteksi! Menghentikan semua proses dengan aman...")
    SHUTDOWN = True

signal.signal(signal.SIGINT, signal_handler)

# --- KONFIGURASI ---
SHODAN_API_KEY = "MASUKKAN_API_KEY_SHODAN_DI_SINI"
LOG_FILE = "found_bugs.txt"
PROXY_FILE = "proxies.txt"
WORDLIST_FILE = "subdomains.txt"
CUSTOM_WORDLIST = None
AMASS_OUTPUT = "amass_subdomains.txt"
NUCLEI_OUTPUT = "nuclei_results.txt"

BUILTIN_WORDLIST = [
    "api", "dev", "staging", "test", "beta", "prod", "admin", "app", "mobile",
    "internal", "private", "backend", "graphql", "v1", "v2", "swagger", "docs",
    "auth", "login", "dashboard", "panel", "web", "www", "api2", "gateway",
    "secure", "sandbox", "demo", "stage", "uat", "preprod", "development"
]

SENSITIVE_PATTERNS = {
    "Email": r"[a-zA-Z0-9-_.]+@[a-zA-Z0-9-_.]+",
    "API_Key/Token": r"(?i)(api_key|token|auth|secret|password|aws_key|bearer|access_token|jwt|oauth)[\s:\"'=]+([a-zA-Z0-9_\-]{16,})",
    "Firebase": r"https://.*\.firebaseio\.com",
    "Sensitive_File": r"\b(id_rsa|id_dsa|config\.php|wp-config\.php|\.env|\.git/config|\.htaccess)\b",
    "Credit_Card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Database_Creds": r"(?i)(db_user|db_pass|database|mysql|postgres|mongodb)[\s:\"'=]+([a-zA-Z0-9_\-]{8,})",
    "Private_Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
]

COMMON_PATHS = [
    "", "/v1", "/api", "/api/v1", "/api/v2", "/swagger-ui.html", "/swagger.json", "/openapi.json", 
    "/.env", "/config", "/debug", "/health", "/metrics", "/.git/config", "/admin", "/graphql",
    "/robots.txt", "/sitemap.xml", "/actuator", "/phpinfo.php", "/info", "/status"
]

MAX_DEPTH = 2
VISITED = set()
FOUND_SUBDOMAINS = set()
lock = threading.Lock()

def log_finding(message):
    if SHUTDOWN: return
    with lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def get_shodan_info(domain):
    if not SHODAN_API_KEY or "MASUKKAN" in SHODAN_API_KEY:
        return
    try:
        res = requests.get(f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=hostname:{domain}", timeout=10).json()
        if res.get('matches'):
            for m in res['matches'][:3]:
                info = f"SHODAN: {m['ip_str']}:{m['port']} | Org: {m.get('org','?')} | Vulns: {m.get('vulns','None')}"
                print(f" [i] {info}")
                log_finding(f"SHODAN INFO {domain}: {info}")
    except: pass

def fetch_subdomains_from_crtsh(domain):
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json()
            for entry in data:
                name = entry.get('name_value', '')
                for line in name.split('\n'):
                    subd = line.strip().lower()
                    if subd.endswith(domain) and not subd.startswith('*.'):
                        subdomains.add(subd)
    except Exception as e:
        print(f"[!] CRT.sh error: {e}")
    return subdomains

def resolve_subdomain(subdomain):
    try:
        dns.resolver.resolve(subdomain, 'A')
        return True
    except:
        return False

def brute_subdomains(domain, wordlist):
    found = set()
    print(f"[*] Mulai brute-force subdomain untuk {domain} ({len(wordlist)} kata)...")
    def check_sub(sub):
        full = f"{sub}.{domain}"
        if resolve_subdomain(full):
            return full
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_sub, word): word for word in wordlist}
        for future in as_completed(futures):
            if SHUTDOWN: break
            result = future.result()
            if result:
                with lock:
                    if result not in FOUND_SUBDOMAINS:
                        FOUND_SUBDOMAINS.add(result)
                        found.add(result)
                        print(f" [+] SUBDOMAIN HIDUP: {result}")
                        log_finding(f"SUBDOMAIN FOUND: {result}")
    return found

def run_amass_enum(domain):
    subdomains = set()
    try:
        print(f"[*] Menjalankan Amass enum -d {domain}")
        cmd = f"amass enum -d {domain} -o {AMASS_OUTPUT} -passive"
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        if os.path.exists(AMASS_OUTPUT):
            with open(AMASS_OUTPUT, "r") as f:
                for line in f:
                    subd = line.strip().lower()
                    if subd.endswith(domain) and resolve_subdomain(subd):
                        subdomains.add(subd)
                        print(f" [+] SUBDOMAIN (Amass): {subd}")
                        log_finding(f"SUBDOMAIN AMASS: {subd}")
    except Exception as e:
        print(f"[!] Amass error: {e}")
    return subdomains

def enumerate_subdomains(domain, use_amass=True, no_brute=False):
    base_domain = domain.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
    print(f"\n[🔍] DEEP SUBDOMAIN ENUMERATION untuk: {base_domain}")

    if use_amass:
        amass_subs = run_amass_enum(base_domain)
        FOUND_SUBDOMAINS.update(amass_subs)
        print(f" [+] Ditemukan {len(amass_subs)} dari Amass")

    crt_subs = fetch_subdomains_from_crtsh(base_domain)
    for sub in crt_subs:
        if sub not in FOUND_SUBDOMAINS:
            FOUND_SUBDOMAINS.add(sub)
            print(f" [+] SUBDOMAIN (crt.sh): {sub}")
            log_finding(f"SUBDOMAIN CRT.SH: {sub}")

    if not no_brute:
        try:
            wordlist = []
            if CUSTOM_WORDLIST and os.path.exists(CUSTOM_WORDLIST):
                with open(CUSTOM_WORDLIST) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            elif os.path.exists(WORDLIST_FILE):
                with open(WORDLIST_FILE) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            else:
                wordlist = BUILTIN_WORDLIST
            brute_subs = brute_subdomains(base_domain, wordlist)
            FOUND_SUBDOMAINS.update(brute_subs)
        except Exception as e:
            print(f"[!] Error brute: {e}")

    www_sub = f"www.{base_domain}"
    if resolve_subdomain(www_sub) and www_sub not in FOUND_SUBDOMAINS:
        FOUND_SUBDOMAINS.add(www_sub)

    print(f"\n[✔] Total subdomain ditemukan: {len(FOUND_SUBDOMAINS)}\n")

# === SCANNING FUNCTIONS (ringkas) ===
def extract_links(response, base_url):
    links = set()
    if 'json' in response.headers.get('Content-Type', ''):
        try:
            for val in response.json().values():
                if isinstance(val, str) and ('http' in val or val.startswith('/')):
                    links.add(urljoin(base_url, val))
        except: pass
    else:
        soup = BeautifulSoup(response.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            links.add(urljoin(base_url, a['href']))
    return links

def parse_swagger(response, base_url):
    endpoints = set()
    try:
        data = response.json()
        for path in data.get('paths', {}):
            endpoints.add(urljoin(base_url, path))
    except: pass
    return endpoints

def scan_endpoint(base_url, path="", proxy=None, delay=1.0, depth=0):
    if SHUTDOWN or depth > MAX_DEPTH: return
    target = urljoin(base_url, path)
    if target in VISITED: return
    VISITED.add(target)

    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.get(target, headers=headers, proxies=proxy, timeout=12, verify=False, allow_redirects=True)
        
        if r.status_code == 200:
            print(f" [+] FOUND (200): {target}")
            log_finding(f"FOUND 200: {target}")

            for label, pattern in SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, r.text, re.IGNORECASE)
                if matches:
                    print(f" [🔥] ALERT: {label} leak → {target}")
                    log_finding(f"LEAK {label}: {target}")

            if any(kw in r.text.lower() for kw in ["swagger", "openapi", "redoc"]):
                print(f" [📖] API DOCS FOUND: {target}")
                for ep in parse_swagger(r, base_url):
                    scan_endpoint(base_url, ep[len(base_url):], proxy, delay, depth+1)

            for link in extract_links(r, base_url):
                rel = urlparse(link).path or "/"
                scan_endpoint(base_url, rel, proxy, delay, depth+1)

        elif r.status_code in [401, 403]:
            print(f" [🔒] PROTECTED ({r.status_code}): {target}")
        
        time.sleep(delay + random.uniform(0.3, 1.0))
    
    except: pass

def start_scan_on_domain(target_url, delay, proxies):
    if SHUTDOWN: return
    print(f"\n[🎯] SCANNING TARGET: {target_url}")
    get_shodan_info(urlparse(target_url).netloc)
    VISITED.clear()

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = []
        for path in COMMON_PATHS:
            if SHUTDOWN: break
            proxy = random.choice(proxies) if proxies else None
            futures.append(executor.submit(scan_endpoint, target_url, path, proxy, delay))
        for f in futures:
            if SHUTDOWN: break
            try: f.result()
            except: pass

def run_nuclei_scan(targets):
    if SHUTDOWN or not targets: return
    print(f"\n[⚡] Menjalankan Nuclei pada {len(targets)} target...")
    temp_file = "nuclei_targets.txt"
    try:
        with open(temp_file, "w") as f:
            for t in targets:
                f.write(t + "\n")
        cmd = ["nuclei", "-l", temp_file, "-severity", "critical,high,medium", "-o", NUCLEI_OUTPUT, "-silent"]
        subprocess.run(cmd, timeout=600)
        if os.path.exists(NUCLEI_OUTPUT):
            with open(NUCLEI_OUTPUT) as f:
                results = f.read().strip()
            if results:
                print(f"\n[🔥] Nuclei menemukan vulnerability:\n{results}")
                log_finding(f"NUCLEI RESULTS:\n{results}")
    except FileNotFoundError:
        print("[!] Nuclei tidak terinstall.")
    except Exception as e:
        print(f"[!] Nuclei error: {e}")
    finally:
        if os.path.exists(temp_file): os.remove(temp_file)

def main():
    parser = argparse.ArgumentParser(description="API Hunter Pro + Amass + Nuclei")
    parser.add_argument("url", nargs="?", help="Target domain/URL")
    parser.add_argument("-l", "--list", help="File list target")
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--wordlist", help="Custom wordlist")
    parser.add_argument("--no-brute", action="store_true")
    parser.add_argument("--no-amass", action="store_true")
    parser.add_argument("--no-nuclei", action="store_true")
    args = parser.parse_args()

    global CUSTOM_WORDLIST
    if args.wordlist: CUSTOM_WORDLIST = args.wordlist

    proxy_list = []
    try:
        with open(PROXY_FILE) as f:
            proxy_list = [{"http": f"http://{l.strip()}", "https": f"http://{l.strip()}"} for l in f if l.strip()]
    except: pass

    targets = []
    if args.list:
        with open(args.list) as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.url:
        targets = [args.url]
    else:
        parser.print_help()
        sys.exit(0)

    all_urls = []
    for raw in targets:
        if SHUTDOWN: break
        url = raw if raw.startswith("http") else "https://" + raw
        domain = urlparse(url).netloc or urlparse(url).path.split("/")[0]

        print(f"\n{'='*60}\n[🌎] TARGET: {domain}\n{'='*60}")

        enumerate_subdomains(domain, use_amass=not args.no_amass, no_brute=args.no_brute)

        target_list = [url]
        for sub in FOUND_SUBDOMAINS:
            sub_url = f"https://{sub}"
            if sub_url != url:
                target_list.append(sub_url)
                all_urls.append(sub_url)
        all_urls.append(url)

        for t in target_list:
            if SHUTDOWN: break
            start_scan_on_domain(t, args.delay, proxy_list)

        FOUND_SUBDOMAINS.clear()

    if not args.no_nuclei and not SHUTDOWN:
        run_nuclei_scan(all_urls)

    print("\n[✔] Selesai. Cek found_bugs.txt dan nuclei_results.txt")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Forced exit.")
        sys.exit(0)
