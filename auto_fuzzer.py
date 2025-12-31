import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import random
import time
import argparse
import sys

# --- KONFIGURASI ---
WORDLIST = "wordlist.txt"  # Default wordlist (download SecLists/Discovery/Web-Content/raft-small-words.txt)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
]
INTERESTING_CODES = [200, 301, 302, 403, 500, 401]
OUTPUT_FILE = "fuzz_results.txt"
lock = threading.Lock()

def fuzz_target(base_url, word, method="GET", param_fuzz=False, delay=1.0):
    ua = random.choice(USER_AGENTS)
    headers = {"User-Agent": ua}
    
    if param_fuzz:
        # Fuzz parameter name (contoh: ?FUZZ=1)
        url = f"{base_url}?{word}=test"
        payload = None
    else:
        # Fuzz path (contoh: /FUZZ atau /api/FUZZ)
        url = base_url.rstrip("/") + "/" + word.strip()
        payload = None

    try:
        if method == "POST":
            r = requests.post(url, data={"test": "fuzz"}, headers=headers, timeout=10, allow_redirects=False)
        else:
            r = requests.get(url, headers=headers, timeout=10, allow_redirects=False)

        size = len(r.content)
        if r.status_code in INTERESTING_CODES or size > 1000:  # Filter noise
            result = f"[+] {r.status_code} | Size: {size} | {url}"
            print(result)
            with lock:
                with open(OUTPUT_FILE, "a") as f:
                    f.write(result + "\n")
                    if r.status_code == 200:
                        f.write(f"    Snippet: {r.text[:300].replace(chr(10), ' ')}\n\n")
    
    except requests.exceptions.RequestException:
        pass
    except Exception as e:
        pass
    
    time.sleep(delay + random.uniform(0.1, 0.5))

def load_wordlist(file):
    try:
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Wordlist {file} tidak ditemukan. Download dulu:")
        print("    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt -O wordlist.txt")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Automatic Fuzzer untuk Bug Bounty - Path & Parameter Discovery")
    parser.add_argument("url", help="Base URL (contoh: https://target.com/api atau https://target.com)")
    parser.add_argument("-w", "--wordlist", default=WORDLIST, help="File wordlist (default: wordlist.txt)")
    parser.add_argument("--param", action="store_true", help="Fuzz parameter name (?FUZZ=test)")
    parser.add_argument("--post", action="store_true", help="Gunakan metode POST")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay antar request (default: 1.0)")
    parser.add_argument("--threads", type=int, default=20, help="Jumlah thread (default: 20)")
    args = parser.parse_args()

    words = load_wordlist(args.wordlist)
    print(f"[+] Loaded {len(words)} words dari {args.wordlist}")
    print(f"[+] Mulai fuzzing: {args.url} | Mode: {'Parameter' if args.param else 'Path'} | Method: {'POST' if args.post else 'GET'}")
    print(f"[+] Hasil disimpan ke: {OUTPUT_FILE}\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for word in words:
            executor.submit(fuzz_target, args.url, word, "POST" if args.post else "GET", args.param, args.delay)

    print(f"\n[+] Fuzzing selesai! Cek {OUTPUT_FILE} untuk hasil lengkap.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh user.")
