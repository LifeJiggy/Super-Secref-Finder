import requests
import re
import threading
import queue
import time
import json
import sys
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init
from sensitive_patterns import SENSITIVE_PATTERNS, validate_pattern

init(autoreset=True)

def print_banner():
    print(Fore.CYAN + r"""
   _____                         _____                     __ 
  / ____|                       / ____|                   / _|
 | (___  _   _ _ __   ___ _ __| (___   ___  ___ _ __ ___| |_ 
  \___ \| | | | '_ \ / _ \ '__|\___ \ / _ \/ __| '__/ _ \  _|
  ____) | |_| | |_) |  __/ |   ____) |  __/ (__| | |  __/ |  
 |_____/ \__,_| .__/ \___|_|  |_____/ \___|\___|_|  \___|_|  
              | |     _____ _           _           
              |_|    |  ___(_)_ __   __| | ___ _ __ 
                     | |_  | | '_ \ / _` |/ _ \ '__|
                     |  _| | | | | | (_| |  __/ |   
                     |_|   |_|_| |_|\__,_|\___|_|   
    """)
    # ...rest of the print_banner function remains the same...
    print(Fore.MAGENTA + "Super Secref Finder\n")
    print(Fore.YELLOW + "[*] Super Secref Finder - Advanced Regex-based Security Scanner\n")
    print(Fore.GREEN + "[*] Developed by: ArkhAngelLifeJiggy")
    print(Fore.YELLOW + "[*] GitHub:https://github.com/LifeJiggy")
    print(Fore.GREEN + "[*] Version: 6.0")
def validate_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and parsed.netloc
    except Exception:
        return False

def fetch_url(url, max_retries=10, timeout=36000):
    tries = 0
    while tries < max_retries:
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            resp = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers)
            if resp.status_code == 200:
                return resp.text, resp.url
            elif resp.status_code == 429:
                print(Fore.RED + f"[!] Rate limit hit for {url}. Doubling delay...")
                time.sleep(tries * 2)
                tries += 1
            elif 300 <= resp.status_code < 400 and 'Location' in resp.headers:
                url = resp.headers['Location']
            else:
                tries += 1
                time.sleep(1)
        except Exception as e:
            print(Fore.RED + f"[!] Fetch error for {url}: {e}")
            tries += 1
            time.sleep(1)
    return None, None

def extract_js_links(text, base_url):
    js_links = set()
    patterns = [
        r'<script[^>]+src=["\']?([^"\'>]+\.js[^"\'>]*)["\']?',
        r'["\'](https?://[^"\'>]+\.js[^"\'>]*)["\']'
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            url = match.group(1).strip()
            url = urljoin(base_url, url)
            if validate_url(url):
                js_links.add(url)
    return sorted(list(js_links))

def extract_context(text, start, end, context_length=50):
    """Extract surrounding text for a match."""
    start_context = max(0, start - context_length)
    end_context = min(len(text), end + context_length)
    return text[start_context:end_context].replace('\n', ' ').strip()

def extract_secrets(text, url, confidence_threshold=0.8):
    findings = []
    seen_matches = set()
    compiled_patterns = {}

    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        try:
            compiled_patterns[pattern_name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            print(Fore.RED + f"[!] Error compiling regex for {pattern_name}: {e}")
            continue

    for pattern_name, regex in compiled_patterns.items():
        for match in regex.finditer(text):
            match_str = match.group(0)
            # Deduplicate based on string only for certain patterns
            dedup_key = f"{pattern_name}:{match_str}" if pattern_name in ["mobile_appcenter_secret", "jwt_token"] else f"{pattern_name}:{match_str}:{match.start()}"
            if dedup_key in seen_matches:
                continue
            seen_matches.add(dedup_key)

            confidence = 0.9 if len(match_str) > 20 else 0.8
            if confidence < confidence_threshold:
                continue

            if not validate_pattern(pattern_name, match_str):
                with open("false_positives.log", "a", encoding="utf-8") as f:
                    f.write(f"{pattern_name}: {match_str}\n")
                continue

            findings.append({
                'type': pattern_name,
                'value': match_str,
                'url': url,
                'confidence': confidence,
                'start': match.start(),
                'end': match.end(),
                'context': extract_context(text, match.start(), match.end())
            })

    return findings

def worker(url_queue, results, lock, delay, verbose):
    while True:
        try:
            url = url_queue.get_nowait()
        except queue.Empty:
            break
        if verbose:
            print(Fore.BLUE + f"[?] Scanning: {url}")
        text, final_url = fetch_url(url)
        if text and final_url:
            secrets = extract_secrets(text, final_url)
            if secrets:
                for secret in secrets:
                    print(Fore.GREEN + f"[+] {secret['type']} found: {secret['value'][:60]}... @ {secret['url']} (Confidence: {secret['confidence']*100}%)")
                    if verbose:
                        print(Fore.MAGENTA + f"    Context: {secret['context'][:100]}...")
                with lock:
                    results.extend(secrets)
        else:
            print(Fore.RED + f"[!] Failed to fetch {url}")
        url_queue.task_done()
        time.sleep(delay)

def interactive_menu():
    print_banner()
    while True:
        try:
            url = input(Fore.YELLOW + "Enter target URL: ").strip()
            if not validate_url(url):
                print(Fore.RED + "Invalid URL. Try again.")
                continue
            threads = input(Fore.YELLOW + "Threads (1-600): ").strip()
            if not threads.isdigit() or not (1 <= int(threads) <= 600):
                print(Fore.RED + "Threads must be between 1 and 600.")
                continue
            threads = int(threads)
            delay = input(Fore.YELLOW + "Delay between requests (1-100 sec): ").strip()
            if not delay.replace('.', '', 1).isdigit() or not (1 <= float(delay) <= 100):
                print(Fore.RED + "Delay must be between 1 and 100 seconds.")
                continue
            delay = float(delay)
            verbose = input(Fore.YELLOW + "Verbose output? (y/n): ").strip().lower() == 'y'
            return url, threads, delay, verbose
        except Exception as e:
            print(Fore.RED + f"Input error: {e}")

def select_js_links(js_links):
    if not js_links:
        print(Fore.YELLOW + "[!] No JavaScript links found.")
        return []
    print(Fore.CYAN + "\n[!] Found JavaScript links:")
    for i, link in enumerate(js_links, 1):
        print(Fore.BLUE + f"{i}. {link}")
    while True:
        try:
            selection = input(Fore.YELLOW + "Enter JS link indices (e.g., 1,2,3 or 'all' or 'none'): ").strip().lower()
            if selection == 'none':
                return []
            if selection == 'all':
                return js_links
            indices = [int(i.strip()) - 1 for i in selection.split(',') if i.strip().isdigit()]
            if not indices or any(i < 0 or i >= len(js_links) for i in indices):
                print(Fore.RED + "Invalid selection. Try again.")
                continue
            return [js_links[i] for i in indices]
        except Exception as e:
            print(Fore.RED + f"Selection error: {e}")

def main():
    while True:
        url, threads, delay, verbose = interactive_menu()
        url_queue = queue.Queue()
        results = []
        lock = threading.Lock()

        # Scan main page
        if verbose:
            print(Fore.CYAN + "\n[!] Scanning main page...")
        url_queue.put(url)
        thread_list = []
        for _ in range(threads):
            t = threading.Thread(target=worker, args=(url_queue, results, lock, delay, verbose))
            t.daemon = True
            thread_list.append(t)
            t.start()
        url_queue.join()
        for t in thread_list:
            t.join()

        # Extract and scan JS links
        text, final_url = fetch_url(url)
        if text:
            js_links = extract_js_links(text, final_url)
            selected_js = select_js_links(js_links)
            if selected_js:
                if verbose:
                    print(Fore.CYAN + "\n[!] Scanning selected JavaScript files...")
                url_queue = queue.Queue()
                for js_url in selected_js:
                    url_queue.put(js_url)
                thread_list = []
                for _ in range(threads):
                    t = threading.Thread(target=worker, args=(url_queue, results, lock, delay, verbose))
                    t.daemon = True
                    thread_list.append(t)
                    t.start()
                url_queue.join()
                for t in thread_list:
                    t.join()

        # Output results
        if results:
            with open('findings.json', 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            print(Fore.CYAN + f"\n[!] Results saved to findings.json")
            # Group findings by type for summary
            summary = {}
            for finding in results:
                ftype = finding['type']
                summary[ftype] = summary.get(ftype, 0) + 1
            print(Fore.CYAN + "\n[!] Summary of findings:")
            for ftype, count in sorted(summary.items()):
                print(Fore.BLUE + f"    {ftype}: {count}")
        else:
            print(Fore.YELLOW + "\n[!] No secrets found.")
        retry = input(Fore.YELLOW + "Scan another URL? (yes/no): ").strip().lower()
        if retry != 'yes':
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"Critical error: {e}")
        retry = input(Fore.YELLOW + "Retry? (yes/no): ").strip().lower()
        if retry == 'yes':
            main()