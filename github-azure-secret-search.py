#!/usr/bin/python3

import os
import sys
import re
import time
import json
import requests
import random
import argparse
import urllib.parse
from functools import partial
from multiprocessing.dummy import Pool
from threading import Lock
from colorama import init, Fore, Style

init(autoreset=True)  # Initialize Colorama

TOKENS_FILE = os.path.dirname(os.path.realpath(__file__)) + '/.tokens'

def display_intro():
    print("--------------------------------------------------")
    print("        GitHub Azure Secrets Search                  ")
    print("--------------------------------------------------")
    print("Search GitHub for exposed Azure credentials")
    print("(tenant IDs, client IDs, client secrets)\n")
    
    print("Usage:")
    print("  python3 github-azure-secret-search.py [options]\n")

    print("Options:")
    print("  -t TOKEN, --token TOKEN      GitHub Token (required)")
    print("  -s SEARCH, --search SEARCH   Search Term. Defaults to 'sharepoint OR filename:.env'")
    print("  -r REGEXP, --regexp REGEXP   Custom regexp to search. Defaults to Azure secrets regex")
    print("  -u, --url                    Display only URLs without matched secret content")
    print("  -o OUTPUT, --output OUTPUT   Save results to a file")
    print("  -h, --help                   Show help\n")

    print("Examples:")
    print("  python3 github-azure-secret-search.py -t GITHUB_TOKEN")
    print("  python3 github-azure-secret-search.py -t GITHUB_TOKEN -s \"AZURE_CLIENT_SECRET OR filename:.env\"")
    print("  python3 github-azure-secret-search.py -t GITHUB_TOKEN -r \"\\b[A-Z_]*CLIENT_SECRET\\s*=\\s*[A-Za-z0-9.~]{32,64}\\b\"")
    print()

def print_authorization_notice():
    print("For authorized security testing and assessment only.\n")

stats = {"pages": 0, "files": 0, "secrets": 0}
stats_lock = Lock()
output_file_handle = None
output_file_path = None

# Search
def githubApiSearchCode(token, search, page, sort, order):
    headers = {"Authorization": "token " + token}
    url = (
        "https://api.github.com/search/code"
        "?per_page=100"
        "&s=" + sort +
        "&type=Code"
        "&o=" + order +
        "&q=" + search +
        "&page=" + str(page)
    )
    try:
        r = requests.get(url, headers=headers, timeout=5)
        return r.json()
    except Exception as e:
        print(f"{Fore.RED}[-] Error occurred: {e}{Style.RESET_ALL}")
        return False

def getRawUrl(result):
    raw_url = result['html_url']
    raw_url = raw_url.replace('https://github.com/', 'https://raw.githubusercontent.com/')
    raw_url = raw_url.replace('/blob/', '/')
    return raw_url

def doGetCode(url):
    try:
        r = requests.get(url, timeout=5)
        return r.text
    except Exception as e:
        print(f"{Fore.RED}[-] Error occurred: {e}{Style.RESET_ALL}")
        return False

# File scan
def readCode(search_regexp, t_regexp, result):
    global output_file_handle
    time.sleep(random.uniform(0.5, 1.5))

    url = getRawUrl(result)
    if url in t_history_urls:
        return

    with stats_lock:
        stats["files"] += 1

    t_history_urls.append(url)
    code = doGetCode(url)
    if not code:
        return

    output = ''
    found_secret = False
    search_matches = re.findall(search_regexp, code)
    color = Fore.WHITE if search_matches else Fore.LIGHTBLACK_EX
    regexp_color = Fore.GREEN if search_matches else Fore.LIGHTGREEN_EX

    found_client_secret = any(
        'CLIENT_SECRET' in rr[1].upper()
        for regexp in t_regexp_compiled
        for rr in re.findall(regexp, code)
    )

    for regexp in t_regexp_compiled:
        r = re.findall(regexp, code)
        if r:
            found_secret = True
            if not output:
                if args.url:
                    output += result['html_url']
                else:

                    if found_client_secret:
                        output += f"{Fore.RED}[SECRET MATCH] {result['html_url']}{Style.RESET_ALL}\n\n"
                    else:
                        output += f"{Fore.YELLOW}[PATTERN MATCH] {result['html_url']}{Style.RESET_ALL}\n\n"

            if not args.url:
                for rr in r:
                    output += (
                        f"{color}{rr[0].lstrip()}{Style.RESET_ALL}"
                        f"{regexp_color}{rr[1]}{Style.RESET_ALL}"
                        f"{color}{rr[-1].rstrip()}{Style.RESET_ALL}\n"
                    )

    if found_secret:
        with stats_lock:
            stats["secrets"] += 1

    if output.strip():
        sys.stdout.write(f"{output}\n")
        if output_file_handle:
            output_file_handle.write(re.sub(r'\033\[[0-9;]*m', '', output) + '\n')

if __name__ == "__main__":
    # Show intro/help if no args or help flags
    if len(sys.argv) < 2 or "--help" in sys.argv or "-h" in sys.argv:
        display_intro()
        sys.exit(0)

    # Argument parsing (no built-in help)
    args_parser = argparse.ArgumentParser(add_help=False)
    args_parser.add_argument("-t", "--token", required=True)
    args_parser.add_argument("-s", "--search")
    args_parser.add_argument("-r", "--regexp")
    args_parser.add_argument("-u", "--url", action="store_true")
    args_parser.add_argument("-o", "--output", type=str)
    args = args_parser.parse_args()

    print_authorization_notice()

    # Output file
    if args.output:
        output_file_path = args.output
        output_file_handle = open(output_file_path, 'w', encoding='utf-8')

    t_tokens = []
    if args.token:
        t_tokens = [t.strip() for t in args.token.split(',') if t.strip()]
    elif os.getenv('GITHUB_TOKEN'):
        t_tokens = [t.strip() for t in os.getenv('GITHUB_TOKEN').split(',') if t.strip()]
    elif os.path.isfile(TOKENS_FILE):
        with open(TOKENS_FILE, 'r') as fp:
            for line in fp:
                r = re.search(r'^([a-f0-9]{40}|ghp_[a-zA-Z0-9]{36}|github_pat_[_a-zA-Z0-9]{82})$', line.strip())
                if r:
                    t_tokens.append(r.group(1))

    if not t_tokens:
        print("[!] GitHub Auth Token is missing.")
        sys.exit(1)

    _search = args.search if args.search else "sharepoint OR filename:.env"
    _search_encoded = urllib.parse.quote(_search)

    # Regex
    t_regexp = []
    if args.regexp:
        if os.path.isfile(args.regexp):
            with open(args.regexp) as json_file:
                data = json.load(json_file)
            if 'pattern' in data:
                t_regexp.append(data['pattern'])
            elif 'patterns' in data:
                t_regexp.extend(data['patterns'])
        else:
            t_regexp.append(args.regexp)
    else:
        t_regexp = [
            r'(?:AZURE_)?TENANT_ID=[A-Za-z0-9-]{36}',
            r'(?:tenantId|tenant_id)=[A-Za-z0-9-]{36}',
            r'(?:AZURE_)?CLIENT_ID=[A-Za-z0-9-]{36}',
            r'(?:clientId|client_id)=[A-Za-z0-9-]{36}',
            r'\b[A-Z_]*CLIENT_SECRET=[A-Za-z0-9.~]{32,64}\b',
            r'\bAZURE_CLIENT_SECRET=[A-Za-z0-9.~]{32,64}\b',
            r'\bGRAPH_TENANT_ID=[A-Za-z0-9-]{36}\b',
            r'\bGRAPH_CLIENT_ID=[A-Za-z0-9-]{36}\b',
            r'\bGRAPH_PERSONAL_CLIENT_ID=[A-Za-z0-9-]{36}\b',
            r'\bGRAPH_CLIENT_SECRET=[A-Za-z0-9.~]{32,64}\b',
            r'\bGRAPH_PERSONAL_CLIENT_SECRET=[A-Za-z0-9.~]{32,64}\b',
            r'\bAZURE_STORAGE_ACCOUNT=[A-Za-z0-9]{3,24}\b',
            r'\bAZURE_STORAGE_KEY=[A-Za-z0-9+/=]{88}\b',
            r'\bAZURE_STORAGE_CONNECTION_STRING=[A-Za-z0-9;=/:\-_.]+',
            r'\bAPPINSIGHTS_INSTRUMENTATIONKEY=[A-Za-z0-9\-]{36}\b',
            r'\bAZURE_SUBSCRIPTION_ID=[A-Za-z0-9-]{36}\b',
            r'\bKEYVAULT_URI=https://[A-Za-z0-9\-]+\.vault\.azure\.net\b',
            r'\bAZURE_KEYVAULT_SECRET=[A-Za-z0-9~!@#$%^&*()_+=\-]{32,64}\b',
        ]

    t_regexp_compiled = [
        re.compile(r'(.{0,100})(' + r + r')(.{0,100})', re.IGNORECASE)
        for r in t_regexp
    ]
    search_regexp = re.compile(_search, re.IGNORECASE)

    t_sort_order = [{'sort': 'indexed', 'order': 'desc'}]

    t_history_urls = []

    for so in t_sort_order:
        page = 1
        print("[*] Fetching results...")

        while True:
            time.sleep(random.uniform(0.5, 1.5))
            token = random.choice(t_tokens)
            t_json = githubApiSearchCode(token, _search_encoded, page, so['sort'], so['order'])

            if not t_json:
                continue

            if 'message' in t_json and 'API rate limit exceeded' in t_json['message']:
                print(f"{Fore.RED}[-] API rate limit exceeded, stopping scan.{Style.RESET_ALL}")
                break

            items = t_json.get('items', [])
            if not items:
                break

            pool = Pool(10)
            pool.map(partial(readCode, search_regexp, t_regexp), items)
            pool.close()
            pool.join()

            with stats_lock:
                stats["pages"] += 1

            page += 1

    print("\n[+] Scan complete")
    print(f"    Pages scanned : {stats['pages']}")
    print(f"    Files scanned : {stats['files']}")

    if output_file_handle:
        output_file_handle.close()
        print(f"[+] Results saved to {output_file_path}")
