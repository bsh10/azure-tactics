#!/usr/bin/python3

import requests
import csv
import json
import time
import argparse
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print("-" * 70)
    print("Microsoft Graph SharePoint Secret Search")
    print("Search SharePoint and OneDrive for hardcoded secrets")
    print("with file enumeration and download via Microsoft Graph\n")
    print("Required Graph permissions:")
    print("  - Sites.Read.All (minimum)")
    print("  - Sites.ReadWrite.All (recommended)")
    print("  - Files.Read.All / Files.ReadWrite.All (optional)")
    print("-" * 70 + "\n")

banner()

def print_authorization_notice():
    print("For authorized security testing and assessment only.\n")

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter
)

parser.add_argument(
    "-t", "--token",
    required=True,
    help="Microsoft Graph access token (JSON Web Token / JWT)"
)
parser.add_argument(
    "-r", "--region",
    default="US",
    help="Search region (default: US)"
)
parser.add_argument(
    "-o", "--output",
    metavar="FILE",
    default="found_secrets.csv",
    help="Search results CSV file (default: found_secrets.csv)"
)
parser.add_argument(
    "-d", "--drive-id",
    help="Drive ID to retrieve direct download URLs"
)
parser.add_argument(
    "-i", "--item-id",
    help="Specific item or folder ID within the drive"
)
parser.add_argument(
    "-O", "--download-output",
    metavar="FILE",
    default="download_urls.csv",
    help="Download URLs CSV file (default: download_urls.csv)"
)
parser.add_argument(
    "-k", "--keywords",
    help="Custom keywords to search for (comma-separated)\n"
    "or filename filtering (in drive dump mode)"
)

parser.epilog = (
    "Examples:\n"
    "  Search only (default keywords):\n"
    "    python3 azure-sharepoint-secret-search.py -t TOKEN\n\n"
    "  Search with custom keywords:\n"
    "    python3 azure-sharepoint-secret-search.py -t TOKEN -k password,secret,apikey\n\n"
    "  Dump entire drive only:\n"
    "    python3 azure-sharepoint-secret-search.py -t TOKEN -d DRIVE_ID\n\n"
    "  Dump specific folder/file only:\n"
    "    python3 azure-sharepoint-secret-search.py -t TOKEN -d DRIVE_ID -i ITEM_ID\n\n"
    "  Dump entire drive with filename filter:\n"
    "    python3 azure-sharepoint-secret-search.py -t TOKEN -d DRIVE_ID -k env,json,pdf\n\n"
)

args = parser.parse_args()

print_authorization_notice()

access_token = args.token

headers_search = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

headers_drive = {
    "Authorization": f"Bearer {access_token}",
    "Accept": "application/json"
}

# Mode info (dump)
if args.drive_id and args.keywords:
    print(f"{Fore.CYAN}[*] Filename filter enabled (-k):{Style.RESET_ALL} {args.keywords}\n")
    print(f"{Fore.CYAN}[*] Matching is substring, case-insensitive (file name only){Style.RESET_ALL}\n")

# HTTP error formatter
def format_http_error(resp):
    body = (resp.text or "").strip()
    if body:
        return body

    www = resp.headers.get("WWW-Authenticate", "").strip()
    if www:
        return f"(empty body) WWW-Authenticate: {www}"

    req_id = resp.headers.get("request-id") or resp.headers.get("x-ms-ags-diagnostic")
    if req_id:
        return f"(empty body) request-id/diagnostic: {req_id}"

    return "(empty body)"

def print_search_hint(status_code):
    if status_code == 400:
        print("      Hint: Use -r or --region with the region shown in the error message above")
    elif status_code == 401:
        print("      Hint: Unauthorized. Verify the token is valid, unexpired, and issued for Microsoft Graph (aud).")
    elif status_code == 403:
        print("      Hint: Forbidden. Verify Graph permissions and admin consent (Sites.Read.All / Files.Read.All, etc.).")
    elif status_code == 429:
        print("      Hint: Rate limited. Slow down requests or retry later.")
    elif status_code >= 500:
        print("      Hint: Microsoft Graph Search backend error. Retry later or use a different keyword/region.")

# Drive enumeration
def get_files(drive_id, url, collected):
    try:
        resp = requests.get(url, headers=headers_drive)
        if resp.status_code != 200:
            print(f"{Fore.RED}[!] Failed ({resp.status_code}): {format_http_error(resp)}{Style.RESET_ALL}")
            return

        data = resp.json()

        # Build filename filter list if -k provided
        kw_list = []
        if args.keywords:
            kw_list = [k.strip().lower() for k in args.keywords.split(",") if k.strip()]

        def name_matches(name: str) -> bool:
            if not kw_list:
                return True
            n = (name or "").lower()
            return any(k in n for k in kw_list)

        # Single file case
        if "file" in data and "@microsoft.graph.downloadUrl" in data:
            file_name = data.get("name", "N/A")
            if name_matches(file_name):
                collected.append((file_name, data["@microsoft.graph.downloadUrl"]))
                if args.keywords:
                    print(f"{Fore.GREEN}[+] File (matched -k):{Style.RESET_ALL} {file_name}")
                else:
                    print(f"{Fore.GREEN}[+] File:{Style.RESET_ALL} {file_name}")
                print(f"      Download URL: {data['@microsoft.graph.downloadUrl']}")
            return

        for item in data.get("value", []):
            name = item.get("name", "N/A")

            if "file" in item and "@microsoft.graph.downloadUrl" in item:
                if name_matches(name):
                    collected.append((name, item["@microsoft.graph.downloadUrl"]))
                    if args.keywords:
                        print(f"{Fore.GREEN}[+] File (matched -k):{Style.RESET_ALL} {name}")
                    else:
                        print(f"{Fore.GREEN}[+] File:{Style.RESET_ALL} {name}")
                    print(f"      Download URL: {item['@microsoft.graph.downloadUrl']}")

            elif "folder" in item:
                print(f"{Fore.CYAN}[*] Entering folder:{Style.RESET_ALL} {name}")
                folder_url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{item['id']}/children"
                get_files(drive_id, folder_url, collected)

        # Pagination
        if "@odata.nextLink" in data:
            get_files(drive_id, data["@odata.nextLink"], collected)

    except Exception as e:
        print(f"{Fore.RED}[!] Exception:{Style.RESET_ALL} {e}")

def run_drive_dumper():
    all_files = []

    if args.item_id:
        print(f"{Fore.CYAN}[*] Dumping item/folder:{Style.RESET_ALL} {args.item_id}\n")
        item_url = f"https://graph.microsoft.com/v1.0/drives/{args.drive_id}/items/{args.item_id}"
        r = requests.get(item_url, headers=headers_drive)

        if r.status_code != 200:
            print(f"{Fore.RED}[!] Failed to fetch item ({r.status_code}): {format_http_error(r)}{Style.RESET_ALL}")
            return

        item_data = r.json()

        if "file" in item_data:
            get_files(args.drive_id, item_url, all_files)
        elif "folder" in item_data:
            child_count = item_data.get("folder", {}).get("childCount")
            if child_count == 0:
                print(f"{Fore.YELLOW}[*] Folder is empty (childCount=0){Style.RESET_ALL}\n")
            children_url = f"{item_url}/children"
            get_files(args.drive_id, children_url, all_files)
        else:
            print(f"{Fore.YELLOW}[!] Item is not a file or folder{Style.RESET_ALL}")
            return

    else:
        print(f"{Fore.CYAN}[*] Dumping entire drive:{Style.RESET_ALL} {args.drive_id}\n")
        root_url = f"https://graph.microsoft.com/v1.0/drives/{args.drive_id}/root/children"
        get_files(args.drive_id, root_url, all_files)

    with open(args.download_output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Name", "DownloadUrl"])
        writer.writerows(all_files)

    print(f"\n{Fore.GREEN}[+] Completed{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Total files found:{Style.RESET_ALL} {len(all_files)}")
    print(f"{Fore.GREEN}[+] Results saved to:{Style.RESET_ALL} {args.download_output}")

# Drive dump only
if args.drive_id:
    run_drive_dumper()
    sys.exit(0)

# Search logic
keywords = [
    "password", "passwd", "pwd", "secret", "secrets", "api", "apikey", "api_key",
    "token", "bearer", "ssh", "rsa", "private key", "pem", "pfx", "cert", "certificate",
    "keyvault", "vault", "confidential", "login", "creds", "credentials",
    "connectionString", "accesskey", "storagekey", "sasToken", "sql",
    ".env", ".config", ".json", ".yml", ".ps1", ".py", ".php"
]

# Override default keywords only if -k is set
if args.keywords:
    keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]

csv_headers = [
    "keyword", "region", "entity_type",
    "site_id", "drive_id", "item_id",
    "email", "last_modified",
    "file_name", "file_url"
]

any_success = False

with open(args.output, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=csv_headers)
    writer.writeheader()

    for keyword in keywords:
        print(f"{Fore.CYAN}[*] Searching for keyword:{Style.RESET_ALL} {keyword}")
        found = False
        http_error = False

        print(f"  {Fore.CYAN}[*] Region:{Style.RESET_ALL} {args.region}")

        search_url = "https://graph.microsoft.com/v1.0/search/query"
        body = {
            "requests": [
                {
                    "entityTypes": ["listItem", "site", "driveItem"],
                    "query": {"queryString": keyword},
                    "region": args.region
                }
            ]
        }

        try:
            r = requests.post(search_url, headers=headers_search, json=body)
            print(f"    [*] HTTP {r.status_code}")

            if r.status_code != 200:
                print(f"    {Fore.RED}[!] {r.status_code}: {format_http_error(r)}{Style.RESET_ALL}")
                print_search_hint(r.status_code)
                http_error = True
            else:
                data = r.json()

                for result in data.get("value", []):
                    for container in result.get("hitsContainers", []):
                        for hit in container.get("hits", []):
                            resource = hit.get("resource", {})
                            parent = resource.get("parentReference", {})

                            last_modified_by = resource.get("lastModifiedBy", {}).get("user", {})
                            user_email = (
                                last_modified_by.get("email")
                                or last_modified_by.get("userPrincipalName")
                                or "N/A"
                            )

                            print(
                                f"{Fore.MAGENTA}      [+] Match ({resource.get('@odata.type','N/A')}): "
                                f"{resource.get('name','N/A')}{Style.RESET_ALL}"
                            )
                            print(f"          URL      : {resource.get('webUrl','N/A')}")
                            print(f"          Drive ID : {parent.get('driveId','N/A')}")
                            print(f"          Item ID  : {resource.get('id','N/A')}")

                            writer.writerow({
                                "keyword": keyword,
                                "region": args.region,
                                "entity_type": resource.get("@odata.type", "N/A"),
                                "site_id": parent.get("siteId", "N/A"),
                                "drive_id": parent.get("driveId", "N/A"),
                                "item_id": resource.get("id", "N/A"),
                                "email": user_email,
                                "last_modified": resource.get("lastModifiedDateTime", "N/A"),
                                "file_name": resource.get("name", "N/A"),
                                "file_url": resource.get("webUrl", "N/A")
                            })

                            found = True
                            any_success = True

        except Exception as e:
            print(f"    {Fore.RED}[!] Exception:{Style.RESET_ALL} {e}")
            http_error = True

        if not found:
            print(f"  {Fore.YELLOW}[!] No results for '{keyword}'{Style.RESET_ALL}")
            if not http_error:
                print("      Hint: Use -r or --region with the region shown in the error message above")

        if http_error:
            break

        time.sleep(1)

if any_success:
    print(f"\n{Fore.GREEN}[+] Done. Results saved to {args.output}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Use -d/--drive-id and -i/--item-id to retrieve direct download URLs{Style.RESET_ALL}")
else:
    print(f"\n{Fore.RED}[!] Search failed. No results were retrieved.{Style.RESET_ALL}")
