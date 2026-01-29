#!/usr/bin/python3

import sys
import json
import csv
import time
import argparse
import requests
from colorama import Fore, Style, init

init(autoreset=True)

print("-" * 70)
print("Microsoft Graph User Enumerator")
print("-" * 70 + "")
print("Azure AD user enumeration via Microsoft Graph\n")

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument(
    "-t", "--token",
    required=True,
    help="Microsoft Graph access token (JWT)"
)
parser.add_argument(
    "-u", "--user",
    help="Target a single user by UPN or object ID (optional)."
)
parser.add_argument(
    "--drive",
    action="store_true",
    help="Also resolve the user's OneDrive via /users/{id}/drive."
)
parser.add_argument(
    "--select",
    default="id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,"
            "onPremisesSyncEnabled,jobTitle,department,officeLocation,"
            "companyName,onPremisesSamAccountName,onPremisesDistinguishedName,"
            "onPremisesSecurityIdentifier",
    help="Fields to select from /users."
)
parser.add_argument(
    "--format",
    choices=["csv", "json"],
    default="csv",
    help="Output format (default: csv)."
)
parser.add_argument(
    "-o", "--output",
    default="users.csv",
    help="Output file (default: users.csv)."
)
parser.add_argument(
    "--sleep",
    type=float,
    default=0.2,
    help="Sleep between Graph requests (default: 0.2s)."
)

args = parser.parse_args()

print("For authorized security testing and assessment only.\n")

HEADERS = {
    "Authorization": f"Bearer {args.token}",
    "Accept": "application/json"
}

def graph_get(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=25)
    except Exception as e:
        print(f"{Fore.RED}[!] Request exception:{Style.RESET_ALL} {e}")
        return None

def graph_error_brief(resp):
    try:
        j = resp.json()
        if "error" in j:
            return f"{j['error'].get('code')}: {j['error'].get('message')}"
        return resp.text
    except Exception:
        return resp.text

def safe_str(v):
    if v is None:
        return "N/A"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)

def get_drive_for_user(user_id):
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/drive?$select=id,driveType,webUrl"
    r = graph_get(url)
    if not r:
        return None

    if r.status_code == 404:
        return None  # OneDrive not provisioned

    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}: {graph_error_brief(r)}"}

    d = r.json()
    return {
        "id": d.get("id"),
        "driveType": d.get("driveType"),
        "webUrl": d.get("webUrl")
    }

def enumerate_users():
    users = []

    if args.user:
        r = graph_get(f"https://graph.microsoft.com/v1.0/users/{args.user}?$select={args.select}")
        if r and r.status_code == 200:
            users.append(r.json())
        return users

    url = f"https://graph.microsoft.com/v1.0/users?$select={args.select}"
    while url:
        r = graph_get(url)
        if not r or r.status_code != 200:
            break
        data = r.json()
        users.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        if url:
            time.sleep(args.sleep)

    return users

def print_summary(users):
    total = len(users)
    enabled = 0
    disabled = 0
    guest = 0
    member = 0
    other = 0
    synced = 0
    created_min = None
    created_max = None

    for u in users:
        ae = u.get("accountEnabled")
        if ae is True:
            enabled += 1
        elif ae is False:
            disabled += 1

        ut = (u.get("userType") or "").lower()
        if ut == "guest":
            guest += 1
        elif ut == "member":
            member += 1
        elif ut:
            other += 1

        if u.get("onPremisesSyncEnabled") is True:
            synced += 1

        cd = u.get("createdDateTime")
        if isinstance(cd, str) and cd:
            if created_min is None or cd < created_min:
                created_min = cd
            if created_max is None or cd > created_max:
                created_max = cd

    print(f"\n{Fore.CYAN}[*] Summary:{Style.RESET_ALL}")
    print(f"    Total users        : {total}")
    print(f"    Enabled            : {enabled}")
    print(f"    Disabled           : {disabled}")
    print(f"    UserType Guest     : {guest}")
    print(f"    UserType Member    : {member}")
    if other:
        print(f"    UserType Other     : {other}")
    print(f"    On-prem synced     : {synced}")
    if created_min or created_max:
        print(f"    createdDateTime    : {safe_str(created_min)} -> {safe_str(created_max)}")
    print()

print(f"{Fore.CYAN}[*] Querying users...{Style.RESET_ALL}")
users = enumerate_users()

if not users:
    print(f"{Fore.RED}[!] No users retrieved.{Style.RESET_ALL}")
    sys.exit(1)

print(f"{Fore.GREEN}[+] Users retrieved:{Style.RESET_ALL} {len(users)}")

enriched = []
for u in users:
    row = dict(u)
    if args.drive and u.get("id"):
        row["drive"] = get_drive_for_user(u["id"])
        time.sleep(args.sleep)
    enriched.append(row)

# Output
if args.format == "json":
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)
    print(f"{Fore.GREEN}[+] Results saved to:{Style.RESET_ALL} {args.output}")
    print_summary(users)
    sys.exit(0)

select_fields = [s.strip() for s in args.select.split(",")]
csv_fields = list(select_fields)

if args.drive:
    csv_fields.extend(["driveType", "driveWebUrl", "driveId", "driveError"])

with open(args.output, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=csv_fields)
    w.writeheader()

    for r in enriched:
        out = {k: safe_str(r.get(k)) for k in select_fields}

        if args.drive:
            d = r.get("drive")
            if isinstance(d, dict):
                out["driveType"] = safe_str(d.get("driveType"))
                out["driveWebUrl"] = safe_str(d.get("webUrl"))
                out["driveId"] = safe_str(d.get("id"))
                out["driveError"] = safe_str(d.get("error"))
            else:
                out["driveType"] = "N/A"
                out["driveWebUrl"] = "N/A"
                out["driveId"] = "N/A"
                out["driveError"] = "N/A"

        w.writerow(out)

print(f"{Fore.GREEN}[+] Results saved to:{Style.RESET_ALL} {args.output}")
print_summary(users)
