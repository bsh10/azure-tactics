#!/usr/bin/python3

import requests
import sys
import argparse
import json
import base64
from colorama import Fore, Style, init

init(autoreset=True)

SUCCESS = Fore.YELLOW + "[SUCCESS]"
ERROR   = Fore.RED + "[ERROR]"
INFO    = Fore.CYAN + "[INFO]"
WARN    = Fore.YELLOW + "[WARN]"

def print_authorization_notice():
    print("For authorized security testing and assessment only.\n")

def display_intro():
    print("-" * 60)
    print(" Azure Service Principal Inspector ")
    print("-" * 60)
    print("Fetch OAuth token, and enumerate Graph permissions\n")

# Get token
def get_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    r = requests.post(url, data=data, headers=headers)
    if r.status_code != 200:
        print(f"{ERROR} Failed to get token ({r.status_code})")
        print(r.text)
        return None

    token = r.json().get("access_token")
    print(f"{SUCCESS} OAuth token retrieved for AppID: {client_id}\n")

    print(Fore.GREEN + "----- ACCESS TOKEN -----")
    print(Fore.WHITE + token)
    print(Fore.GREEN + "------------------------\n")

    return token

# JWT decoder
def decode_jwt(token):
    print(f"{INFO} Decoding JWT access token (no signature verification)\n")

    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
    except Exception as e:
        print(f"{ERROR} Failed to decode JWT: {e}")
        return [], None

    roles = payload.get("roles", [])

    print(Fore.GREEN + Style.BRIGHT + "----- JWT CLAIMS -----")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}App ID (appid): {Style.RESET_ALL}{payload.get('appid')}")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}Tenant ID (tid): {Style.RESET_ALL}{payload.get('tid')}")
    print()

    if roles:
        print(f"{Fore.MAGENTA}{Style.BRIGHT}Roles present in token:")
        for r in roles:
            print(f"  {Fore.YELLOW}- {r}")
    else:
        print(f"{WARN} No roles claim present in token")

    print(Fore.GREEN + Style.BRIGHT + "----------------------\n")
    return roles, payload

# Get Service Principals
def get_service_principal(token, app_id):
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{app_id}'"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print(f"{ERROR} Failed to get service principal ({r.status_code})")
        print(r.text)
        return None

    sp = r.json().get("value", [None])[0]
    if not sp:
        print(f"{ERROR} No service principal found for AppID")
        return None

    print(f"{SUCCESS} Found Service Principal")
    print(f"  Display Name : {sp.get('displayName')}")
    print(f"  Object ID    : {sp.get('id')}\n")

    return sp.get("id")

# Get app role assignments
def get_app_roles(token, sp_id):
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print(f"{ERROR} Failed to get appRoleAssignments ({r.status_code})")
        print(r.text)
        return

    assignments = r.json().get("value", [])
    if not assignments:
        print(f"{INFO} No app role assignments found via Graph API\n")
        return

    print(f"{SUCCESS} App Role Assignments (Graph API view):\n")
    for a in assignments:
        print(Fore.WHITE + json.dumps(a, indent=2))
        print()

# Capability tests
def run_capability_tests(token, roles):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    tests = []
    if any(r.startswith("User.") for r in roles):
        tests.append(("User", "GET", "https://graph.microsoft.com/v1.0/users?$top=1"))
    if any(r.startswith("Sites.") for r in roles):
        tests.append(("Sites", "GET", "https://graph.microsoft.com/v1.0/sites?search=*"))

    if not tests:
        print(f"{WARN} No User./Sites. roles detected; skipping capability tests.\n")
        return

    sites_out = []
    sites_error = None

    print(f"{INFO} Running lightweight capability tests...\n")

    for category, method, url in tests:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {category} -> {url}")

        resp = requests.request(method, url, headers=headers)
        print(f"    {Fore.CYAN}[*]{Style.RESET_ALL} HTTP {resp.status_code}")

        if resp.status_code != 200:
            print(f"    {Fore.RED}[!] Error body:{Style.RESET_ALL} {resp.text}\n")
            if category == "Sites":
                sites_error = {
                    "url": url,
                    "http_status": resp.status_code,
                    "body": resp.text
                }
            continue

        data = resp.json()

        if category == "User":
            users = data.get("value", [])
            if users:
                u = users[0]
                print(f"    Display Name : {u.get('displayName')}")
                print(f"    UPN          : {u.get('userPrincipalName')}")
                print(f"    User ID      : {u.get('id')}\n")

        elif category == "Sites":
            for s in data.get("value", []):
                sites_out.append({
                    "displayName": s.get("displayName"),
                    "webUrl": s.get("webUrl"),
                    "id": s.get("id")
                })

            if sites_out:
                s0 = sites_out[0]
                print(f"    displayName: {s0.get('displayName')}")
                print(f"    webUrl     : {s0.get('webUrl')}")
                print(f"    id         : {s0.get('id')}\n")

            print(f"    {Fore.CYAN}[*]{Style.RESET_ALL} Saved {len(sites_out)} site(s) to sites.json\n")

    # Save sites.json only
    try:
        payload = {"sites": sites_out}
        if sites_error:
            payload["error"] = sites_error

        with open("sites.json", "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"{ERROR} Failed to write sites.json: {e}")

    print(f"{INFO} Capability tests finished\n")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("-t", "--tenant", required=True, help="Tenant ID")
    parser.add_argument("-c", "--client", required=True, help="Client (App) ID")
    parser.add_argument("-s", "--secret", required=True, help="Client Secret")

    if len(sys.argv) == 1:
        display_intro()
        parser.print_usage()
        sys.exit(0)

    if "-h" in sys.argv or "--help" in sys.argv:
        display_intro()
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    print_authorization_notice()

    token = get_token(args.tenant, args.client, args.secret)
    if not token:
        sys.exit(1)

    roles, _ = decode_jwt(token)

    sp_id = get_service_principal(token, args.client)
    if not sp_id:
        sys.exit(1)

    get_app_roles(token, sp_id)

    run_capability_tests(token, roles)
