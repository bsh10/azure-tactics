<p align="center">
  <img src="assets/azure-tactics-logo.png" alt="Azure Tactics" width="800">
</p>

# Azure Tactics

Azure Tactics is a collection of lightweight offensive security tools designed to simulate real-world cloud attack paths, including credential harvesting, privilege discovery, and initial access techniques, with a focus on Azure AD and Microsoft Graph. Specifically, it targets:

- Exposed credentials in source code
- Over-permissioned service principals
- SharePoint and OneDrive secret sprawl
- Identity reconnaissance within Azure AD

Azure Tactics is intended for **authorized security testing, red team engagements, and internal security assessments only**.

---
## Installation

Azure Tactics requires Python 3 and minimal dependencies.

### 1. Clone repository
```bash
git clone https://github.com/bsh10/azure-tactics.git
cd azure-tactics
```

### 2. Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---
## Table of Contents

1. [GitHub Azure Secrets Search](#github-azure-secrets-search)
2. [Azure Service Principal Inspector](#azure-service-principal-inspector)
3. [SharePoint Secrets Search](#sharepoint-secrets-search)
4. [Azure User Enumerator](#azure-user-enumerator)
5. [Disclaimer](#disclaimer)

Azure Tactics currently includes **four tools**, each aligned with a distinct phase of a cloud attack chain. Additional tools will be added over time.

---
## GitHub Azure Secrets Search

### Description

This tool searches GitHub for exposed Azure and Microsoft Graph application credentials, allowing effective collection of secrets that may grant access to cloud tenants. It specifically targets **Tenant IDs, Client IDs, and Client Secrets**. By default, it searches for `.env` files and performs pattern-based detection using regular expressions, highlighting discovered secrets in red.

These credentials are frequently leaked in:
- `.env` files
- configuration files
- CI/CD pipelines
- test scripts and sample code

### Example credential formats

```
Tenant ID: b26e2270-d3a4-4b9f-8c4f-3c9d4b9d8e12
Client ID: 1c3d4e5f-1234-4a5b-9cde-9876543210ab
Client Secret: ~Q8x3pZz9FJ7H2kA9fD3... (long opaque string)
```

To use this tool, a GitHub API token is required.

You can generate one by:
1. Navigating to **GitHub → Settings → Developer settings → Personal access tokens**
2. Creating a **Fine-grained** or **Classic** token
3. Granting, at minimum, **public_repo** (or equivalent read-only) access

Once created, pass the token to the tool using the `--token` option.

### Example usage
```bash
python3 github-azure-secret-search.py --token GITHUB_TOKEN

python3 github-azure-secret-search.py --token GITHUB_TOKEN --search "AZURE_CLIENT_SECRET OR filename:.env"

python3 github-azure-secret-search.py -t GITHUB_TOKEN -r "\b[A-Z_]*CLIENT_SECRET\s*=\s*[A-Za-z0-9.~]{32,64}\b"
```

---
## Azure Service Principal Inspector

### Description

Azure Service Principal Inspector is used to discover the effective privileges and access associated with an Microsoft Graph application using a **Tenant ID**, **Client ID**, and **Client Secret**.

If the provided **Tenant ID**, **Client ID**, and **Client Secret** are valid, the tool first obtains an OAuth JWT access token and then:

- Decodes and displays token claims
- Enumerates Microsoft Graph roles and permissions
- Confirms access via basic Graph capability tests (users and sites)

This allows determination of what an application can actually do, rather than relying solely on assigned permissions.

### Example usage
```bash
python3 azure-sp-inspector.py   -t <tenant_id>   -c <client_id>   -s <client_secret>
```

---
## SharePoint Secrets Search

### Description

This tool searches SharePoint and OneDrive content for secrets via Microsoft Graph using an OAuth JWT access token, simulating cloud-native lateral movement after initial access.

It is effective at identifying passwords, API keys, application secrets, configuration files, and sensitive documents stored in SharePoint or OneDrive, including content embedded in image files. Because it operates through Microsoft Graph using legitimate OAuth tokens, this activity is generally low-noise and may remain undetected for a period of time.

Additionally, it can:
- Enumerate SharePoint sites and drives
- Extract files from entire drives (subject to permissions)
- Generate direct file download URLs via Microsoft Graph
- Detect and report tenant region information from token and Graph metadata
- Save results to CSV, including file paths, locations, and matching indicators for review and reporting

### Minimum permissions required

At minimum, this tool requires one of the following:
- `Sites.Read.All`
- `Files.Read.All`

Higher permissions enable broader enumeration and file access.

Microsoft Graph requires the tenant region to be specified when performing search operations. By default, the tool uses the **US** region; however, if the tenant resides in a different region, it will detect and display it. The region can also be explicitly set using the `--region` option.

### Default search keywords

By default, the tool searches for a curated set of high-signal keywords and file patterns commonly associated with exposed secrets and sensitive configuration data, including:

```
password, passwd, pwd, secret, secrets, api, apikey, api_key,
token, bearer, ssh, rsa, private key, pem, pfx, cert, certificate,
keyvault, vault, confidential, login, creds, credentials,
connectionString, accesskey, storagekey, sasToken, sql,
.env, .config, .json, .yml, .ps1, .py, .php
```

These defaults are designed to balance coverage and signal quality and can be overridden or extended using the `--keywords` option.

### Search using default keywords
```bash
python3 azure-sharepoint-secret-search.py --token GRAPH_ACCESS_TOKEN
```

### Search with custom keywords
```bash
python3 azure-sharepoint-secret-search.py   --token GRAPH_ACCESS_TOKEN   --keywords 'password,secret,apikey'
```

### Drive and file extraction workflow

During search operations, the tool reports the **Drive ID** and **Item ID** for discovered files. These identifiers can be reused to perform targeted extraction actions without repeating the initial search phase.

Once a drive has been identified, the following options are available:

1. Use the `--drive` option with a **Drive ID** to dump the entire SharePoint or OneDrive drive.
The tool will enumerate all files within the drive and generate direct Microsoft Graph download URLs for each accessible file.
2. Use the `--drive` option together with the `--item` option to dump a specific file by its **Item ID**, generating a direct download link for that file only.

### Dump entire SharePoint drive
```bash
python3 azure-sharepoint-secret-search.py   --token GRAPH_ACCESS_TOKEN   --drive-id DRIVE_ID
```

### Dump a specific file
```bash
python3 azure-sharepoint-secret-search.py   --token GRAPH_ACCESS_TOKEN   --drive-id DRIVE_ID   --item-id ITEM_ID
```

### Use filename filters when dumping a drive
```bash
python3 azure-sharepoint-secret-search.py   --token GRAPH_ACCESS_TOKEN   --drive-id DRIVE_ID   --keywords env,json,pdf
```

---
## Azure User Enumerator

### Description

This tool performs identity reconnaissance by enumerating Azure AD users and extracting key identity attributes.

It provides visibility into:
- Enabled vs disabled accounts
- Guest vs member users
- Hybrid (on-premises synchronized) accounts
- Account age and creation trends
- Organizational metadata (department, title, location)

### Minimum permissions required

- `User.Read.All` (Application or Delegated)

### Example usage
```bash
python3 azure-user-enumerator.py --token GRAPH_ACCESS_TOKEN
```

---
## Disclaimer

All tools in this repository are intended **for authorized security testing and assessment only**.

You are responsible for ensuring you have explicit permission to test any Azure tenant, application, or data source.
