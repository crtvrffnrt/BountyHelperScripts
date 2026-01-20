# BountyHelperScripts

Small helper scripts for bug bounty recon and Azure/DNS workflows. Use only on explicitly authorized scopes.

Most DNS tools use the Shodan DNS API for historical data that normal resolvers miss.

## Setup

- Shodan key: set `SHODANAPI` or place it in `~/.shodan/api_key`
- Dependencies:
  - Python scripts: `python3`
  - Azure scripts: `az` CLI logged in (`az login`)

## Tools

### subtaker.py 
Find CNAMEs via Shodan DNS and match them against known provider suffix fragments to flag potential takeover candidates.
Free Shodan api key is limited in api requests. i recommend using freelancer Subscription to use this script on big domain lists. 
```bash
export SHODANAPI="YOUR_SHODAN_API_KEY"
./subtaker.py -i scope.txt -d az-domainfragments.txt --deadcheck
./subtaker.py -i scope.txt -d target-domainfragments.txt -O json --output out.json
```

Help:
```text
usage: subtaker.py [-i INPUT_FILE] [-d FRAGMENTS_FILE] [-O {table,json,csv}]
                   [--output OUT_FILE] [--debug] [--deadcheck] [--onlydead]
                   [-h]

Query Shodan DNS data for target domains and match results against
suffix fragments. Emits a live table to stdout and optionally writes
JSON/CSV output files.

options:
  -i INPUT_FILE        Input scope file (required).
  -d FRAGMENTS_FILE    Suffix fragments file (required).
  -O {table,json,csv}  Output file format when --output is used. Default: table.
  --output OUT_FILE    Write JSON/CSV to this file.
  --debug              Enable debug logging.
  --deadcheck          Check HTTP/HTTPS liveness.
  --onlydead           Only output dead endpoints and check Traffic Manager registerability.
  -h, --help           Show this help and exit.

Examples:
  ./subtaker.py -i scope.txt -d target-domainfragments.txt
  ./subtaker.py -i scope.txt -d target-domainfragments.txt -O json --output out.json
  ./subtaker.py -i scope.txt -d target-domainfragments.txt --deadcheck --debug
```

### txtfinder.py
Search Shodan DNS TXT records for a string (verification tokens, SPF fragments, etc.).

```bash
export SHODANAPI="YOUR_SHODAN_API_KEY"
./txtfinder.py -i scope.txt -s "google-site-verification"
```

Help:
```text
usage: txtfinder.py [-i INPUT_FILE] [-s SEARCH_STRING] [--debug] [-h]

Query Shodan DNS data for target domains and find TXT records
containing a search string.

options:
  -i INPUT_FILE     Input scope file (required).
  -s SEARCH_STRING  Search string (required).
  --debug           Enable debug logging.
  -h, --help        Show this help and exit.

Examples:
  ./txtfinder.py -i scope.txt -s "ms="
  ./txtfinder.py -i scope.txt -s "google-site-verification" --debug
```

### azvm_dns_availability.sh
Check Azure Public IP DNS name availability from a file of hostnames. Creates temp resource groups per region and cleans them up on exit.

```bash
./azvm_dns_availability.sh -f dnsnames.txt
```

Help:
```text
Usage:
  check_dns_availability.sh -f filename.txt
  check_dns_availability.sh --help

Description:
  Checks Azure Public IP DNS name availability for each entry in the input file.
  A temporary resource group is created per Azure region encountered so checks
  can run in-region. All temporary resource groups created by this run are
  deleted automatically at the end (even on Ctrl+C).

Input file format:
  - One DNS name per line (e.g., mylabel.westeurope.cloudapp.azure.com)
  - Empty lines and comments (# ...) are ignored
  - If no location segment is present, the location must be provided in the DNS
    name as the second dot-separated field

Output behavior:
  - Progress is shown as moving dots on stderr only
  - Each DNS name is printed to stdout as AVAILABLE/UNAVAILABLE during the run
  - A summary is printed to stdout at the end (checked/available/unavailable)

Options:
  -f FILE        File containing DNS names (required)
  -h, --help     Show this help page

Examples:
  ./check_dns_availability.sh -f dnsnames.txt

Notes:
  - Requires Azure CLI (`az`) logged in with permissions to create/delete
    resource groups.
  - Temporary resource groups are tagged with:
      created-by=check_dns_availability.sh
      run-id=<unique-id>
```

### fastilian.sh
Create a minimal Azure VM with a Public IP DNS label. Uses an allow-all NSG and waits for VM readiness.

```bash
./fastilian.sh --name myvm --location eastus
./fastilian.sh -n myvm --vm-size Standard_B2ats_v2
```

Help:
```text
Fastilian - minimal Azure VM creator with DNS label support

Usage:
  ./fastilian.sh --name <vm-name> [options]

Required:
  -name, --name, -n
      VM name and Public IP DNS label (must be unique within the region).
      Example name: avatarprodeastuscluster

Optional:
  --location <region>
      Azure location/region for the resource group and VM.
      This determines the DNS zone:
      <name>.<location>.cloudapp.azure.com
      Default: germanywestcentral

  --vm-size <sku>
      Azure VM size/SKU.
      Default: Standard_B2ats_v2

  --image <urn>
      Azure image URN.
      Default: Debian:debian-13:13-gen2:latest

  -h, --help
      Show this help and exit.

Behavior:
  - Creates a resource group named: fastilian-<name>-rg
  - Creates a VM named exactly: <name>
  - Configures an NSG that allows all inbound and outbound traffic
  - Waits for VM agent readiness and checks SSH availability

Examples:
  ./fastilian.sh --name avatarprodeastuscluster --location eastus
  ./fastilian.sh -n myvm --vm-size Standard_B2ats_v2
  ./fastilian.sh --name testvm --image Debian:debian-13:13-gen2:latest
```

### frontdoorcreator.sh
Create Azure Front Door profiles/endpoints for a hostname or a list. Supports origin/health probe tuning and auto-named resource groups.

```bash
./frontdoorcreator.sh -H my-api-endpoint --origin-host api.example.com
./frontdoorcreator.sh -l hostnames.txt --origin-host api.example.com --location eastus
```

Help:
```text
Usage:
  ./frontdoorcreator.sh -H <target-hostname> [options]
  ./frontdoorcreator.sh -l <file-with-hostnames> [options]

Required (choose one):
  -H, --hostname            Target hostname to derive the endpoint name from
  -l, --list                Text file with one hostname per line

Optional:
      --location            Azure region for the resource group (default: westeurope)
      --sku                 Front Door SKU (default: Standard_AzureFrontDoor)
      --origin-host         Backend hostname (default: placeholder.example.com)
      --origin-host-header  Origin host header (default: same as --origin-host)
      --resource-group      Exact resource group name (single-host only)
      --rg-prefix           Resource group prefix for auto names (default: afd-)
      --profile-name        Front Door profile name (defaults to <endpoint>)
      --endpoint-name       Front Door endpoint name override (defaults to first label of hostname)
      --origin-group-name   Origin group name (default: og-default)
      --origin-name         Origin name (default: origin-1)
      --route-name          Route name (default: route-default)
      --probe-path          Health probe path (default: /health)
      --probe-protocol      Health probe protocol (default: Https)
      --probe-request-type  Health probe request type (default: GET)
      --probe-interval      Health probe interval in seconds (default: 60)
      --origin-priority     Origin priority for load balancing (default: 1)
      --origin-weight       Origin weight for load balancing (default: 1000)
      --http-port           Origin HTTP port (default: 80)
      --https-port          Origin HTTPS port (default: 443)
      --wait-timeout        Max seconds to wait per resource (default: 900)
      --no-wait             Skip provisioning-state waits
      --debug               Enable Azure CLI debug output
  -h, --help                Show this help and exit

Examples:
  ./frontdoorcreator.sh -H my-api-endpoint
  ./frontdoorcreator.sh -H my-api.azurefd.net --origin-host api.example.com
  ./frontdoorcreator.sh -l hostnames.txt --origin-host api.example.com --location eastus

Notes:
  - The final Front Door hostname will look like:
      https://<endpoint-name>-<random>.z01.azurefd.net
  - Auto-generated resource groups end with: -<unix-timestamp>-frontdoorcreator
  - Origin host should be publicly reachable for a healthy endpoint.
```
