# BountyHelperScripts

A small collection of helper scripts for bug bounty hunting, cloud reconnaissance, and exposure analysis.
All tools are designed for authorized testing within approved scopes.

---

## subtaker.sh

subtaker.sh enumerates subdomains and DNS records using the Shodan DNS API and identifies potential subdomain takeover candidates by correlating CNAME and A records with known cloud provider suffixes such as azurewebsites.net, azurefd.net, cloudfront.net, and similar platforms.

The script focuses on reconnaissance and exposure identification. It does not perform exploitation and does not bypass cloud provider ownership controls.

---
Before running the script, export your Shodan API key:

```bash
export SHODANAPI="YOUR_SHODAN_API_KEY"
```

---

### Basic Usage

```bash
./subtaker.sh -i scope.txt -d target-domainfragments.txt --deadcheck
```

---

### Parameters

### -i scope.txt

File containing root domains to enumerate via the Shodan DNS API.


### -d target-domainfragments.txt

File containing domain suffix fragments to match against DNS values.
These fragments typically represent cloud providers or managed services that are commonly involved in subdomain takeover scenarios.

Example:

```text
azurewebsites.net
azurefd.net
cloudfront.net
herokuapp.com
github.io
```

---

### --deadcheck

Enables HTTP and HTTPS reachability checks for matched targets.
Results are classified as `live` or `dead` based on network responses.

A `dead` result indicates that the backend does not respond, not that takeover is possible.

---

### -O table | json | csv

Example:

```bash
./subtaker.sh -i scope.txt -d fragments.txt -O json --output results.json --deadcheck
```

