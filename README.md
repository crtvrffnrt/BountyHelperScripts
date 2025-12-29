# BountyHelperScripts

## subtaker.sh

subtaker.sh enumerates subdomains and DNS records using the Shodan DNS API and identifies potential subdomain takeover candidates by correlating CNAME and A records with known cloud provider suffixes such as azurewebsites.net, azurefd.net, and similar platforms. It is intended for reconnaissance and exposure analysis, not automated exploitation.

---

## Usage

Before running the script, export your Shodan API key:

```bash

 SHODANAPI="YOUR_SHODAN_API_KEY"
./subtaker.sh -i scope.txt -d target-domainfragments.txt --deadcheck
``` bas```bash

##
-i scope.txt
File containing root domains to enumerate via the Shodan DNS API.

-d target-domainfragments.txt
File containing domain suffix fragments to match against DNS values.
Example entries:
