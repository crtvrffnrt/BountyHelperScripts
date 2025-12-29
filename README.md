# BountyHelperScripts

A focused collection of Python helper tools for bug bounty hunting, cloud reconnaissance, and DNS exposure analysis.  
All scripts are designed for authorized testing within explicitly approved scopes and prioritize high-signal findings over noisy automation.

The tools rely on the Shodan DNS API to extract historical and current DNS intelligence that is often missed by live resolvers, making them particularly useful for large-scale scope analysis and takeover reconnaissance.

---

## Included Tools

### subtaker.py

subtaker.py enumerates DNS CNAME records for scoped domains via the Shodan DNS API and correlates them against known cloud and managed service suffixes.  
Its primary goal is to identify potential subdomain takeover candidates caused by dangling or unclaimed backend resources.

The script performs reconnaissance only.  
It does not attempt exploitation, service claiming, or provider ownership bypass.

Core features:
• Core-domain normalization and deduplication  
• Matching against customizable suffix fragment lists  
• Optional HTTP and HTTPS liveness checks  
• Live table output to stdout  
• Optional JSON or CSV export  
• Built-in retry, backoff, and rate-limit handling  

---

#### Basic Usage

```bash
export SHODANAPI="YOUR_SHODAN_API_KEY"
./subtaker.py -i scope.txt -d target-domainfragments.txt --deadcheck
