#!/usr/bin/env bash
# Resolve hostnames for a given IPv4 using multiple data sources (DNS + APIs).
# Usage: ./findhostname.sh 1.2.3.4

set -uo pipefail

ip=${1:-}
if [[ -z "$ip" ]]; then
  echo "Usage: $0 <ipv4>" >&2
  exit 1
fi

# Basic IPv4 sanity check
if ! [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Invalid IPv4 provided: $ip" >&2
  exit 1
fi

# Load API keys when present; the script still works with only DNS tools.
if [[ -f /Tools/apikeys.txt ]]; then
  # shellcheck disable=SC1091
  source /Tools/apikeys.txt
fi

declare -A seen
results=()

add_host() {
  local host
  host=$(echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]*$//')
  host=${host%.}
  [[ -z $host ]] && return
  # Rough hostname validation to avoid junk tokens
  if [[ $host =~ ^[a-z0-9._-]+(\.[a-z0-9._-]+)+$ ]]; then
    if [[ -z ${seen[$host]:-} ]]; then
      seen[$host]=1
      results+=("$host")
    fi
  fi
}

collect_from_command() {
  local cmd_output
  cmd_output=$1
  while IFS= read -r line; do
    add_host "$line"
  done <<< "$cmd_output"
}

# 1) Live reverse DNS via dig/host/dnsx
if command -v dig >/dev/null 2>&1; then
  collect_from_command "$(dig +short -x "$ip" 2>/dev/null)"
fi

if command -v host >/dev/null 2>&1; then
  collect_from_command "$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $5}')"
fi

if command -v dnsx >/dev/null 2>&1; then
  collect_from_command "$(echo "$ip" | dnsx -ptr -silent 2>/dev/null)"
fi

# Helper for JSON APIs
call_api() {
  local url="$1"
  shift
  curl -m 15 -sS "$url" "$@" 2>/dev/null
}

# 2) Shodan
if [[ -n ${SHODAN_API_KEY:-} ]]; then
  api_resp=$(call_api "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}")
  if [[ -n $api_resp ]]; then
    collect_from_command "$(echo "$api_resp" | jq -r '.hostnames[]?' 2>/dev/null || true)"
  fi
fi

# 3) VirusTotal (current + historical resolutions)
if [[ -n ${vtapi:-} ]]; then
  api_resp=$(call_api "https://www.virustotal.com/api/v3/ip_addresses/${ip}/resolutions?limit=40" -H "x-apikey: ${vtapi}")
  if [[ -n $api_resp ]]; then
    collect_from_command "$(echo "$api_resp" | jq -r '.data[].attributes.host_name // empty' 2>/dev/null || true)"
  fi
fi

# 4) SecurityTrails (current + history)
if [[ -n ${securitytrailsapi:-} ]]; then
  api_resp=$(call_api "https://api.securitytrails.com/v1/ips/${ip}" -H "APIKEY: ${securitytrailsapi}")
  if [[ -n $api_resp ]]; then
    collect_from_command "$(echo "$api_resp" | jq -r '.current.hostnames[]?, .historic[].hostname? // empty' 2>/dev/null || true)"
  fi
fi

# 5) ipinfo reverse hostname
if [[ -n ${ipinfoapi:-} ]]; then
  api_resp=$(call_api "https://ipinfo.io/${ip}/json?token=${ipinfoapi}")
  if [[ -n $api_resp ]]; then
    collect_from_command "$(echo "$api_resp" | jq -r '.hostname // empty' 2>/dev/null || true)"
  fi
fi

# 6) PassiveTotal (RiskIQ) reverse DNS if credentials exist
if [[ -n ${riskiquser:-} && -n ${riskiqkey:-} ]]; then
  api_resp=$(call_api "https://api.passivetotal.org/v2/dns/passive" -u "${riskiquser}:${riskiqkey}" -H 'Content-Type: application/json' --data "{\"query\":\"${ip}\"}")
  if [[ -n $api_resp ]]; then
    collect_from_command "$(echo "$api_resp" | jq -r '.results[]?.value // empty' 2>/dev/null || true)"
  fi
fi

# 7) ip.thc.org reverse DNS lookup
api_resp=$(call_api "https://ip.thc.org/${ip}?nocolor=1&noheader=1")
if [[ -n $api_resp ]]; then
  collect_from_command "$api_resp"
fi

# Output unique hostnames only
printf '%s\n' "${results[@]}"
