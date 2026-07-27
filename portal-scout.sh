#!/usr/bin/env bash

# Find publicly reachable VPN, firewall, router, gateway, and appliance portals.
# Each IP is a bounded job so an unresponsive target cannot hold up the list.

set -uo pipefail

SCRIPT_NAME=${0##*/}
INPUT_FILE=""
VERBOSE=0
USE_HOSTNAMES=1
USE_NUCLEI=0
HTTP_TIMEOUT=5
IP_TIMEOUT=""

FALLBACK_PORTS="80,443,4443,7443,8000,8080,8443,9443,10443"
# Probe these directly even when SYN discovery misses or filters a response.
FORCE_PORTS="80,443,8443,9443,10443"
EXTRA_PORTS="81,82,83,84,85,88,280,300,591,593,631,800,801,808,880,981,1010,1080,1311,2082,2083,2086,2087,2095,2096,3000,3001,3128,3333,3443,4000,4100,4118,4343,4443,4567,4711,4712,5000,5001,5104,5443,5800,5988,5989,6080,6443,7000,7001,7070,7080,7443,7777,8000-8010,8042,8060,8069,8080-8091,8180,8200,8222,8243,8280,8281,8333,8443,8500,8530,8531,8800,8834,8880,8888,8899,8983,9000,9001,9043,9060,9080,9090,9200,9443,10000,10443,12443,18080,18443,20000,28017,30000,32768,44443,50000,60443"

usage() {
  cat >&2 <<EOF
Usage: $SCRIPT_NAME [options] IP_FILE

Options:
  -v, --verbose       Show phase details on stderr
  --timeout N         Per HTTP request timeout (default: 5 seconds)
  --ip-timeout N      Hard timeout per IP, in seconds (default depends on list size)
  --no-hostnames      Skip hostname enrichment
  --nuclei            Add bounded Nuclei panel confirmation (slower)
  --no-nuclei         Disable Nuclei confirmation (the default)
  -h, --help          Show this help

Normal scanning automatically scales with the number of IPs:
  1-12: detailed scan, maximum 180 seconds/IP
  13-99: balanced scan, maximum 120 seconds/IP
  100+: focused scan, maximum 60 seconds/IP
EOF
}

die() { printf '[fatal] %s\n' "$*" >&2; exit 1; }
is_uint() { [[ ${1:-} =~ ^[0-9]+$ ]]; }
detail() { ((VERBOSE)) && printf '[%(%H:%M:%S)T] %s\n' -1 "$*" >&2 || true; }

while (($#)); do
  case "$1" in
    -v|--verbose) VERBOSE=1; shift ;;
    --timeout) (($# >= 2)) || die '--timeout needs a value'; HTTP_TIMEOUT=$2; shift 2 ;;
    --ip-timeout) (($# >= 2)) || die '--ip-timeout needs a value'; IP_TIMEOUT=$2; shift 2 ;;
    --no-hostnames) USE_HOSTNAMES=0; shift ;;
    --nuclei) USE_NUCLEI=1; shift ;;
    --no-nuclei) USE_NUCLEI=0; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown option: $1" ;;
    *) [[ -z $INPUT_FILE ]] || die 'only one input file may be supplied'; INPUT_FILE=$1; shift ;;
  esac
done

[[ -n $INPUT_FILE && -r $INPUT_FILE ]] || { usage; exit 1; }
is_uint "$HTTP_TIMEOUT" && ((HTTP_TIMEOUT > 0)) || die '--timeout must be a positive integer'
[[ -z $IP_TIMEOUT ]] || { is_uint "$IP_TIMEOUT" && ((IP_TIMEOUT > 0)) || die '--ip-timeout must be a positive integer'; }

required=(naabu httpx curl openssl dig jq rg awk sed sort xargs timeout)
((USE_NUCLEI == 0)) || required+=(nuclei)
for tool in "${required[@]}"; do command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"; done

mapfile -t IPS < <(awk '
  function valid(s,a,i,n) { n=split(s,a,"."); if (n != 4) return 0; for (i=1;i<=4;i++) if (a[i] !~ /^[0-9]+$/ || a[i]<0 || a[i]>255 || (length(a[i])>1 && substr(a[i],1,1)=="0")) return 0; return 1 }
  { sub(/\r$/,""); gsub(/^[[:space:]]+|[[:space:]]+$/ ,""); if ($0!="" && $0!~/^#/ && valid($0)) print }
' "$INPUT_FILE" | sort -u)
((${#IPS[@]})) || die 'the input did not contain a valid IPv4 address'

TOTAL=${#IPS[@]}
if ((TOTAL <= 12)); then PROFILE=detailed; DEFAULT_IP_TIMEOUT=180
elif ((TOTAL <= 99)); then PROFILE=balanced; DEFAULT_IP_TIMEOUT=120
else PROFILE=focused; DEFAULT_IP_TIMEOUT=60
fi
IP_TIMEOUT=${IP_TIMEOUT:-$DEFAULT_IP_TIMEOUT}
SHODAN_KEY=${SHODANAPI:-${SHODAN_API_KEY:-}}
detail "${TOTAL} IPs: $PROFILE profile, hard limit ${IP_TIMEOUT}s/IP"

# Keep scan progress out of redirected URL output.
if [[ -t 1 ]]; then exec 3>&1; else exec 3>/dev/null; fi
progress() {
  local current=$1 ip=$2 width=28 filled bar empty
  filled=$((current * width / TOTAL)); ((filled == 0)) && filled=1
  printf -v bar '%*s' "$filled" ''; bar=${bar// /#}
  printf -v empty '%*s' "$((width - filled))" ''
  printf '\r[%s%s] (%d/%d) %s' "$bar" "$empty" "$current" "$TOTAL" "$ip" >&3
}

url_host() { local rest=${1#*://}; rest=${rest%%/*}; rest=${rest##*@}; printf '%s\n' "${rest%%:*}"; }
url_origin() { local scheme=${1%%://*} rest=${1#*://}; printf '%s://%s\n' "$scheme" "${rest%%/*}"; }
canonicalize_url() {
  local url=${1//$'\r'/}; url=${url//$'\n'/}; url=${url%#}
  [[ $url =~ ^https://([^/:]+):443(/.*)?$ ]] && { printf 'https://%s%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]:-}"; return; }
  [[ $url =~ ^http://([^/:]+):80(/.*)?$ ]] && { printf 'http://%s%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]:-}"; return; }
  printf '%s\n' "$url"
}
resolve_location() {
  local current=$1 location=${2//$'\r'/} scheme origin dir
  case "$location" in
    http://*|https://*) printf '%s\n' "$location" ;;
    //*) scheme=${current%%://*}; printf '%s:%s\n' "$scheme" "$location" ;;
    /*) origin=$(url_origin "$current"); printf '%s%s\n' "$origin" "$location" ;;
    \#*) printf '%s%s\n' "${current%%#*}" "$location" ;;
    *) dir=${current%%\?*}; dir=${dir%/*}; printf '%s/%s\n' "$dir" "$location" ;;
  esac
}

fetch_classify() {
  local ip=$1 requested=$2 current=$2 response code location next ch nh i origin confidence=""
  for ((i=0;i<3;i++)); do
    response=$(curl -ksS --compressed --connect-timeout 3 --max-time "$HTTP_TIMEOUT" --max-filesize 1048576 -A 'Mozilla/5.0 portal-scout/3.0' -D - -o - -w $'\n__PORTAL_SCOUT_CODE__:%{http_code}' "$current" 2>/dev/null) || true
    code=${response##*__PORTAL_SCOUT_CODE__:}; [[ $code =~ ^[0-9]{3}$ && $code != 000 ]] || return 0
    response=${response%$'\n__PORTAL_SCOUT_CODE__:'*}
    if [[ $code =~ ^30[12378]$ ]]; then
      location=$(awk 'BEGIN{IGNORECASE=1} /^Location:/ {sub(/^[^:]+:[[:space:]]*/,""); sub(/\r$/,""); x=$0} END{print x}' <<< "$response")
      [[ -n $location ]] || break; next=$(resolve_location "$current" "$location"); ch=$(url_host "$current"); nh=$(url_host "$next")
      [[ $nh == "$ch" || $nh == "$ip" ]] || dig +time=1 +tries=1 +short A "$nh" 2>/dev/null | rg -Fxq -- "$ip" || break
      current=${next%%#*}; continue
    fi
    break
  done
  rg -qi '<title[^>]*>[[:space:]]*(400 Bad Request|403 Forbidden|404 Not Found|405 Method Not Allowed)|<h1[^>]*>[[:space:]]*(Bad Request|Forbidden|Not Found)' <<< "$response" && return 0
  rg -qi "com[.]atlassian[.]jira|atlassian-token|wp-login[.]php|content=['\"]Grafana|Jenkins-Crumb|gon[.]gitlab_url" <<< "$response" && return 0
  local strong=0 product=0 auth=0 network=0 generic=0
  # Modern FortiOS pages identify themselves with these UI markers rather than
  # the older /remote/logincheck or SVPNCOOKIE strings.
  rg -qi 'SVPNCOOKIE|/remote/logincheck|FortiClient|sslvpn-portal|ftnt-fortinet-grid|top[.]location.*remote/login|Barracuda|WatchGuard|Firebox|Sophos([ -]+(Firewall|UTM|User Portal))?|Cyberoam|SonicWall|GlobalProtect|Pulse Secure|Ivanti Connect Secure|Juniper Networks Secure Access|Citrix Gateway|NetScaler Gateway|AnyConnect|[+/]CSCOE[+/]|WebVPN|Mobile Access Portal|BIG-IP|OpenVPN Connect|Vigor Login Page|DrayTek|RouterOS|pfSense|OPNsense|Zyxel.*(Firewall|USG)|UniFi Network' <<< "$response" && strong=1
  rg -qi 'Fortinet|FortiGate|Barracuda|WatchGuard|Sophos|Cyberoam|SonicWall|Palo Alto|GlobalProtect|Pulse|Ivanti|Juniper|Citrix|NetScaler|Cisco|Check Point|F5|OpenVPN|DrayTek|MikroTik|RouterOS|pfSense|OPNsense|Zyxel|Huawei|Netgear|D-Link|TP-Link|Ubiquiti|UniFi|Aruba|Meraki' <<< "$response" && product=1
  rg -qi "type[[:space:]]*=[[:space:]]*['\"]?password|name[[:space:]]*=[[:space:]]*['\"][^'\"]*(password|passwd)|current-password|sign[ -]*in|user[ _-]*name" <<< "$response" && auth=1
  rg -qi 'SSL[- _]?VPN|VPN Portal|VPN Login|Virtual Office|Clientless Access|Remote Access|remote/login|sslvpn|webvpn|user portal|global-protect|dana-na|my[.]policy' <<< "$response" && network=1
  rg -qi '<title[^>]*>[^<]*(login|logon|sign[ -]?in|authentication|admin|router|firewall|gateway)|administration|management (console|interface|portal)' <<< "$response" && generic=1
  if ((strong || (product && (auth || network || generic)) || (network && auth))); then
    confidence=high
  elif ((auth && generic)); then
    confidence=uncertain
  else
    return 0
  fi
  origin=$(url_origin "$current")
  # Preserve the URL that actually identified the portal.  In particular,
  # FortiGate SSL-VPN commonly serves its identifying JavaScript at the root.
  if rg -qi 'Barracuda' <<< "$response"; then current="$origin/portal/index.html#Logon"
  elif rg -qi 'Vigor Login Page|DrayTek' <<< "$response"; then current="$origin/weblogin.htm"; fi
  printf '%s\t%s\n' "$confidence" "$(canonicalize_url "$current")"
}

scan_target() {
  local ip=$1 profile=$2 port_output sockets live host_names host_urls all_bases paths max_bases workers rate
  case "$profile" in
    detailed) port_output=$( { printf '%s\n' "$ip" | naabu -rate 1500 -c 50 -retries 1 -timeout 1000 -Pn -scan-type s -silent -no-color -disable-update-check -top-ports 1000; printf '%s\n' "$ip" | naabu -rate 1500 -c 50 -retries 1 -timeout 1000 -Pn -scan-type s -silent -no-color -disable-update-check -port "$EXTRA_PORTS"; } 2>/dev/null || true); paths="/ /remote/login?lang=en /portal/index.html /weblogin.htm /login /login?redir=%2F /admin/ /userportal/ /sslvpn/ /vpn/ /webvpn.html /+CSCOE+/logon.html /dana-na/auth/url_default/welcome.cgi /global-protect/login.esp /my.policy /tmui/login.jsp /webfig/ /cgi-bin/luci"; max_bases=60; workers=24; rate=100 ;;
    balanced) port_output=$(printf '%s\n' "$ip" | naabu -rate 2200 -c 50 -retries 0 -timeout 800 -Pn -scan-type s -silent -no-color -disable-update-check -port "$FALLBACK_PORTS,$EXTRA_PORTS" 2>/dev/null || true); paths="/ /remote/login?lang=en /portal/index.html /login /login?redir=%2F /admin/ /sslvpn/ /vpn/ /global-protect/login.esp"; max_bases=25; workers=16; rate=120 ;;
    focused) port_output=$(printf '%s\n' "$ip" | naabu -rate 3000 -c 50 -retries 0 -timeout 600 -Pn -scan-type s -silent -no-color -disable-update-check -port "$FALLBACK_PORTS" 2>/dev/null || true); paths="/ /remote/login?lang=en /login /login?redir=%2F /sslvpn/"; max_bases=12; workers=10; rate=150 ;;
  esac
  sockets=$({ printf '%s\n' "$port_output"; for port in ${FORCE_PORTS//,/ }; do printf '%s:%s\n' "$ip" "$port"; done; } | sed $'s/\033\\[[0-9;]*m//g' | rg '^[0-9]+(\.[0-9]+){3}:[0-9]+$' | sort -u)
  live=$(printf '%s\n' "$sockets" | httpx -silent -no-color -threads 50 -rate-limit "$rate" -timeout "$HTTP_TIMEOUT" -retries 0 -disable-update-check 2>/dev/null | rg '^https?://' | sort -u | head -n "$max_bases" || true)
  [[ -n $live ]] || return 0
  host_urls=""
  if ((USE_HOSTNAMES)) && [[ $profile == detailed ]]; then
    host_names=$( {
      dig +time=1 +tries=1 +short -x "$ip" 2>/dev/null | sed 's/\.$//'
      {
        curl -fsS --connect-timeout 2 --max-time 4 "https://api.hackertarget.com/reverseiplookup/?q=$ip" 2>/dev/null
        curl -fsS --connect-timeout 2 --max-time 4 "https://urlscan.io/api/v1/search/?q=ip:$ip&size=20" 2>/dev/null | jq -r '.results[]? | .page.domain // .page.hostname // .task.domain // empty' 2>/dev/null
        [[ -z ${SHODAN_KEY:-} ]] || curl -fsS --connect-timeout 2 --max-time 4 "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_KEY" 2>/dev/null | jq -r '.hostnames[]?, .domains[]?' 2>/dev/null
      } &
      while IFS= read -r base; do [[ $base == https://* ]] || continue; timeout 4s openssl s_client -connect "${base#https://}" -servername "$ip" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | rg -o 'DNS:[^,[:space:]]+' | sed 's/^DNS://'; done <<< "$live"
      wait
    } | tr '[:upper:]' '[:lower:]' | sort -u)
    host_urls=$(while IFS= read -r host; do
      [[ $host =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] || continue
      dig +time=1 +tries=1 +short A "$host" 2>/dev/null | rg -Fxq -- "$ip" || continue
      while IFS= read -r base; do scheme=${base%%://*}; authority=${base#*://}; port=${authority##*:}; [[ $authority == *:* ]] || { [[ $scheme == https ]] && port=443 || port=80; }; printf '%s://%s:%s\n' "$scheme" "$host" "$port"; done <<< "$live"
    done <<< "$host_names" | sort -u | httpx -silent -no-color -threads 20 -rate-limit "$rate" -timeout "$HTTP_TIMEOUT" -retries 0 -disable-update-check 2>/dev/null | rg '^https?://' | sort -u || true)
  fi
  all_bases=$(printf '%s\n%s\n' "$live" "$host_urls" | rg '^https?://' | sort -u | head -n "$max_bases")
  export HTTP_TIMEOUT
  export -f url_host url_origin canonicalize_url resolve_location fetch_classify
  while IFS= read -r base; do for path in $paths; do printf '%s\0%s\0' "$ip" "${base%/}$path"; done; done <<< "$all_bases" | xargs -0 -r -P "$workers" -n 2 bash -c 'fetch_classify "$1" "$2"' _ 2>/dev/null || true
}

export FALLBACK_PORTS FORCE_PORTS EXTRA_PORTS HTTP_TIMEOUT USE_HOSTNAMES SHODAN_KEY
# scan_target is run in a fresh bash process for each IP, so it must receive
# every helper subsequently used by its xargs classifier children.
export -f url_host url_origin canonicalize_url resolve_location fetch_classify scan_target

all_candidates=""
for index in "${!IPS[@]}"; do
  ip=${IPS[index]}; progress "$((index + 1))" "$ip"
  if target_candidates=$(timeout --kill-after=10s "${IP_TIMEOUT}s" bash -c 'scan_target "$@"' _ "$ip" "$PROFILE" 2>/dev/null); then
    all_candidates+=$'\n'"$target_candidates"
  else
    status=$?; detail "$ip stopped after ${IP_TIMEOUT}s (exit $status)"
  fi
done
[[ -t 1 ]] && printf '\n\n' >&3

if ((USE_NUCLEI)) && [[ -n $all_candidates ]]; then
  NUCLEI_EXPOSED_PANELS=${NUCLEI_EXPOSED_PANELS:-"$HOME/nuclei-templates/http/exposed-panels"}
  [[ -d $NUCLEI_EXPOSED_PANELS ]] || die "Nuclei exposed-panels directory not found: $NUCLEI_EXPOSED_PANELS"
  detail 'Nuclei confirmation: exposed-panels templates against candidate origins'
  all_candidates+=$'\n'"$(printf '%s\n' "$all_candidates" |
    awk -F '\t' '$2~/^https?:\/\// {u=$2; if (match(u, /^https?:\/\/[^\/]+/)) print substr(u, RSTART, RLENGTH)}' | sort -u |
    nuclei -t "$NUCLEI_EXPOSED_PANELS" -severity info -rate-limit 50 -concurrency 10 -timeout "$HTTP_TIMEOUT" -retries 0 \
      -jsonl -silent -no-color -disable-update-check 2>/dev/null |
    jq -r '"high\\t" + (."matched-at" // .url // .host // empty)' 2>/dev/null || true)"
fi

results=$(printf '%s\n' "$all_candidates" | awk -F '\t' '$1~/^(high|uncertain)$/ && $2~/^https?:\/\// {rank=($1=="high"?2:1); if(rank>r[$2])r[$2]=rank} END{for(u in r) print r[u]"\t"u}' | sort -t $'\t' -k2,2)
detail "complete: $(printf '%s\n' "$results" | sed '/^$/d' | wc -l) unique portal URL(s)"
while IFS=$'\t' read -r rank url; do
  [[ -n ${url:-} ]] || continue
  if [[ -t 1 ]]; then
    [[ $rank == 2 ]] && colour=$'\033[1;91m' || colour=$'\033[97m'
    printf '%s\033]8;;%s\033\\%s\033]8;;\033\\\033[0m\n' "$colour" "$url" "$url"
  else printf '%s\n' "$url"; fi
done <<< "$results"
