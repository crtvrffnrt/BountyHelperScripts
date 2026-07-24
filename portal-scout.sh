#!/usr/bin/env bash

# Find publicly reachable VPN, firewall, router, gateway, and appliance portals.
# Runtime state is kept in shell memory and pipes. No logs or work files are made.

set -uo pipefail

SCRIPT_NAME=${0##*/}
INPUT_FILE=""
QUICK=0
VERBOSE=0
USE_HOSTNAMES=1
USE_NUCLEI=1
TOP_PORTS=1000
NAABU_RATE=2500
HTTP_RATE=200
HTTP_WORKERS=32
DNS_WORKERS=16
HTTP_TIMEOUT=5

# These are scanned in addition to the top-port set. The small forced set is
# independently HTTP-probed so a filtered/missed SYN response does not hide the
# most common portal ports.
FALLBACK_PORTS="80,443,4443,7443,8000,8080,8443,9443,10443"
FORCE_PORTS="80,443,8443,9443"
EXTRA_PORTS="81,82,83,84,85,88,280,300,591,593,631,800,801,808,880,981,1010,1080,1311,2082,2083,2086,2087,2095,2096,3000,3001,3128,3333,3443,4000,4100,4118,4343,4443,4567,4711,4712,5000,5001,5104,5443,5800,5988,5989,6080,6443,7000,7001,7070,7080,7443,7777,8000-8010,8042,8060,8069,8080-8091,8180,8200,8222,8243,8280,8281,8333,8443,8500,8530,8531,8800,8834,8880,8888,8899,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,10000,10443,12443,18080,18443,20000,28017,30000,32768,44443,50000,60443"

usage() {
  cat >&2 <<EOF
Usage: $SCRIPT_NAME [options] IP_FILE

Options:
  --quick          Scan only common/VPN/admin ports
  -v, --verbose    Show timestamped phase and result details on stderr
  --top-ports N    naabu top-port set: 100 or 1000 (default: 1000)
  --naabu-rate N   Global naabu rate (default: 2500)
  --http-rate N    Global httpx request rate (default: 200)
  --workers N      Concurrent portal checks (default: 32)
  --dns-workers N  Concurrent hostname lookups (default: 16)
  --timeout N      Per-request timeout (default: 5 seconds)
  --no-hostnames   Skip hostname enrichment
  --nuclei         Add Nuclei exposed-panel confirmation (default; slower)
  --no-nuclei      Disable Nuclei confirmation
  -h, --help       Show this help

Default terminal output is one cyclic # progress line, one blank line, then URLs.
When stdout is redirected, only URL lines are written.
EOF
}

die() { printf '[fatal] %s\n' "$*" >&2; exit 1; }
is_uint() { [[ ${1:-} =~ ^[0-9]+$ ]]; }
detail() { ((VERBOSE)) && printf '[%(%H:%M:%S)T] %s\n' -1 "$*" >&2 || true; }

INDICATOR_PID=""
indicator_start() {
  [[ -t 1 ]] || return 0
  (
    local width=28 n=1 bar
    while :; do
      printf -v bar '%*s' "$n" ''
      bar=${bar// /#}
      printf '\r%-28s' "$bar"
      ((n++)); ((n > width)) && n=1
      sleep 0.20
    done
  ) &
  INDICATOR_PID=$!
}
indicator_stop() {
  if [[ -n ${INDICATOR_PID:-} ]]; then
    kill "$INDICATOR_PID" 2>/dev/null || true
    wait "$INDICATOR_PID" 2>/dev/null || true
    INDICATOR_PID=""
    printf '\r%-28s\n\n' '############################'
  fi
}
trap 'indicator_stop' EXIT INT TERM

while (($#)); do
  case "$1" in
    --quick) QUICK=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    --top-ports) (($# >= 2)) || die '--top-ports needs a value'; TOP_PORTS=$2; shift 2 ;;
    --naabu-rate) (($# >= 2)) || die '--naabu-rate needs a value'; NAABU_RATE=$2; shift 2 ;;
    --http-rate) (($# >= 2)) || die '--http-rate needs a value'; HTTP_RATE=$2; shift 2 ;;
    --workers) (($# >= 2)) || die '--workers needs a value'; HTTP_WORKERS=$2; shift 2 ;;
    --dns-workers) (($# >= 2)) || die '--dns-workers needs a value'; DNS_WORKERS=$2; shift 2 ;;
    --timeout) (($# >= 2)) || die '--timeout needs a value'; HTTP_TIMEOUT=$2; shift 2 ;;
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
for value in "$NAABU_RATE" "$HTTP_RATE" "$HTTP_WORKERS" "$DNS_WORKERS" "$HTTP_TIMEOUT"; do
  is_uint "$value" || die 'numeric options must contain positive integers'
  ((value > 0)) || die 'numeric options must be greater than zero'
done
[[ $TOP_PORTS == 100 || $TOP_PORTS == 1000 ]] || die '--top-ports must be 100 or 1000'

required=(naabu httpx curl openssl dig jq rg awk sed sort xargs timeout)
((USE_NUCLEI == 0)) || required+=(nuclei)
for tool in "${required[@]}"; do command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"; done

mapfile -t IPS < <(awk '
  function valid(s,a,i,n) {
    n=split(s,a,"."); if (n != 4) return 0
    for (i=1;i<=4;i++) if (a[i] !~ /^[0-9]+$/ || a[i]<0 || a[i]>255 || (length(a[i])>1 && substr(a[i],1,1)=="0")) return 0
    return 1
  }
  { sub(/\r$/,""); gsub(/^[[:space:]]+|[[:space:]]+$/ ,""); if ($0!="" && $0!~/^#/ && valid($0)) print }
' "$INPUT_FILE" | sort -u)
((${#IPS[@]})) || die 'the input did not contain a valid IPv4 address'

SHODAN_KEY=${SHODANAPI:-${SHODAN_API_KEY:-}}
detail "accepted ${#IPS[@]} unique IPv4 target(s); no work files or logs"
indicator_start

scan_naabu() {
  local mode=$1
  local -a common=(-rate "$NAABU_RATE" -c 100 -retries 1 -timeout 1000 -Pn -scan-type s -silent -no-color -disable-update-check)
  case "$mode" in
    top) printf '%s\n' "${IPS[@]}" | naabu "${common[@]}" -top-ports "$TOP_PORTS" ;;
    extra) printf '%s\n' "${IPS[@]}" | naabu "${common[@]}" -port "$EXTRA_PORTS" ;;
    quick) printf '%s\n' "${IPS[@]}" | naabu "${common[@]}" -port "$FALLBACK_PORTS" ;;
  esac
}

detail "port discovery: -Pn SYN scan, rate $NAABU_RATE, concurrency 100, one retry"
if ((QUICK)); then
  NAABU_OUTPUT=$(scan_naabu quick 2>/dev/null || true)
else
  # The independent top-port and appliance-port passes run concurrently.
  NAABU_OUTPUT=$( { scan_naabu top & scan_naabu extra & wait; } 2>/dev/null || true)
fi

# Force only the highest-value web ports. httpx chooses TLS first and falls back
# to cleartext, avoiding the old two-request-per-socket behavior.
SOCKET_TEXT=$(
  {
    printf '%s\n' "$NAABU_OUTPUT"
    for ip in "${IPS[@]}"; do
      IFS=, read -ra forced <<< "$FORCE_PORTS"
      for port in "${forced[@]}"; do printf '%s:%s\n' "$ip" "$port"; done
    done
  } | sed $'s/\033\\[[0-9;]*m//g' | rg '^[0-9]+(\.[0-9]+){3}:[0-9]+$' | sort -u
)
mapfile -t SOCKETS <<< "$SOCKET_TEXT"
detail "port discovery complete: ${#SOCKETS[@]} discovered/forced socket(s)"

detail "HTTP protocol detection: rate $HTTP_RATE, automatic HTTPS-to-HTTP fallback"
LIVE_TEXT=$(printf '%s\n' "${SOCKETS[@]}" | httpx -silent -no-color -threads 100 \
  -rate-limit "$HTTP_RATE" -timeout "$HTTP_TIMEOUT" -retries 1 -disable-update-check 2>/dev/null || true)
mapfile -t DIRECT_BASES < <(printf '%s\n' "$LIVE_TEXT" | rg '^https?://' | sort -u)
detail "HTTP protocol detection complete: ${#DIRECT_BASES[@]} live IP URL(s)"

url_host() {
  local rest=${1#*://}; rest=${rest%%/*}; rest=${rest##*@}; printf '%s\n' "${rest%%:*}"
}
url_origin() { local scheme=${1%%://*} rest=${1#*://}; printf '%s://%s\n' "$scheme" "${rest%%/*}"; }
canonicalize_url() {
  local url=${1//$'\r'/}; url=${url//$'\n'/}; url=${url%#}
  [[ $url =~ ^https://([^/:]+):443(/.*)?$ ]] && { printf 'https://%s%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]:-}"; return; }
  [[ $url =~ ^http://([^/:]+):80(/.*)?$ ]] && { printf 'http://%s%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]:-}"; return; }
  printf '%s\n' "$url"
}
export -f url_host

discover_names() {
  local ip=$1 rev ptr base hostport
  rev=$(awk -F. '{print $4"."$3"."$2"."$1".in-addr.arpa"}' <<< "$ip")
  dig +time=1 +tries=1 +short -x "$ip" 2>/dev/null | sed 's/\.$//' | awk -v ip="$ip" '{print ip"\t"tolower($0)}'

  # Passive sources run concurrently and have short hard limits.
  {
    curl -fsS --connect-timeout 2 --max-time 4 "https://api.hackertarget.com/reverseiplookup/?q=$ip" 2>/dev/null |
      awk -v ip="$ip" '{print ip"\t"tolower($0)}' &
    curl -fsS --connect-timeout 2 --max-time 4 "https://urlscan.io/api/v1/search/?q=ip:$ip&size=20" 2>/dev/null |
      jq -r --arg ip "$ip" '.results[]? | [$ip, (.page.domain // .page.hostname // .task.domain // empty)] | @tsv' 2>/dev/null &
    if [[ -n ${SHODAN_KEY:-} ]]; then
      curl -fsS --connect-timeout 2 --max-time 4 "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_KEY" 2>/dev/null |
        jq -r --arg ip "$ip" '.hostnames[]?, .domains[]? | [$ip, .] | @tsv' 2>/dev/null &
    fi
    wait
  }

  while IFS= read -r base; do
    [[ $(url_host "$base") == "$ip" && $base == https://* ]] || continue
    hostport=${base#https://}; hostport=${hostport%%/*}
    timeout 4s openssl s_client -connect "$hostport" -servername "$ip" </dev/null 2>/dev/null |
      openssl x509 -noout -ext subjectAltName 2>/dev/null |
      rg -o 'DNS:[^,[:space:]]+' | sed 's/^DNS://' |
      awk -v ip="$ip" '{print ip"\t"tolower($0)}' || true
  done <<< "${DIRECT_TEXT:-}"
}
export -f discover_names
export SHODAN_KEY

HOST_MAP_TEXT=""
if ((USE_HOSTNAMES)); then
  detail "hostname enrichment: $DNS_WORKERS parallel workers, 4-second passive-source ceiling"
  DIRECT_TEXT=$(printf '%s\n' "${DIRECT_BASES[@]}"); export DIRECT_TEXT
  RAW_NAMES=$(printf '%s\n' "${IPS[@]}" | xargs -r -P "$DNS_WORKERS" -n 1 bash -c 'discover_names "$1"' _ 2>/dev/null || true)
  CANDIDATE_NAMES=$(printf '%s\n' "$RAW_NAMES" |
    awk -F '\t' 'NF==2 {gsub(/^[[:space:]]+|[[:space:].]+$/,"",$2); print $1"\t"tolower($2)}' |
    rg $'^[0-9]+(\.[0-9]+){3}\t[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$' | sort -u)
  validate_name() {
    local ip=$1 host=$2
    dig +time=1 +tries=1 +short A "$host" 2>/dev/null | rg -Fxq -- "$ip" && printf '%s\t%s\n' "$ip" "$host"
  }
  export -f validate_name
  HOST_MAP_TEXT=$(while IFS=$'\t' read -r ip host; do printf '%s\0%s\0' "$ip" "$host"; done <<< "$CANDIDATE_NAMES" |
    xargs -0 -r -P "$DNS_WORKERS" -n 2 bash -c 'validate_name "$1" "$2"' _ | sort -u)
fi
mapfile -t HOST_MAP <<< "$HOST_MAP_TEXT"
detail "hostname enrichment complete: $(printf '%s\n' "$HOST_MAP_TEXT" | sed '/^$/d' | wc -l) verified relationship(s)"

HOST_URL_TEXT=$( 
  if [[ -n $HOST_MAP_TEXT ]]; then
    while IFS=$'\t' read -r ip host; do
      for base in "${DIRECT_BASES[@]}"; do
        [[ $(url_host "$base") == "$ip" ]] || continue
        scheme=${base%%://*}; authority=${base#*://}; port=${authority##*:}
        [[ $authority == *:* ]] || { [[ $scheme == https ]] && port=443 || port=80; }
        printf '%s://%s:%s\n' "$scheme" "$host" "$port"
      done
    done <<< "$HOST_MAP_TEXT" | sort -u |
      httpx -silent -no-color -threads 100 -rate-limit "$HTTP_RATE" -timeout "$HTTP_TIMEOUT" -retries 1 -disable-update-check 2>/dev/null || true
  fi
)
mapfile -t ALL_BASES < <({ printf '%s\n' "${DIRECT_BASES[@]}"; printf '%s\n' "$HOST_URL_TEXT"; } | rg '^https?://' | sort -u)
detail "portal classification: ${#ALL_BASES[@]} base URL(s), $HTTP_WORKERS workers"

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
  local ip=$1 requested=$2 current=$2 response code location next ch nh i origin confidence vendor
  for ((i=0;i<4;i++)); do
    response=$(curl -ksS --compressed --connect-timeout 3 --max-time "$HTTP_TIMEOUT" --max-filesize 1048576 \
      -A 'Mozilla/5.0 portal-scout/2.0' -D - -o - -w $'\n__PORTAL_SCOUT_CODE__:%{http_code}' "$current" 2>/dev/null) || true
    code=${response##*__PORTAL_SCOUT_CODE__:}; [[ $code =~ ^[0-9]{3}$ && $code != 000 ]] || return 0
    response=${response%$'\n__PORTAL_SCOUT_CODE__:'*}
    if [[ $code =~ ^30[12378]$ ]]; then
      location=$(awk 'BEGIN{IGNORECASE=1} /^Location:/ {sub(/^[^:]+:[[:space:]]*/,""); sub(/\r$/,""); x=$0} END{print x}' <<< "$response")
      [[ -n $location ]] || break
      next=$(resolve_location "$current" "$location"); ch=$(url_host "$current"); nh=$(url_host "$next")
      if [[ $nh != "$ch" ]]; then dig +time=1 +tries=1 +short A "$nh" 2>/dev/null | rg -Fxq -- "$ip" || break; fi
      current=${next%%#*}; continue
    fi
    break
  done

  rg -qi '<title[^>]*>[[:space:]]*(400 Bad Request|403 Forbidden|404 Not Found|405 Method Not Allowed)|<h1[^>]*>[[:space:]]*(Bad Request|Forbidden|Not Found)' <<< "$response" && return 0
  rg -qi "com[.]atlassian[.]jira|atlassian-token|wp-login[.]php|content=['\"]Grafana|Jenkins-Crumb|gon[.]gitlab_url" <<< "$response" && return 0

  local strong=0 product=0 auth=0 network=0 generic=0
  rg -qi 'SVPNCOOKIE|/remote/logincheck|FortiClient|sslvpn-portal|Barracuda|WatchGuard|Firebox|Sophos([ -]+(Firewall|UTM|User Portal))?|Cyberoam|SonicWall|GlobalProtect|Pulse Secure|Ivanti Connect Secure|Juniper Networks Secure Access|Citrix Gateway|NetScaler Gateway|AnyConnect|[+/]CSCOE[+/]|WebVPN|Mobile Access Portal|BIG-IP|OpenVPN Connect|Vigor Login Page|DrayTek|RouterOS|MikroTik|pfSense|OPNsense|Zyxel.*(Firewall|USG)|UniFi Network|Check Point|CheckPoint|Endpoint Security VPN' <<< "$response" && strong=1
  rg -qi 'Fortinet|FortiGate|Barracuda|WatchGuard|Sophos|Cyberoam|SonicWall|Palo Alto|GlobalProtect|Pulse|Ivanti|Juniper|Citrix|NetScaler|Cisco|Check Point|CheckPoint|F5|OpenVPN|DrayTek|MikroTik|RouterOS|pfSense|OPNsense|Zyxel|Huawei|Netgear|D-Link|TP-Link|Ubiquiti|UniFi|Aruba|Meraki' <<< "$response" && product=1
  rg -qi "type[[:space:]]*=[[:space:]]*['\"]?password|name[[:space:]]*=[[:space:]]*['\"][^'\"]*(password|passwd)|current-password|sign[ -]*in|user[ _-]*name" <<< "$response" && auth=1
  rg -qi 'SSL[- _]?VPN|VPN Portal|VPN Login|Virtual Office|Clientless Access|Remote Access|remote/login|sslvpn|webvpn|user portal|global-protect|dana-na|my[.]policy' <<< "$response" && network=1
  rg -qi '<title[^>]*>[^<]*(login|logon|sign[ -]?in|authentication|admin|router|firewall|gateway)|administration|management (console|interface|portal)' <<< "$response" && generic=1
  ((strong || (product && (auth || network || generic)))) && confidence=high
  [[ -n ${confidence:-} ]] || ((auth && generic)) && confidence=uncertain
  [[ -n ${confidence:-} ]] || return 0
  [[ $code == 404 && $strong == 0 ]] && return 0

  origin=$(url_origin "$current")
  if rg -qi 'SVPNCOOKIE|/remote/logincheck|FortiClient|sslvpn-portal|Fortinet|FortiGate' <<< "$response"; then vendor=fortinet; current="$origin/remote/login?lang=en"
  elif rg -qi 'Check Point|CheckPoint|Endpoint Security VPN|Mobile Access Portal' <<< "$response"; then vendor=checkpoint; current="$origin/sslvpn/Login/Login"
  elif rg -qi 'Barracuda' <<< "$response"; then vendor=barracuda; current="$origin/portal/index.html"
  elif rg -qi 'Vigor Login Page|DrayTek' <<< "$response"; then vendor=draytek; current="$origin/weblogin.htm"
  fi
  printf '%s\t%s\n' "$confidence" "$(canonicalize_url "$current")"
}

export HTTP_TIMEOUT
export -f url_origin canonicalize_url resolve_location fetch_classify

# Schedule individual base/path checks so the full worker pool is used even
# when only a handful of hosts are live.
CANDIDATES=$(
  {
    for base in "${ALL_BASES[@]}"; do
      host=$(url_host "$base")
      ip=$(dig +time=1 +tries=1 +short A "$host" 2>/dev/null | head -1)
      [[ -n $ip ]] || ip=$host
      for path in / '/remote/login?lang=en' /portal/index.html /weblogin.htm /login /admin/ /userportal/ /sslvpn/ /vpn/ /webvpn.html /+CSCOE+/logon.html /dana-na/auth/url_default/welcome.cgi /global-protect/login.esp /my.policy /tmui/login.jsp /webfig/ /cgi-bin/luci; do
        printf '%s\0%s\0' "$ip" "${base%/}$path"
      done
    done
  } | xargs -0 -r -P "$HTTP_WORKERS" -n 2 bash -c 'fetch_classify "$1" "$2"' _ 2>/dev/null || true
)

if ((USE_NUCLEI)); then
  detail 'Nuclei exposed-panels confirmation enabled'
  PANEL_PORTS='80,443,4443,8000,8080,8443,9443,10443,12443,20443'
  PANEL_TARGETS=$(printf '%s\n' "${IPS[@]}" | naabu -silent -Pn -rate 3000 -p "$PANEL_PORTS" 2>/dev/null || true)
  NUCLEI_RESULTS=$(printf '%s\n' "$PANEL_TARGETS" | httpx -silent -nf -timeout 8 -retries 1 2>/dev/null |
    timeout 120s nuclei -silent -t "$HOME/nuclei-templates/http/exposed-panels/" -jsonl -no-color 2>/dev/null |
    jq -r 'select(. != null) | "high\t" + (.["matched-at"] // .matched_at // .url // .host // empty)' 2>/dev/null || true)
  CANDIDATES+=$'\n'"$NUCLEI_RESULTS"
fi

# Keep one best login URL per scheme/host. Path and port probes remain broad,
# but one appliance must not produce one result for every matching asset path.
RESULTS=$(printf '%s\n' "$CANDIDATES" | awk -F '\t' '
  function authority(u, x,a,h) {
    split(u,x,"://"); split(x[2],a,"/"); h=a[1]
    if (h ~ /^\[/) { sub(/\]:[0-9]+$/, "]", h); return h }
    sub(/:[0-9]+$/, "", h); return h
  }
  $1~/^(high|uncertain)$/ && $2~/^https?:\/\// {
    key=authority($2); rank=($1=="high"?2:1)
    if ($2 ~ /\/sslvpn\/Login\/Login|\/remote\/login/i) rank+=3
    else if ($2 ~ /\/(login|logon|portal|userportal)/i) rank+=2
    if (!(key in best) || rank>score[key]) { best[key]=$2; score[key]=rank }
  }
  END { for(k in best) print score[k]"\t"best[k] }
' | sort -t $'\t' -k2,2)
COUNT=$(printf '%s\n' "$RESULTS" | sed '/^$/d' | wc -l)
detail "complete: $COUNT unique portal URL(s)"
indicator_stop
trap - EXIT INT TERM

while IFS=$'\t' read -r rank url; do
  [[ -n ${url:-} ]] || continue
  if [[ -t 1 ]]; then
    [[ $rank == 2 ]] && colour=$'\033[1;91m' || colour=$'\033[97m'
    printf '%s\033]8;;%s\033\\%s\033]8;;\033\\\033[0m\n' "$colour" "$url" "$url"
  else
    printf '%s\n' "$url"
  fi
done <<< "$RESULTS"
