#!/usr/bin/env bash

set -u
set -o pipefail

## minimal logging helper
log_err() {
  if [[ "${DEBUG:-0}" -eq 1 ]]; then
    printf "%s\n" "$*"
  else
    printf "%s\n" "$*" >&2
  fi
}

log_dbg() {
  if [[ "${DEBUG:-0}" -eq 1 ]]; then
    printf "[debug] %s\n" "$*"
  fi
}

usage() {
  cat <<'USAGE'
Usage: ./subtaker.sh -i scope.txt -d target-domainfragments.txt -O table|json|csv [--output out.json] [--debug]
USAGE
}

DEBUG=0
INPUT=""
FRAGMENTS=""
OUT_FORMAT="table"
OUT_FILE=""
DEADCHECK=0
TIMEOUT=10

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i)
      INPUT="$2"
      shift 2
      ;;
    -d)
      FRAGMENTS="$2"
      shift 2
      ;;
    -O)
      OUT_FORMAT="$2"
      shift 2
      ;;
    --output)
      OUT_FILE="$2"
      shift 2
      ;;
    --debug)
      DEBUG=1
      shift
      ;;
    --deadcheck)
      DEADCHECK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log_err "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$INPUT" || -z "$FRAGMENTS" ]]; then
  log_err "Missing required input files."
  usage
  exit 1
fi

if [[ -z "${SHODANAPI:-}" ]]; then
  log_err "SHODANAPI environment variable is not set."
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  log_err "curl not found."
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  log_err "jq not found."
  exit 1
fi

if [[ ! -r "$INPUT" ]]; then
  log_err "Cannot read input file: $INPUT"
  exit 1
fi

if [[ ! -r "$FRAGMENTS" ]]; then
  log_err "Cannot read fragments file: $FRAGMENTS"
  exit 1
fi

case "$OUT_FORMAT" in
  table|json|csv) ;;
  *)
    log_err "Unsupported output format: $OUT_FORMAT"
    exit 1
    ;;
 esac

## load suffix fragments
suffixes=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%%#*}"
  line="${line//[[:space:]]/}"
  [[ -z "$line" ]] && continue
  suffixes+=("${line,,}")
done < "$FRAGMENTS"

is_suffix_match() {
  local host="$1"
  local s
  host="${host%.}"
  host="${host,,}"
  for s in "${suffixes[@]}"; do
    s="${s%.}"
    if [[ "$host" == "$s" || "$host" == *".$s" ]]; then
      return 0
    fi
  done
  return 1
}

## Shodan DNS API helper:
## - Uses curl to fetch JSON for a given endpoint
## - Handles rate limits with exponential backoff
## - Emits errors only when the API fails or throttles repeatedly
shodan_get() {
  local url="$1"
  local attempt=0
  local max_attempts=5
  local delay=1
  local body status

  while (( attempt < max_attempts )); do
    attempt=$((attempt + 1))
    log_dbg "Shodan request (attempt $attempt/$max_attempts): $url"
    ## Capture body and HTTP status in one request to avoid double calls.
    body=$(curl -sS -w "\n%{http_code}" "$url") || {
      log_err "Request failed: $url"
      return 1
    }
    status="${body##*$'\n'}"
    body="${body%$'\n'*}"

    if [[ "$status" == "200" ]]; then
      log_dbg "Shodan response 200 for: $url"
      printf "%s" "$body"
      return 0
    fi

    ## 429 or explicit rate-limit message -> backoff and retry.
    if [[ "$status" == "429" || "$body" == *"rate limit"* ]]; then
      log_dbg "Rate limited (status $status); backing off ${delay}s"
      sleep "$delay"
      delay=$((delay * 2))
      continue
    fi

    log_err "Shodan API error ($status): $url"
    return 1
  done

  log_err "Shodan API rate limit exceeded: $url"
  return 1
}

declare -A reverse_cache
declare -A dedupe

domains=()
subdomains=()
values=()
live_states=()
live_protos=()

add_result() {
  local domain="$1"
  local fqdn="$2"
  local value="$3"
  local key

  key="$domain|$fqdn|$value"
  if [[ -z "${dedupe[$key]:-}" ]]; then
    dedupe[$key]=1
    domains+=("$domain")
    subdomains+=("$fqdn")
    values+=("$value")
    live_states+=("")
    live_protos+=("")
  fi
}

## Live check helper for HTTP/HTTPS
check_live() {
  local host="$1"
  local code=""

  if [[ -z "$host" ]]; then
    printf "dead\t"
    return 0
  fi

  ## HTTPS first
  code=$(curl -k -sS \
    --connect-timeout "$TIMEOUT" \
    --max-time "$TIMEOUT" \
    -o /dev/null \
    -w "%{http_code}" \
    "https://$host" 2>/dev/null) || code=""

  if [[ -n "$code" && "$code" != "000" ]]; then
    printf "live\thttps"
    return 0
  fi

  ## HTTP fallback
  code=$(curl -sS \
    --connect-timeout "$TIMEOUT" \
    --max-time "$TIMEOUT" \
    -o /dev/null \
    -w "%{http_code}" \
    "http://$host" 2>/dev/null) || code=""

  if [[ -n "$code" && "$code" != "000" ]]; then
    printf "live\thttp"
    return 0
  fi

  printf "dead\t"
}

get_reverse_hostnames() {
  local ip="$1"
  local cached
  local res

  if [[ -z "$ip" ]]; then
    log_dbg "Reverse lookup skipped: empty IP"
    return 1
  fi

  cached="${reverse_cache[$ip]:-}"
  if [[ -n "$cached" ]]; then
    log_dbg "Reverse cache hit for $ip -> $cached"
    printf "%s" "$cached"
    return 0
  fi

  log_dbg "Reverse lookup for IP: $ip"
  res=$(shodan_get "https://api.shodan.io/dns/reverse?ips=$ip&key=$SHODANAPI") || {
    reverse_cache[$ip]=""
    return 1
  }

  cached=$(printf "%s" "$res" | jq -r --arg ip "$ip" '.[$ip][]?' | tr '\n' ' ')
  log_dbg "Reverse lookup result for $ip -> $cached"
  reverse_cache[$ip]="$cached"
  printf "%s" "$cached"
}

while IFS= read -r domain || [[ -n "$domain" ]]; do
  domain="${domain%%#*}"
  domain="${domain//[[:space:]]/}"
  [[ -z "$domain" ]] && continue

  log_dbg "Processing domain: $domain"
  resp=$(shodan_get "https://api.shodan.io/dns/domain/$domain?key=$SHODANAPI") || {
    log_err "Skipping domain (unresolved): $domain"
    continue
  }

  if ! printf "%s" "$resp" | jq -e . >/dev/null 2>&1; then
    log_err "Invalid JSON from Shodan for domain: $domain"
    continue
  fi

  log_dbg "Parsed JSON OK for: $domain"

  while IFS=$'\t' read -r sub type value; do
    fqdn="$domain"
    if [[ -n "$sub" ]]; then
      fqdn="$sub.$domain"
    fi

    if [[ "$type" == "CNAME" ]]; then
      log_dbg "CNAME $fqdn -> $value"
      if is_suffix_match "$value"; then
        log_dbg "Matched suffix for $fqdn -> $value"
        add_result "$domain" "$fqdn" "$value"
      else
        log_dbg "No suffix match for $fqdn -> $value"
      fi
    else
      if [[ -z "$value" ]]; then
        log_dbg "A record empty value for $fqdn; skipping"
        continue
      fi
      log_dbg "A record $fqdn -> $value (reverse lookup)"
      hostnames=$(get_reverse_hostnames "$value" || true)
      if [[ -z "$hostnames" ]]; then
        log_dbg "No reverse hostnames for $value"
      fi
      for host in $hostnames; do
        if is_suffix_match "$host"; then
          log_dbg "Matched suffix for $fqdn -> $host"
          add_result "$domain" "$fqdn" "$host"
        fi
      done
    fi
  done < <(printf "%s" "$resp" | jq -r '.data[] | select(.type=="A" or .type=="CNAME") | [.subdomain, .type, .value] | @tsv')

done < "$INPUT"

if [[ "$DEADCHECK" -eq 1 ]]; then
  for i in "${!values[@]}"; do
    result=$(check_live "${values[$i]}")
    live_states[$i]="${result%%$'\t'*}"
    live_protos[$i]="${result#*$'\t'}"
  done
fi

## print table to stdout
if [[ "$DEADCHECK" -eq 1 ]]; then
  printf "%-30s %-45s %-45s %-6s %s\n" "DOMAIN" "SUBDOMAIN" "VALUE" "LIVE" "PROTO"
  printf "%-30s %-45s %-45s %-6s %s\n" "------" "---------" "-----" "----" "-----"
else
  printf "%-30s %-45s %s\n" "DOMAIN" "SUBDOMAIN" "VALUE"
  printf "%-30s %-45s %s\n" "------" "---------" "-----"
fi
for i in "${!domains[@]}"; do
  if [[ "$DEADCHECK" -eq 1 ]]; then
    printf "%-30s %-45s %-45s %-6s %s\n" "${domains[$i]}" "${subdomains[$i]}" "${values[$i]}" "${live_states[$i]}" "${live_protos[$i]}"
  else
    printf "%-30s %-45s %s\n" "${domains[$i]}" "${subdomains[$i]}" "${values[$i]}"
  fi
done

if [[ -n "$OUT_FILE" ]]; then
  tmpfile=$(mktemp)
  for i in "${!domains[@]}"; do
    if [[ "$DEADCHECK" -eq 1 ]]; then
      printf "%s\t%s\t%s\t%s\t%s\n" "${domains[$i]}" "${subdomains[$i]}" "${values[$i]}" "${live_states[$i]}" "${live_protos[$i]}" >> "$tmpfile"
    else
      printf "%s\t%s\t%s\n" "${domains[$i]}" "${subdomains[$i]}" "${values[$i]}" >> "$tmpfile"
    fi
  done

  if [[ "$OUT_FORMAT" == "json" ]]; then
    if [[ "$DEADCHECK" -eq 1 ]]; then
      jq -R -s -c 'split("\n")[:-1] | map(split("\t") | {domain:.[0], subdomain:.[1], value:.[2], live:.[3], proto:.[4]})' "$tmpfile" > "$OUT_FILE"
    else
      jq -R -s -c 'split("\n")[:-1] | map(split("\t") | {domain:.[0], subdomain:.[1], value:.[2]})' "$tmpfile" > "$OUT_FILE"
    fi
  elif [[ "$OUT_FORMAT" == "csv" ]]; then
    {
      if [[ "$DEADCHECK" -eq 1 ]]; then
        jq -R -s -r 'split("\n")[:-1] | map(split("\t")) | ("domain,subdomain,value,live,proto"), (.[] | @csv)' "$tmpfile"
      else
        jq -R -s -r 'split("\n")[:-1] | map(split("\t")) | ("domain,subdomain,value"), (.[] | @csv)' "$tmpfile"
      fi
    } > "$OUT_FILE"
  fi

  rm -f "$tmpfile"
fi
