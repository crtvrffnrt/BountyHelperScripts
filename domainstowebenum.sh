#!/usr/bin/env bash
set -euo pipefail

input=${1:-doms.txt}
output=${2:-https_live_urls.txt}
[[ -f $input ]] || { printf 'Input file not found: %s\n' "$input" >&2; exit 1; }
for tool in subfinder dnsx httpx; do
  command -v "$tool" >/dev/null || { printf 'Missing tool: %s\n' "$tool" >&2; exit 1; }
done
httpx -version 2>&1 | grep -qi 'projectdiscovery' || {
  printf 'httpx must be the ProjectDiscovery binary\n' >&2; exit 1;
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sed 's/\r$//; s/^[[:space:]]*//; s/[[:space:]]*$//; /^[[:space:]]*$/d; /^#/d' "$input" | sort -u > "$tmp/domains"
[[ -s $tmp/domains ]] || { echo 'No domains in input' >&2; exit 1; }

show() {
  printf '\n[*] %s (%s results)\n' "$1" "$(wc -l < "$2")"
  cat "$2"
}

show 'Input domains' "$tmp/domains"
subfinder -silent -dL "$tmp/domains" | sort -u > "$tmp/subdomains"
show 'Discovered subdomains' "$tmp/subdomains"
sort -u "$tmp/domains" "$tmp/subdomains" | dnsx -silent -a | sort -u > "$tmp/resolved"
show 'Resolved hosts' "$tmp/resolved"
if [[ -s $tmp/resolved ]]; then
  httpx -silent -p https:443 -nf -timeout 5 -retries 1 -l "$tmp/resolved" | sort -u > "$tmp/urls"
else
  : > "$tmp/urls"
fi
show 'Live HTTPS URLs' "$tmp/urls"
cp "$tmp/urls" "$output"
printf '\n[+] Saved %s URLs to %s\n' "$(wc -l < "$output")" "$output"
