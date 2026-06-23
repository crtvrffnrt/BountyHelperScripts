#!/usr/bin/env bash

set -o pipefail

AZMAP_API_BASE="https://azmap.dev/api/tenant"
GRAPH_API_BASE="https://graph.microsoft.com/v1.0"
LOGIN_BASE="https://login.microsoftonline.com"

OUTPUT_FORMAT="text"
OUTPUT_FILE=""
TIMEOUT="20"
SLEEP_SECONDS="0"
VERBOSE=0
DEBUG=0
INCLUDE_FALLBACK=0
INCLUDE_REGISTERED_DOMAINS=0

TENANT_INPUTS=()
DOMAIN_INPUTS=()
FALLBACK_DOMAIN_INPUTS=()
TMP_DIR=""
GRAPH_TOKEN_CACHE=""

usage() {
  cat <<'EOF'
Usage:
  ./tenant-domain-lookup.sh --tenant-id <tenant-id>
  ./tenant-domain-lookup.sh --domain <domain>
  ./tenant-domain-lookup.sh --fallback-domain <fallback-domain>
  ./tenant-domain-lookup.sh --tenant-file tenants.txt
  ./tenant-domain-lookup.sh --domain-file domains.txt
  ./tenant-domain-lookup.sh --fallback-domain-file fallback-domains.txt

Options:
  --tenant-id <tenant-id>                 Resolve tenant ID to related domains.
  --tenant-file <file>                    Read tenant IDs, one per line.
  --domain <domain>                       Resolve domain to tenant ID.
  --domain-file <file>                    Read domains, one per line.
  --fallback-domain <domain>              Resolve fallback/onmicrosoft-style domain.
  --fallback-domain-file <file>           Read fallback domains, one per line.
  --output-format text|json               Default: text.
  --output-file <file>                    Write output to file instead of stdout.
  --include-fallback                      Include discovered fallback/onmicrosoft domains in domain lists.
  --include-registered-domains            For domain/fallback-domain text mode, output domains instead of only tenant IDs.
  --timeout <seconds>                     curl timeout. Default: 20.
  --sleep <seconds>                       Sleep between requests. Default: 0.
  --verbose                               Progress logs to stderr.
  --debug                                 Debug logs to stderr.
  --help                                  Show this help.

Authentication for Microsoft Graph fallback:
  Optional. The primary related-domain lookup uses azmap.dev and does not need auth.
  Graph fallback can use either:
    GRAPH_TOKEN=<bearer-token>
    AZURE_ACCESS_TOKEN=<bearer-token>
    AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

Examples:
  ./tenant-domain-lookup.sh --tenant-id 72f988bf-86f1-41af-91ab-2d7cd011db47
  ./tenant-domain-lookup.sh --tenant-file tenants.txt --output-format text --output-file domains.txt
  ./tenant-domain-lookup.sh --domain example.com --output-format json
  ./tenant-domain-lookup.sh --tenant-file tenants.txt --output-format json --output-file results.json --verbose
EOF
}

log_verbose() {
  if [[ "$VERBOSE" -eq 1 || "$DEBUG" -eq 1 ]]; then
    printf '[verbose] %s\n' "$*" >&2
  fi
}

log_debug() {
  if [[ "$DEBUG" -eq 1 ]]; then
    printf '[debug] %s\n' "$*" >&2
  fi
}

die_params() {
  printf 'Parameter error: %s\n\n' "$*" >&2
  usage >&2
  exit 2
}

die_deps() {
  printf 'Missing dependency: %s\n' "$*" >&2
  exit 3
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}

require_tools() {
  command -v curl >/dev/null 2>&1 || die_deps "curl"
  command -v jq >/dev/null 2>&1 || die_deps "jq"
}

trim() {
  local value="$*"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

normalize_input() {
  local type="$1"
  local value
  value="$(trim "${2:-}")"
  value="${value%$'\r'}"

  case "$type" in
    tenant)
      printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
      ;;
    domain|fallback_domain)
      value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
      value="${value#http://}"
      value="${value#https://}"
      value="${value%%/*}"
      value="${value%%:*}"
      value="${value%.}"
      printf '%s' "$value"
      ;;
    *)
      printf '%s' "$value"
      ;;
  esac
}

read_input_file() {
  local type="$1"
  local file="$2"
  [[ -f "$file" ]] || die_params "input file not found: $file"

  local line value
  while IFS= read -r line || [[ -n "$line" ]]; do
    value="$(normalize_input "$type" "$line")"
    [[ -z "$value" ]] && continue
    [[ "$value" == \#* ]] && continue
    printf '%s\n' "$value"
  done < "$file"
}

validate_uuid() {
  [[ "$1" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

validate_domain() {
  local domain="$1"
  [[ ${#domain} -le 253 ]] || return 1
  [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]
}

urlencode() {
  jq -nr --arg v "$1" '$v|@uri'
}

json_string() {
  jq -Rn --arg v "$1" '$v'
}

http_get_json() {
  local url="$1"
  local body_file="$2"
  local headers_file="$3"
  local status

  log_debug "GET $url"
  status="$(
    curl -sS \
      --connect-timeout "$TIMEOUT" \
      --max-time "$TIMEOUT" \
      -H 'accept: application/json' \
      -D "$headers_file" \
      -o "$body_file" \
      -w '%{http_code}' \
      "$url" 2>"$body_file.curlerr"
  )"
  local curl_exit=$?
  if [[ "$curl_exit" -ne 0 ]]; then
    printf '000'
    return "$curl_exit"
  fi
  printf '%s' "$status"
}

http_get_json_auth() {
  local url="$1"
  local token="$2"
  local body_file="$3"
  local headers_file="$4"
  local status

  log_debug "GET $url (Authorization: Bearer [redacted])"
  status="$(
    curl -sS \
      --connect-timeout "$TIMEOUT" \
      --max-time "$TIMEOUT" \
      -H 'accept: application/json' \
      -H "Authorization: Bearer $token" \
      -D "$headers_file" \
      -o "$body_file" \
      -w '%{http_code}' \
      "$url" 2>"$body_file.curlerr"
  )"
  local curl_exit=$?
  if [[ "$curl_exit" -ne 0 ]]; then
    printf '000'
    return "$curl_exit"
  fi
  printf '%s' "$status"
}

http_post_form() {
  local url="$1"
  local body_file="$2"
  local headers_file="$3"
  shift 3
  local status

  log_debug "POST $url (form body redacted)"
  status="$(
    curl -sS \
      --connect-timeout "$TIMEOUT" \
      --max-time "$TIMEOUT" \
      -H 'accept: application/json' \
      -D "$headers_file" \
      -o "$body_file" \
      -w '%{http_code}' \
      "$url" "$@" 2>"$body_file.curlerr"
  )"
  local curl_exit=$?
  if [[ "$curl_exit" -ne 0 ]]; then
    printf '000'
    return "$curl_exit"
  fi
  printf '%s' "$status"
}

get_graph_token() {
  if [[ -n "$GRAPH_TOKEN_CACHE" ]]; then
    printf '%s' "$GRAPH_TOKEN_CACHE"
    return 0
  fi

  if [[ -n "${GRAPH_TOKEN:-}" ]]; then
    GRAPH_TOKEN_CACHE="$GRAPH_TOKEN"
    printf '%s' "$GRAPH_TOKEN_CACHE"
    return 0
  fi

  if [[ -n "${AZURE_ACCESS_TOKEN:-}" ]]; then
    GRAPH_TOKEN_CACHE="$AZURE_ACCESS_TOKEN"
    printf '%s' "$GRAPH_TOKEN_CACHE"
    return 0
  fi

  if [[ -n "${AZURE_TENANT_ID:-}" && -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" ]]; then
    local body headers status
    body="$TMP_DIR/graph-token-body.json"
    headers="$TMP_DIR/graph-token-headers.txt"
    status="$(http_post_form \
      "https://login.microsoftonline.com/$(urlencode "$AZURE_TENANT_ID")/oauth2/v2.0/token" \
      "$body" \
      "$headers" \
      --data-urlencode "client_id=$AZURE_CLIENT_ID" \
      --data-urlencode "client_secret=$AZURE_CLIENT_SECRET" \
      --data-urlencode "scope=https://graph.microsoft.com/.default" \
      --data-urlencode "grant_type=client_credentials")"

    if [[ "$status" == "200" ]] && jq -e '.access_token' "$body" >/dev/null 2>&1; then
      GRAPH_TOKEN_CACHE="$(jq -r '.access_token' "$body")"
      printf '%s' "$GRAPH_TOKEN_CACHE"
      return 0
    fi
    log_verbose "Graph token request failed with HTTP $status"
  fi

  return 1
}

call_azmap() {
  local mode="$1"
  local value="$2"
  local body="$TMP_DIR/azmap-${mode}-$(printf '%s' "$value" | tr -c 'a-zA-Z0-9._-' '_').json"
  local headers="$body.headers"
  local status url

  case "$mode" in
    tenant) url="${AZMAP_API_BASE}?tenant_id=$(urlencode "$value")" ;;
    domain|fallback_domain) url="${AZMAP_API_BASE}?domain=$(urlencode "$value")" ;;
    *) return 1 ;;
  esac

  status="$(http_get_json "$url" "$body" "$headers")"
  jq -n \
    --arg status "$status" \
    --arg body "$body" \
    --arg url "$url" \
    '{
      provider: "azmap",
      url: $url,
      http_status: ($status|tonumber? // 0),
      body_file: $body
    }'
}

call_openid() {
  local value="$1"
  local body="$TMP_DIR/openid-$(printf '%s' "$value" | tr -c 'a-zA-Z0-9._-' '_').json"
  local headers="$body.headers"
  local url="${LOGIN_BASE}/$(urlencode "$value")/v2.0/.well-known/openid-configuration"
  local status

  status="$(http_get_json "$url" "$body" "$headers")"
  jq -n \
    --arg status "$status" \
    --arg body "$body" \
    --arg url "$url" \
    '{
      provider: "microsoft_openid",
      url: $url,
      http_status: ($status|tonumber? // 0),
      body_file: $body
    }'
}

call_graph_tenant_info() {
  local mode="$1"
  local value="$2"
  local token
  token="$(get_graph_token)" || {
    jq -n '{provider:"microsoft_graph", skipped:true, reason:"no_graph_token"}'
    return 0
  }

  local body="$TMP_DIR/graph-${mode}-$(printf '%s' "$value" | tr -c 'a-zA-Z0-9._-' '_').json"
  local headers="$body.headers"
  local url status
  case "$mode" in
    tenant) url="${GRAPH_API_BASE}/tenantRelationships/findTenantInformationByTenantId(tenantId='$(urlencode "$value")')" ;;
    domain|fallback_domain) url="${GRAPH_API_BASE}/tenantRelationships/findTenantInformationByDomainName(domainName='$(urlencode "$value")')" ;;
    *) return 1 ;;
  esac

  status="$(http_get_json_auth "$url" "$token" "$body" "$headers")"
  jq -n \
    --arg status "$status" \
    --arg body "$body" \
    --arg url "$url" \
    '{
      provider: "microsoft_graph",
      url: $url,
      http_status: ($status|tonumber? // 0),
      body_file: $body
    }'
}

normalize_result() {
  local input_type="$1"
  local input="$2"
  local azmap_meta="$3"
  local openid_meta="$4"
  local graph_meta="$5"
  local az_body openid_body graph_body safe_az safe_openid safe_graph

  az_body="$(jq -r '.body_file // empty' <<<"$azmap_meta")"
  openid_body="$(jq -r '.body_file // empty' <<<"$openid_meta")"
  graph_body="$(jq -r '.body_file // empty' <<<"$graph_meta")"

  safe_az="$TMP_DIR/safe-azmap.json"
  safe_openid="$TMP_DIR/safe-openid.json"
  safe_graph="$TMP_DIR/safe-graph.json"

  if [[ -n "$az_body" && -f "$az_body" ]] && jq -e . "$az_body" >/dev/null 2>&1; then
    cp "$az_body" "$safe_az"
  else
    printf 'null\n' > "$safe_az"
  fi

  if [[ -n "$openid_body" && -f "$openid_body" ]] && jq -e . "$openid_body" >/dev/null 2>&1; then
    cp "$openid_body" "$safe_openid"
  else
    printf 'null\n' > "$safe_openid"
  fi

  if [[ -n "$graph_body" && -f "$graph_body" ]] && jq -e . "$graph_body" >/dev/null 2>&1; then
    cp "$graph_body" "$safe_graph"
  else
    printf 'null\n' > "$safe_graph"
  fi

  jq -n \
    --arg input_type "$input_type" \
    --arg input "$input" \
    --argjson az "$azmap_meta" \
    --argjson oid "$openid_meta" \
    --argjson graph "$graph_meta" \
    --argjson include_fallback "$INCLUDE_FALLBACK" \
    --slurpfile azbody_file "$safe_az" \
    --slurpfile oidbody_file "$safe_openid" \
    --slurpfile graphbody_file "$safe_graph" \
    '
    def domainish:
      select(type == "string")
      | ascii_downcase
      | sub("\\.$"; "")
      | select(test("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"));

    def uuid_from_issuer:
      if type == "string" then
        capture("(?<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})").id? // null
      else null end;

    def compact_unique:
      map(select(. != null and . != "")) | unique;

    (($azbody_file[0] // null) as $azbody
      | ($oidbody_file[0] // null) as $oidbody
      | ($graphbody_file[0] // null) as $graphbody
      | ($azbody.tenant_id // $graphbody.tenantId // ($oidbody.issuer | uuid_from_issuer)) as $tenant_id
      | ([
          ($azbody.related_domains // [])[]?,
          $graphbody.defaultDomainName?,
          (if (($azbody.tenant_name? // "") != "") then ($azbody.tenant_name + ".onmicrosoft.com") else empty end)
        ] | map(domainish) | compact_unique) as $all_domains
      | ([
          $graphbody.defaultDomainName?,
          (if (($azbody.tenant_name? // "") != "") then ($azbody.tenant_name + ".onmicrosoft.com") else empty end),
          ($azbody.related_domains // [])[]?
        ] | map(domainish | select(endswith(".onmicrosoft.com"))) | compact_unique) as $fallback_domains
      | ([
          ($azbody.related_domains // [])[]?,
          (if $include_fallback == 1 then $fallback_domains[]? else empty end)
        ] | map(domainish) | compact_unique) as $output_domains
      | ([
          (if ($az.http_status // 0) >= 400 then "azmap: HTTP " + ($az.http_status|tostring) else empty end),
          (if ($oid.http_status // 0) >= 400 then "openid: HTTP " + ($oid.http_status|tostring) else empty end),
          (if (($graph.http_status? // 0) >= 400) then "graph: HTTP " + ($graph.http_status|tostring) else empty end),
          (if ($tenant_id == null) then "tenant_id_not_found" else empty end)
        ] | compact_unique) as $errors
      | {
          ok: ($tenant_id != null),
          input: $input,
          input_type: $input_type,
          tenant_id: $tenant_id,
          fallback_domain: ($fallback_domains[0] // null),
          fallback_domains: $fallback_domains,
          domains: $output_domains,
          registered_domains: ($all_domains | map(select(endswith(".onmicrosoft.com") | not)) | unique),
          errors: $errors,
          api: {
            azmap: {
              http_status: ($az.http_status // null),
              tenant_id: $azbody.tenant_id?,
              tenant_name: $azbody.tenant_name?,
              brand_name: $azbody.brand_name?,
              related_count: $azbody.related_count?
            },
            openid: {
              http_status: ($oid.http_status // null),
              issuer: $oidbody.issuer?,
              tenant_id: ($oidbody.issuer | uuid_from_issuer)
            },
            graph: {
              skipped: ($graph.skipped // false),
              reason: $graph.reason?,
              http_status: ($graph.http_status // null),
              tenant_id: $graphbody.tenantId?,
              display_name: $graphbody.displayName?,
              default_domain_name: $graphbody.defaultDomainName?,
              federation_brand_name: $graphbody.federationBrandName?
            }
          }
        }
    )
    '
}

lookup_core() {
  local input_type="$1"
  local input="$2"
  local azmap_meta openid_meta graph_meta

  log_verbose "processing $input_type: $input"
  azmap_meta="$(call_azmap "$input_type" "$input")"
  openid_meta="$(call_openid "$input")"
  graph_meta="$(call_graph_tenant_info "$input_type" "$input")"
  normalize_result "$input_type" "$input" "$azmap_meta" "$openid_meta" "$graph_meta"
}

invalid_result() {
  local input_type="$1"
  local input="$2"
  local message="$3"
  jq -n \
    --arg input_type "$input_type" \
    --arg input "$input" \
    --arg message "$message" \
    '{
      ok: false,
      input: $input,
      input_type: $input_type,
      tenant_id: null,
      fallback_domain: null,
      fallback_domains: [],
      domains: [],
      registered_domains: [],
      errors: [$message],
      api: {}
    }'
}

lookup_by_tenant_id() {
  local tenant_id="$1"
  if ! validate_uuid "$tenant_id"; then
    invalid_result "tenant_id" "$tenant_id" "invalid_tenant_id"
    return 0
  fi
  lookup_core "tenant" "$tenant_id" | jq '.input_type = "tenant_id"'
}

lookup_by_domain() {
  local domain="$1"
  if ! validate_domain "$domain"; then
    invalid_result "domain" "$domain" "invalid_domain"
    return 0
  fi
  lookup_core "domain" "$domain"
}

lookup_by_fallback_domain() {
  local domain="$1"
  if ! validate_domain "$domain"; then
    invalid_result "fallback_domain" "$domain" "invalid_fallback_domain"
    return 0
  fi
  lookup_core "fallback_domain" "$domain"
}

dedupe_array() {
  local -n arr_ref="$1"
  local tmp="$TMP_DIR/dedupe.txt"
  printf '%s\n' "${arr_ref[@]}" | awk 'NF && !seen[$0]++' > "$tmp"
  mapfile -t arr_ref < "$tmp"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tenant-id)
        [[ $# -ge 2 ]] || die_params "--tenant-id requires a value"
        TENANT_INPUTS+=("$(normalize_input tenant "$2")")
        shift 2
        ;;
      --tenant-file)
        [[ $# -ge 2 ]] || die_params "--tenant-file requires a file"
        mapfile -t _file_values < <(read_input_file tenant "$2")
        TENANT_INPUTS+=("${_file_values[@]}")
        shift 2
        ;;
      --domain)
        [[ $# -ge 2 ]] || die_params "--domain requires a value"
        DOMAIN_INPUTS+=("$(normalize_input domain "$2")")
        shift 2
        ;;
      --domain-file)
        [[ $# -ge 2 ]] || die_params "--domain-file requires a file"
        mapfile -t _file_values < <(read_input_file domain "$2")
        DOMAIN_INPUTS+=("${_file_values[@]}")
        shift 2
        ;;
      --fallback-domain)
        [[ $# -ge 2 ]] || die_params "--fallback-domain requires a value"
        FALLBACK_DOMAIN_INPUTS+=("$(normalize_input fallback_domain "$2")")
        shift 2
        ;;
      --fallback-domain-file)
        [[ $# -ge 2 ]] || die_params "--fallback-domain-file requires a file"
        mapfile -t _file_values < <(read_input_file fallback_domain "$2")
        FALLBACK_DOMAIN_INPUTS+=("${_file_values[@]}")
        shift 2
        ;;
      --output-format)
        [[ $# -ge 2 ]] || die_params "--output-format requires text or json"
        OUTPUT_FORMAT="$2"
        [[ "$OUTPUT_FORMAT" == "text" || "$OUTPUT_FORMAT" == "json" ]] || die_params "invalid --output-format: $OUTPUT_FORMAT"
        shift 2
        ;;
      --output-file)
        [[ $# -ge 2 ]] || die_params "--output-file requires a file"
        OUTPUT_FILE="$2"
        shift 2
        ;;
      --include-fallback)
        INCLUDE_FALLBACK=1
        shift
        ;;
      --include-registered-domains)
        INCLUDE_REGISTERED_DOMAINS=1
        shift
        ;;
      --timeout)
        [[ $# -ge 2 ]] || die_params "--timeout requires seconds"
        [[ "$2" =~ ^[0-9]+$ && "$2" -gt 0 ]] || die_params "--timeout must be a positive integer"
        TIMEOUT="$2"
        shift 2
        ;;
      --sleep)
        [[ $# -ge 2 ]] || die_params "--sleep requires seconds"
        [[ "$2" =~ ^[0-9]+([.][0-9]+)?$ ]] || die_params "--sleep must be numeric"
        SLEEP_SECONDS="$2"
        shift 2
        ;;
      --verbose)
        VERBOSE=1
        shift
        ;;
      --debug)
        DEBUG=1
        VERBOSE=1
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die_params "unknown argument: $1"
        ;;
    esac
  done
}

assert_input_mode() {
  local modes=0
  [[ "${#TENANT_INPUTS[@]}" -gt 0 ]] && modes=$((modes + 1))
  [[ "${#DOMAIN_INPUTS[@]}" -gt 0 ]] && modes=$((modes + 1))
  [[ "${#FALLBACK_DOMAIN_INPUTS[@]}" -gt 0 ]] && modes=$((modes + 1))
  [[ "$modes" -eq 1 ]] || die_params "provide exactly one input type"

  dedupe_array TENANT_INPUTS
  dedupe_array DOMAIN_INPUTS
  dedupe_array FALLBACK_DOMAIN_INPUTS
}

write_json_output() {
  local results_file="$1"
  local out
  out="$(jq -s '{
    ok: (map(.ok) | all),
    result_count: length,
    results: .
  }' "$results_file")"

  if [[ -n "$OUTPUT_FILE" ]]; then
    printf '%s\n' "$out" > "$OUTPUT_FILE"
  else
    printf '%s\n' "$out"
  fi
}

write_text_output() {
  local results_file="$1"
  local jq_filter

  if [[ "${#TENANT_INPUTS[@]}" -gt 0 ]]; then
    jq_filter='[.[].domains[]?] | map(ascii_downcase) | unique | .[]'
  elif [[ "$INCLUDE_REGISTERED_DOMAINS" -eq 1 ]]; then
    if [[ "$INCLUDE_FALLBACK" -eq 1 ]]; then
      jq_filter='[.[] | (.registered_domains[]?, .fallback_domains[]?)] | map(ascii_downcase) | unique | .[]'
    else
      jq_filter='[.[].registered_domains[]?] | map(ascii_downcase) | unique | .[]'
    fi
  else
    jq_filter='[.[].tenant_id?] | map(select(. != null and . != "")) | unique | .[]'
  fi

  if [[ -n "$OUTPUT_FILE" ]]; then
    jq -r -s "$jq_filter" "$results_file" > "$OUTPUT_FILE"
  else
    jq -r -s "$jq_filter" "$results_file"
  fi
}

run() {
  require_tools
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tenant-domain-lookup.XXXXXX")" || exit 1
  trap cleanup EXIT

  parse_args "$@"
  assert_input_mode

  local results_file="$TMP_DIR/results.jsonl"
  local total=0

  # Tenant-ID mode is domain-list oriented by default, including fallback when available.
  if [[ "${#TENANT_INPUTS[@]}" -gt 0 && "$INCLUDE_FALLBACK" -eq 0 ]]; then
    INCLUDE_FALLBACK=1
  fi

  for value in "${TENANT_INPUTS[@]}"; do
    lookup_by_tenant_id "$value" >> "$results_file"
    total=$((total + 1))
    [[ "$SLEEP_SECONDS" != "0" ]] && sleep "$SLEEP_SECONDS"
  done

  for value in "${DOMAIN_INPUTS[@]}"; do
    lookup_by_domain "$value" >> "$results_file"
    total=$((total + 1))
    [[ "$SLEEP_SECONDS" != "0" ]] && sleep "$SLEEP_SECONDS"
  done

  for value in "${FALLBACK_DOMAIN_INPUTS[@]}"; do
    lookup_by_fallback_domain "$value" >> "$results_file"
    total=$((total + 1))
    [[ "$SLEEP_SECONDS" != "0" ]] && sleep "$SLEEP_SECONDS"
  done

  log_verbose "processed $total input(s)"

  if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    write_json_output "$results_file"
  else
    write_text_output "$results_file"
  fi

  if jq -e -s 'all(.ok == true)' "$results_file" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

run "$@"
