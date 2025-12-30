#!/bin/bash

DNS_FILE=""
RUN_ID="$(date +%Y%m%d%H%M%S)-$$-$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
RG_PREFIX="dns-check-${RUN_ID}"
declare -A TEMP_RGS_BY_LOCATION
CREATED_RGS=()
DOT_COUNT=0
CHECKED_COUNT=0
AVAILABLE_COUNT=0

usage() {
  cat <<'EOF'
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
  - Only AVAILABLE DNS names are printed to stdout during the run
  - A summary is printed to stdout at the end (checked count, and if none available)

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
EOF
}

while getopts ":f:h-:" opt; do
  case "$opt" in
    f)
      DNS_FILE="$OPTARG"
      ;;
    h)
      usage
      exit 0
      ;;
    -)
      case "$OPTARG" in
        help)
          usage
          exit 0
          ;;
        *)
          echo "Error: Invalid option --$OPTARG" >&2
          usage
          exit 1
          ;;
      esac
      ;;
    \?)
      echo "Error: Invalid option -$OPTARG" >&2
      usage
      exit 1
      ;;
    :)
      echo "Error: Option -$OPTARG requires an argument." >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$DNS_FILE" ]; then
  echo "Error: Missing -f filename." >&2
  usage
  exit 1
fi

if [ ! -f "$DNS_FILE" ]; then
  echo "Error: $DNS_FILE not found." >&2
  exit 1
fi

cleanup() {
  local rg
  if [ "${#CREATED_RGS[@]}" -eq 0 ]; then
    return
  fi
  echo "" >&2
  for rg in "${CREATED_RGS[@]}"; do
    az group delete --name "$rg" --yes >/dev/null 2>&1
  done
}

trap cleanup EXIT INT TERM

print_dot() {
  DOT_COUNT=$((DOT_COUNT + 1))
  if [ "$DOT_COUNT" -gt 12 ]; then
    printf "\r            \r" >&2
    DOT_COUNT=1
  fi
  printf "." >&2
}

ensure_temp_rg_for_location() {
  local location="$1"
  local rg_name

  if [ -n "${TEMP_RGS_BY_LOCATION[$location]}" ]; then
    return 0
  fi

  rg_name="${RG_PREFIX}-${location}"
  az group create \
    --name "$rg_name" \
    --location "$location" \
    --tags "created-by=check_dns_availability.sh" "run-id=$RUN_ID" \
    >/dev/null 2>&1

  if [ $? -ne 0 ]; then
    echo "" >&2
    echo "Error: Failed to create temp resource group in $location." >&2
    exit 1
  fi

  TEMP_RGS_BY_LOCATION[$location]="$rg_name"
  CREATED_RGS+=("$rg_name")
}

check_dns_availability() {
  local dns_label="$1"
  local location="$2"
  local rg_name="$3"
  local pip_name="dns-check-${dns_label}-${RUN_ID}"

  az network public-ip create \
    --resource-group "$rg_name" \
    --name "$pip_name" \
    --location "$location" \
    --dns-name "$dns_label" \
    >/dev/null 2>&1

  if [ $? -ne 0 ]; then
    return 1
  fi

  az network public-ip delete \
    --resource-group "$rg_name" \
    --name "$pip_name" \
    >/dev/null 2>&1

  return 0
}

while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"
  line="$(echo "$line" | xargs)"
  if [[ -z "$line" ]]; then
    continue # Skip empty/comment lines
  fi

  full_dns_name="$line"
  dns_label=$(echo "$full_dns_name" | cut -d'.' -f1)
  location=$(echo "$full_dns_name" | cut -d'.' -f2)

  if [ -z "$location" ] || [ "$location" = "$full_dns_name" ]; then
    echo "" >&2
    echo "Error: Could not determine location for '$full_dns_name'." >&2
    exit 1
  fi

  CHECKED_COUNT=$((CHECKED_COUNT + 1))
  print_dot

  ensure_temp_rg_for_location "$location"

  check_dns_availability "$dns_label" "$location" "${TEMP_RGS_BY_LOCATION[$location]}"
  check_result=$?
  if [ $check_result -eq 0 ]; then
    AVAILABLE_COUNT=$((AVAILABLE_COUNT + 1))
    echo "$full_dns_name"
  fi

done < "$DNS_FILE"

echo ""
echo "Checked $CHECKED_COUNT DNS name(s)."
if [ "$AVAILABLE_COUNT" -eq 0 ]; then
  echo "All DNS names are unavailable."
fi
