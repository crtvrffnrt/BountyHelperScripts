#!/bin/bash

DNS_FILE=""
RUN_ID="$(date +%Y%m%d%H%M%S)-$$-$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
RG_PREFIX="dns-check-${RUN_ID}"
declare -A TEMP_RGS_BY_LOCATION
CREATED_RGS=()
DELETED_RGS=0
FAILED_DELETE_RGS=0
TOTAL_COUNT=0
DOT_COUNT=0
CHECKED_COUNT=0
AVAILABLE_COUNT=0
UNAVAILABLE_COUNT=0
FAILED_COUNT=0
CLEANUP_DONE=0

if [ -t 1 ]; then
  COLOR_GREEN="\033[0;32m"
  COLOR_RED="\033[0;31m"
  COLOR_YELLOW="\033[0;33m"
  COLOR_BLUE="\033[0;34m"
  COLOR_BOLD="\033[1m"
  COLOR_RESET="\033[0m"
else
  COLOR_GREEN=""
  COLOR_RED=""
  COLOR_YELLOW=""
  COLOR_BLUE=""
  COLOR_BOLD=""
  COLOR_RESET=""
fi
if [ -t 2 ]; then
  PROGRESS_TTY=1
else
  PROGRESS_TTY=0
fi

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
  - Each DNS name is printed to stdout as AVAILABLE/UNAVAILABLE during the run
  - A summary is printed to stdout at the end (checked/available/unavailable)

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
  if [ "$CLEANUP_DONE" -eq 1 ]; then
    return
  fi
  CLEANUP_DONE=1
  if [ "${#CREATED_RGS[@]}" -eq 0 ]; then
    return
  fi
  for rg in "${CREATED_RGS[@]}"; do
    az group delete --name "$rg" --yes >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      DELETED_RGS=$((DELETED_RGS + 1))
    else
      FAILED_DELETE_RGS=$((FAILED_DELETE_RGS + 1))
    fi
  done
}

trap cleanup EXIT INT TERM

render_progress() {
  local dots

  DOT_COUNT=$((DOT_COUNT + 1))
  if [ "$DOT_COUNT" -gt 12 ]; then
    DOT_COUNT=1
  fi

  dots="$(printf "%*s" "$DOT_COUNT" "" | tr ' ' '.')"
  if [ "$PROGRESS_TTY" -eq 1 ]; then
    printf "\r\033[2K%s\n\033[2KProgress: %d/%d\033[1A" "$dots" "$CHECKED_COUNT" "$TOTAL_COUNT" >&2
  else
    printf "." >&2
  fi
}

end_progress() {
  if [ "$PROGRESS_TTY" -eq 1 ]; then
    printf "\r\033[2K\033[1B\033[2K\033[1A" >&2
  else
    printf "\n" >&2
  fi
}

print_available() {
  if [ "$PROGRESS_TTY" -eq 1 ]; then
    printf "\r\033[2K\033[1B\033[2K\033[1A" >&2
  fi
  printf "%b\n" "${COLOR_GREEN}AVAILABLE${COLOR_RESET} $1"
  if [ "$PROGRESS_TTY" -eq 1 ]; then
    printf "\r\033[2K%s\n\033[2KProgress: %d/%d\033[1A" "$(printf "%*s" "$DOT_COUNT" "" | tr ' ' '.')" "$CHECKED_COUNT" "$TOTAL_COUNT" >&2
  fi
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
    printf "\n" >&2
    printf "Warning: Failed to create temp resource group in %s. Skipping.\n" "$location" >&2
    return 1
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
    continue
  fi
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
done < "$DNS_FILE"

printf "%b\n" "${COLOR_BLUE}${COLOR_BOLD}DNS Check${COLOR_RESET}   .--.    .-.-."
printf "%b\n" "            [==]  | | | |  signal: locked"
printf "%b\n" "             ||   | |_| |  grid: stable"
printf "%b\n" "            /__\\  '-----'  mode: neon"
printf "\n"

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
  render_progress

  ensure_temp_rg_for_location "$location"
  if [ $? -ne 0 ]; then
    FAILED_COUNT=$((FAILED_COUNT + 1))
    continue
  fi

  check_dns_availability "$dns_label" "$location" "${TEMP_RGS_BY_LOCATION[$location]}"
  check_result=$?
  if [ $check_result -eq 0 ]; then
    AVAILABLE_COUNT=$((AVAILABLE_COUNT + 1))
    print_available "$full_dns_name"
  else
    UNAVAILABLE_COUNT=$((UNAVAILABLE_COUNT + 1))
  fi

done < "$DNS_FILE"

end_progress
cleanup

printf "\n"
printf "%b\n" "${COLOR_BOLD}Summary${COLOR_RESET}"
printf "%b\n" "Checked $CHECKED_COUNT DNS name(s)."
printf "%b\n" "Available: $AVAILABLE_COUNT"
printf "%b\n" "Unavailable: $UNAVAILABLE_COUNT"
if [ "$FAILED_COUNT" -gt 0 ]; then
  printf "%b\n" "${COLOR_YELLOW}Skipped due to errors: $FAILED_COUNT${COLOR_RESET}"
fi
if [ "$AVAILABLE_COUNT" -eq 0 ]; then
  printf "%b\n" "${COLOR_YELLOW}All DNS names are unavailable.${COLOR_RESET}"
fi
printf "%b\n" "Resource groups created: ${#CREATED_RGS[@]}"
if [ "${#CREATED_RGS[@]}" -eq 0 ]; then
  printf "%b\n" "Resource groups deleted: 0"
else
  printf "%b\n" "Resource groups deleted: $DELETED_RGS"
  if [ "$FAILED_DELETE_RGS" -gt 0 ]; then
    printf "%b\n" "${COLOR_YELLOW}Resource groups failed to delete: $FAILED_DELETE_RGS${COLOR_RESET}"
  else
    printf "%b\n" "${COLOR_GREEN}All created resource groups deleted successfully.${COLOR_RESET}"
  fi
fi
