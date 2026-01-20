#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_ROUTING_METHOD="Performance"
readonly DEFAULT_TTL=30
readonly DEFAULT_MONITOR_PROTOCOL="HTTP"
readonly DEFAULT_MONITOR_PORT=80
readonly DEFAULT_MONITOR_PATH="/"

PROFILE_NAME=""
RESOURCE_GROUP=""
LOCATION=""
DNS_NAME=""
ROUTING_METHOD="$DEFAULT_ROUTING_METHOD"
TTL="$DEFAULT_TTL"
MONITOR_PROTOCOL="$DEFAULT_MONITOR_PROTOCOL"
MONITOR_PORT="$DEFAULT_MONITOR_PORT"
MONITOR_PATH="$DEFAULT_MONITOR_PATH"
TARGETS_FILE=""
QUIET_MODE="false"

AZURE_CONFIG_DIR="${AZURE_CONFIG_DIR:-$HOME/.azure}"
export AZURE_CONFIG_DIR

usage() {
    cat <<EOF
Usage:
  ./trafficmanager.sh --name <profile-name> --resource-group <rg> --dns-name <relative-name> [options]
  ./trafficmanager.sh --targets <file> --resource-group <rg> [options]

Required:
  -n, --name               Traffic Manager profile name
  -g, --resource-group     Resource group name
  -d, --dns-name           Relative DNS name (profile will be reachable at <name>.trafficmanager.net)
  -t, --targets            File with full Traffic Manager hostnames (one per line)

Optional:
  -l, --location           Azure region to create the resource group if it does not exist
  --routing-method         Routing method (default: ${ROUTING_METHOD})
  --ttl                    DNS TTL in seconds (default: ${TTL})
  --monitor-protocol       Health monitor protocol (default: ${MONITOR_PROTOCOL})
  --monitor-port           Health monitor port (default: ${MONITOR_PORT})
  --monitor-path           Health monitor path (default: ${MONITOR_PATH})
  -h, --help               Show this help and exit

Examples:
  ./trafficmanager.sh --name tm-demo --resource-group rg-demo --dns-name demo-tm
  ./trafficmanager.sh -n tm1 -g rg1 -d myapp --routing-method Weighted --ttl 60
  ./trafficmanager.sh --targets targets.txt -g rg-demo --location westeurope

Targets file format:
  - One hostname per line, e.g. aadbridgetrafficmanager-int-zt-kv.trafficmanager.net
  - Empty lines and comments (# ...) are ignored
EOF
}

display_message() {
    local message="$1"
    local color="${2:-}"
    local force="${3:-false}"
    if [[ "$QUIET_MODE" == "true" && "$force" != "true" ]]; then
        return 0
    fi
    case "$color" in
        red) printf '\033[91m%s\033[0m\n' "$message" ;;
        green) printf '\033[92m%s\033[0m\n' "$message" ;;
        yellow) printf '\033[93m%s\033[0m\n' "$message" ;;
        blue) printf '\033[94m%s\033[0m\n' "$message" ;;
        *) printf '%s\n' "$message" ;;
    esac
}

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        display_message "Missing required command: $cmd" "red"
        exit 1
    fi
}

check_azure_authentication() {
    if ! az account show --only-show-errors >/dev/null 2>&1; then
        display_message "Authenticate to Azure first: az login --use-device-code" "red"
        exit 1
    fi
}

validate_label() {
    local label="$1"
    local description="$2"

    if [[ -z "$label" ]]; then
        if [[ "$QUIET_MODE" == "true" ]]; then
            return 1
        fi
        display_message "$description cannot be empty." "red"
        exit 1
    fi

    if [[ ! "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]; then
        if [[ "$QUIET_MODE" == "true" ]]; then
            return 1
        fi
        display_message "$description must be 1-63 chars and use only letters, numbers, or hyphens." "red"
        exit 1
    fi
}

ensure_resource_group() {
    if az group exists --name "$RESOURCE_GROUP" --only-show-errors | grep -iq true; then
        return 0
    fi

    if [[ -z "$LOCATION" ]]; then
        display_message "Resource group '$RESOURCE_GROUP' not found. Provide --location to create it." "red"
        exit 1
    fi

    display_message "Creating resource group '$RESOURCE_GROUP' in $LOCATION..." "blue"
    az group create \
        --name "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --only-show-errors >/dev/null
}

trim_line() {
    local line="$1"
    line="${line#${line%%[![:space:]]*}}"
    line="${line%${line##*[![:space:]]}}"
    printf '%s' "$line"
}

normalize_target_label() {
    local line
    line="$(trim_line "$1")"
    if [[ -z "$line" ]]; then
        return 0
    fi

    line="$(printf '%s' "$line" | sed -E 's/[[:space:]]+$//' )"
    line="$(printf '%s' "$line" | sed -E 's/\.trafficmanager\.net$//I')"
    printf '%s' "$line"
}

create_profile() {
    display_message "Creating Traffic Manager profile '$PROFILE_NAME'..." "blue"
    local az_error=""
    if az_error=$(az network traffic-manager profile create \
        --name "$PROFILE_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --routing-method "$ROUTING_METHOD" \
        --unique-dns-name "$DNS_NAME" \
        --ttl "$TTL" \
        --monitor-protocol "$MONITOR_PROTOCOL" \
        --monitor-port "$MONITOR_PORT" \
        --monitor-path "$MONITOR_PATH" \
        --only-show-errors 2>&1); then
        return 0
    fi

    if echo "$az_error" | grep -qi "unrecognized arguments: --unique-dns-name"; then
        display_message "Azure CLI does not support --unique-dns-name; retrying with --relative-name." "yellow"
        if az network traffic-manager profile create \
            --name "$PROFILE_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --routing-method "$ROUTING_METHOD" \
            --relative-name "$DNS_NAME" \
            --ttl "$TTL" \
            --monitor-protocol "$MONITOR_PROTOCOL" \
            --monitor-port "$MONITOR_PORT" \
            --monitor-path "$MONITOR_PATH" \
            --only-show-errors >/dev/null; then
            return 0
        fi
    fi

    if [[ "$QUIET_MODE" == "true" ]]; then
        return 1
    fi
    display_message "Failed to create profile '$PROFILE_NAME'." "red"
    display_message "$az_error" "red"
    return 1
}

parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -n|--name)
                PROFILE_NAME="$2"
                shift 2
                ;;
            -g|--resource-group)
                RESOURCE_GROUP="$2"
                shift 2
                ;;
            -d|--dns-name)
                DNS_NAME="$2"
                shift 2
                ;;
            -t|--targets)
                TARGETS_FILE="$2"
                shift 2
                ;;
            -l|--location)
                LOCATION="$2"
                shift 2
                ;;
            --routing-method)
                ROUTING_METHOD="$2"
                shift 2
                ;;
            --ttl)
                TTL="$2"
                shift 2
                ;;
            --monitor-protocol)
                MONITOR_PROTOCOL="$2"
                shift 2
                ;;
            --monitor-port)
                MONITOR_PORT="$2"
                shift 2
                ;;
            --monitor-path)
                MONITOR_PATH="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                display_message "Unknown argument: $1" "red"
                usage
                exit 1
                ;;
        esac
    done

    if [[ -n "$TARGETS_FILE" && ( -n "$PROFILE_NAME" || -n "$DNS_NAME" ) ]]; then
        display_message "Use either --targets or --name/--dns-name, not both." "red"
        usage
        exit 1
    fi

    if [[ -n "$TARGETS_FILE" ]]; then
        if [[ -z "$RESOURCE_GROUP" ]]; then
            display_message "Missing required --resource-group." "red"
            usage
            exit 1
        fi
        return 0
    fi

    if [[ -z "$PROFILE_NAME" || -z "$RESOURCE_GROUP" || -z "$DNS_NAME" ]]; then
        display_message "Missing required arguments." "red"
        usage
        exit 1
    fi
}

main() {
    parse_args "$@"
    require_command az
    check_azure_authentication

    ensure_resource_group

    if [[ -n "$TARGETS_FILE" ]]; then
        if [[ ! -f "$TARGETS_FILE" ]]; then
            display_message "Targets file not found: $TARGETS_FILE" "red"
            exit 1
        fi

        QUIET_MODE="true"
        local success_count=0
        local failure_count=0

        while IFS= read -r line || [[ -n "$line" ]]; do
            line="$(trim_line "$line")"
            if [[ -z "$line" || "$line" == \#* ]]; then
                continue
            fi

            local label
            label="$(normalize_target_label "$line")"
            if [[ -z "$label" ]]; then
                continue
            fi

            PROFILE_NAME="$label"
            DNS_NAME="$label"

            if ! validate_label "$PROFILE_NAME" "Profile name"; then
                failure_count=$((failure_count + 1))
                continue
            fi
            if ! validate_label "$DNS_NAME" "DNS name"; then
                failure_count=$((failure_count + 1))
                continue
            fi

            if create_profile; then
                success_count=$((success_count + 1))
                printf "CREATED %s %s.trafficmanager.net\n" "$PROFILE_NAME" "$DNS_NAME"
            else
                failure_count=$((failure_count + 1))
            fi
        done < "$TARGETS_FILE"

        QUIET_MODE="false"
        if [[ "$success_count" -eq 0 ]]; then
            display_message "Unable to create any Traffic Manager profiles from $TARGETS_FILE." "yellow" "true"
            exit 1
        fi

        display_message "Created ${success_count} profile(s). Failed: ${failure_count}." "green" "true"
        return 0
    fi

    validate_label "$PROFILE_NAME" "Profile name"
    validate_label "$DNS_NAME" "DNS name"

    create_profile

    display_message "--- Deployment Complete ---" "green"
    display_message "Traffic Manager profile: $PROFILE_NAME" "green"
    display_message "DNS name: ${DNS_NAME}.trafficmanager.net" "green"
}

main "$@"
