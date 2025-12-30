#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_LOCATION="westeurope"
readonly DEFAULT_SKU="Standard_AzureFrontDoor"
readonly DEFAULT_RESOURCE_GROUP_PREFIX="afd-"
readonly DEFAULT_ORIGIN_HOST="placeholder.example.com"
readonly DEFAULT_PROBE_PATH="/health"
readonly DEFAULT_PROBE_PROTOCOL="Https"
readonly DEFAULT_PROBE_REQUEST_TYPE="GET"
readonly DEFAULT_ROUTE_NAME="route-default"
readonly DEFAULT_ORIGIN_GROUP_NAME="og-default"
readonly DEFAULT_ORIGIN_NAME="origin-1"
readonly DEFAULT_WAIT_TIMEOUT=900
readonly DEFAULT_PROBE_INTERVAL_SECONDS=60
readonly DEFAULT_PROBE_SAMPLE_SIZE=4
readonly DEFAULT_PROBE_SAMPLES_REQUIRED=3
readonly DEFAULT_PROBE_ADDITIONAL_LATENCY_MS=50
readonly DEFAULT_ORIGIN_PRIORITY=1
readonly DEFAULT_ORIGIN_WEIGHT=1000

LOCATION="$DEFAULT_LOCATION"
SKU="$DEFAULT_SKU"
RESOURCE_GROUP_PREFIX="$DEFAULT_RESOURCE_GROUP_PREFIX"
ORIGIN_HOST="$DEFAULT_ORIGIN_HOST"
ORIGIN_HOST_HEADER=""
PROBE_PATH="$DEFAULT_PROBE_PATH"
PROBE_PROTOCOL="$DEFAULT_PROBE_PROTOCOL"
PROBE_REQUEST_TYPE="$DEFAULT_PROBE_REQUEST_TYPE"
PROBE_INTERVAL_SECONDS="$DEFAULT_PROBE_INTERVAL_SECONDS"
PROBE_SAMPLE_SIZE="$DEFAULT_PROBE_SAMPLE_SIZE"
PROBE_SAMPLES_REQUIRED="$DEFAULT_PROBE_SAMPLES_REQUIRED"
PROBE_ADDITIONAL_LATENCY_MS="$DEFAULT_PROBE_ADDITIONAL_LATENCY_MS"
ROUTE_NAME="$DEFAULT_ROUTE_NAME"
ORIGIN_GROUP_NAME="$DEFAULT_ORIGIN_GROUP_NAME"
ORIGIN_NAME="$DEFAULT_ORIGIN_NAME"
ORIGIN_PRIORITY="$DEFAULT_ORIGIN_PRIORITY"
ORIGIN_WEIGHT="$DEFAULT_ORIGIN_WEIGHT"
WAIT_TIMEOUT="$DEFAULT_WAIT_TIMEOUT"
HTTP_PORT=80
HTTPS_PORT=443

action_host=""
LIST_FILE=""
RESOURCE_GROUP=""
PROFILE_NAME=""
ENDPOINT_NAME=""
PROFILE_NAME_EXPLICIT="false"
ENDPOINT_NAME_EXPLICIT="false"
NO_WAIT="false"
AZ_DEBUG="false"
AZ_SHOW_FLAGS=(--only-show-errors)
AZ_QUIET_FLAGS=(--only-show-errors --output none)

AZURE_CONFIG_DIR="${AZURE_CONFIG_DIR:-$HOME/.azure}"
export AZURE_CONFIG_DIR

usage() {
    cat <<EOF
Usage:
  ./frontdoorcreator.sh -H <target-hostname> [options]
  ./frontdoorcreator.sh -l <file-with-hostnames> [options]

Required (choose one):
  -H, --hostname            Target hostname to derive the endpoint name from
  -l, --list                Text file with one hostname per line

Optional:
      --location            Azure region for the resource group (default: ${LOCATION})
      --sku                 Front Door SKU (default: ${SKU})
      --origin-host         Backend hostname (default: ${ORIGIN_HOST})
      --origin-host-header  Origin host header (default: same as --origin-host)
      --resource-group      Exact resource group name (single-host only)
      --rg-prefix           Resource group prefix for auto names (default: ${RESOURCE_GROUP_PREFIX})
      --profile-name        Front Door profile name (defaults to <endpoint>)
      --endpoint-name       Front Door endpoint name override (defaults to first label of hostname)
      --origin-group-name   Origin group name (default: ${ORIGIN_GROUP_NAME})
      --origin-name         Origin name (default: ${ORIGIN_NAME})
      --route-name          Route name (default: ${ROUTE_NAME})
      --probe-path          Health probe path (default: ${PROBE_PATH})
      --probe-protocol      Health probe protocol (default: ${PROBE_PROTOCOL})
      --probe-request-type  Health probe request type (default: ${PROBE_REQUEST_TYPE})
      --probe-interval      Health probe interval in seconds (default: ${PROBE_INTERVAL_SECONDS})
      --origin-priority     Origin priority for load balancing (default: ${ORIGIN_PRIORITY})
      --origin-weight       Origin weight for load balancing (default: ${ORIGIN_WEIGHT})
      --http-port           Origin HTTP port (default: ${HTTP_PORT})
      --https-port          Origin HTTPS port (default: ${HTTPS_PORT})
      --wait-timeout        Max seconds to wait per resource (default: ${WAIT_TIMEOUT})
      --no-wait             Skip provisioning-state waits
      --debug               Enable Azure CLI debug output
  -h, --help                Show this help and exit

Examples:
  ./frontdoorcreator.sh -H my-api-endpoint
  ./frontdoorcreator.sh -H my-api.azurefd.net --origin-host api.example.com
  ./frontdoorcreator.sh -l hostnames.txt --origin-host api.example.com --location eastus

Notes:
  - The final Front Door hostname will look like:
      https://<endpoint-name>-<random>.z01.azurefd.net
  - Auto-generated resource groups end with: -<unix-timestamp>-frontdoorcreator
  - Origin host should be publicly reachable for a healthy endpoint.
EOF
}

display_message() {
    local message="$1"
    local color="${2:-}"
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
    if [[ "$AZ_DEBUG" == "true" ]]; then
        if ! az account show "${AZ_SHOW_FLAGS[@]}"; then
            display_message "Authenticate to Azure first: az login --use-device-code" "red"
            exit 1
        fi
        return 0
    fi

    if ! az account show "${AZ_SHOW_FLAGS[@]}" >/dev/null 2>&1; then
        display_message "Authenticate to Azure first: az login --use-device-code" "red"
        exit 1
    fi
}

normalize_endpoint_name() {
    local input="$1"
    local base

    if [[ "$input" == *.* ]]; then
        base="${input%%.*}"
    else
        base="$input"
    fi

    base=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')

    if [[ -z "$base" ]]; then
        display_message "Derived endpoint name is empty." "red"
        return 1
    fi

    if [[ ! "$base" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
        display_message "Endpoint name must contain only lowercase letters, numbers, or hyphens: $base" "red"
        return 1
    fi

    printf '%s' "$base"
}

trim_line() {
    local line="$1"
    line="${line#${line%%[![:space:]]*}}"
    line="${line%${line##*[![:space:]]}}"
    printf '%s' "$line"
}

wait_for_provisioning() {
    local description="$1"
    shift
    local command=("$@")
    local deadline=$((SECONDS + WAIT_TIMEOUT))

    if [[ "$NO_WAIT" == "true" ]]; then
        return 0
    fi

    display_message "Waiting for $description to reach provisioningState=Succeeded..." "blue"
    while true; do
        local state
        if [[ "$AZ_DEBUG" == "true" ]]; then
            state=$("${command[@]}" | tee /dev/stderr | tr -d '\r' || true)
        else
            state=$("${command[@]}" 2>/dev/null | tr -d '\r' || true)
        fi

        if [[ "$state" == "Succeeded" ]]; then
            display_message "$description is ready." "green"
            return 0
        fi

        if [[ "$state" == "Failed" || "$state" == "Canceled" ]]; then
            display_message "$description provisioning failed with state: $state" "red"
            return 1
        fi

        if (( SECONDS >= deadline )); then
            display_message "$description provisioning timed out after ${WAIT_TIMEOUT}s." "red"
            return 1
        fi

        display_message "$description state: ${state:-unknown}. Waiting 10 seconds..." "yellow"
        sleep 10
    done
}

create_frontdoor_for_hostname() {
    local target_hostname="$1"
    local endpoint_name="$ENDPOINT_NAME"
    local profile_name="$PROFILE_NAME"
    local resource_group="$RESOURCE_GROUP"
    local origin_host_header="$ORIGIN_HOST_HEADER"

    if [[ -z "$endpoint_name" ]]; then
        endpoint_name=$(normalize_endpoint_name "$target_hostname")
    fi

    if [[ -z "$profile_name" ]]; then
        profile_name="$endpoint_name"
    fi

    if [[ -z "$resource_group" ]]; then
        local timestamp
        timestamp=$(date +%s)
        resource_group="${RESOURCE_GROUP_PREFIX}${endpoint_name}-rg-${timestamp}-frontdoorcreator"
    fi

    if [[ -z "$origin_host_header" ]]; then
        origin_host_header="$ORIGIN_HOST"
    fi

    display_message "--- Configuration ---" "blue"
    display_message "Target Hostname : $target_hostname"
    display_message "Endpoint Name   : $endpoint_name"
    display_message "Profile Name    : $profile_name"
    display_message "Resource Group  : $resource_group"
    display_message "Location        : $LOCATION"
    display_message "Origin Host     : $ORIGIN_HOST"
    display_message "---------------------" "blue"

    if az group exists --name "$resource_group" "${AZ_SHOW_FLAGS[@]}" | grep -iq true; then
        display_message "Resource group '$resource_group' already exists." "red"
        return 1
    fi

    display_message "Creating resource group '$resource_group'..." "blue"
    if ! az group create \
        --name "$resource_group" \
        --location "$LOCATION" \
        "${AZ_QUIET_FLAGS[@]}"; then
        display_message "Failed to create resource group '$resource_group'." "red"
        return 1
    fi

    display_message "Creating Front Door profile '$profile_name'..." "blue"
    if ! az afd profile create \
        --profile-name "$profile_name" \
        --resource-group "$resource_group" \
        --sku "$SKU" \
        "${AZ_QUIET_FLAGS[@]}"; then
        display_message "Failed to create profile '$profile_name'." "red"
        return 1
    fi

    if ! wait_for_provisioning "Profile $profile_name" \
        az afd profile show \
        --profile-name "$profile_name" \
        --resource-group "$resource_group" \
        "${AZ_SHOW_FLAGS[@]}" \
        --query provisioningState \
        -o tsv; then
        return 1
    fi

    local endpoint_created="false"
    local attempt=1
    while [[ "$endpoint_created" == "false" && "$attempt" -le 3 ]]; do
        display_message "Creating Front Door endpoint '$endpoint_name' (attempt $attempt/3)..." "blue"
        local endpoint_error=""
        if endpoint_error=$(az afd endpoint create \
            --resource-group "$resource_group" \
            --profile-name "$profile_name" \
            --endpoint-name "$endpoint_name" \
            --enabled-state Enabled \
            "${AZ_QUIET_FLAGS[@]}" 2>&1); then
            endpoint_created="true"
            break
        fi

        if echo "$endpoint_error" | grep -qiE "Conflict|isn't available|name.*available"; then
            local suffix
            suffix=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 6 || true)
            local next_endpoint="${endpoint_name}-${suffix}"
            display_message "Endpoint name '$endpoint_name' unavailable. Retrying with '$next_endpoint'." "yellow"
            endpoint_name="$next_endpoint"

            if [[ "$PROFILE_NAME_EXPLICIT" == "false" && "$profile_name" != "$endpoint_name" ]]; then
                display_message "Recreating profile to match new endpoint name '$endpoint_name'." "yellow"
                az afd profile delete \
                    --profile-name "$profile_name" \
                    --resource-group "$resource_group" \
                    --yes \
                    "${AZ_SHOW_FLAGS[@]}" >/dev/null 2>&1 || true
                profile_name="$endpoint_name"
                if ! az afd profile create \
                    --profile-name "$profile_name" \
                    --resource-group "$resource_group" \
                    --sku "$SKU" \
                    "${AZ_QUIET_FLAGS[@]}"; then
                    display_message "Failed to create profile '$profile_name'." "red"
                    return 1
                fi

                if ! wait_for_provisioning "Profile $profile_name" \
                    az afd profile show \
                    --profile-name "$profile_name" \
                    --resource-group "$resource_group" \
                    "${AZ_SHOW_FLAGS[@]}" \
                    --query provisioningState \
                    -o tsv; then
                    return 1
                fi
            fi
        else
            display_message "Failed to create endpoint '$endpoint_name'." "red"
            if [[ "$AZ_DEBUG" == "true" ]]; then
                display_message "$endpoint_error" "red"
            fi
            return 1
        fi

        attempt=$((attempt + 1))
    done

    if [[ "$endpoint_created" == "false" ]]; then
        display_message "Failed to create endpoint after multiple attempts." "red"
        return 1
    fi

    if ! wait_for_provisioning "Endpoint $endpoint_name" \
        az afd endpoint show \
        --resource-group "$resource_group" \
        --profile-name "$profile_name" \
        --endpoint-name "$endpoint_name" \
        "${AZ_SHOW_FLAGS[@]}" \
        --query provisioningState \
        -o tsv; then
        return 1
    fi

    display_message "Creating origin group '$ORIGIN_GROUP_NAME'..." "blue"
    if ! az afd origin-group create \
        --resource-group "$resource_group" \
        --profile-name "$profile_name" \
        --origin-group-name "$ORIGIN_GROUP_NAME" \
        --probe-path "$PROBE_PATH" \
        --probe-protocol "$PROBE_PROTOCOL" \
        --probe-request-type "$PROBE_REQUEST_TYPE" \
        --probe-interval-in-seconds "$PROBE_INTERVAL_SECONDS" \
        --sample-size "$PROBE_SAMPLE_SIZE" \
        --successful-samples-required "$PROBE_SAMPLES_REQUIRED" \
        --additional-latency-in-milliseconds "$PROBE_ADDITIONAL_LATENCY_MS" \
        "${AZ_QUIET_FLAGS[@]}"; then
        display_message "Failed to create origin group '$ORIGIN_GROUP_NAME'." "red"
        return 1
    fi

    if ! wait_for_provisioning "Origin group $ORIGIN_GROUP_NAME" \
        az afd origin-group show \
        --resource-group "$resource_group" \
        --profile-name "$profile_name" \
        --origin-group-name "$ORIGIN_GROUP_NAME" \
        "${AZ_SHOW_FLAGS[@]}" \
        --query provisioningState \
        -o tsv; then
        return 1
    fi

    display_message "Creating origin '$ORIGIN_NAME'..." "blue"
    if ! az afd origin create \
        --resource-group "$resource_group" \
        --profile-name "$profile_name" \
        --origin-group-name "$ORIGIN_GROUP_NAME" \
        --origin-name "$ORIGIN_NAME" \
        --host-name "$ORIGIN_HOST" \
        --origin-host-header "$origin_host_header" \
        --priority "$ORIGIN_PRIORITY" \
        --weight "$ORIGIN_WEIGHT" \
        --http-port "$HTTP_PORT" \
        --https-port "$HTTPS_PORT" \
        --enabled-state Enabled \
        "${AZ_QUIET_FLAGS[@]}"; then
        display_message "Failed to create origin '$ORIGIN_NAME'." "red"
        return 1
    fi

    if ! wait_for_provisioning "Origin $ORIGIN_NAME" \
        az afd origin show \
        --resource-group "$resource_group" \
        --profile-name "$profile_name" \
        --origin-group-name "$ORIGIN_GROUP_NAME" \
        --origin-name "$ORIGIN_NAME" \
        "${AZ_SHOW_FLAGS[@]}" \
        --query provisioningState \
        -o tsv; then
        return 1
    fi

    display_message "Creating route '$ROUTE_NAME'..." "blue"
    if ! az afd route create \
        --resource-group "$resource_group" \
        --profile-name "$profile_name" \
        --endpoint-name "$endpoint_name" \
        --route-name "$ROUTE_NAME" \
        --origin-group "$ORIGIN_GROUP_NAME" \
        --supported-protocols Http Https \
        --patterns-to-match "/*" \
        --forwarding-protocol MatchRequest \
        --https-redirect Enabled \
        --link-to-default-domain Enabled \
        "${AZ_QUIET_FLAGS[@]}"; then
        display_message "Failed to create route '$ROUTE_NAME'." "red"
        return 1
    fi

    if ! wait_for_provisioning "Route $ROUTE_NAME" \
        az afd route show \
        --resource-group "$resource_group" \
        --profile-name "$profile_name" \
        --endpoint-name "$endpoint_name" \
        --route-name "$ROUTE_NAME" \
        "${AZ_SHOW_FLAGS[@]}" \
        --query provisioningState \
        -o tsv; then
        return 1
    fi

    local final_hostname
    if [[ "$AZ_DEBUG" == "true" ]]; then
    final_hostname=$(az afd endpoint show \
        --resource-group "$resource_group" \
        --profile-name "$profile_name" \
            --endpoint-name "$endpoint_name" \
            "${AZ_SHOW_FLAGS[@]}" \
            --query hostName \
            -o tsv || true)
    else
        final_hostname=$(az afd endpoint show \
            --resource-group "$resource_group" \
            --profile-name "$profile_name" \
            --endpoint-name "$endpoint_name" \
            "${AZ_SHOW_FLAGS[@]}" \
            --query hostName \
            -o tsv 2>/dev/null || true)
    fi

    display_message "--- Deployment Complete ---" "green"
    if [[ -n "$final_hostname" ]]; then
        display_message "Front Door endpoint: https://${final_hostname}" "green"
    else
        display_message "Front Door endpoint created; hostname lookup failed." "yellow"
    fi

    return 0
}

parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
    case "$1" in
            -H|--hostname)
                action_host="$2"
                shift 2
                ;;
            -l|--list)
                LIST_FILE="$2"
                shift 2
                ;;
            --location)
                LOCATION="$2"
                shift 2
                ;;
            --sku)
                SKU="$2"
                shift 2
                ;;
            --origin-host)
                ORIGIN_HOST="$2"
                shift 2
                ;;
            --origin-host-header)
                ORIGIN_HOST_HEADER="$2"
                shift 2
                ;;
            --resource-group)
                RESOURCE_GROUP="$2"
                shift 2
                ;;
            --rg-prefix)
                RESOURCE_GROUP_PREFIX="$2"
                shift 2
                ;;
            --profile-name)
                PROFILE_NAME="$2"
                PROFILE_NAME_EXPLICIT="true"
                shift 2
                ;;
            --endpoint-name)
                ENDPOINT_NAME="$2"
                ENDPOINT_NAME_EXPLICIT="true"
                shift 2
                ;;
            --origin-group-name)
                ORIGIN_GROUP_NAME="$2"
                shift 2
                ;;
            --origin-name)
                ORIGIN_NAME="$2"
                shift 2
                ;;
            --route-name)
                ROUTE_NAME="$2"
                shift 2
                ;;
            --probe-path)
                PROBE_PATH="$2"
                shift 2
                ;;
            --probe-protocol)
                PROBE_PROTOCOL="$2"
                shift 2
                ;;
            --probe-request-type)
                PROBE_REQUEST_TYPE="$2"
                shift 2
                ;;
            --probe-interval)
                PROBE_INTERVAL_SECONDS="$2"
                shift 2
                ;;
            --origin-priority)
                ORIGIN_PRIORITY="$2"
                shift 2
                ;;
            --origin-weight)
                ORIGIN_WEIGHT="$2"
                shift 2
                ;;
            --http-port)
                HTTP_PORT="$2"
                shift 2
                ;;
            --https-port)
                HTTPS_PORT="$2"
                shift 2
                ;;
            --wait-timeout)
                WAIT_TIMEOUT="$2"
                shift 2
                ;;
            --no-wait)
                NO_WAIT="true"
                shift 1
                ;;
            --debug)
                AZ_DEBUG="true"
                shift 1
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

    if [[ -n "$action_host" && -n "$LIST_FILE" ]]; then
        display_message "Choose either -H or -l, not both." "red"
        exit 1
    fi

    if [[ -z "$action_host" && -z "$LIST_FILE" ]]; then
        display_message "Missing required hostname or list file." "red"
        usage
        exit 1
    fi

    if [[ -n "$LIST_FILE" && -n "$RESOURCE_GROUP" ]]; then
        display_message "--resource-group can only be used with -H (single-host mode)." "red"
        exit 1
    fi
}

main() {
    parse_args "$@"
    if [[ "$AZ_DEBUG" == "true" ]]; then
        AZ_SHOW_FLAGS=(--debug)
        AZ_QUIET_FLAGS=(--debug)
    fi
    require_command az
    check_azure_authentication

    if [[ -n "$action_host" ]]; then
        create_frontdoor_for_hostname "$action_host"
        return 0
    fi

    if [[ ! -f "$LIST_FILE" ]]; then
        display_message "List file not found: $LIST_FILE" "red"
        exit 1
    fi

    local success_count=0
    local failure_count=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(trim_line "$line")
        if [[ -z "$line" || "$line" == \#* ]]; then
            continue
        fi

        display_message "Processing hostname: $line" "blue"
        if create_frontdoor_for_hostname "$line"; then
            success_count=$((success_count + 1))
        else
            failure_count=$((failure_count + 1))
            display_message "Failed to create Front Door for hostname: $line" "red"
        fi
    done < "$LIST_FILE"

    display_message "Batch run complete. Success: ${success_count}, Failed: ${failure_count}" "blue"

    if [[ "$failure_count" -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
