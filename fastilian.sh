#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_LOCATION="germanywestcentral"
readonly DEFAULT_VM_SIZE="Standard_B2ats_v2"
readonly DEFAULT_IMAGE="Debian:debian-13:13-gen2:latest"
readonly RG_PREFIX="fastilian-"
readonly CREATOR_TAG="fastilian"

LOCATION="$DEFAULT_LOCATION"
VM_SIZE="$DEFAULT_VM_SIZE"
VM_IMAGE="$DEFAULT_IMAGE"

PROJECT_NAME=""
RESOURCE_GROUP=""
VM_NAME=""
NSG_NAME=""
PUBLIC_IP=""
ADMIN_USERNAME=""
ADMIN_PASSWORD=""

# Ensure Azure CLI uses the current session's context instead of creating .azure in the working directory.
AZURE_CONFIG_DIR="${AZURE_CONFIG_DIR:-$HOME/.azure}"
export AZURE_CONFIG_DIR

usage() {
    cat <<EOF
Fastilian - minimal Azure VM creator with DNS label support

Usage:
  ./fastilian.sh --name <vm-name> [options]

Required:
  -name, --name, -n
      VM name and Public IP DNS label (must be unique within the region).
      Example name: avatarprodeastuscluster

Optional:
  --location <region>
      Azure location/region for the resource group and VM.
      This determines the DNS zone:
      <name>.<location>.cloudapp.azure.com
      Default: ${LOCATION}

  --vm-size <sku>
      Azure VM size/SKU.
      Default: ${VM_SIZE}

  --image <urn>
      Azure image URN.
      Default: ${VM_IMAGE}

  -h, --help
      Show this help and exit.

Behavior:
  - Creates a resource group named: ${RG_PREFIX}<name>-rg
  - Creates a VM named exactly: <name>
  - Configures an NSG that allows all inbound and outbound traffic
  - Waits for VM agent readiness and checks SSH availability

Examples:
  ./fastilian.sh --name avatarprodeastuscluster --location eastus
  ./fastilian.sh -n myvm --vm-size Standard_B2ats_v2
  ./fastilian.sh --name testvm --image Debian:debian-13:13-gen2:latest
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
    if ! az account show --only-show-errors >/dev/null 2>&1; then
        display_message "Authenticate to Azure first: az login --use-device-code" "red"
        exit 1
    fi
}

validate_project_name() {
    local name="$1"
    if [[ -z "$name" ]]; then
        display_message "Project name cannot be empty." "red"
        exit 1
    fi

    if [[ ! "$name" =~ ^[a-zA-Z0-9-]+$ ]]; then
        display_message "Project name must contain only letters, numbers, or hyphens." "red"
        exit 1
    fi
}

generate_random_password() {
    tr -dc 'A-Za-z0-9!@#%^&*' < /dev/urandom | head -c 24 || true
}

generate_random_username() {
    local suffix
    suffix=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 6 || true)
    printf 'fast%s' "$suffix"
}

create_resource_group() {
    display_message "Creating resource group '$RESOURCE_GROUP' in $LOCATION..." "blue"
    az group create \
        --name "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --tags createdBy="$CREATOR_TAG" project="$PROJECT_NAME" \
        --only-show-errors >/dev/null
}

create_nsg() {
    display_message "Creating network security group '$NSG_NAME'..." "blue"
    az network nsg create \
        --name "$NSG_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --only-show-errors >/dev/null
}

configure_nsg_rules_allow_all() {
    display_message "Configuring NSG rules (allow all inbound/outbound)..." "blue"

    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$NSG_NAME" \
        --name "AllowAllInbound" \
        --priority 100 \
        --direction Inbound \
        --access Allow \
        --protocol '*' \
        --source-address-prefixes '*' \
        --source-port-ranges '*' \
        --destination-address-prefixes '*' \
        --destination-port-ranges '*' \
        --only-show-errors >/dev/null

    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$NSG_NAME" \
        --name "AllowAllOutbound" \
        --priority 100 \
        --direction Outbound \
        --access Allow \
        --protocol '*' \
        --source-address-prefixes '*' \
        --source-port-ranges '*' \
        --destination-address-prefixes '*' \
        --destination-port-ranges '*' \
        --only-show-errors >/dev/null
}

wait_for_vm_power_state() {
    local desired_state="$1"
    local message="$2"

    display_message "$message" "blue"
    while true; do
        local state
        state=$(az vm get-instance-view \
            --resource-group "$RESOURCE_GROUP" \
            --name "$VM_NAME" \
            --query "instanceView.statuses[?starts_with(code,'PowerState/')].code" \
            -o tsv)

        if [[ "$state" == "$desired_state" ]]; then
            display_message "VM reached state $desired_state." "green"
            break
        fi

        display_message "Current state: ${state:-unknown}. Waiting 10 seconds..." "yellow"
        sleep 10
    done
}

wait_for_vm_agent_ready() {
    display_message "Waiting for VM agent to report ProvisioningState/succeeded ..." "blue"
    while true; do
        local agent_status
        agent_status=$(az vm get-instance-view \
            --resource-group "$RESOURCE_GROUP" \
            --name "$VM_NAME" \
            --query "instanceView.vmAgent.statuses[?code=='ProvisioningState/succeeded'].displayStatus" \
            -o tsv)

        if [[ "$agent_status" == "Ready" ]]; then
            display_message "VM agent is Ready." "green"
            return
        fi

        display_message "VM agent still provisioning. Sleeping 15 seconds..." "yellow"
        sleep 15
    done
}

retrieve_public_ip() {
    PUBLIC_IP=$(az vm show \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        -d \
        --query "publicIps" \
        -o tsv)
}

wait_for_ssh() {
    local attempts=20
    for ((i=1; i<=attempts; i++)); do
        if command -v timeout >/dev/null 2>&1; then
            if timeout 5 bash -c "echo > /dev/tcp/${PUBLIC_IP}/22" >/dev/null 2>&1; then
                display_message "SSH port is reachable." "green"
                return 0
            fi
        else
            if bash -c "echo > /dev/tcp/${PUBLIC_IP}/22" >/dev/null 2>&1; then
                display_message "SSH port is reachable." "green"
                return 0
            fi
        fi
        display_message "SSH not reachable yet (attempt ${i}/${attempts}). Sleeping 10s..." "yellow"
        sleep 10
    done
    display_message "SSH port did not open in time." "red"
    return 1
}

print_connection_details() {
    cat <<EOF

Connect to your VM with the following details:
  Resource Group : $RESOURCE_GROUP
  VM Name        : $VM_NAME
  Location       : $LOCATION
  Public IP      : $PUBLIC_IP
  Username       : $ADMIN_USERNAME
  Password       : $ADMIN_PASSWORD

Suggested SSH command:
  sshpass -p "$ADMIN_PASSWORD" ssh -o StrictHostKeyChecking=no "$ADMIN_USERNAME@$PUBLIC_IP"
EOF
}

attempt_auto_ssh() {
    if ! command -v sshpass >/dev/null 2>&1; then
        display_message "sshpass not installed; showing SSH command instead of auto-connecting." "yellow"
        print_connection_details
        return
    fi

    display_message "Attempting automatic SSH login using sshpass..." "blue"
    if sshpass -p "$ADMIN_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$ADMIN_USERNAME@$PUBLIC_IP"; then
        display_message "SSH session closed." "green"
    else
        display_message "Automatic SSH attempt failed. Use the suggested command manually." "red"
        print_connection_details
    fi
}

parse_args() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -name|--name|-n)
                PROJECT_NAME="$2"
                shift 2
                ;;
            --location)
                LOCATION="$2"
                shift 2
                ;;
            --vm-size)
                VM_SIZE="$2"
                shift 2
                ;;
            --image)
                VM_IMAGE="$2"
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

    if [[ -z "$PROJECT_NAME" ]]; then
        display_message "Missing required arguments." "red"
        usage
        exit 1
    fi
}

main() {
    parse_args "$@"
    require_command az
    PROJECT_NAME=$(echo "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]')
    validate_project_name "$PROJECT_NAME"
    check_azure_authentication

    RESOURCE_GROUP="${RG_PREFIX}${PROJECT_NAME}-rg"
    VM_NAME="$PROJECT_NAME"
    NSG_NAME="${RG_PREFIX}${PROJECT_NAME}-nsg"

    if az group exists --name "$RESOURCE_GROUP" --only-show-errors | grep -iq true; then
        display_message "Resource group '$RESOURCE_GROUP' already exists. Choose a different project name." "red"
        exit 1
    fi

    ADMIN_USERNAME=$(generate_random_username)
    ADMIN_PASSWORD=$(generate_random_password)

    create_resource_group
    create_nsg
    configure_nsg_rules_allow_all

    display_message "Starting VM deployment..." "blue"
    PUBLIC_IP=$(az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --image "$VM_IMAGE" \
        --size "$VM_SIZE" \
        --nsg "$NSG_NAME" \
        --public-ip-address-dns-name "$PROJECT_NAME" \
        --admin-username "$ADMIN_USERNAME" \
        --admin-password "$ADMIN_PASSWORD" \
        --authentication-type password \
        --enable-secure-boot false \
        --public-ip-sku Standard \
        --tags createdBy="$CREATOR_TAG" project="$PROJECT_NAME" \
        --only-show-errors \
        --query "publicIpAddress" \
        -o tsv)

    wait_for_vm_power_state "PowerState/running" "Waiting for VM to enter 'running' state..."
    wait_for_vm_agent_ready
    retrieve_public_ip

    print_connection_details
    if wait_for_ssh; then
        attempt_auto_ssh
    else
        display_message "Skipping automatic SSH because the port is still closed." "yellow"
    fi
}

main "$@"
