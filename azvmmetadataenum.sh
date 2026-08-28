#!/usr/bin/env bash

# Azure IMDS metadata enumerator / pentest triage helper.
#
# All network requests are GET requests to 169.254.169.254. The script bypasses
# proxies, rate-limits itself, displays issued access tokens, and dynamically
# falls back when a preferred API version is unavailable.
#
# Requires: bash, curl, jq, base64
# Optional: openssl (attested document extraction), sha256sum, file

set -u
set -o pipefail

readonly IMDS="http://169.254.169.254"
readonly PREFERRED_INSTANCE_VERSION="2025-11-15"
readonly FALLBACK_INSTANCE_VERSION="2025-04-07"
readonly IDENTITY_VERSION="2019-08-01"
readonly LOADBALANCER_VERSION="2020-10-01"
readonly EVENTS_VERSION="2020-07-01"
readonly ATTESTED_FALLBACK_VERSION="2025-04-07"

TIMEOUT=5
EVENT_TIMEOUT=10
REQUESTED_VERSION=""
IDENTITY_RESOURCES=(
    'https://management.azure.com/'
    'https://graph.microsoft.com/'
    'https://vault.azure.net'
    'https://storage.azure.com/'
)
EXTRA_IDENTITY_RESOURCE=""
IDENTITY_SELECTOR_NAME=""
IDENTITY_SELECTOR_VALUE=""
TRY_IDENTITY=1
SHOW_RAW=0
OUTPUT_DIR=""
USE_COLOR=1

usage() {
    cat <<'EOF'
Usage: metadataenum.sh [options]

Azure IMDS metadata enumeration using GET requests only.

Options:
  --api-version VERSION       Prefer this instance/attested API version.
  --timeout SECONDS           Normal request timeout (default: 5).
  --event-timeout SECONDS     Scheduled-events timeout (default: 10).
  --identity-resource URI     Request one additional token audience.
  --client-id ID              Select a user-assigned identity by client ID.
  --object-id ID              Select a user-assigned identity by object ID.
  --msi-res-id RESOURCE_ID    Select a user-assigned identity by ARM ID.
  --skip-identity             Do not request a managed-identity token.
  --raw                       Print complete raw JSON response bodies.
  --output-dir DIR            Save evidence JSON and request-index.tsv.
  --no-color                  Disable ANSI colors.
  -h, --help                  Show this help.

Examples:
  ./metadataenum.sh
  ./metadataenum.sh --raw --output-dir ./imds-evidence
  ./metadataenum.sh --client-id UUID
  ./metadataenum.sh --identity-resource https://database.windows.net/
EOF
}

die() {
    printf '[!] %s\n' "$*" >&2
    exit 1
}

is_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

while (($#)); do
    case "$1" in
        --api-version)
            (($# >= 2)) || die "--api-version requires a value"
            REQUESTED_VERSION="$2"
            shift 2
            ;;
        --timeout)
            (($# >= 2)) || die "--timeout requires a value"
            is_positive_integer "$2" || die "--timeout must be a positive integer"
            TIMEOUT="$2"
            shift 2
            ;;
        --event-timeout)
            (($# >= 2)) || die "--event-timeout requires a value"
            is_positive_integer "$2" || die "--event-timeout must be a positive integer"
            EVENT_TIMEOUT="$2"
            shift 2
            ;;
        --identity-resource)
            (($# >= 2)) || die "--identity-resource requires a value"
            EXTRA_IDENTITY_RESOURCE="$2"
            shift 2
            ;;
        --client-id|--object-id|--msi-res-id)
            (($# >= 2)) || die "$1 requires a value"
            [[ -z "$IDENTITY_SELECTOR_NAME" ]] || die "use only one identity selector"
            case "$1" in
                --client-id) IDENTITY_SELECTOR_NAME="client_id" ;;
                --object-id) IDENTITY_SELECTOR_NAME="object_id" ;;
                --msi-res-id) IDENTITY_SELECTOR_NAME="msi_res_id" ;;
            esac
            IDENTITY_SELECTOR_VALUE="$2"
            shift 2
            ;;
        --skip-identity)
            TRY_IDENTITY=0
            shift
            ;;
        --raw)
            SHOW_RAW=1
            shift
            ;;
        --output-dir)
            (($# >= 2)) || die "--output-dir requires a value"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-color)
            USE_COLOR=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1 (use --help)"
            ;;
    esac
done

for required in curl jq base64; do
    command -v "$required" >/dev/null 2>&1 || die "$required not found"
done

if [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then
    USE_COLOR=0
fi

if ((USE_COLOR)); then
    RED=$'\033[1;31m'
    GREEN=$'\033[1;32m'
    YELLOW=$'\033[1;33m'
    BLUE=$'\033[1;34m'
    MAGENTA=$'\033[1;35m'
    CYAN=$'\033[1;36m'
    WHITE=$'\033[1;37m'
    GRAY=$'\033[0;90m'
    RESET=$'\033[0m'
else
    RED="" GREEN="" YELLOW="" BLUE="" MAGENTA="" CYAN=""
    WHITE="" GRAY="" RESET=""
fi

section() {
    printf '\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BLUE" "$RESET"
    printf '%s%s%s\n' "$WHITE" "$1" "$RESET"
    printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BLUE" "$RESET"
}

high() { printf '%s[HIGH]%s %s\n' "$RED" "$RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*"; }
good() { printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$*"; }
info() { printf '%s[*]%s %s\n' "$CYAN" "$RESET" "$*"; }

value() {
    local label="$1" data="${2:-}"
    [[ -n "$data" && "$data" != "null" ]] || data="-"
    printf '%s%-30s%s %s\n' "$CYAN" "$label:" "$RESET" "$data"
}

TMP_DIR="$(mktemp -d)" || die "could not create temporary directory"
cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" && "$TMP_DIR" == /tmp/* ]]; then
        rm -rf -- "$TMP_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

REQUEST_INDEX="$TMP_DIR/request-index.tsv"
printf 'timestamp_utc\tlabel\thttp_status\tcurl_status\tbytes\tpath\n' >"$REQUEST_INDEX"

LAST_HTTP_CODE=""
LAST_CURL_STATUS=""
LAST_BYTES=""
LAST_ERROR=""

imds_get() {
    local label="$1" path="$2" destination="$3" request_timeout="${4:-$TIMEOUT}"
    local error_file="$TMP_DIR/curl-error" started
    started="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    : >"$error_file"

    LAST_HTTP_CODE="$(
        curl --silent --show-error --noproxy '*' \
            --connect-timeout "$TIMEOUT" --max-time "$request_timeout" \
            --request GET -H 'Metadata: true' \
            --output "$destination" --write-out '%{http_code}' \
            "$IMDS$path" 2>"$error_file"
    )"
    LAST_CURL_STATUS=$?
    LAST_BYTES="$(wc -c <"$destination" | tr -d ' ')"
    LAST_ERROR="$(tr '\n' ' ' <"$error_file")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$started" "$label" "${LAST_HTTP_CODE:-000}" "$LAST_CURL_STATUS" \
        "$LAST_BYTES" "$path" >>"$REQUEST_INDEX"
    sleep 0.22
}

imds_identity_get() {
    local resource="$1" destination="$2" error_file="$TMP_DIR/curl-error" started
    started="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    : >"$error_file"

    local -a curl_args=(
        --silent --show-error --noproxy '*'
        --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT"
        --request GET -H 'Metadata: true'
        --get --data-urlencode "api-version=$IDENTITY_VERSION"
        --data-urlencode "resource=$resource"
    )
    if [[ -n "$IDENTITY_SELECTOR_NAME" ]]; then
        curl_args+=(--data-urlencode "$IDENTITY_SELECTOR_NAME=$IDENTITY_SELECTOR_VALUE")
    fi

    LAST_HTTP_CODE="$(
        curl "${curl_args[@]}" --output "$destination" --write-out '%{http_code}' \
            "$IMDS/metadata/identity/oauth2/token" 2>"$error_file"
    )"
    LAST_CURL_STATUS=$?
    LAST_BYTES="$(wc -c <"$destination" | tr -d ' ')"
    LAST_ERROR="$(tr '\n' ' ' <"$error_file")"
    printf '%s\tidentity:%s\t%s\t%s\t%s\t%s\n' \
        "$started" "$resource" "${LAST_HTTP_CODE:-000}" "$LAST_CURL_STATUS" "$LAST_BYTES" \
        "/metadata/identity/oauth2/token?api-version=$IDENTITY_VERSION&resource=$resource" \
        >>"$REQUEST_INDEX"
    sleep 0.22
}

json_ok() {
    jq -e . "$1" >/dev/null 2>&1
}

copy_evidence() {
    local source="$1" name="$2"
    [[ -n "$OUTPUT_DIR" && -s "$source" ]] || return 0
    cp -- "$source" "$OUTPUT_DIR/$name"
}

if [[ -n "$OUTPUT_DIR" ]]; then
    mkdir -p -- "$OUTPUT_DIR" || die "could not create output directory: $OUTPUT_DIR"
    OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
fi

printf '%s' "$MAGENTA"
cat <<'EOF'
    _                      ___ __  ______  ____
   / \   _____   _______  |_ _|  \/  |  \/  / ___
  / _ \ |_  / | | | '__|  | || |\/| | |\/| |/ _ \
 / ___ \ / /| |_| | |     | || |  | | |  | |  __/
/_/   \_/___|\__,_|_|    |___|_|  |_|_|  |_|\___|

        Azure IMDS Metadata Enumerator
EOF
printf '%s' "$RESET"

section "0. REACHABILITY AND VERSION NEGOTIATION"

VERSIONS_FILE="$TMP_DIR/versions.json"
imds_get "versions" "/metadata/versions" "$VERSIONS_FILE"
if [[ "$LAST_HTTP_CODE" != "200" ]] || ! json_ok "$VERSIONS_FILE"; then
    die "IMDS versions endpoint unavailable (HTTP ${LAST_HTTP_CODE:-000}; ${LAST_ERROR:-no response})"
fi

ADVERTISED_VERSION="$(jq -r '.apiVersions // [] | sort | last // empty' "$VERSIONS_FILE")"
value "Newest advertised version" "$ADVERTISED_VERSION"
value "Preferred instance version" "${REQUESTED_VERSION:-$PREFERRED_INSTANCE_VERSION}"
high "IMDS is reachable without application authentication from this process."
printf '%s    This is expected Azure behavior; exposure becomes security-relevant when an untrusted%s\n' "$GRAY" "$RESET"
printf '%s    process or SSRF primitive can reach the link-local endpoint.%s\n' "$GRAY" "$RESET"

INSTANCE_FILE="$TMP_DIR/instance.json"
INSTANCE_VERSION="${REQUESTED_VERSION:-$PREFERRED_INSTANCE_VERSION}"
imds_get "instance" "/metadata/instance?api-version=$INSTANCE_VERSION" "$INSTANCE_FILE"
if [[ "$LAST_HTTP_CODE" != "200" ]] || ! jq -e '.compute and .network' "$INSTANCE_FILE" >/dev/null 2>&1; then
    warn "Instance API $INSTANCE_VERSION failed (HTTP ${LAST_HTTP_CODE:-000}); falling back."
    INSTANCE_VERSION="${ADVERTISED_VERSION:-$FALLBACK_INSTANCE_VERSION}"
    imds_get "instance-fallback" "/metadata/instance?api-version=$INSTANCE_VERSION" "$INSTANCE_FILE"
fi

if [[ "$LAST_HTTP_CODE" != "200" ]] || ! jq -e '.compute and .network' "$INSTANCE_FILE" >/dev/null 2>&1; then
    die "instance metadata unavailable (HTTP ${LAST_HTTP_CODE:-000}; ${LAST_ERROR:-invalid JSON})"
fi
value "Selected instance version" "$INSTANCE_VERSION"
if [[ -n "$ADVERTISED_VERSION" && "$INSTANCE_VERSION" != "$ADVERTISED_VERSION" ]]; then
    info "Selected version is accepted by this VM but differs from the versions endpoint."
fi

section "1. AZURE RESOURCE AND IDENTITY CONTEXT"

while IFS=$'\t' read -r label filter; do
    value "$label" "$(jq -r "$filter // empty" "$INSTANCE_FILE")"
done <<'EOF'
VM Name	.compute.name
Computer Name	.compute.osProfile.computerName
Admin Username	.compute.osProfile.adminUsername
Provider	.compute.provider
Resource Group	.compute.resourceGroupName
Subscription ID	.compute.subscriptionId
VM ID	.compute.vmId
Region	.compute.location
Azure Environment	.compute.azEnvironment
Resource ID	.compute.resourceId
EOF

high "The subscription, resource group, VM ID, and full ARM hierarchy are disclosed."
info "The admin username is useful for SSH, log, sudo-policy, and lateral-path review."

section "2. NETWORK AND LOAD-BALANCER CONTEXT"

value "NIC Count" "$(jq '.network.interface | length' "$INSTANCE_FILE")"
jq -r '.network.interface[]? |
    "MAC=\(.macAddress // "-") compartment=\(.interfaceCompartmentId // "-")"' \
    "$INSTANCE_FILE" | while IFS= read -r line; do good "$line"; done

jq -r '.network.interface[]?.ipv4.ipAddress[]? |
    [(.privateIpAddress // "-"), (.publicIpAddress // "-")] | @tsv' \
    "$INSTANCE_FILE" | while IFS=$'\t' read -r private_ip public_ip; do
        value "Private IPv4" "$private_ip"
        value "Public IPv4" "$public_ip"
    done

jq -r '.network.interface[]?.ipv4.subnet[]? |
    "\(.address // "-")/\(.prefix // "-")"' "$INSTANCE_FILE" \
    | while IFS= read -r subnet; do high "Local Azure subnet: $subnet"; done

jq -r '.network.interface[]?.ipv6.ipAddress[]?.privateIpAddress // empty' \
    "$INSTANCE_FILE" | while IFS= read -r ipv6; do value "Private IPv6" "$ipv6"; done

LB_FILE="$TMP_DIR/loadbalancer.json"
LB_VERSION="$INSTANCE_VERSION"
imds_get "loadbalancer" "/metadata/loadbalancer?api-version=$LB_VERSION" "$LB_FILE"
if [[ "$LAST_HTTP_CODE" != "200" ]] || ! json_ok "$LB_FILE"; then
    LB_VERSION="$LOADBALANCER_VERSION"
    imds_get "loadbalancer-fallback" "/metadata/loadbalancer?api-version=$LB_VERSION" "$LB_FILE"
fi

if [[ "$LAST_HTTP_CODE" == "200" ]] && json_ok "$LB_FILE"; then
    value "Load-balancer API" "$LB_VERSION"
    value "Frontend mappings" "$(jq '[.loadbalancer.publicIpAddresses[]?] | length' "$LB_FILE")"
    value "Inbound rules" "$(jq '[.loadbalancer.inboundRules[]?] | length' "$LB_FILE")"
    value "Outbound rules" "$(jq '[.loadbalancer.outboundRules[]?] | length' "$LB_FILE")"
    jq -r '.loadbalancer.publicIpAddresses[]? |
        "frontend=\(.frontendIpAddress // "-") private=\(.privateIpAddress // "-")"' \
        "$LB_FILE" | while IFS= read -r mapping; do high "Load balancer: $mapping"; done
else
    warn "Load-balancer metadata unavailable (HTTP ${LAST_HTTP_CODE:-000})."
fi

section "3. SECURITY POSTURE"

while IFS=$'\t' read -r label filter; do
    value "$label" "$(jq -r "$filter // empty" "$INSTANCE_FILE")"
done <<'EOF'
Security Type	.compute.securityProfile.securityType
Secure Boot	.compute.securityProfile.secureBootEnabled
Virtual TPM	.compute.securityProfile.virtualTpmEnabled
Encryption at Host	.compute.securityProfile.encryptionAtHost
SSH Password Disabled	.compute.osProfile.disablePasswordAuthentication
Host Compatibility Layer	.compute.isHostCompatibilityLayerVm
EOF

[[ "$(jq -r '.compute.securityProfile.secureBootEnabled // empty' "$INSTANCE_FILE")" == "false" ]] \
    && warn "Secure Boot is disabled."
[[ "$(jq -r '.compute.securityProfile.virtualTpmEnabled // empty' "$INSTANCE_FILE")" == "false" ]] \
    && warn "Virtual TPM is disabled."
[[ "$(jq -r '.compute.securityProfile.encryptionAtHost // empty' "$INSTANCE_FILE")" == "false" ]] \
    && warn "Encryption at host is disabled."
[[ "$(jq -r '.compute.osProfile.disablePasswordAuthentication // empty' "$INSTANCE_FILE")" == "false" ]] \
    && high "Azure OS profile indicates that SSH password authentication is enabled."

section "4. OS, IMAGE, PLAN, AND CAPABILITIES"

while IFS=$'\t' read -r label filter; do
    value "$label" "$(jq -r "$filter // empty" "$INSTANCE_FILE")"
done <<'EOF'
OS Type	.compute.osType
Publisher	.compute.publisher
Offer	.compute.offer
SKU	.compute.sku
Image Version	.compute.version
VM Size	.compute.vmSize
Image ID	.compute.storageProfile.imageReference.id
Image Publisher	.compute.storageProfile.imageReference.publisher
Image Offer	.compute.storageProfile.imageReference.offer
Image SKU	.compute.storageProfile.imageReference.sku
Image Requested Version	.compute.storageProfile.imageReference.version
Image Exact Version	.compute.storageProfile.imageReference.exactVersion
Community Gallery Image	.compute.storageProfile.imageReference.communityGalleryImageId
Shared Gallery Image	.compute.storageProfile.imageReference.sharedGalleryImageId
Plan Name	.compute.plan.name
Plan Product	.compute.plan.product
Plan Publisher	.compute.plan.publisher
License Type	.compute.licenseType
Hibernation Enabled	.compute.additionalCapabilities.hibernationEnabled
EOF

section "5. SSH PUBLIC KEYS"

KEY_COUNT="$(jq '.compute.publicKeys | length' "$INSTANCE_FILE")"
value "Configured public keys" "$KEY_COUNT"
jq -r '.compute.publicKeys[]? | [.path, .keyData] | @tsv' "$INSTANCE_FILE" \
    | while IFS=$'\t' read -r key_path key_data; do
        key_type="${key_data%% *}"
        key_comment="$(printf '%s\n' "$key_data" | awk '{$1=$2=""; sub(/^  */,""); print}')"
        printf '\n'
        value "Authorized Keys Path" "$key_path"
        value "Key Type" "$key_type"
        value "Key Comment" "$key_comment"
        if command -v ssh-keygen >/dev/null 2>&1; then
            key_file="$TMP_DIR/key-$RANDOM.pub"
            printf '%s\n' "$key_data" >"$key_file"
            value "Fingerprint" "$(ssh-keygen -lf "$key_file" 2>/dev/null | awk '{print $2 " " $4}')"
        fi
    done

section "6. TAGS AND ENVIRONMENT DISCLOSURE"

TAG_COUNT="$(jq '.compute.tagsList // [] | length' "$INSTANCE_FILE")"
value "Structured tags" "$TAG_COUNT"
if ((TAG_COUNT > 0)); then
    jq -r '.compute.tagsList[] | "    \(.name) = \(.value)"' "$INSTANCE_FILE"
else
    LEGACY_TAGS="$(jq -r '.compute.tags // empty' "$INSTANCE_FILE")"
    if [[ -n "$LEGACY_TAGS" ]]; then
        printf '%s\n' "$LEGACY_TAGS" | tr ';' '\n' | sed 's/^/    /'
    else
        good "No tags were returned."
    fi
fi
info "Review tags for environment names, owners, applications, backup IDs, and internal references."

decode_metadata_blob() {
    local label="$1" filter="$2" encoded_file="$TMP_DIR/$3.b64" decoded_file="$TMP_DIR/$3.decoded"
    jq -jr "$filter // empty" "$INSTANCE_FILE" >"$encoded_file"
    if [[ ! -s "$encoded_file" ]]; then
        good "No $label returned."
        return
    fi

    high "$label is present."
    if ! base64 -d <"$encoded_file" >"$decoded_file" 2>/dev/null; then
        warn "$label is not valid base64; raw encoded value remains available with --raw."
        return
    fi

    value "$label decoded bytes" "$(wc -c <"$decoded_file" | tr -d ' ')"
    if command -v sha256sum >/dev/null 2>&1; then
        value "$label SHA-256" "$(sha256sum "$decoded_file" | awk '{print $1}')"
    fi

    local mime=""
    command -v file >/dev/null 2>&1 && mime="$(file -b --mime "$decoded_file" 2>/dev/null || true)"
    value "$label content type" "$mime"
    if [[ "$mime" != *charset=binary* ]]; then
        printf '%sDecoded %s (first 200 lines):%s\n' "$WHITE" "$label" "$RESET"
        sed -n '1,200p' "$decoded_file" | sed 's/^/    /'
        if grep -Eiq '(pass(word)?|secret|token|api[_-]?key|client[_-]?secret|connectionstring|https?://)' "$decoded_file"; then
            high "$label contains credential- or endpoint-related keywords; review carefully."
        fi
    else
        warn "$label appears binary and was not printed to the terminal."
    fi
}

section "7. USER DATA AND CUSTOM DATA"
decode_metadata_blob "userData" '.compute.userData' "userdata"
decode_metadata_blob "customData" '.compute.customData' "customdata"

section "8. STORAGE AND KEY-VAULT REFERENCES"

jq -r '.compute.storageProfile.osDisk |
    ["Name", .name],
    ["OS type", .osType],
    ["Size GB", .diskSizeGB],
    ["Create option", .createOption],
    ["Caching", .caching],
    ["Storage type", .managedDisk.storageAccountType],
    ["Managed disk ID", .managedDisk.id],
    ["Ephemeral option", .diffDiskSettings.option],
    ["Ephemeral placement", .diffDiskSettings.placement],
    ["Full caching", .diffDiskSettings.enableFullCaching],
    ["Write accelerator", .writeAcceleratorEnabled]
    | @tsv' "$INSTANCE_FILE" | while IFS=$'\t' read -r label data; do value "OS Disk $label" "$data"; done

for filter in \
    '.compute.storageProfile.osDisk.encryptionSettings.diskEncryptionKey.sourceVault.id' \
    '.compute.storageProfile.osDisk.encryptionSettings.diskEncryptionKey.secretUrl' \
    '.compute.storageProfile.osDisk.encryptionSettings.keyEncryptionKey.sourceVault.id' \
    '.compute.storageProfile.osDisk.encryptionSettings.keyEncryptionKey.keyUrl'; do
    reference="$(jq -r "$filter // empty" "$INSTANCE_FILE")"
    [[ -z "$reference" ]] || high "Encryption/Key Vault reference: $reference"
done

value "Resource disk size" "$(jq -r '.compute.storageProfile.resourceDisk.size // empty' "$INSTANCE_FILE")"
value "Data disk count" "$(jq '.compute.storageProfile.dataDisks | length' "$INSTANCE_FILE")"
jq -r '.compute.storageProfile.dataDisks[]? |
    "LUN=\(.lun) name=\(.name) size=\(.diskSizeGB)GB type=\(.managedDisk.storageAccountType) " +
    "caching=\(.caching) shared=\(.isSharedDisk) ultra=\(.isUltraDisk) " +
    "IOPS=\(.opsPerSecondThrottle) BPS=\(.bytesPerSecondThrottle) ID=\(.managedDisk.id)"' \
    "$INSTANCE_FILE" | while IFS= read -r disk; do info "$disk"; done

section "9. TOPOLOGY AND PLACEMENT"

while IFS=$'\t' read -r label filter; do
    value "$label" "$(jq -r "$filter // empty" "$INSTANCE_FILE")"
done <<'EOF'
VM Scale Set	.compute.vmScaleSetName
VMSS Resource ID	.compute.virtualMachineScaleSet.id
Placement Group	.compute.placementGroupId
Host ID	.compute.host.id
Host Group	.compute.hostGroup.id
Interconnect Group	.compute.interconnectGroupId
Interconnect Subgroup	.compute.interconnectSubgroupId
Zone	.compute.zone
Physical Zone	.compute.physicalZone
Fault Domain	.compute.platformFaultDomain
Sub-Fault Domain	.compute.platformSubFaultDomain
System Fault Domain	.compute.systemFaultDomain
Update Domain	.compute.platformUpdateDomain
Priority	.compute.priority
Eviction Policy	.compute.evictionPolicy
In Standby Pool	.compute.isVmInStandbyPool
Extended Location Name	.compute.extendedLocation.name
Extended Location Type	.compute.extendedLocation.type
EOF

[[ "$(jq -r '.compute.priority // empty' "$INSTANCE_FILE")" =~ [Ss]pot ]] \
    && high "This appears to be a Spot VM."

section "10. ATTESTED METADATA"

ATTESTED_FILE="$TMP_DIR/attested.json"
ATTESTED_VERSION="$INSTANCE_VERSION"
imds_get "attested" "/metadata/attested/document?api-version=$ATTESTED_VERSION" "$ATTESTED_FILE"
if [[ "$LAST_HTTP_CODE" != "200" ]] || ! jq -e '.signature' "$ATTESTED_FILE" >/dev/null 2>&1; then
    ATTESTED_VERSION="$ATTESTED_FALLBACK_VERSION"
    imds_get "attested-fallback" "/metadata/attested/document?api-version=$ATTESTED_VERSION" "$ATTESTED_FILE"
fi

if [[ "$LAST_HTTP_CODE" == "200" ]] && jq -e '.signature' "$ATTESTED_FILE" >/dev/null 2>&1; then
    value "Attested API" "$ATTESTED_VERSION"
    value "Encoding" "$(jq -r '.encoding // empty' "$ATTESTED_FILE")"
    value "Signature base64 bytes" "$(jq -r '.signature | length' "$ATTESTED_FILE")"
    ATTESTED_DER="$TMP_DIR/attested.der"
    jq -jr '.signature' "$ATTESTED_FILE" | base64 -d >"$ATTESTED_DER" 2>/dev/null || true
    if command -v sha256sum >/dev/null 2>&1 && [[ -s "$ATTESTED_DER" ]]; then
        value "PKCS#7 SHA-256" "$(sha256sum "$ATTESTED_DER" | awk '{print $1}')"
    fi
    if command -v openssl >/dev/null 2>&1 && [[ -s "$ATTESTED_DER" ]]; then
        ATTESTED_CONTENT="$TMP_DIR/attested-content.json"
        if openssl cms -verify -inform DER -in "$ATTESTED_DER" -noverify \
            -out "$ATTESTED_CONTENT" >/dev/null 2>&1; then
            good "PKCS#7 signature integrity verified (certificate chain trust not validated)."
            if json_ok "$ATTESTED_CONTENT"; then
                jq . "$ATTESTED_CONTENT"
                copy_evidence "$ATTESTED_CONTENT" "attested-content.json"
            fi
        else
            warn "Could not extract/verify the PKCS#7 attested document with OpenSSL."
        fi
    fi
else
    warn "Attested metadata unavailable (HTTP ${LAST_HTTP_CODE:-000})."
fi

section "11. SCHEDULED EVENTS"

EVENTS_FILE="$TMP_DIR/scheduledevents.json"
imds_get "scheduledevents" "/metadata/scheduledevents?api-version=$EVENTS_VERSION" \
    "$EVENTS_FILE" "$EVENT_TIMEOUT"
if [[ "$LAST_HTTP_CODE" == "200" ]] && json_ok "$EVENTS_FILE"; then
    EVENT_COUNT="$(jq '.Events // [] | length' "$EVENTS_FILE")"
    value "Scheduled events" "$EVENT_COUNT"
    if ((EVENT_COUNT > 0)); then
        high "Azure infrastructure events are pending."
        jq '.Events' "$EVENTS_FILE"
    fi
elif [[ "$LAST_CURL_STATUS" == "28" ]]; then
    warn "Scheduled-events request timed out after ${EVENT_TIMEOUT}s; state remains unknown."
else
    warn "Scheduled-events metadata unavailable (HTTP ${LAST_HTTP_CODE:-000})."
    json_ok "$EVENTS_FILE" && jq . "$EVENTS_FILE"
fi

section "12. MANAGED IDENTITY"

if ((TRY_IDENTITY)); then
    if [[ -n "$EXTRA_IDENTITY_RESOURCE" ]]; then
        IDENTITY_RESOURCES+=("$EXTRA_IDENTITY_RESOURCE")
    fi
    for IDENTITY_RESOURCE in "${IDENTITY_RESOURCES[@]}"; do
        IDENTITY_LABEL="$(sed 's#^https\?://##; s#[^A-Za-z0-9._-]#-#g; s#-$##' <<<"$IDENTITY_RESOURCE")"
        IDENTITY_FILE="$TMP_DIR/identity-${IDENTITY_LABEL}.json"
        IDENTITY_REDACTED_FILE="$TMP_DIR/identity-${IDENTITY_LABEL}-redacted.json"
        TOKEN_CLAIMS_FILE="$TMP_DIR/identity-${IDENTITY_LABEL}-claims.json"
        warn "Requesting a managed-identity token for $IDENTITY_RESOURCE."
        imds_identity_get "$IDENTITY_RESOURCE" "$IDENTITY_FILE"
        if [[ "$LAST_HTTP_CODE" == "200" ]] && jq -e '.access_token' "$IDENTITY_FILE" >/dev/null 2>&1; then
            TOKEN="$(jq -r '.access_token' "$IDENTITY_FILE")"
            jq '.access_token = "[REDACTED]"' "$IDENTITY_FILE" >"$IDENTITY_REDACTED_FILE"
            high "A managed identity token was issued for $IDENTITY_RESOURCE."
            jq '{token_type,resource,expires_on,not_before,client_id,object_id,msi_res_id}' "$IDENTITY_FILE"
            printf '%s[SENSITIVE TOKEN: %s]%s %s\n' "$RED" "$IDENTITY_RESOURCE" "$RESET" "$TOKEN"
            if command -v sha256sum >/dev/null 2>&1; then
                value "Token SHA-256" "$(printf '%s' "$TOKEN" | sha256sum | awk '{print $1}')"
            fi

            JWT_PAYLOAD="${TOKEN#*.}"
            JWT_PAYLOAD="${JWT_PAYLOAD%%.*}"
            case $((${#JWT_PAYLOAD} % 4)) in
                2) JWT_PAYLOAD="${JWT_PAYLOAD}==" ;;
                3) JWT_PAYLOAD="${JWT_PAYLOAD}=" ;;
            esac
            printf '%s' "$JWT_PAYLOAD" | tr '_-' '/+' | base64 -d >"$TOKEN_CLAIMS_FILE" 2>/dev/null || true
            if json_ok "$TOKEN_CLAIMS_FILE"; then
                printf '%sJWT claims:%s\n' "$WHITE" "$RESET"
                jq '{aud,iss,tid,oid,appid,azp,idtyp,xms_mirid,roles,scp,nbf,exp}' "$TOKEN_CLAIMS_FILE"
                copy_evidence "$TOKEN_CLAIMS_FILE" "identity-${IDENTITY_LABEL}-token-claims.json"
            fi
            unset TOKEN JWT_PAYLOAD
            copy_evidence "$IDENTITY_REDACTED_FILE" "identity-${IDENTITY_LABEL}-redacted.json"
        else
            value "Identity HTTP status ($IDENTITY_RESOURCE)" "${LAST_HTTP_CODE:-000}"
            if json_ok "$IDENTITY_FILE"; then
                jq . "$IDENTITY_FILE"
            else
                warn "Identity endpoint did not return JSON (${LAST_ERROR:-no response})."
            fi
            info "Identity not found may mean no identity is assigned, or the selected identity is invalid."
        fi
    done
else
    info "Managed-identity request skipped by operator."
fi

section "13. IMDS REQUEST-GUARD CHECKS"

NO_HEADER_FILE="$TMP_DIR/no-header.json"
started="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
NO_HEADER_CODE="$(curl --silent --noproxy '*' --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
    --request GET --output "$NO_HEADER_FILE" --write-out '%{http_code}' \
    "$IMDS/metadata/instance?api-version=$INSTANCE_VERSION" 2>/dev/null || true)"
printf '%s\tguard-no-metadata-header\t%s\t-\t%s\t%s\n' "$started" "${NO_HEADER_CODE:-000}" \
    "$(wc -c <"$NO_HEADER_FILE" | tr -d ' ')" "/metadata/instance?api-version=$INSTANCE_VERSION" >>"$REQUEST_INDEX"
sleep 0.22

XFF_FILE="$TMP_DIR/x-forwarded-for.json"
started="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
XFF_CODE="$(curl --silent --noproxy '*' --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
    --request GET -H 'Metadata: true' -H 'X-Forwarded-For: 127.0.0.1' \
    --output "$XFF_FILE" --write-out '%{http_code}' \
    "$IMDS/metadata/instance?api-version=$INSTANCE_VERSION" 2>/dev/null || true)"
printf '%s\tguard-x-forwarded-for\t%s\t-\t%s\t%s\n' "$started" "${XFF_CODE:-000}" \
    "$(wc -c <"$XFF_FILE" | tr -d ' ')" "/metadata/instance?api-version=$INSTANCE_VERSION" >>"$REQUEST_INDEX"

value "Without Metadata:true" "HTTP ${NO_HEADER_CODE:-000}"
value "With X-Forwarded-For" "HTTP ${XFF_CODE:-000}"
if [[ "$NO_HEADER_CODE" != "200" ]]; then
    good "Metadata header requirement is enforced."
else
    high "Instance metadata was returned without the Metadata:true header."
fi
if [[ "$XFF_CODE" != "200" ]]; then
    good "X-Forwarded-For requests are rejected."
else
    high "Instance metadata was returned despite X-Forwarded-For."
fi

section "14. COMPLETE FIELD INVENTORY"

value "Compute leaf fields" "$(jq '[.compute | paths(scalars)] | length' "$INSTANCE_FILE")"
value "Network leaf fields" "$(jq '[.network | paths(scalars)] | length' "$INSTANCE_FILE")"
jq -r 'paths(scalars) as $p |
    [($p | map(if type == "number" then "[\(.)]" else tostring end) | join(".")),
     (getpath($p) | tostring)] | @tsv' "$INSTANCE_FILE" \
    | while IFS=$'\t' read -r path data; do printf '    %-72s %s\n' "$path" "$data"; done

if ((SHOW_RAW)); then
    section "15. RAW IMDS RESPONSES"
    printf '%sInstance metadata:%s\n' "$WHITE" "$RESET"
    jq . "$INSTANCE_FILE"
    if json_ok "$LB_FILE"; then
        printf '%sLoad-balancer metadata:%s\n' "$WHITE" "$RESET"
        jq . "$LB_FILE"
    fi
    if json_ok "$EVENTS_FILE"; then
        printf '%sScheduled-events metadata:%s\n' "$WHITE" "$RESET"
        jq . "$EVENTS_FILE"
    fi
    printf '%sVersions:%s\n' "$WHITE" "$RESET"
    jq . "$VERSIONS_FILE"
fi

copy_evidence "$VERSIONS_FILE" "versions.json"
copy_evidence "$INSTANCE_FILE" "instance.json"
copy_evidence "$LB_FILE" "loadbalancer.json"
copy_evidence "$EVENTS_FILE" "scheduledevents.json"
copy_evidence "$ATTESTED_FILE" "attested.json"

section "EVIDENCE INDEX AND PRIORITIES"

column -t -s $'\t' "$REQUEST_INDEX" 2>/dev/null || sed -n '1,200p' "$REQUEST_INDEX"
if [[ -n "$OUTPUT_DIR" ]]; then
    cp -- "$REQUEST_INDEX" "$OUTPUT_DIR/request-index.tsv"
    good "Evidence saved under $OUTPUT_DIR"
fi

printf '\n%sPrioritized next tests:%s\n' "$WHITE" "$RESET"
printf '  1. Review decoded user/custom data and tags for secrets and internal endpoints.\n'
printf '  2. Map disclosed private addresses/subnets only where they are in assessment scope.\n'
printf '  3. If identity exists, enumerate Azure RBAC with the redacted identity context.\n'
printf '  4. Review Key Vault/disk-key references and load-balancer mappings.\n'
printf '  5. Compare Secure Boot, vTPM, encryption-at-host, and SSH posture to policy.\n'
printf '  6. Treat IMDS reachability as impactful only when paired with untrusted local code or SSRF.\n'

good "IMDS metadata enumeration complete."
