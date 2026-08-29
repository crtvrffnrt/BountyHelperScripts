#!/usr/bin/env bash
# Azure Storage name and endpoint enumeration. Findings are URL-only stdout;
# progress is sent to stderr so stdout can be piped directly into a file.
set -uo pipefail

readonly TIMEOUT=4 PARALLEL=32
SEARCH="" TMP_DIR="" DONE_WORK=0
declare -A BASE_STATUS BASE_LENGTH
BASE_WORDS=(dev development prod production test testing qa uat stage staging preprod preview demo sandbox lab poc pilot temp tmp old new backup backups archive data files file blob blobs storage store assets static media images documents docs upload uploads download downloads logs logging audit security internal external public private shared customer customers client clients migration migrate terraform infra infrastructure ops devops build release artifact artifacts package packages deploy deployment ci cd cicd monitor analytics reports export exports import imports database db sql etl datalake raw processed landing input output cache cdn azure az cloud platform services svc resource resources primary secondary common core main frontend backend function functions automation secrets east west north south central eu europe germany ger weu westeu northeu neu nwe prodde prodeu)
NUMBERS=(1 2 3 01 02 03 001 002 2024 2025 2026 2027)
REGIONS=(weu westeu neu northeu cee eus eastus westus centralus germany eu)
LEGAL=(ag gmbh ug se inc corp ltd llc group holding company co cloud)
ENDPOINTS=(blob:blob.core.windows.net web:web.core.windows.net dfs:dfs.core.windows.net file:file.core.windows.net queue:queue.core.windows.net table:table.core.windows.net blob:blob.core.chinacloudapi.cn web:web.core.chinacloudapi.cn dfs:dfs.core.chinacloudapi.cn blob:blob.core.usgovcloudapi.net web:web.core.usgovcloudapi.net dfs:dfs.core.usgovcloudapi.net blob:blob.core.cloudapi.de web:web.core.cloudapi.de dfs:dfs.core.cloudapi.de)

usage() { printf 'Usage: %s -s <string>\n' "${0##*/}" >&2; }
fail() { printf '%s\n' "$1" >&2; usage; exit 2; }
progress() {
  local width=37 filled i bar=""
  filled=$((DONE_WORK % (width + 1)))
  for ((i=0;i<filled;i++)); do bar+="#"; done
  for ((i=filled;i<width;i++)); do bar+="."; done
  printf '\r%s' "$bar" >&2
}
tick() { ((DONE_WORK++)); ((DONE_WORK % 32 == 0)) && progress; }
cleanup() { local status=$?; [[ -n ${TMP_DIR:-} && -d $TMP_DIR ]] && rm -rf -- "$TMP_DIR"; printf '\n' >&2; exit "$status"; }
trap cleanup EXIT
trap 'exit 130' INT TERM

valid_name() { [[ $1 =~ ^[a-z0-9]{3,24}$ ]]; }
normalize() { local value=${1,,}; value=${value//[^a-z0-9]/}; valid_name "$value" && printf '%s\n' "$value"; }
words() { printf '%s' "$SEARCH" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9][^a-z0-9]*/ /g'; }
add_name() { local value; value=$(normalize "$1" 2>/dev/null || true); [[ -n $value ]] && printf '%s\n' "$value"; }

core_stems() {
  local joined singular stripped suffix word initials="" first="" last=""
  joined=$(normalize "$SEARCH" 2>/dev/null || true); [[ -n $joined ]] || return 0
  add_name "$joined"
  while read -r word; do [[ -n $word ]] || continue; initials+="${word:0:1}"; [[ -n $first ]] && : || first=$word; last=$word; done < <(words)
  add_name "$initials"; add_name "$first$last"; add_name "$last$first"
  singular=$joined; [[ $singular == *s && ${#singular} -gt 3 ]] && singular=${singular%s}; add_name "$singular"
  for suffix in "${LEGAL[@]}"; do
    if [[ $joined == *"$suffix" && ${#joined} -gt ${#suffix} ]]; then stripped=${joined%"$suffix"}; add_name "$stripped"; fi
    add_name "${joined}${suffix}"
  done
  add_name "${joined:0:3}"; add_name "${joined:0:6}"; add_name "${joined:0:10}"
}

phase1() {
  local a b; core_stems; mapfile -t _phase_words < <(words)
  for a in "${_phase_words[@]}"; do add_name "$a"; done
  for a in "${_phase_words[@]}"; do for b in "${_phase_words[@]}"; do [[ $a != "$b" ]] && add_name "$a$b" && add_name "$b$a"; done; done
}
phase2() {
  local stem word number
  while read -r stem; do [[ -n $stem ]] || continue
    for word in "${BASE_WORDS[@]}"; do add_name "$stem$word"; add_name "$word$stem"; done
    for number in "${NUMBERS[@]}"; do add_name "$stem$number"; add_name "${number}${stem}"; done
  done < "$TMP_DIR/phase1-candidates.txt"
}
phase3() {
  local a b c region; mapfile -t _phase_words < <(words)
  for a in "${_phase_words[@]}"; do for b in "${BASE_WORDS[@]}"; do
    add_name "$a$b"; add_name "$b$a"
    for region in "${REGIONS[@]}"; do add_name "$a$b$region"; add_name "$region$a$b"; done
  done; done
  if ((${#_phase_words[@]} >= 3)); then
    a=${_phase_words[0]}; b=${_phase_words[1]}; c=${_phase_words[2]}
    add_name "$a$b$c"; add_name "$a$c$b"; add_name "$b$a$c"; add_name "$b$c$a"; add_name "$c$a$b"; add_name "$c$b$a"
  fi
}
phase4() {
  local stem word number region suffix
  while read -r stem; do [[ -n $stem ]] || continue
    for word in dev prod test qa stage uat data web api app internal public backup; do for number in "${NUMBERS[@]}"; do
      add_name "$stem$word$number"; add_name "$word$stem$number"; add_name "$stem$number$word"
    done; done
    for region in "${REGIONS[@]}"; do add_name "$stem$region"; add_name "$region$stem"; for suffix in "${LEGAL[@]}"; do add_name "$stem$region$suffix"; done; done
  done < "$TMP_DIR/core.txt"
}
phase5() {
  local stem word v1 v2
  while read -r stem; do [[ -n $stem ]] || continue
    v1=${stem//oo/u}; v1=${v1//ee/e}; v1=${v1//aa/a}; v2=${stem//company/co}; v2=${v2//corporation/corp}
    add_name "$v1"; add_name "$v2"
    for word in "${BASE_WORDS[@]}"; do add_name "$v1$word"; add_name "$word$v1"; add_name "$v2$word"; add_name "$word$v2"; done
  done < "$TMP_DIR/core.txt"
}

endpoint_count_for_phase() { case $1 in 1) printf '2\n';; 2) printf '%s\n' "${#ENDPOINTS[@]}";; *) printf '%s\n' "$(( ${#ENDPOINTS[@]}*2 ))";; esac; }
make_baselines() {
  local definition domain scheme control url status length key
  control="azzz$(tr -dc 'a-z0-9' < /dev/urandom | head -c 14)"
  for definition in "${ENDPOINTS[@]}"; do
    domain=${definition#*:}
    for scheme in https http; do
      url="$scheme://${control}.${domain}/"
      read -r status length < <(curl -ksS --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" -o /dev/null -w '%{http_code} %{size_download}' "$url" 2>/dev/null || printf '000 0\n')
      key="$scheme|$domain"
      BASE_STATUS["$key"]=${status:-000}; BASE_LENGTH["$key"]=${length:-0}
    done
  done
}
probe_url() {
  local url=$1 scheme=$2 domain=$3 status length key base_status base_length
  key="$scheme|$domain"
  read -r status length < <(curl -ksS --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" -o /dev/null -w '%{http_code} %{size_download}' "$url" 2>/dev/null || printf '000 0\n')
  base_status=${BASE_STATUS[$key]:-000}; base_length=${BASE_LENGTH[$key]:-0}
  if [[ ${status:-000} != 000 && ( ${base_status:-000} == 000 || ${status:-000} != "${base_status:-000}" || ${length:-0} != "${base_length:-0}" ) ]]; then printf '%s\n' "$url"; fi
}
probe_candidates() {
  local phase=$1 candidates=$2 limit index candidate definition domain scheme url result seq=0 pending=0 pid
  local -a pids=() results=()
  limit=$(endpoint_count_for_phase "$phase")
  while read -r candidate; do [[ -n $candidate ]] || continue; index=0
    for definition in "${ENDPOINTS[@]}"; do ((index++)); ((index > limit)) && break; domain=${definition#*:}
      for scheme in https $([[ $phase -ge 3 ]] && printf 'http'); do
        [[ -n $scheme ]] || continue; url="$scheme://${candidate}.${domain}/"; result="$TMP_DIR/result-$phase-$seq"; ((seq++))
        probe_url "$url" "$scheme" "$domain" > "$result" & pids+=("$!"); results+=("$result"); ((pending++))
        if ((pending >= PARALLEL)); then
          for pid in "${pids[@]}"; do wait "$pid" || true; done
          for result in "${results[@]}"; do cat "$result"; done
          pids=(); results=(); pending=0
          tick
        fi
      done
    done
  done < "$candidates"
  if ((pending)); then
    for pid in "${pids[@]}"; do wait "$pid" || true; done
    for result in "${results[@]}"; do cat "$result"; done
    tick
  fi
}
run_phase() {
  local phase=$1 candidate_file="$TMP_DIR/phase${1}-candidates.txt" result_file="$TMP_DIR/phase${1}-urls.txt"
  probe_candidates "$phase" "$candidate_file" | sort -u > "$result_file"
  while read -r url; do printf '%s\n' "$url"; done < "$result_file"
}

parse_args() {
  [[ $# -eq 2 && $1 == -s ]] || fail "Only -s <string> is supported"; SEARCH=$2
  [[ -n ${SEARCH//[[:space:]]/} ]] || fail "Search string must not be empty"
  [[ -n $(normalize "$SEARCH" 2>/dev/null || true) ]] || fail "Search string must produce a valid Azure Storage name"
}
main() {
  parse_args "$@"; command -v curl >/dev/null 2>&1 || fail "curl is required"
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/azstorageenum.XXXXXXXX") || exit 1
  core_stems | sort -u > "$TMP_DIR/core.txt"
  make_baselines
  phase1 | sort -u > "$TMP_DIR/phase1-candidates.txt"; run_phase 1
  phase2 | sort -u > "$TMP_DIR/phase2-candidates.txt"; run_phase 2
  phase3 | sort -u > "$TMP_DIR/phase3-candidates.txt"; run_phase 3
  phase4 | sort -u > "$TMP_DIR/phase4-candidates.txt"; run_phase 4
  phase5 | sort -u > "$TMP_DIR/phase5-candidates.txt"; run_phase 5
}
main "$@"
