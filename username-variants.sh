#!/usr/bin/env bash
# Interactive username generator. Prompts are written to stderr; usernames go
# only to stdout, so: ./username-variants.sh > usernames.txt works cleanly.

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
  printf 'This script requires Bash 4 or newer.\n' >&2
  exit 1
fi

prompt() {
  local label=$1 value
  printf '%s: ' "$label" >&2
  IFS= read -r value || true
  printf '%s' "$value"
}

# Lowercase and retain only characters normally accepted in usernames.
# This also folds spaces, apostrophes and punctuation out of compound names.
normalise() {
  local value=$1
  value=${value,,}
  value=$(printf '%s' "$value" | LC_ALL=C tr -cd '[:alnum:]')
  printf '%s' "$value"
}

first=$(normalise "$(prompt 'First name')")
middle=$(normalise "$(prompt 'Middle name (optional)')")
last=$(normalise "$(prompt 'Last name')")
additional_last=$(normalise "$(prompt 'Additional last name (optional)')")

if [[ -z $first || -z $last ]]; then
  printf 'First name and last name must contain at least one letter or number.\n' >&2
  exit 1
fi

declare -A seen=()
separators=('' '.' '_' '-')

emit() {
  local candidate=$1
  # A duplicate is expected during combinatorial generation, not an error.
  [[ -n $candidate && -z ${seen[$candidate]+x} ]] || return 0
  seen[$candidate]=1
  printf '%s\n' "$candidate"
}

join() {
  local separator=$1; shift
  local result='' part
  for part in "$@"; do
    [[ -n $part ]] || continue
    if [[ -n $result ]]; then result+=$separator; fi
    result+=$part
  done
  printf '%s' "$result"
}

initial() { printf '%s' "${1:0:1}"; }

fi=$(initial "$first")
li=$(initial "$last")
given=($first $fi)
surname=($last $li)

if [[ -n $middle ]]; then
  mi=$(initial "$middle")
  middle_forms=($middle $mi)
else
  middle_forms=()
fi

if [[ -n $additional_last ]]; then
  ali=$(initial "$additional_last")
  # Treat a second surname both independently and as a compound family name.
  surname+=($additional_last $ali)
  for separator in "${separators[@]}"; do
    surname+=("$(join "$separator" "$last" "$additional_last")")
    surname+=("$(join "$separator" "$additional_last" "$last")")
    surname+=("$(join "$separator" "$li" "$additional_last")")
    surname+=("$(join "$separator" "$last" "$ali")")
  done
fi

# Remove duplicate surname forms before composing broader patterns.
declare -A surname_seen=()
unique_surnames=()
for value in "${surname[@]}"; do
  [[ -n $value && -z ${surname_seen[$value]+x} ]] || continue
  surname_seen[$value]=1
  unique_surnames+=("$value")
done

# Core patterns: standalone names, given/surname pairings, and their reverses.
for separator in "${separators[@]}"; do
  for g in "${given[@]}"; do
    emit "$g"
    for s in "${unique_surnames[@]}"; do
      emit "$(join "$separator" "$g" "$s")"
      emit "$(join "$separator" "$s" "$g")"
    done
  done
  for s in "${unique_surnames[@]}"; do emit "$s"; done
done

# Middle-name patterns are only generated when a middle name was provided.
if (( ${#middle_forms[@]} )); then
  for separator in "${separators[@]}"; do
    for g in "${given[@]}"; do
      for m in "${middle_forms[@]}"; do
        emit "$(join "$separator" "$g" "$m")"
        emit "$(join "$separator" "$m" "$g")"
        for s in "${unique_surnames[@]}"; do
          emit "$(join "$separator" "$g" "$m" "$s")"
          emit "$(join "$separator" "$g" "$s" "$m")"
          emit "$(join "$separator" "$m" "$g" "$s")"
          emit "$(join "$separator" "$s" "$g" "$m")"
          emit "$(join "$separator" "$s" "$m" "$g")"
        done
      done
    done
  done
fi

# A supplied additional surname is a distinct name component, not merely a
# surname alias. Generate all orders, initials, and mixed separators for it.
if [[ -n $additional_last ]]; then
  components=($first $last $additional_last)
  short_components=($fi $li $ali)
  orders=(
    '0 1 2' '0 2 1' '1 0 2'
    '1 2 0' '2 0 1' '2 1 0'
  )

  for order in "${orders[@]}"; do
    read -r one two three <<< "$order"
    # Full words, including every combination of the two separators.
    for left_separator in "${separators[@]}"; do
      for right_separator in "${separators[@]}"; do
        emit "${components[one]}$left_separator${components[two]}$right_separator${components[three]}"
      done
    done

    # Initial/full combinations cover forms such as m.m.m, maxmustermanm,
    # and their reverse-order equivalents (using Max Musterman as a placeholder).
    for one_form in "${components[one]}" "${short_components[one]}"; do
      for two_form in "${components[two]}" "${short_components[two]}"; do
        for three_form in "${components[three]}" "${short_components[three]}"; do
          for left_separator in "${separators[@]}"; do
            for right_separator in "${separators[@]}"; do
              emit "$one_form$left_separator$two_form$right_separator$three_form"
            done
          done
        done
      done
    done
  done

  # Organisations sometimes truncate the final surname component. Generate
  # useful 1ÔÇô4 character stems (or the whole name when it is shorter).
  for width in 1 2 3 4; do
    add_stem=${additional_last:0:width}
    last_stem=${last:0:width}
    [[ -n $add_stem ]] && emit "$first$last$add_stem"
    [[ -n $add_stem ]] && emit "$first$additional_last$last_stem"
  done
fi

# Common short numeric suffixes used in name-based corporate usernames.
# Keep suffixing to conventional, readable bases instead of every permutation.
numeric_bases=($first "$first$last" "$fi$last" "$last$first" "$last$fi")
if [[ -n $additional_last ]]; then
  numeric_bases+=(
    "$first$additional_last" "$first$last$additional_last"
    "$first$additional_last$last" "$first.$last.$additional_last"
    "${first}_${last}_${additional_last}" "${first}-${last}-${additional_last}"
  )
fi
if [[ -n $middle ]]; then
  numeric_bases+=("$first$middle$last" "$fi$mi$last")
fi
for base in "${numeric_bases[@]}"; do
  for suffix in 0 1 2 123 2024 2025 2026; do emit "$base$suffix"; done
done

# Preserve common case-sensitive conventions for canonical, low-noise forms.
title_case() { printf '%s' "${1^}"; }
title_first=$(title_case "$first")
title_last=$(title_case "$last")
emit "$title_first"
emit "$title_last"
emit "${first^^}"
emit "${last^^}"
for separator in '' '.' '_'; do
  emit "$title_first$separator$title_last"
  emit "${first^^}$separator${last^^}"
done
if [[ -n $additional_last ]]; then
  title_additional=$(title_case "$additional_last")
  emit "$title_additional"
  emit "${additional_last^^}"
  for separator in '' '.' '_'; do
    emit "$title_first$separator$title_additional"
    emit "$title_first$separator$title_last$separator$title_additional"
    emit "$title_first$separator$title_additional$separator$title_last"
    emit "${first^^}$separator${additional_last^^}"
    emit "${first^^}$separator${last^^}$separator${additional_last^^}"
  done
fi
