#!/usr/bin/env bash
# Shared download cache for the pinned Windows media (pins.tsv). Sourced by build.sh and tests, never run.

LAB_ISO_CACHE="${LAB_ISO_CACHE:-$HOME/.cache/ostyr-lab/iso-cache}"
PINS_FILE="${PINS_FILE:-$LAB_DIR/images/pins.tsv}"

pin_field() {
    awk -F'\t' -v name="$1" -v column="$2" '$1 == name {print $column}' "$PINS_FILE"
}

legacy_iso_caches() {
    local main_repo
    main_repo="$(dirname "$(git -C "$REPO_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || printf '%s/.git' "$REPO_DIR")")"
    printf '%s\n' "${LAB_LEGACY_ISO_CACHE:-$main_repo/lab/state/iso-cache}" "${LAB_LEGACY_ISO_CACHE:-$LAB_DIR/state/iso-cache}"
}

migrate_legacy_iso_cache() {
    local legacy file
    while IFS= read -r legacy; do
        if [[ -d "$legacy" && "$legacy" != "$LAB_ISO_CACHE" ]]; then
            for file in "$legacy"/*; do
                if [[ -f "$file" && "$file" != *.part && ! -e "$LAB_ISO_CACHE/$(basename "$file")" ]]; then
                    log "moving $file into the shared cache $LAB_ISO_CACHE"
                    mv -n "$file" "$LAB_ISO_CACHE/"
                fi
            done
        fi
    done < <(legacy_iso_caches)
}

sha256_of() {
    sha256sum "$1" | cut -d' ' -f1
}

download_pinned() {
    local name="$1" url="$2" expected="$3" file="$4"
    local part actual
    rm -f "$file".??????.part
    part="$(mktemp --suffix=.part "$file.XXXXXX")"
    curl --fail --silent --show-error --location --output "$part" "$url" || die "$name: download from $url failed"
    actual="$(sha256_of "$part")"
    if [[ "$actual" != "$expected" ]]; then
        rm -f "$part"
        die "$name: sha256 $actual does not match the pin $expected; review the pin before changing it"
    fi
    mv "$part" "$file"
}

fetch_pinned() {
    local name="$1"
    local url expected file
    url="$(pin_field "$name" 5)"
    expected="$(pin_field "$name" 2)"
    file="$LAB_ISO_CACHE/$(pin_field "$name" 3)"
    [[ -n "$url" && "$expected" =~ ^[0-9a-f]{64}$ ]] || die "no valid pin for $name in $PINS_FILE"
    mkdir -p "$LAB_ISO_CACHE"
    migrate_legacy_iso_cache
    (
        flock 9
        if [[ -f "$file" && "$(sha256_of "$file")" != "$expected" ]]; then
            log "$name: cached file does not match the pin, downloading it again"
            rm -f "$file"
        fi
        [[ -f "$file" ]] || download_pinned "$name" "$url" "$expected" "$file"
    ) 9>"$file.lock" || die "$name: cache preparation failed"
    printf '%s' "$file"
}
