#!/usr/bin/env bash
# Validate every list, rebuild derived files and checksums.
#
#   tools/build-lists.sh            validate + rebuild abuse-ips.ipv4 and lists/SHA256SUMS
#   tools/build-lists.sh --check    validate + fail if a derived file is out of date (CI)
#   tools/build-lists.sh --geo      also rebuild lists/geo/<cc>-v4.txt / -v6.txt for every
#                                   code in lists/geo/COUNTRIES from the five RIR
#                                   delegated-extended statistics files
#
# Uses the exact same parser/aggregator as the runtime script (sourced as a library),
# so what CI accepts is what servers accept.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export AD_LIB=1
# shellcheck source=/dev/null
source ./abuse-defender.sh
trap - ERR
set +E

MODE=build
GEO=0
for a in "$@"; do
    case $a in
    --check) MODE=check ;;
    --geo) GEO=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
    esac
done

fail=0
problem() { echo "FAIL: $*" >&2; fail=1; }
note() { echo "  $*"; }

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

# --------------------------------------------------------------------------
# 1. strict validation of the curated lists
# --------------------------------------------------------------------------
# file family policy builtin-name
LISTS=(
"lists/bogons-v4.txt 4 block bogons-v4"
"lists/bogons-v6.txt 6 block bogons-v6"
"lists/abuse-v4.txt 4 block abuse-v4"
"lists/abuse-v6.txt 6 block abuse-v6"
"lists/cloud-allow-v4.txt 4 allow cloud-v4"
"lists/cloud-allow-v6.txt 6 allow cloud-v6"
)

check_raw_format() {   # no tabs, no CR, trailing newline, UTF-8 without BOM
    local f=$1
    if grep -q $'\r' "$f"; then problem "$f contains CR (Windows line endings)"; fi
    if grep -q $'\t' "$f"; then problem "$f contains TAB characters"; fi
    if [[ -s "$f" && "$(tail -c1 "$f" | od -An -c | tr -d ' ')" != '\n' ]]; then problem "$f has no trailing newline"; fi
    if head -c3 "$f" | od -An -tx1 | grep -q 'ef bb bf'; then problem "$f starts with a UTF-8 BOM"; fi
}

echo "Validating curated lists"
for row in "${LISTS[@]}"; do
    read -r file fam pol bname <<<"$row"
    [[ -f "$file" ]] || { problem "$file missing"; continue; }
    check_raw_format "$file"
    if ! normalize_list "$fam" "$pol" 1 <"$file" >"$WORK/n" 2>"$WORK/e"; then
        problem "$file: $(cat "$WORK/e")"; continue
    fi
    # entries of the other family are silently skipped by the parser: refuse them here
    if normalize_list any none 0 <"$file" 2>/dev/null | grep -qv "$( [[ $fam == 4 ]] && echo '\.' || echo ':')"; then
        problem "$file contains addresses of the wrong family"
    fi
    # entries must already be network addresses (no host bits) so the file is unambiguous
    while read -r raw; do
        n="$(printf '%s\n' "$raw" | normalize_list "$fam" none 0 2>/dev/null)"
        [[ "$raw" == */* ]] || raw="$raw/$([[ $fam == 4 ]] && echo 32 || echo 128)"
        [[ "$n" == "$(printf '%s\n' "$raw" | tr 'A-F' 'a-f')" ]] || note "$file: '$raw' is written as $n after normalisation"
    done < <(sed -e 's/[#;].*//' -e 's/[[:space:]]//g' "$file" | grep .)
    sort "$WORK/n" | uniq -d | while read -r d; do problem "$file: duplicate entry $d"; done
    aggregate_family "$fam" <"$WORK/n" >"$WORK/a"
    before="$(sort -u "$WORK/n" | wc -l)"; after="$(wc -l <"$WORK/a")"
    if (( after < before )); then note "$file: $before entries aggregate to $after (overlaps/adjacent blocks merged at runtime)"; fi
    # the built-in fallback copy in abuse-defender.sh must match
    if ! diff -u <(builtin_list "$bname" | normalize_list "$fam" "$pol" 1 | aggregate_family "$fam") "$WORK/a" >"$WORK/d"; then
        problem "built-in list '$bname' in abuse-defender.sh differs from $file:"; cat "$WORK/d" >&2
    fi
    note "$file: OK ($(wc -l <"$WORK/a") entries after aggregation)"
done

check_raw_format lists/domains.txt
if ! validate_domains <lists/domains.txt >"$WORK/dom" 2>"$WORK/e"; then problem "lists/domains.txt: $(cat "$WORK/e")"; fi
diff -q <(builtin_list domains) "$WORK/dom" >/dev/null || problem "built-in domains differ from lists/domains.txt"
note "lists/domains.txt: OK"

# sanity: bogons and allow lists must not contradict each other in a dangerous way
for f in 4 6; do
    normalize_list "$f" allow 1 <"lists/cloud-allow-v$f.txt" >/dev/null 2>&1 || problem "cloud-allow-v$f invalid"
done

# --------------------------------------------------------------------------
# 2. optional: country lists from RIR delegated-extended statistics
# --------------------------------------------------------------------------
RIR_URLS=(
https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest
https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest
https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest
)

build_geo() {
    local cc CC u i=0 date
    mkdir -p lists/geo "$WORK/rir"
    for u in "${RIR_URLS[@]}"; do
        i=$((i + 1))
        curl -fsSL --retry 3 --connect-timeout 20 --max-time 600 -o "$WORK/rir/$i" "$u" || { problem "download failed: $u"; return 1; }
        [[ "$(grep -c '|ipv4|' "$WORK/rir/$i")" -gt 1000 ]] || { problem "suspiciously small RIR file: $u"; return 1; }
    done
    date="$(date -u +%Y-%m-%d)"
    while read -r cc; do
        cc="${cc%%#*}"; cc="${cc//[[:space:]]/}"; [[ -n "$cc" ]] || continue
        [[ "$cc" =~ ^[a-z]{2}$ ]] || { problem "bad country code '$cc' in lists/geo/COUNTRIES"; continue; }
        CC="${cc^^}"
        # IPv4: start + address count (not always a power of two) -> ranges -> CIDRs
        {
            printf '# Country %s, IPv4, allocated+assigned, aggregated. Built %s with tools/build-lists.sh --geo\n' "$CC" "$date"
            printf '# Source: RIR delegated-extended statistics (RIPE NCC, ARIN, APNIC, LACNIC, AFRINIC)\n'
            cat "$WORK"/rir/* | awk -F'|' -v cc="$CC" '$2==cc && $3=="ipv4" && ($7=="allocated" || $7=="assigned") {
                    split($4,o,"."); s=o[1]*16777216+o[2]*65536+o[3]*256+o[4]; printf "%.0f %.0f\n", s, s+$5-1 }' |
                sort -k1,1n -k2,2nr | merge_ranges4
        } >"$WORK/geo4"
        {
            printf '# Country %s, IPv6, allocated+assigned. Built %s with tools/build-lists.sh --geo\n' "$CC" "$date"
            printf '# Source: RIR delegated-extended statistics (RIPE NCC, ARIN, APNIC, LACNIC, AFRINIC)\n'
            cat "$WORK"/rir/* | awk -F'|' -v cc="$CC" '$2==cc && $3=="ipv6" && ($7=="allocated" || $7=="assigned") { print $4 "/" $5 }' |
                normalize_list 6 block 0 | aggregate6
        } >"$WORK/geo6"
        local n4 n6
        n4="$(grep -vc '^#' "$WORK/geo4" || true)"; n6="$(grep -vc '^#' "$WORK/geo6" || true)"
        if (( n4 < 1 )); then problem "geo $cc: no IPv4 data"; continue; fi
        # shrink guard against a broken RIR file
        if [[ -f "lists/geo/$cc-v4.txt" ]]; then
            local old; old="$(grep -vc '^#' "lists/geo/$cc-v4.txt" || true)"
            if (( old > 50 && n4 * 2 < old )); then problem "geo $cc: shrank from $old to $n4 entries - refusing"; continue; fi
        fi
        cp "$WORK/geo4" "lists/geo/$cc-v4.txt"; cp "$WORK/geo6" "lists/geo/$cc-v6.txt"
        note "lists/geo/$cc: $n4 IPv4 / $n6 IPv6 prefixes"
    done <lists/geo/COUNTRIES
}

if [[ $GEO -eq 1 ]]; then echo "Building country lists"; build_geo || true; fi

if [[ -d lists/geo ]]; then
    for f in lists/geo/*-v4.txt lists/geo/*-v6.txt; do
        [[ -f "$f" ]] || continue
        fam="${f: -5:1}"
        normalize_list "$fam" block 1 <"$f" >/dev/null 2>"$WORK/e" || problem "$f: $(head -n3 "$WORK/e")"
    done
fi

# --------------------------------------------------------------------------
# 3. derived files
# --------------------------------------------------------------------------
# abuse-ips.ipv4 is consumed by v1 installs (old cron script does
#   for IP in $(curl ...); do iptables -A abuse-defender -d $IP -j DROP; done
# in OUTPUT without a loopback exception). It must stay: plain IPv4 CIDRs, one per line,
# no comments/blank lines/tabs/CR. 0.0.0.0/8 is excluded because v1 installs have no
# "lo" exception and connections to 0.0.0.0 are delivered locally on Linux.
gen_legacy() {
    {
        normalize_list 4 block 1 <lists/bogons-v4.txt | grep -vx '0.0.0.0/8'
        normalize_list 4 block 1 <lists/abuse-v4.txt
    } | aggregate4
}

gen_sums() {
    local f
    {
        for f in abuse-defender.sh abuse-ips.ipv4 lists/*.txt lists/geo/*.txt; do
            [[ -f "$f" ]] && sha256sum "$f"
        done
    } | sed 's/ \*/  /'
}

gen_legacy >"$WORK/abuse-ips.ipv4"
if grep -Eqv '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$' "$WORK/abuse-ips.ipv4"; then problem "derived abuse-ips.ipv4 has a non-CIDR line"; fi

if [[ $MODE == check ]]; then
    cmp -s "$WORK/abuse-ips.ipv4" abuse-ips.ipv4 || problem "abuse-ips.ipv4 is out of date - run tools/build-lists.sh"
    gen_sums >"$WORK/SHA256SUMS"
    cmp -s "$WORK/SHA256SUMS" lists/SHA256SUMS || problem "lists/SHA256SUMS is out of date - run tools/build-lists.sh"
else
    cp "$WORK/abuse-ips.ipv4" abuse-ips.ipv4
    gen_sums >"$WORK/SHA256SUMS"
    cp "$WORK/SHA256SUMS" lists/SHA256SUMS
    note "wrote abuse-ips.ipv4 ($(wc -l <abuse-ips.ipv4) entries) and lists/SHA256SUMS"
fi

if [[ $fail -ne 0 ]]; then echo "list validation FAILED" >&2; exit 1; fi
echo "All lists valid."
