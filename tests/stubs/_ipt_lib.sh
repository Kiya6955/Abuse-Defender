# shellcheck shell=bash
# Shared state helpers for the iptables / iptables-restore test stubs.
# State file: one line per user chain ("-N name") and per rule ("-A chain spec"),
# rules of a chain kept in order. Builtin chains: INPUT FORWARD OUTPUT.

ipt_init() {
    IPT_FAM=4
    case "$(basename "$0")" in ip6tables*) IPT_FAM=6 ;; esac
    IPT_STATE="$AD_FAKE/ipt$IPT_FAM.state"
    touch "$IPT_STATE"
    printf '%s %s\n' "$(basename "$0")" "$*" >>"$AD_FAKE/calls.log"
}

builtin_chain() { [[ $1 == INPUT || $1 == OUTPUT || $1 == FORWARD ]]; }
chain_exists() { builtin_chain "$1" || grep -Fxq -- "-N $1" "$2"; }

# rule target must be a builtin target or an existing chain
target_ok() {
    local spec=$1 st=$2 t
    t="$(awk '{ for (i=1;i<NF;i++) if ($i=="-j") { print $(i+1); exit } }' <<<"$spec")"
    [[ -z "$t" ]] && return 0
    case $t in ACCEPT|DROP|RETURN|LOG|REJECT|SET|MARK) return 0 ;; esac
    chain_exists "$t" "$st"
}

# simulate missing kernel features: files $AD_FAKE/ipt-nofeature-* contain a substring
feature_ok() {
    local spec=$1 f pat
    for f in "$AD_FAKE"/ipt-nofeature-*; do
        [[ -f "$f" ]] || continue
        pat="$(cat "$f")"
        [[ "$spec" == *"$pat"* ]] && return 1
    done
    return 0
}

# like iptables-nft: every set named by --match-set / --add-set must already exist
# (this is checked for iptables-restore --test too)
sets_ok() {
    local spec=$1 sn
    while read -r sn; do
        [[ -z "$sn" || -f "$AD_FAKE/ipset/$sn" ]] || { echo "iptables-restore v1.8.10 (nf_tables): Set $sn doesn't exist." >&2; return 1; }
    done < <(awk '{ for (i=1;i<NF;i++) if ($i=="--match-set" || $i=="--add-set") print $(i+1) }' <<<"$spec")
    return 0
}

add_rule() {   # add_rule STATE CHAIN SPEC
    local st=$1 ch=$2 spec=$3
    chain_exists "$ch" "$st" || { echo "iptables: No chain/target/match by that name ($ch)" >&2; return 1; }
    target_ok "$spec" "$st" || { echo "iptables: target in '$spec' does not exist" >&2; return 1; }
    sets_ok "$spec" || return 1
    feature_ok "$spec" || { echo "iptables: Couldn't load match/target (stub)" >&2; return 1; }
    printf -- '-A %s %s\n' "$ch" "$spec" >>"$st"
}
