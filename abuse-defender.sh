#!/usr/bin/env bash
# shellcheck shell=bash
#
# Abuse Defender - stop a Linux server from sending traffic that triggers
# hosting-provider abuse reports (netscan to private/bogon space, honeypots, ...).
#
#   https://github.com/Kiya6955/Abuse-Defender
#
# Quick start (interactive menu):
#   bash <(curl -fsSL https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-defender.sh)
#
# Non-interactive:
#   abuse-defender.sh install --yes
#   abuse-defender status | update | block 203.0.113.7 | whitelist 10.8.0.0/16 | uninstall --yes
#
# Design notes live in docs/DESIGN.md. Every rule this tool creates lives in its own
# nftables table (inet abuse_defender) or in its own iptables chains ("abuse-defender*")
# and ipsets ("ad4-*", "ad6-*"). Nothing else on the system is ever flushed.

# SC2015: "A && B || C" is used deliberately where C must run if A or B fails.
# shellcheck disable=SC2015
set -Eeuo pipefail
shopt -s extglob

AD_VERSION="2.0.0"
AD_REPO="Kiya6955/Abuse-Defender"
AD_URL="https://github.com/${AD_REPO}"

# ---------------------------------------------------------------------------
# Paths (AD_ROOT is only used by the test-suite to run inside a fake root)
# ---------------------------------------------------------------------------
R="${AD_ROOT:-}"
PROC_DIR="${AD_PROC:-/proc}"
CONF_DIR="$R/etc/abuse-defender"
CONF_FILE="${AD_CONFIG:-$CONF_DIR/abuse-defender.conf}"
WHITELIST_FILE="$CONF_DIR/whitelist.txt"
CUSTOM_FILE="$CONF_DIR/custom-block.txt"
USER_DOMAINS_FILE="$CONF_DIR/domains.txt"
STATE_DIR="$R/var/lib/abuse-defender"
CACHE_DIR="$STATE_DIR/lists"
APPLIED_DIR="$STATE_DIR/applied"
PREVIOUS_DIR="$STATE_DIR/previous"
BACKUP_DIR="$STATE_DIR/backup"
RUN_DIR="$R/run/abuse-defender"
INSTALL_BIN="$R/usr/local/sbin/abuse-defender"
INSTALL_BIN_REAL="/usr/local/sbin/abuse-defender"   # path written into unit files
SYSTEMD_DIR="$R/etc/systemd/system"
SYSTEMD_RUN="$R/run/systemd/system"
CRON_D_DIR="$R/etc/cron.d"
CRON_FILE="$CRON_D_DIR/abuse-defender"
PERIODIC_DIR="$R/etc/periodic"
LOCAL_D_DIR="$R/etc/local.d"
LOGROTATE_FILE="$R/etc/logrotate.d/abuse-defender"
HOSTS_FILE="$R/etc/hosts"
OLD_UPDATE_SCRIPT="$R/root/abuse-defender-update.sh"
DEFAULT_LOG_FILE="$R/var/log/abuse-defender.log"

NFT_TABLE_NAME="abuse_defender"
IPT_MAIN="abuse-defender"            # main chain (name kept from v1 for migration)
IPT_PREFIX="abuse-defender"          # every chain we own starts with this
IPSET_PREFIX4="ad4-"
IPSET_PREFIX6="ad6-"
HOSTS_BEGIN="# >>> abuse-defender managed block (do not edit) >>>"
HOSTS_END="# <<< abuse-defender managed block <<<"

DEFAULT_MIRRORS="https://raw.githubusercontent.com/${AD_REPO}/main https://cdn.jsdelivr.net/gh/${AD_REPO}@main https://fastly.jsdelivr.net/gh/${AD_REPO}@main https://gcore.jsdelivr.net/gh/${AD_REPO}@main"

# ---------------------------------------------------------------------------
# Global runtime state
# ---------------------------------------------------------------------------
ASSUME_YES=0
DRY_RUN=0
QUIET=0
FORCE=0
OPT_BACKEND=""
OPT_JITTER=0
OPT_KEEP_CONFIG=0
OPT_CONFIRM_TIMEOUT=""
OPT_NO_CONFIRM=0
OPT_SETS_ONLY=0
TMP_ROOT=""
LOCK_HELD=0
LOCK_DIR_FALLBACK=""
PENDING_CONFIRM=0
UPDATE_CHANGED=0
UPDATE_FAILED=0
INTERACTIVE=0
PROMPT_STDIN=0      # 1 = the explicit "menu" command reads answers from stdin (scriptable)
REPORT=()           # summary lines of an automatic replacement of an older install
IS_ROOT=0
[[ $EUID -eq 0 || "${AD_ALLOW_NONROOT:-0}" == 1 ]] && IS_ROOT=1   # AD_ALLOW_NONROOT: test-suite only

# Resolved at runtime
BACKEND=""          # nft | ipset | iptables
NFT_FAMILY=""       # inet | ip
IPV4_ON=1
IPV6_ON=0
IPT_W=()
IPT_HAS_CONNTRACK=1
IPT_HAS_LOG=1
IPT_HAS_LOGUID=1
IPT_HAS_HASHLIMIT=1
IPT_HAS_SET=1
IPT_HAS_SETTARGET=1
RENDER_NOTES=()

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [[ -t 2 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[36m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_OFF=""
fi

LOG_FILE="$DEFAULT_LOG_FILE"
LOG_TO_FILE=0

_logfile() {
    [[ $LOG_TO_FILE -eq 1 && $DRY_RUN -eq 0 ]] || return 0
    { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >>"$LOG_FILE"; } 2>/dev/null || true
}
info()  { _logfile INFO "$*";  [[ $QUIET -eq 1 ]] || printf '%s\n' "${C_BLU}::${C_OFF} $*" >&2; }
ok()    { _logfile OK "$*";    [[ $QUIET -eq 1 ]] || printf '%s\n' "${C_GRN}OK${C_OFF} $*" >&2; }
warn()  { _logfile WARN "$*";  printf '%s\n' "${C_YEL}WARNING:${C_OFF} $*" >&2; }
err()   { _logfile ERROR "$*"; printf '%s\n' "${C_RED}ERROR:${C_OFF} $*" >&2; }
die()   { err "$*"; exit 1; }
say()   { printf '%s\n' "$*"; }
have()  { command -v "$1" >/dev/null 2>&1; }

on_err() {
    local rc=$? line=${1:-?}
    # Only report unexpected failures; expected ones are handled with `|| ...`.
    [[ "${BASH_COMMAND:-}" == return* ]] && return 0
    err "unexpected failure (exit $rc) at line $line: ${BASH_COMMAND:-?}"
}
trap 'on_err $LINENO' ERR

# ---------------------------------------------------------------------------
# Generic utilities
# ---------------------------------------------------------------------------
cleanup() {
    local rc=$?
    trap - ERR
    if [[ $PENDING_CONFIRM -eq 1 ]]; then
        # Interrupted (Ctrl+C, lost SSH session, error) while the user still had
        # to confirm new rules: go back to the previous rules.
        PENDING_CONFIRM=0
        warn "interrupted before the new rules were confirmed - rolling back"
        rollback_rules || err "rollback failed - run: abuse-defender disable"
        rm -f "$RUN_DIR/pending-confirm" 2>/dev/null || true
    fi
    if [[ -n "$TMP_ROOT" && -d "$TMP_ROOT" ]]; then rm -rf -- "$TMP_ROOT"; fi
    if [[ -n "$LOCK_DIR_FALLBACK" && -d "$LOCK_DIR_FALLBACK" ]]; then rm -rf -- "$LOCK_DIR_FALLBACK"; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

tmp_init() {
    [[ -n "$TMP_ROOT" ]] && return 0
    TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/abuse-defender.XXXXXX")"
}

# lock_acquire [timeout-seconds]
lock_acquire() {
    [[ $LOCK_HELD -eq 1 ]] && return 0
    [[ $DRY_RUN -eq 1 ]] && return 0     # dry-run changes nothing, not even /run
    local timeout=${1:-120}
    mkdir -p "$RUN_DIR"
    if have flock; then
        exec 9>"$RUN_DIR/lock"
        if ! flock -w "$timeout" 9; then
            die "another abuse-defender instance is running (lock: $RUN_DIR/lock)"
        fi
    else
        local d="$RUN_DIR/lock.d" waited=0 pid
        while ! mkdir "$d" 2>/dev/null; do
            pid="$(cat "$d/pid" 2>/dev/null || true)"
            if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
                rm -rf -- "$d"; continue
            fi
            (( waited++ >= timeout )) && die "another abuse-defender instance is running ($d)"
            sleep 1
        done
        echo "$$" >"$d/pid"
        LOCK_DIR_FALLBACK="$d"
    fi
    LOCK_HELD=1
}

lock_release() {
    [[ $LOCK_HELD -eq 1 ]] || return 0
    if [[ -n "$LOCK_DIR_FALLBACK" ]]; then rm -rf -- "$LOCK_DIR_FALLBACK"; LOCK_DIR_FALLBACK=""
    else exec 9>&-; fi
    LOCK_HELD=0
}

# prompt VAR MESSAGE [TIMEOUT]: returns 1 on end of input or timeout.
# Reads from the terminal even when stdin is a pipe (curl | bash). The explicit
# "menu" command reads from stdin instead, so the menu can be driven by a script.
prompt() {
    local __var=$1 __msg=$2 __timeout=${3:-} __ans="" __rc=0
    local -a topt=()
    [[ -n "$__timeout" ]] && topt=(-t "$__timeout")
    if [[ $PROMPT_STDIN -eq 0 ]] && [[ -r /dev/tty ]] && { : </dev/tty; } 2>/dev/null; then
        printf '%s' "$__msg" >/dev/tty
        IFS= read -r ${topt[@]+"${topt[@]}"} __ans </dev/tty || __rc=1
    else
        printf '%s' "$__msg"
        IFS= read -r ${topt[@]+"${topt[@]}"} __ans || __rc=1
        # echo scripted answers so a transcript stays readable
        [[ -t 0 ]] || printf '%s\n' "$__ans"
    fi
    [[ $__rc -eq 1 && -n "$__ans" ]] && __rc=0
    printf -v "$__var" '%s' "$__ans"
    return "$__rc"
}

# ask_yes_no "question" default(y|n)
ask_yes_no() {
    local q=$1 def=${2:-n} ans=""
    [[ $ASSUME_YES -eq 1 ]] && return 0
    if [[ $INTERACTIVE -ne 1 ]]; then
        [[ $def == y ]] && return 0
        return 1
    fi
    local hint="[y/N]"; [[ $def == y ]] && hint="[Y/n]"
    prompt ans "$q $hint: " || ans=""
    ans="${ans,,}"
    [[ -z "$ans" ]] && ans=$def
    [[ $ans == y || $ans == yes ]]
}

pause() {
    [[ $INTERACTIVE -eq 1 ]] || return 0
    local _x; prompt _x "Press Enter to continue... " || true
}

# write stdin to a file atomically (same directory, then rename)
atomic_write() {
    local dest=$1 mode=${2:-0644} tmp
    mkdir -p "$(dirname -- "$dest")"
    tmp="$(mktemp "$(dirname -- "$dest")/.ad-tmp.XXXXXX")"
    if ! cat >"$tmp"; then rm -f -- "$tmp"; return 1; fi
    chmod "$mode" "$tmp" 2>/dev/null || true
    mv -f -- "$tmp" "$dest"
}

sha256_of() {
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif have openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
    else cksum "$1" | awk '{print $1 "-" $2}'
    fi
}

count_lines() { if [[ -s "$1" ]]; then grep -c . "$1" || true; else echo 0; fi; }

now_epoch() { date +%s; }

is_systemd() { [[ -d "$SYSTEMD_RUN" ]] && have systemctl; }

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# key|default|validation-regex|description
CONFIG_SCHEMA=(
"ENABLED|yes|^(yes|no)$|Master switch. 'no' keeps the config but removes all rules."
"BACKEND|auto|^(auto|nft|ipset|iptables)$|Firewall backend: auto (nft > ipset+iptables > iptables), nft, ipset, iptables."
"EGRESS_INTERFACES|auto|^(auto|all|[A-Za-z0-9_.-]+( [A-Za-z0-9_.-]+)*)$|Interfaces to filter: auto (interfaces holding a default route), all (every non-loopback interface), or a list like \"eth0 ens3\"."
"CATEGORIES|bogons abuse|^((bogons|abuse|spamhaus|feodo)( (bogons|abuse|spamhaus|feodo))*)?$|Block categories: bogons abuse spamhaus feodo."
"GEO_COUNTRIES||^([a-z]{2}( [a-z]{2})*)?$|Outbound country blocking, ISO codes, e.g. \"ir\" (empty = off)."
"APPLY_FORWARD|no|^(yes|no)$|Also filter routed/forwarded traffic (Docker containers, WireGuard/OpenVPN clients, NAT)."
"STATEFUL|yes|^(yes|no)$|Let replies to inbound connections through (conntrack ESTABLISHED,RELATED). Strongly recommended."
"AUTO_WHITELIST|yes|^(yes|no)$|Auto-allow default gateways, DNS resolvers, cloud metadata IPs and directly connected subnets."
"PROTECT_SSH_CLIENT|yes|^(yes|no)$|Auto-allow the IPs of currently connected SSH clients."
"LOG_BLOCKED|yes|^(yes|no)$|Write a rate-limited kernel log line for blocked packets (see: abuse-defender hits)."
"LOG_RATE|10|^[0-9]{1,4}$|Max kernel log lines per minute per rule."
"BLOCK_SMTP|no|^(yes|no)$|Block outbound SMTP (spam abuse reports)."
"SMTP_PORTS|25|^[0-9]{1,5}( [0-9]{1,5})*$|SMTP ports to block when BLOCK_SMTP=yes (e.g. \"25 465 587\")."
"BLOCK_PORTS|no|^(yes|no)$|Block outbound connections to classic scan-target ports."
"BLOCK_TCP_PORTS|23 135 139 445|^([0-9]{1,5}( [0-9]{1,5})*)?$|TCP ports blocked when BLOCK_PORTS=yes."
"BLOCK_UDP_PORTS|137 138|^([0-9]{1,5}( [0-9]{1,5})*)?$|UDP ports blocked when BLOCK_PORTS=yes."
"SCAN_GUARD|no|^(yes|no)$|Rate-limit port-scan behaviour (many new destinations per port / many ports per host). Needs nft or ipset."
"SCAN_GUARD_EXEMPT_PORTS|53 80 443 853|^([0-9]{1,5}( [0-9]{1,5})*)?$|TCP ports the scan guard never limits (max 14)."
"SCAN_GUARD_DESTS_PER_MIN|60|^[0-9]{1,6}$|Max NEW distinct destination IPs per minute per TCP port."
"SCAN_GUARD_PORTS_PER_MIN|30|^[0-9]{1,6}$|Max NEW distinct TCP ports per minute per destination IP."
"HOSTS_BLOCK|yes|^(yes|no)$|Sinkhole the domains from lists/domains.txt + domains.txt in a managed /etc/hosts block."
"UPDATE_ENABLED|yes|^(yes|no)$|Automatic list updates (systemd timer or cron)."
"UPDATE_INTERVAL|daily|^(6h|12h|daily|weekly)$|How often to update lists: 6h, 12h, daily, weekly."
"MIRRORS|$DEFAULT_MIRRORS|^https://[^] \"'\`\$;|&<>*?[{}]+( https://[^] \"'\`\$;|&<>*?[{}]+)*$|Base URLs tried in order to download lists (HTTPS only)."
"VERIFY_CHECKSUMS|yes|^(yes|strict|no)$|Verify downloads against SHA256SUMS: yes (when published), strict (required), no."
"MAX_SHRINK_PERCENT|50|^[0-9]{1,3}$|Reject a downloaded list that is this many percent smaller than the last good one."
"LOG_FILE|$DEFAULT_LOG_FILE|^(/[A-Za-z0-9_./-]+)?$|Log file (empty = no file logging; journald still captures timer output)."
"CONFIRM_TIMEOUT|60|^[0-9]{1,4}$|Seconds to confirm risky changes interactively before automatic rollback (0 = no prompt)."
)

declare -A CFG=()

# split a schema row into SK SD SR SDESC (the regex may itself contain '|')
schema_split() {
    local row=$1 rest
    SK="${row%%|*}"; rest="${row#*|}"
    SD="${rest%%|*}"; rest="${rest#*|}"
    SDESC="${rest##*|}"; SR="${rest%|*}"
}

config_defaults() {
    local row
    for row in "${CONFIG_SCHEMA[@]}"; do
        schema_split "$row"
        CFG[$SK]="$SD"
    done
}

config_regex() {
    local row
    for row in "${CONFIG_SCHEMA[@]}"; do
        schema_split "$row"
        [[ $SK == "$1" ]] && { printf '%s' "$SR"; return 0; }
    done
    return 1
}

# Parse KEY=VALUE lines without ever executing the file.
CONFIG_OBSOLETE=0
MONITOR_NOTICE=0
config_load() {
    config_defaults
    [[ -f "$CONF_FILE" ]] || return 0
    local line key val re n=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        n=$((n + 1))
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! "$line" =~ ^[[:space:]]*([A-Z0-9_]+)=(.*)$ ]]; then
            warn "config line $n ignored (not KEY=VALUE): $line"; continue
        fi
        key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
        val="${val%%+([[:space:]])}"
        if [[ "$val" =~ ^\"(.*)\"$ || "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
        case $key in
        IPV6|IP_FAMILY|LANGUAGE)   # removed settings: IPv6 is always automatic, UI is English
            CONFIG_OBSOLETE=1; continue ;;
        MODE)
            CONFIG_OBSOLETE=1
            if [[ $val == monitor && $MONITOR_NOTICE -eq 0 ]]; then
                MONITOR_NOTICE=1
                warn "monitor mode no longer exists - protection is enforced (use 'disable' to turn it off)"
            fi
            continue ;;
        esac
        if ! re="$(config_regex "$key")"; then
            warn "config line $n: unknown key $key (ignored)"; continue
        fi
        if [[ ! "$val" =~ $re ]]; then
            warn "config line $n: invalid value for $key: '$val' (default kept)"; continue
        fi
        CFG[$key]="$val"
    done <"$CONF_FILE"
}

config_write() {
    [[ $DRY_RUN -eq 1 ]] && { info "[dry-run] would write $CONF_FILE"; return 0; }
    local row
    {
        printf '# Abuse Defender configuration (v%s)\n' "$AD_VERSION"
        printf '# Edit, then run: abuse-defender apply\n'
        printf '# Plain KEY="value" lines; this file is parsed, never executed.\n'
        printf '# Extra files: %s (allow), %s (block), %s (extra domains)\n\n' \
            "${WHITELIST_FILE#"$R"}" "${CUSTOM_FILE#"$R"}" "${USER_DOMAINS_FILE#"$R"}"
        for row in "${CONFIG_SCHEMA[@]}"; do
            schema_split "$row"
            printf '# %s\n# default: "%s"\n%s="%s"\n\n' "$SDESC" "${SD#"$R"}" "$SK" "${CFG[$SK]}"
        done
    } | atomic_write "$CONF_FILE" 0600
}

config_set() {
    local key=$1 val=$2 re
    re="$(config_regex "$key")" || die "unknown setting $key"
    [[ "$val" =~ $re ]] || die "invalid value for $key: '$val'"
    CFG[$key]="$val"
}

word_in() { local w=$1; shift; local x; for x in "$@"; do [[ $x == "$w" ]] && return 0; done; return 1; }

config_list_add() {   # config_list_add KEY word
    local key=$1 w=$2 out
    # shellcheck disable=SC2086
    if word_in "$w" ${CFG[$key]}; then return 0; fi
    out="${CFG[$key]:+${CFG[$key]} }$w"
    config_set "$key" "$out"
}
config_list_del() {
    local key=$1 w=$2 out="" x
    for x in ${CFG[$key]}; do [[ $x == "$w" ]] || out="${out:+$out }$x"; done
    config_set "$key" "$out"
}

apply_runtime_config() {
    LOG_FILE="${CFG[LOG_FILE]}"
    if [[ -n "$LOG_FILE" && $IS_ROOT -eq 1 ]]; then LOG_TO_FILE=1; else LOG_TO_FILE=0; fi
}

# ---------------------------------------------------------------------------
# List parsing / validation / aggregation (pure awk: works with gawk, mawk, busybox)
# ---------------------------------------------------------------------------
# Reads raw list lines; prints normalised "addr/prefix" lines.
#   -v want=4|6|any   family filter (other family silently skipped)
#   -v policy=block|allow|none   safety policy
#   -v strict=1       exit 3 if any line is invalid
# Errors go to stderr as "invalid: <reason>: <text>".
# shellcheck disable=SC2016
AWK_NORMALIZE='
function hexval(s,   i,c,v,d){ v=0; s=tolower(s); for(i=1;i<=length(s);i++){ c=substr(s,i,1); d=index("0123456789abcdef",c); if(d==0) return -1; v=v*16+d-1 } return v }
function okgrp(s){ return (s ~ /^[0-9a-fA-F]+$/ && length(s)<=4) }
function parse4(a,   n,i,p){ n=split(a,p,"."); if(n!=4) return 0
  for(i=1;i<=4;i++){ if(p[i] !~ /^[0-9]+$/ || length(p[i])>3) return 0
    if(length(p[i])>1 && substr(p[i],1,1)=="0") return 0
    if(p[i]+0>255) return 0; O[i]=p[i]+0 } return 1 }
function parse6(a,   n,i,parts,head,tail,hn,tn,h,t,k,dbl){
  if (a ~ /[^0-9a-fA-F:]/) return 0
  dbl=index(a,"::")
  if (dbl) { if (index(substr(a,dbl+2),"::")) return 0
    head=substr(a,1,dbl-1); tail=substr(a,dbl+2)
    hn=(head=="")?0:split(head,h,":"); tn=(tail=="")?0:split(tail,t,":")
    if (hn+tn>7) return 0
    k=0; for(i=1;i<=hn;i++){ if(!okgrp(h[i])) return 0; G[k++]=hexval(h[i]) }
    for(i=0;i<8-hn-tn;i++) G[k++]=0
    for(i=1;i<=tn;i++){ if(!okgrp(t[i])) return 0; G[k++]=hexval(t[i]) }
  } else { n=split(a,parts,":"); if(n!=8) return 0
    for(i=1;i<=8;i++){ if(!okgrp(parts[i])) return 0; G[i-1]=hexval(parts[i]) } }
  return 1 }
function mask6(p,   i,b,div){ for(i=0;i<8;i++){ b=p-16*i; if(b>=16) continue; if(b<=0){G[i]=0; continue}; div=2^(16-b); G[i]=int(G[i]/div)*div } }
function fmt6(   i,best,bl,cs,cl,s){ best=-1;bl=0;cs=-1;cl=0
  for(i=0;i<8;i++){ if(G[i]==0){ if(cs<0){cs=i;cl=1}else cl++; if(cl>bl){bl=cl;best=cs} } else {cs=-1;cl=0} }
  if(bl<2) best=-1
  s=""; for(i=0;i<8;i++){ if(i==best){ s=s "::"; i+=bl-1; continue }
    if(s!="" && substr(s,length(s),1)!=":") s=s ":"; s=s sprintf("%x",G[i]) }
  return s }
# does G/p overlap the IPv6 prefix whose first group is f0 with length q (q<=16)
function ov6(p,f0,q,   m,d){ m=(p<q)?p:q; d=2^(16-m); return int(G[0]/d)==int(f0/d) }
function bad(reason, txt){ errors++; printf "invalid: %s: %s\n", reason, txt > "/dev/stderr" }
{
  line=$0; sub(/\r$/,"",line); tok=""; extra=""
  if (match(line, /"cidr"[ \t]*:[ \t]*"[^"]*"/)) {
    tok=substr(line,RSTART,RLENGTH); sub(/^"cidr"[ \t]*:[ \t]*"/,"",tok); sub(/"$/,"",tok)
  } else {
    if (line ~ /^[ \t]*[{]/) next
    sub(/[#;].*$/,"",line); gsub(/^[ \t]+|[ \t]+$/,"",line)
    if (line=="" || line ~ /^\/\//) next
    nf=split(line,f,/[ \t,]+/); tok=f[1]
    if (keep && nf>1) extra=" " f[2]
  }
  orig=tok
  n=split(tok,cp,"/"); if(n>2){ bad("syntax",orig); next }
  addr=cp[1]; pfx=(n==2)?cp[2]:""
  if (n==2 && pfx !~ /^[0-9]+$/) { bad("prefix",orig); next }
  if (addr ~ /:/) {
    fam=6; sub(/%.*$/,"",addr)
    if (!parse6(addr)) { bad("ipv6 address",orig); next }
    if (pfx=="") pfx=128; pfx+=0
    if (pfx>128) { bad("prefix",orig); next }
  } else {
    fam=4
    if (!parse4(addr)) { bad("ipv4 address",orig); next }
    if (pfx=="") pfx=32; pfx+=0
    if (pfx>32) { bad("prefix",orig); next }
  }
  if (want!="any" && want!=fam) next
  if (fam==4) {
    num=O[1]*16777216+O[2]*65536+O[3]*256+O[4]; sz=2^(32-pfx); net=num-(num%sz)
    if (policy=="block") {
      if (pfx<4) { bad("range too broad for a block list",orig); next }
      if (int(net/16777216)==127 || (pfx<8 && int(net/2^(32-pfx))==int(127*16777216/2^(32-pfx)))) { bad("overlaps loopback 127.0.0.0/8",orig); next }
    }
    if (policy=="allow" && pfx<8) { bad("range too broad for a whitelist",orig); next }
    out=sprintf("%d.%d.%d.%d/%d", int(net/16777216), int(net/65536)%256, int(net/256)%256, net%256, pfx)
  } else {
    mask6(pfx)
    if (policy=="block") {
      if (pfx<7) { bad("range too broad for a block list",orig); next }
      if (pfx<=128 && G[0]==0&&G[1]==0&&G[2]==0&&G[3]==0&&G[4]==0&&G[5]==0&&G[6]==0&&G[7]<=1 && (pfx==128 ? G[7]==1 : pfx<=127)) { bad("overlaps ::1 loopback",orig); next }
      if (ov6(pfx,65152,10)) { bad("overlaps fe80::/10 link-local (needed by IPv6 neighbour discovery)",orig); next }
      if (ov6(pfx,65280,8)) { bad("overlaps ff00::/8 multicast (needed by IPv6 neighbour discovery)",orig); next }
    }
    if (policy=="allow" && pfx<16) { bad("range too broad for a whitelist",orig); next }
    out=fmt6() "/" pfx
  }
  print out extra
}
END { if (strict && errors>0) exit 3 }
'

# normalize_list FAMILY POLICY STRICT < in > out
normalize_list() {
    awk -v want="$1" -v policy="$2" -v strict="${3:-1}" "$AWK_NORMALIZE"
}

# Aggregate IPv4 CIDRs: dedupe, drop covered entries, merge adjacent blocks.
aggregate4() {
    awk -F/ 'NF==2 { split($1,o,"."); n=o[1]*16777216+o[2]*65536+o[3]*256+o[4]; printf "%.0f %.0f\n", n, n+2^(32-$2)-1 }' |
    sort -k1,1n -k2,2nr | merge_ranges4
}

# stdin: "start end" integer pairs sorted by start; stdout: minimal CIDR cover
merge_ranges4() {
    awk '
    function n2ip(n){ return sprintf("%d.%d.%d.%d", int(n/16777216), int(n/65536)%256, int(n/256)%256, n%256) }
    function emit(s,e,   size,p){ while (s<=e) { size=1; p=32
        while (p>0 && (s % (size*2))==0 && s+size*2-1<=e) { size*=2; p-- }
        printf "%s/%d\n", n2ip(s), p; s+=size } }
    NR==1 { cs=$1+0; ce=$2+0; next }
    { if ($1+0 <= ce+1) { if ($2+0 > ce) ce=$2+0 } else { emit(cs,ce); cs=$1+0; ce=$2+0 } }
    END { if (NR) emit(cs,ce) }'
}

# Dedupe IPv6 CIDRs (canonical input): drop exact duplicates and entries covered by
# a shorter prefix in the same list. Output sorted.
aggregate6() {
    awk -F/ '
    function hexval(s,   i,c,v,d){ v=0; for(i=1;i<=length(s);i++){ c=substr(s,i,1); d=index("0123456789abcdef",c); v=v*16+d-1 } return v }
    function parse(a,   i,h,t,hn,tn,k,dbl,head,tail){ dbl=index(a,"::")
      if (dbl) { head=substr(a,1,dbl-1); tail=substr(a,dbl+2); hn=(head=="")?0:split(head,h,":"); tn=(tail=="")?0:split(tail,t,":")
        k=0; for(i=1;i<=hn;i++) G[k++]=hexval(h[i]); for(i=0;i<8-hn-tn;i++) G[k++]=0; for(i=1;i<=tn;i++) G[k++]=hexval(t[i]) }
      else { split(a,h,":"); for(i=1;i<=8;i++) G[i-1]=hexval(h[i]) } }
    function key(p,   i,b,div,s,v){ s=""; for(i=0;i<8;i++){ b=p-16*i; v=G[i]
        if (b<=0) v=0; else if (b<16) { div=2^(16-b); v=int(v/div)*div }
        s=s sprintf("%x:",v) } return s p }
    NF==2 { n++; A[n]=$1; P[n]=$2+0; L[$2+0]=1; parse($1); K[n]=key($2+0); if (K[n] in S) { D[n]=1 } else S[K[n]]=n }
    END {
      for (i=1;i<=n;i++) { if (D[i]) continue; parse(A[i])
        for (q in L) { q+=0; if (q>=P[i]) continue; if ((key(q)) in S) { D[i]=1; break } }
        if (!D[i]) print A[i] "/" P[i] }
    }' | sort -u
}

aggregate_family() { if [[ $1 == 4 ]]; then aggregate4; else aggregate6; fi; }

# validate_domains < in > out ; exit 3 on invalid entries
validate_domains() {
    awk '{ line=$0; sub(/\r$/,"",line); sub(/#.*/,"",line); gsub(/^[ \t]+|[ \t]+$/,"",line); if (line=="") next
           line=tolower(line)
           if (line !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/ || length(line)>253) { errors++; print "invalid domain: " line > "/dev/stderr"; next }
           if (!(line in seen)) { seen[line]=1; print line } }
         END { if (errors>0) exit 3 }'
}

# validate a single IP/CIDR given by the user; prints the normalised form
normalize_one() {
    local input=$1 policy=$2 out
    [[ "$input" =~ ^[0-9A-Fa-f:./]+$ ]] || return 1
    out="$(printf '%s\n' "$input" | normalize_list any "$policy" 1 2>/dev/null)" || return 1
    [[ -n "$out" ]] || return 1
    printf '%s\n' "$out"
}

family_of() { if [[ $1 == *:* ]]; then echo 6; else echo 4; fi; }

# ---------------------------------------------------------------------------
# Built-in fallback lists (used only when nothing could ever be downloaded).
# Must stay identical to lists/*.txt - checked by tests/run.sh.
# ---------------------------------------------------------------------------
builtin_list() {
    case $1 in
    bogons-v4) cat <<'EOF'
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
EOF
    ;;
    bogons-v6) cat <<'EOF'
::/128
::ffff:0:0/96
100::/64
100:0:0:1::/64
2001:2::/48
2001:10::/28
2001:db8::/32
3fff::/20
5f00::/16
fc00::/7
EOF
    ;;
    abuse-v4) cat <<'EOF'
25.0.0.0/8
45.14.174.0/24
102.0.0.0/8
103.29.38.0/24
103.49.99.0/24
103.58.50.0/24
103.58.82.0/24
114.208.187.0/24
185.235.86.0/23
195.130.0.0/19
195.137.167.0/24
206.191.152.0/24
216.218.185.0/24
EOF
    ;;
    abuse-v6) : ;;
    cloud-v4) cat <<'EOF'
100.100.2.136/32
100.100.2.138/32
100.100.100.200/32
169.254.169.123/32
169.254.169.253/32
169.254.169.254/32
EOF
    ;;
    cloud-v6) cat <<'EOF'
fd00:ec2::123/128
fd00:ec2::253/128
fd00:ec2::254/128
fd20:ce::254/128
EOF
    ;;
    domains) cat <<'EOF'
appclick.co
pushnotificationws.com
EOF
    ;;
    *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Sources: where each cached list comes from and how it is validated
# ---------------------------------------------------------------------------
# Sets SRC_REPO (repo-relative paths, tried in order), SRC_URLS (external URLs),
# SRC_FAM, SRC_POLICY, SRC_MIN, SRC_STRICT, SRC_BUILTIN
source_info() {
    local name=$1 cc
    SRC_REPO=""; SRC_URLS=""; SRC_FAM=4; SRC_POLICY=block; SRC_MIN=0; SRC_STRICT=1; SRC_BUILTIN=0
    case $name in
    bogons-v4) SRC_REPO="lists/bogons-v4.txt"; SRC_MIN=10; SRC_BUILTIN=1 ;;
    bogons-v6) SRC_REPO="lists/bogons-v6.txt"; SRC_FAM=6; SRC_MIN=3; SRC_BUILTIN=1 ;;
    abuse-v4)  SRC_REPO="lists/abuse-v4.txt abuse-ips.ipv4"; SRC_MIN=1; SRC_BUILTIN=1 ;;
    abuse-v6)  SRC_REPO="lists/abuse-v6.txt"; SRC_FAM=6; SRC_BUILTIN=1 ;;
    cloud-v4)  SRC_REPO="lists/cloud-allow-v4.txt"; SRC_POLICY=allow; SRC_BUILTIN=1 ;;
    cloud-v6)  SRC_REPO="lists/cloud-allow-v6.txt"; SRC_FAM=6; SRC_POLICY=allow; SRC_BUILTIN=1 ;;
    domains)   SRC_REPO="lists/domains.txt"; SRC_POLICY=domains; SRC_BUILTIN=1 ;;
    spamhaus-v4) SRC_URLS="https://www.spamhaus.org/drop/drop_v4.json https://www.spamhaus.org/drop/drop.txt"; SRC_MIN=300; SRC_STRICT=0 ;;
    spamhaus-v6) SRC_URLS="https://www.spamhaus.org/drop/drop_v6.json"; SRC_FAM=6; SRC_MIN=5; SRC_STRICT=0 ;;
    feodo-v4)  SRC_URLS="https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"; SRC_STRICT=0 ;;
    geo-??-v4|geo-??-v6)
        cc="${name:4:2}"; SRC_FAM="${name: -1}"; SRC_MIN=1; SRC_STRICT=0
        [[ $SRC_FAM == 6 ]] && SRC_MIN=0
        SRC_REPO="lists/geo/${cc}-v${SRC_FAM}.txt"
        if [[ $SRC_FAM == 4 ]]; then
            SRC_URLS="https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/${cc}/ipv4-aggregated.txt https://www.ipdeny.com/ipblocks/data/aggregated/${cc}-aggregated.zone"
        else
            SRC_URLS="https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/${cc}/ipv6-aggregated.txt https://www.ipdeny.com/ipv6/ipaddresses/aggregated/${cc}-aggregated.zone"
        fi ;;
    *) return 1 ;;
    esac
}

# Which cached lists the current configuration needs
needed_sources() {
    local c cc f
    echo domains
    for f in $(active_fams); do
        echo "cloud-v$f"
        for c in ${CFG[CATEGORIES]}; do
            [[ $c == feodo && $f == 6 ]] && continue
            echo "$c-v$f"
        done
        for cc in ${CFG[GEO_COUNTRIES]}; do echo "geo-$cc-v$f"; done
    done
    return 0
}

# Print the content to use for a list: last good download, else built-in.
list_content() {
    local name=$1
    if [[ -f "$CACHE_DIR/$name.txt" ]]; then cat "$CACHE_DIR/$name.txt"; return 0; fi
    builtin_list "$name" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Downloading
# ---------------------------------------------------------------------------
http_get() {  # http_get URL OUTFILE
    local url=$1 out=$2
    if have curl; then
        curl -fsSL --proto '=https' --retry 2 --retry-delay 2 --connect-timeout 10 --max-time 120 \
            --max-filesize 50000000 -A "abuse-defender/$AD_VERSION" -o "$out" "$url" 2>/dev/null
    elif have wget; then
        wget -q -T 30 -t 2 -U "abuse-defender/$AD_VERSION" -O "$out" "$url" 2>/dev/null
    else
        return 2
    fi
}

declare -A SUMS_CACHE=()
declare -A DEAD_HOSTS=()   # hosts that failed at the connection level during this run
host_of() { local h=${1#https://}; printf '%s' "${h%%/*}"; }
# http_get_tracked URL OUT : like http_get, but skips hosts that are unreachable
http_get_tracked() {
    local url=$1 out=$2 h rc=0
    h="$(host_of "$url")"
    [[ -n "${DEAD_HOSTS[$h]+x}" ]] && return 1
    http_get "$url" "$out" || rc=$?
    case $rc in
    0) return 0 ;;
    5|6|7|28|35|60) DEAD_HOSTS[$h]=1; warn "mirror $h unreachable (curl exit $rc) - skipping it for this run" ;;
    esac
    return 1
}
# mirror_sums BASE -> path of the downloaded SHA256SUMS for that mirror ("" if none)
mirror_sums() {
    local base=$1 f
    if [[ -n "${SUMS_CACHE[$base]+x}" ]]; then printf '%s' "${SUMS_CACHE[$base]}"; return 0; fi
    tmp_init
    f="$TMP_ROOT/sums.$(printf '%s' "$base" | cksum | awk '{print $1}')"
    if http_get_tracked "$base/lists/SHA256SUMS" "$f" && grep -Eq '^[0-9a-f]{64}  ' "$f"; then
        SUMS_CACHE[$base]="$f"
    else
        SUMS_CACHE[$base]=""
    fi
    printf '%s' "${SUMS_CACHE[$base]}"
}

# verify_sum BASE RELPATH FILE -> 0 ok/unknown-allowed, 1 mismatch/required-missing
verify_sum() {
    local base=$1 rel=$2 file=$3 sums expected actual
    [[ ${CFG[VERIFY_CHECKSUMS]} == no ]] && return 0
    sums="$(mirror_sums "$base")"
    if [[ -z "$sums" ]]; then
        [[ ${CFG[VERIFY_CHECKSUMS]} == strict ]] && { warn "no SHA256SUMS at $base (strict mode)"; return 1; }
        return 0
    fi
    expected="$(awk -v f="$rel" '$2==f || $2=="*" f {print $1; exit}' "$sums")"
    if [[ -z "$expected" ]]; then
        [[ ${CFG[VERIFY_CHECKSUMS]} == strict ]] && { warn "$rel not listed in SHA256SUMS"; return 1; }
        return 0
    fi
    actual="$(sha256_of "$file")"
    if [[ "$actual" != "$expected" ]]; then
        warn "checksum mismatch for $rel from $base (stale CDN cache or tampering) - trying next mirror"
        return 1
    fi
}

# fetch_source NAME OUT -> raw downloaded content in OUT; sets FETCHED_FROM
fetch_source() {
    local name=$1 out=$2 base rel url
    FETCHED_FROM=""
    source_info "$name" || return 1
    for rel in $SRC_REPO; do
        for base in ${CFG[MIRRORS]}; do
            if http_get_tracked "$base/$rel" "$out" && [[ -s "$out" ]]; then
                if verify_sum "$base" "$rel" "$out"; then FETCHED_FROM="$base/$rel"; return 0; fi
            fi
        done
    done
    for url in $SRC_URLS; do
        if http_get_tracked "$url" "$out" && [[ -s "$out" ]]; then FETCHED_FROM="$url"; return 0; fi
    done
    return 1
}

# process_source NAME RAWFILE OUTFILE -> validated, normalised, aggregated list
process_source() {
    local name=$1 raw=$2 out=$3 errs total bad
    source_info "$name"
    errs="$out.err"
    if [[ $SRC_POLICY == domains ]]; then
        validate_domains <"$raw" >"$out" 2>"$errs" || { warn "$name: $(head -n 3 "$errs" | tr '\n' ' ')"; return 1; }
        return 0
    fi
    if ! normalize_list "$SRC_FAM" "$SRC_POLICY" "$SRC_STRICT" <"$raw" 2>"$errs" | aggregate_family "$SRC_FAM" >"$out"; then
        warn "$name rejected: invalid entries: $(head -n 3 "$errs" | tr '\n' ' ')"
        return 1
    fi
    if [[ $SRC_STRICT -eq 1 && -s "$errs" ]]; then
        warn "$name rejected: $(head -n 3 "$errs" | tr '\n' ' ')"; return 1
    fi
    bad="$(count_lines "$errs")"; total="$(count_lines "$out")"
    if [[ $SRC_STRICT -eq 0 && $bad -gt 0 ]]; then
        if (( bad * 20 > total + bad )); then
            warn "$name rejected: $bad of $((total + bad)) lines invalid"; return 1
        fi
        info "$name: skipped $bad unusable line(s)"
    fi
    return 0
}

# sanity checks against size thresholds and the last good copy
sanity_check() {
    local name=$1 new=$2 newc oldc pct
    source_info "$name"
    newc="$(count_lines "$new")"
    if (( newc < SRC_MIN )); then
        warn "$name rejected: only $newc entries (minimum $SRC_MIN)"; return 1
    fi
    if [[ -f "$CACHE_DIR/$name.txt" && $FORCE -eq 0 ]]; then
        oldc="$(count_lines "$CACHE_DIR/$name.txt")"
        pct="${CFG[MAX_SHRINK_PERCENT]}"
        if (( oldc >= 20 && newc * 100 < oldc * (100 - pct) )); then
            warn "$name rejected: shrank from $oldc to $newc entries (> ${pct}%); use --force to accept"
            return 1
        fi
    fi
    return 0
}

update_sources() {
    local name raw out names=("$@")
    tmp_init
    mkdir -p "$TMP_ROOT/dl"
    [[ ${#names[@]} -gt 0 ]] || mapfile -t names < <(needed_sources)
    [[ $DRY_RUN -eq 1 ]] || mkdir -p "$CACHE_DIR"
    for name in "${names[@]}"; do
        raw="$TMP_ROOT/dl/$name.raw"; out="$TMP_ROOT/dl/$name.txt"
        if ! fetch_source "$name" "$raw"; then
            UPDATE_FAILED=1
            if [[ -f "$CACHE_DIR/$name.txt" ]]; then
                warn "$name: download failed on all mirrors - keeping last good copy"
            else
                source_info "$name"
                if [[ $SRC_BUILTIN -eq 1 ]]; then warn "$name: download failed - using built-in copy"
                else warn "$name: download failed and no cached copy - this category stays empty"; fi
            fi
            continue
        fi
        if ! process_source "$name" "$raw" "$out" || ! sanity_check "$name" "$out"; then
            UPDATE_FAILED=1
            warn "$name: keeping last good copy"
            continue
        fi
        if [[ -f "$CACHE_DIR/$name.txt" ]] && cmp -s "$out" "$CACHE_DIR/$name.txt"; then
            info "$name: unchanged ($(count_lines "$out") entries)"
            continue
        fi
        if [[ $DRY_RUN -eq 1 ]]; then
            info "[dry-run] $name: $(count_lines "$out") entries from $FETCHED_FROM"
            continue
        fi
        atomic_write "$CACHE_DIR/$name.txt" 0644 <"$out"
        printf 'source=%s\nfetched=%s\nentries=%s\n' "$FETCHED_FROM" "$(now_epoch)" "$(count_lines "$out")" |
            atomic_write "$CACHE_DIR/$name.meta" 0644
        UPDATE_CHANGED=1
        ok "$name: $(count_lines "$out") entries from $FETCHED_FROM"
    done
    if [[ $DRY_RUN -eq 0 ]]; then
        printf 'time=%s\nstatus=%s\n' "$(now_epoch)" "$([[ $UPDATE_FAILED -eq 0 ]] && echo ok || echo partial)" |
            atomic_write "$STATE_DIR/last-update" 0644
    fi
}

# ---------------------------------------------------------------------------
# Host detection (gateway, DNS, connected subnets, SSH clients, egress ifaces)
# ---------------------------------------------------------------------------
valid_ifname() { [[ "$1" =~ ^[A-Za-z0-9_.-]{1,15}$ && "$1" != lo ]]; }

detect_default_routes() {  # prints "dev via" pairs for v4 and v6 default routes
    have ip || return 0
    local fam
    for fam in -4 -6; do
        { ip "$fam" route show default 2>/dev/null || true; } | awk '
            { dev=""; via=""; for (i=1;i<=NF;i++) { if ($i=="dev") dev=$(i+1); if ($i=="via") via=$(i+1) }
              if (dev!="") print dev, (via==""?"-":via) }'
    done
}

detect_egress_ifaces() {
    local mode="${CFG[EGRESS_INTERFACES]}" dev
    if [[ $mode == all ]]; then return 0; fi
    if [[ $mode != auto ]]; then
        for dev in $mode; do valid_ifname "$dev" && echo "$dev"; done
        return 0
    fi
    detect_default_routes | awk '{print $1}' | sed 's/@.*//' | sort -u | while read -r dev; do
        if valid_ifname "$dev"; then echo "$dev"; fi
    done
    return 0
}

detect_gateways() { detect_default_routes | awk '$2!="-" {print $2}' | sort -u || true; }

detect_dns() {
    local f files=("$R/etc/resolv.conf")
    if grep -Eqs '^[[:space:]]*nameserver[[:space:]]+(127\.|::1)' "$R/etc/resolv.conf"; then
        files+=("$R/run/systemd/resolve/resolv.conf")
    fi
    for f in "${files[@]}"; do
        if [[ -r "$f" ]]; then awk '$1=="nameserver" {print $2}' "$f"; fi
    done
    if have resolvectl; then
        resolvectl dns 2>/dev/null | awk -F: '{ sub(/^[^:]*\)?:/, ""); n=split($0,a," "); for (i=1;i<=n;i++) print a[i] }' || true
    fi
    return 0
}

detect_connected() {
    have ip || return 0
    { ip -o addr show scope global 2>/dev/null || true; } | awk '$2!="lo" && ($3=="inet" || $3=="inet6") {
        a=$4; if (a !~ /\//) a=a (($3=="inet")?"/32":"/128"); print a }'
}

detect_ssh_clients() {
    local ports p
    [[ -n "${SSH_CONNECTION:-}" ]] && printf '%s\n' "${SSH_CONNECTION%% *}"
    [[ -n "${SSH_CLIENT:-}" ]] && printf '%s\n' "${SSH_CLIENT%% *}"
    have ss || return 0
    ports="$({ ss -Hltnp 2>/dev/null || true; } | awk '/sshd/ { n=split($4,a,":"); print a[n] }' | sort -u)"
    [[ -n "$ports" ]] || ports=22
    for p in $ports; do
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        { ss -Htn state established "( sport = :$p )" 2>/dev/null || true; } | awk '{ a=$NF; sub(/:[0-9]+$/,"",a); gsub(/[][]/,"",a); sub(/^::ffff:/,"",a); sub(/%.*/,"",a); print a }'
    done
    return 0
}

ipv6_available() {
    [[ -e "$PROC_DIR/net/if_inet6" ]] || return 1
    local v
    v="$(cat "$PROC_DIR/sys/net/ipv6/conf/all/disable_ipv6" 2>/dev/null || echo 0)"
    [[ "$v" == 1 ]] && return 1
    return 0
}

detect_conflicts() {   # prints human readable notes about other firewall managers
    if have ufw && ufw status 2>/dev/null | grep -qi 'status: active'; then
        echo "ufw is active: compatible (we only add our own chain/table; keep 'ufw' outgoing policy as you like)"
    fi
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        local fb
        fb="$(awk -F= '/^FirewallBackend/ {print $2}' "$R/etc/firewalld/firewalld.conf" 2>/dev/null || true)"
        echo "firewalld is running (backend: ${fb:-unknown}): a 'firewall-cmd --reload' may remove iptables-based rules; the 15-minute ensure timer restores them"
    fi
    if [[ -S "$R/var/run/docker.sock" || -S "$R/run/docker.sock" || -d "$R/etc/docker" ]]; then
        echo "Docker detected: container traffic goes through FORWARD - set APPLY_FORWARD=yes to protect it"
    fi
    if have iptables && iptables -V 2>/dev/null | grep -q legacy && have nft && nft list tables 2>/dev/null | grep -q .; then
        echo "both iptables-legacy rules and nftables tables are in use on this host (works, but harder to debug)"
    fi
    local d
    for d in "$PROC_DIR"/sys/net/ipv4/conf/wg* "$PROC_DIR"/sys/net/ipv4/conf/tun* "$PROC_DIR"/sys/net/ipv4/conf/tailscale* "$PROC_DIR"/sys/net/ipv4/conf/zt*; do
        if [[ -e "$d" ]]; then
            echo "VPN/overlay interfaces present (wg/tun/tailscale/zt): they are not egress interfaces and are not filtered unless EGRESS_INTERFACES=all"
            break
        fi
    done
    return 0
}

# ---------------------------------------------------------------------------
# Backend selection and feature probing
# ---------------------------------------------------------------------------
ipt_cmd() { if [[ $1 == 6 ]]; then echo ip6tables; else echo iptables; fi; }
ipt() { local f=$1; shift; "$(ipt_cmd "$f")" ${IPT_W[@]+"${IPT_W[@]}"} "$@"; }
ipt_restore() { local f=$1; shift; "$(ipt_cmd "$f")-restore" "$@"; }

nft_probe() {   # nft_probe FAMILY -> 0 if nftables works for that family
    have nft || return 1
    local fam=$1 t="abuse_defender_probe"
    printf 'add table %s %s\ndelete table %s %s\ntable %s %s {\n set s { type ipv4_addr; flags interval; }\n chain c { type filter hook output priority 0; policy accept; ip daddr @s counter return; }\n}\n' \
        "$fam" "$t" "$fam" "$t" "$fam" "$t" | nft -f - >/dev/null 2>&1 || return 1
    nft delete table "$fam" "$t" >/dev/null 2>&1 || true
    return 0
}

ipt_probe() {   # probe iptables features for family $1, sets IPT_HAS_*
    local f=$1 c="${IPT_PREFIX}-probe" s
    have "$(ipt_cmd "$f")" || return 1
    if "$(ipt_cmd "$f")" -w -L -n >/dev/null 2>&1; then IPT_W=(-w); else IPT_W=(); fi
    ipt "$f" -N "$c" >/dev/null 2>&1 || ipt "$f" -F "$c" >/dev/null 2>&1 || return 1
    ipt "$f" -A "$c" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN >/dev/null 2>&1 || IPT_HAS_CONNTRACK=0
    ipt "$f" -A "$c" -m limit --limit 1/min -j LOG --log-prefix "x " >/dev/null 2>&1 || IPT_HAS_LOG=0
    ipt "$f" -A "$c" -m limit --limit 1/min -j LOG --log-prefix "x " --log-uid >/dev/null 2>&1 || IPT_HAS_LOGUID=0
    ipt "$f" -A "$c" -p tcp -m hashlimit --hashlimit-above 10/min --hashlimit-mode dstport --hashlimit-name "adprobe$f" -j RETURN >/dev/null 2>&1 || IPT_HAS_HASHLIMIT=0
    if have ipset; then
        s="ad${f}-probe"
        if ipset create "$s" hash:net family "$([[ $f == 6 ]] && echo inet6 || echo inet)" -exist >/dev/null 2>&1; then
            ipt "$f" -A "$c" -m set --match-set "$s" dst -j RETURN >/dev/null 2>&1 || IPT_HAS_SET=0
            ipset create "${s}p" hash:ip,port family "$([[ $f == 6 ]] && echo inet6 || echo inet)" timeout 60 -exist >/dev/null 2>&1 &&
                { ipt "$f" -A "$c" -j SET --add-set "${s}p" dst,dst >/dev/null 2>&1 || IPT_HAS_SETTARGET=0; }
        else
            IPT_HAS_SET=0
        fi
    else
        IPT_HAS_SET=0
    fi
    ipt "$f" -F "$c" >/dev/null 2>&1 || true
    ipt "$f" -X "$c" >/dev/null 2>&1 || true
    if have ipset; then ipset destroy "ad${f}-probe" >/dev/null 2>&1 || true; ipset destroy "ad${f}-probep" >/dev/null 2>&1 || true; fi
    return 0
}

# choose BACKEND / NFT_FAMILY / IPV6_ON from config and kernel probes.
# IPv4 is always protected; IPv6 only when the host has working IPv6 and the backend can filter it.
select_backend() {
    local want="${OPT_BACKEND:-${CFG[BACKEND]}}"
    BACKEND=""; NFT_FAMILY=""; IPV4_ON=1; IPV6_ON=0
    local v6ok=0
    if ipv6_available; then v6ok=1; fi

    if [[ $DRY_RUN -eq 1 && $IS_ROOT -ne 1 ]]; then
        # no kernel access: guess from installed binaries
        case $want in
        auto) if have nft; then BACKEND=nft; elif have ipset; then BACKEND=ipset; else BACKEND=iptables; fi ;;
        *) BACKEND=$want ;;
        esac
        NFT_FAMILY=inet; IPV6_ON=$v6ok
        return 0
    fi

    if [[ $want == auto || $want == nft ]]; then
        if nft_probe inet; then BACKEND=nft; NFT_FAMILY=inet; IPV6_ON=$v6ok
        elif nft_probe ip; then
            BACKEND=nft; NFT_FAMILY=ip
            [[ $v6ok -eq 1 ]] && warn "nftables 'inet' family unsupported here - IPv6 is not filtered"
        elif [[ $want == nft ]]; then die "BACKEND=nft requested but nftables is not usable on this host"
        fi
    fi
    if [[ -z "$BACKEND" ]]; then
        have iptables || die "no usable firewall: install nftables (recommended) or iptables"
        ipt_probe 4 || die "iptables is installed but not usable (missing kernel support or privileges?)"
        if [[ $v6ok -eq 1 ]] && have ip6tables && ip6tables -L -n >/dev/null 2>&1; then IPV6_ON=1; fi
        if [[ $want != iptables && $IPT_HAS_SET -eq 1 ]] && have ipset; then BACKEND=ipset
        elif [[ $want == ipset ]]; then die "BACKEND=ipset requested but ipset is not usable"
        else BACKEND=iptables; fi
        if [[ $IPV6_ON -eq 1 ]]; then
            local c4=$IPT_HAS_CONNTRACK l4=$IPT_HAS_LOG u4=$IPT_HAS_LOGUID h4=$IPT_HAS_HASHLIMIT s4=$IPT_HAS_SET t4=$IPT_HAS_SETTARGET
            ipt_probe 6 || IPV6_ON=0
            # keep the intersection of features
            IPT_HAS_CONNTRACK=$((c4 & IPT_HAS_CONNTRACK)); IPT_HAS_LOG=$((l4 & IPT_HAS_LOG)); IPT_HAS_LOGUID=$((u4 & IPT_HAS_LOGUID))
            IPT_HAS_HASHLIMIT=$((h4 & IPT_HAS_HASHLIMIT)); IPT_HAS_SETTARGET=$((t4 & IPT_HAS_SETTARGET))
            if [[ $BACKEND == ipset && $IPT_HAS_SET -eq 0 ]]; then warn "ipset unusable for IPv6 - IPv6 rules skipped"; IPV6_ON=0; IPT_HAS_SET=$s4; fi
        fi
    fi
    return 0
}

active_fams() { [[ $IPV4_ON -eq 1 ]] && printf '4 '; [[ $IPV6_ON -eq 1 ]] && printf '6'; printf '\n'; }
family_label() {   # family_label V4 V6
    if [[ $2 == 1 ]]; then echo "IPv4+IPv6"; else echo "IPv4 only (no IPv6 on this host)"; fi
}

iptables_variant() {
    have iptables || { echo none; return 0; }
    local v; v="$(iptables -V 2>/dev/null || true)"
    case $v in *nf_tables*) echo nft ;; *legacy*) echo legacy ;; *) echo legacy ;; esac
}

# ---------------------------------------------------------------------------
# Plan: compute every set we will load
# ---------------------------------------------------------------------------
# set descriptor lines in $dir/sets.txt : "<setname> <family> <kind> <tag>"
#   kind: allow | local | custom | block
plan_build() {
    local dir=$1 fam c cc f
    mkdir -p "$dir/sets"
    : >"$dir/sets.txt"; : >"$dir/auto-allow.txt"
    local -a fams=()
    read -r -a fams <<<"$(active_fams)"

    # --- automatic safety whitelist ---
    if [[ ${CFG[AUTO_WHITELIST]} == yes ]]; then
        local gw ns
        for gw in $(detect_gateways); do echo "$gw gateway"; done
        for ns in $(detect_dns); do echo "$ns dns-resolver"; done
        for f in "${fams[@]}"; do list_content "cloud-v$f" | sed 's/[[:space:]]*#.*//; s/$/ cloud-metadata/'; done
    fi >"$dir/auto.raw"
    if [[ ${CFG[PROTECT_SSH_CLIENT]} == yes ]]; then
        detect_ssh_clients | sed 's/$/ ssh-client/' >>"$dir/auto.raw"
    fi
    # keep only valid entries (one awk pass), record why; never loopback
    { awk -v keep=1 -v want=any -v policy=allow -v strict=0 "$AWK_NORMALIZE" <"$dir/auto.raw" 2>/dev/null || true; } |
        awk '$1 !~ /^127\./ && $1 != "::1/128" && !seen[$1]++' >"$dir/auto-allow.txt"
    if [[ ${CFG[AUTO_WHITELIST]} == yes ]]; then
        detect_connected | normalize_list any none 0 2>/dev/null | sed 's/$/ connected-subnet/' >"$dir/local.raw" || true
    else
        : >"$dir/local.raw"
    fi

    local uf l
    for uf in "$WHITELIST_FILE" "$CUSTOM_FILE"; do
        [[ -f "$uf" ]] || continue
        while read -r l; do warn "${uf#"$R"}: $l (ignored)"; done < <(
            { normalize_list any "$([[ $uf == "$WHITELIST_FILE" ]] && echo allow || echo block)" 0 <"$uf" 2>&1 >/dev/null || true; } | head -n 5)
    done
    for fam in "${fams[@]}"; do
        # allow = user whitelist + auto entries
        {
            [[ -f "$WHITELIST_FILE" ]] && normalize_list "$fam" allow 0 <"$WHITELIST_FILE" 2>/dev/null
            awk '{print $1}' "$dir/auto-allow.txt" | normalize_list "$fam" allow 0 2>/dev/null
        } | aggregate_family "$fam" >"$dir/sets/allow_v$fam"
        echo "allow_v$fam $fam allow allow" >>"$dir/sets.txt"

        awk '{print $1}' "$dir/local.raw" | normalize_list "$fam" none 0 2>/dev/null | aggregate_family "$fam" >"$dir/sets/local_v$fam"
        echo "local_v$fam $fam local local" >>"$dir/sets.txt"

        if [[ -f "$CUSTOM_FILE" ]]; then normalize_list "$fam" block 0 <"$CUSTOM_FILE" 2>/dev/null; fi | aggregate_family "$fam" >"$dir/sets/custom_v$fam"
        echo "custom_v$fam $fam custom custom" >>"$dir/sets.txt"

        for c in ${CFG[CATEGORIES]}; do
            [[ $c == feodo && $fam == 6 ]] && continue
            list_content "$c-v$fam" | normalize_list "$fam" block 0 2>/dev/null | aggregate_family "$fam" >"$dir/sets/${c}_v$fam"
            echo "${c}_v$fam $fam block $c" >>"$dir/sets.txt"
        done
        for cc in ${CFG[GEO_COUNTRIES]}; do
            f="geo_${cc}_v$fam"
            list_content "geo-$cc-v$fam" | normalize_list "$fam" block 0 2>/dev/null | aggregate_family "$fam" >"$dir/sets/$f"
            [[ -s "$dir/sets/$f" ]] || warn "country list '$cc' (IPv$fam) is empty - run: abuse-defender update"
            echo "$f $fam block geo-$cc" >>"$dir/sets.txt"
        done
    done

    # egress interfaces
    detect_egress_ifaces >"$dir/egress.txt"
    if [[ ${CFG[EGRESS_INTERFACES]} != all && ! -s "$dir/egress.txt" ]]; then
        warn "no default-route interface detected - filtering ALL non-loopback interfaces"
    fi
    return 0
}

ports_csv() { local IFS=,; printf '%s' "$*"; }
ports_nft() { local out="" p; for p in "$@"; do out="${out:+$out, }$p"; done; printf '%s' "$out"; }
valid_ports() { local p; for p in "$@"; do [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )) || return 1; done; }

# ---------------------------------------------------------------------------
# Rendering: nftables
# ---------------------------------------------------------------------------
# render_nft DIR LEVEL ; LEVEL 0=full 1=no log uid 2=no logging 3=no optional modules
render_nft() {
    local dir=$1 level=$2 T="$NFT_FAMILY $NFT_TABLE_NAME"
    local out="$dir/ruleset.nft" name fam kind tag type ifs="" i
    local log=0 loguid=0 mods=1 verdict=" drop" pfx="AD-DROP"
    [[ ${CFG[LOG_BLOCKED]} == yes && $level -lt 2 ]] && log=1
    [[ $log -eq 1 && $level -lt 1 ]] && loguid=1
    [[ $level -ge 3 ]] && mods=0
    local rate="${CFG[LOG_RATE]}"

    if [[ -s "$dir/egress.txt" ]]; then
        while read -r i; do ifs="${ifs:+$ifs, }\"$i\""; done <"$dir/egress.txt"
    fi
    logdrop() {   # logdrop MATCH TAG
        local m=$1 tg=$2 fl=""
        [[ $loguid -eq 1 ]] && fl=" flags skuid"
        [[ $log -eq 1 ]] && printf '    %s limit rate %s/minute burst 5 packets log prefix "%s %s: " level info%s\n' "$m" "$rate" "$pfx" "$tg" "$fl"
        printf '    %s counter%s comment "%s"\n' "$m" "$verdict" "$tg"
    }
    {
        printf '# written by abuse-defender %s - do not edit\n' "$AD_VERSION"
        printf 'add table %s\ndelete table %s\ntable %s {\n' "$T" "$T" "$T"
        while read -r name fam kind tag; do
            [[ $fam == 6 && $NFT_FAMILY != inet ]] && continue
            type=ipv4_addr; [[ $fam == 6 ]] && type=ipv6_addr
            printf '  set %s { type %s; flags interval; }\n' "$name" "$type"
        done <"$dir/sets.txt"
        if [[ $mods -eq 1 && ${CFG[SCAN_GUARD]} == yes ]]; then
            if [[ $IPV4_ON -eq 1 ]]; then
                printf '  set sg_seen_v4 { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 10m; size 262144; }\n'
                printf '  set sg_port_v4 { type inet_service; flags dynamic,timeout; timeout 5m; size 65536; }\n'
                printf '  set sg_host_v4 { type ipv4_addr; flags dynamic,timeout; timeout 5m; size 262144; }\n'
            fi
            if [[ $IPV6_ON -eq 1 ]]; then
                printf '  set sg_seen_v6 { type ipv6_addr . inet_service; flags dynamic,timeout; timeout 10m; size 262144; }\n'
                printf '  set sg_port_v6 { type inet_service; flags dynamic,timeout; timeout 5m; size 65536; }\n'
                printf '  set sg_host_v6 { type ipv6_addr; flags dynamic,timeout; timeout 5m; size 262144; }\n'
            fi
        fi

        printf '  chain egress {\n'
        [[ ${CFG[STATEFUL]} == yes ]] && printf '    ct state established,related return\n'
        [[ $IPV4_ON -eq 1 ]] && printf '    meta nfproto ipv4 udp sport 68 udp dport 67 return\n'
        if [[ $IPV6_ON -eq 1 ]]; then
            printf '    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-report, mld2-listener-report } return\n'
            printf '    udp sport 546 udp dport 547 return\n'
        fi
        addrf() { if [[ $1 == 6 ]]; then echo ip6; else echo ip; fi; }
        while read -r name fam kind tag; do
            [[ $kind == allow ]] || continue; [[ $fam == 6 && $IPV6_ON -ne 1 ]] && continue
            printf '    %s daddr @%s return\n' "$(addrf "$fam")" "$name"
        done <"$dir/sets.txt"
        while read -r name fam kind tag; do
            [[ $kind == custom ]] || continue; [[ $fam == 6 && $IPV6_ON -ne 1 ]] && continue
            logdrop "$(addrf "$fam") daddr @$name" "custom"
        done <"$dir/sets.txt"
        if [[ $mods -eq 1 ]]; then
            if [[ ${CFG[BLOCK_SMTP]} == yes ]]; then
                # shellcheck disable=SC2086
                logdrop "tcp dport { $(ports_nft ${CFG[SMTP_PORTS]}) }" "smtp"
            fi
            if [[ ${CFG[BLOCK_PORTS]} == yes ]]; then
                # shellcheck disable=SC2086
                [[ -n "${CFG[BLOCK_TCP_PORTS]}" ]] && logdrop "tcp dport { $(ports_nft ${CFG[BLOCK_TCP_PORTS]}) }" "ports"
                # shellcheck disable=SC2086
                [[ -n "${CFG[BLOCK_UDP_PORTS]}" ]] && logdrop "udp dport { $(ports_nft ${CFG[BLOCK_UDP_PORTS]}) }" "ports"
            fi
            [[ ${CFG[SCAN_GUARD]} == yes ]] && printf '    tcp flags & (syn | ack) == syn jump scanguard\n'
        fi
        while read -r name fam kind tag; do
            [[ $kind == local ]] || continue; [[ $fam == 6 && $IPV6_ON -ne 1 ]] && continue
            printf '    %s daddr @%s return\n' "$(addrf "$fam")" "$name"
        done <"$dir/sets.txt"
        while read -r name fam kind tag; do
            [[ $kind == block ]] || continue; [[ $fam == 6 && $IPV6_ON -ne 1 ]] && continue
            logdrop "$(addrf "$fam") daddr @$name" "$tag"
        done <"$dir/sets.txt"
        printf '  }\n'

        if [[ $mods -eq 1 && ${CFG[SCAN_GUARD]} == yes ]]; then
            local ex="${CFG[SCAN_GUARD_EXEMPT_PORTS]}" d="${CFG[SCAN_GUARD_DESTS_PER_MIN]}" p="${CFG[SCAN_GUARD_PORTS_PER_MIN]}" v
            printf '  chain scanguard {\n'
            # shellcheck disable=SC2086
            [[ -n "$ex" ]] && printf '    tcp dport { %s } return\n' "$(ports_nft $ex)"
            for v in 4 6; do
                [[ $v == 6 && $IPV6_ON -ne 1 ]] && continue
                [[ $v == 4 && $IPV4_ON -ne 1 ]] && continue
                printf '    %s daddr . tcp dport @sg_seen_v%s return\n' "$(addrf $v)" "$v"
                local nfp=ipv4; [[ $v == 6 ]] && nfp=ipv6
                [[ $log -eq 1 ]] && printf '    meta nfproto %s update @sg_port_v%s { tcp dport limit rate over %s/minute burst %s packets } limit rate %s/minute burst 5 packets log prefix "%s scanguard: " level info\n' "$nfp" "$v" "$d" "$((d * 2))" "$rate" "$pfx"
                printf '    meta nfproto %s update @sg_port_v%s { tcp dport limit rate over %s/minute burst %s packets } counter%s comment "scanguard"\n' "$nfp" "$v" "$d" "$((d * 2))" "$verdict"
                printf '    update @sg_host_v%s { %s daddr limit rate over %s/minute burst %s packets } counter%s comment "scanguard"\n' "$v" "$(addrf $v)" "$p" "$p" "$verdict"
                printf '    update @sg_seen_v%s { %s daddr . tcp dport }\n' "$v" "$(addrf $v)"
            done
            printf '  }\n'
        fi

        printf '  chain output {\n    type filter hook output priority 0; policy accept;\n'
        if [[ -n "$ifs" ]]; then printf '    oifname { %s } jump egress\n' "$ifs"
        else printf '    oifname != "lo" jump egress\n'; fi
        printf '  }\n'
        if [[ ${CFG[APPLY_FORWARD]} == yes ]]; then
            printf '  chain forward {\n    type filter hook forward priority 0; policy accept;\n'
            if [[ -n "$ifs" ]]; then printf '    oifname { %s } jump egress\n' "$ifs"
            else printf '    oifname != "lo" jump egress\n'; fi
            printf '  }\n'
        fi
        printf '}\n'
        # elements in chunks (same file = same atomic transaction)
        while read -r name fam kind tag; do
            [[ $fam == 6 && $NFT_FAMILY != inet ]] && continue
            [[ -s "$dir/sets/$name" ]] || continue
            awk -v t="$T" -v s="$name" '
                { buf = buf (n ? ", " : "") $0; n++
                  if (n == 500) { printf "add element %s %s { %s }\n", t, s, buf; buf=""; n=0 } }
                END { if (n) printf "add element %s %s { %s }\n", t, s, buf }' "$dir/sets/$name"
        done <"$dir/sets.txt"
    } >"$out"
    unset -f logdrop addrf
}

# ---------------------------------------------------------------------------
# Rendering: iptables (+ ipset)
# ---------------------------------------------------------------------------
ipset_name() {  # setname(allow_v4) -> ad4-allow ; geo_ir_v4 -> ad4-geo-ir
    local n=$1 fam base
    fam="${n##*_v}"; base="${n%_v*}"; base="${base//_/-}"
    printf 'ad%s-%s' "$fam" "$base"
}

render_ipt() {
    local dir=$1 level=$2 use_set=0 fam
    [[ $BACKEND == ipset ]] && use_set=1
    local log=0 loguid=0 mods=1 rate="${CFG[LOG_RATE]}" verdict=" -j DROP" pfx="AD-DROP"
    [[ ${CFG[LOG_BLOCKED]} == yes && $level -lt 2 && $IPT_HAS_LOG -eq 1 ]] && log=1
    [[ $log -eq 1 && $level -lt 1 && $IPT_HAS_LOGUID -eq 1 ]] && loguid=1
    [[ $level -ge 3 ]] && mods=0
    : >"$dir/jumps.txt"; : >"$dir/chains.txt"; : >"$dir/ipsets.txt"
    for fam in 4 6; do
        [[ $fam == 6 && $IPV6_ON -ne 1 ]] && continue
        [[ $fam == 4 && $IPV4_ON -ne 1 ]] && continue
        local out="$dir/rules$fam.ipt" M="$IPT_MAIN" name f kind tag chain
        local -a chains=("$M") body=()
        lg() {  # lg MATCH TAG  -> log+drop lines into body
            local m=$1 tg=$2 uidopt=""
            [[ $loguid -eq 1 ]] && uidopt=" --log-uid"
            [[ $log -eq 1 ]] && body+=("-A $M $m -m limit --limit $rate/min --limit-burst 5 -j LOG --log-prefix \"$pfx ${tg:0:18}: \" --log-level 6$uidopt")
            body+=("-A $M $m$verdict")
        }
        body+=("-A $M -o lo -j RETURN")
        if [[ ${CFG[STATEFUL]} == yes && $IPT_HAS_CONNTRACK -eq 1 ]]; then
            body+=("-A $M -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN")
        elif [[ ${CFG[STATEFUL]} == yes ]]; then
            RENDER_NOTES+=("conntrack match unavailable: replies to inbound connections from blocked ranges may be dropped")
        fi
        if [[ $fam == 4 ]]; then
            body+=("-A $M -p udp --sport 68 --dport 67 -j RETURN")
        else
            local ty
            for ty in 133 135 136 131 143; do body+=("-A $M -p ipv6-icmp --icmpv6-type $ty -j RETURN"); done
            body+=("-A $M -p udp --sport 546 --dport 547 -j RETURN")
        fi
        # set-like sections
        section() {  # section KIND -> emits rules for each matching set
            local want=$1
            while read -r name f kind tag; do
                [[ $f == "$fam" && $kind == "$want" ]] || continue
                if [[ $use_set -eq 1 ]]; then
                    local sn; sn="$(ipset_name "$name")"
                    printf '%s %s %s\n' "$sn" "$fam" "$name" >>"$dir/ipsets.txt"
                    case $kind in
                    allow|local) body+=("-A $M -m set --match-set $sn dst -j RETURN") ;;
                    *) lg "-m set --match-set $sn dst" "$tag" ;;
                    esac
                else
                    case $kind in
                    allow|local)
                        while read -r e; do [[ -n "$e" ]] && body+=("-A $M -d $e -j RETURN"); done <"$dir/sets/$name" ;;
                    *)
                        chain="${IPT_PREFIX}-${tag}"; chain="${chain:0:28}"
                        chains+=("$chain")
                        printf '%s\n' "$chain" >"$dir/chain.$fam.$chain"
                        while read -r e; do [[ -n "$e" ]] && printf -- '-A %s -d %s -j %s-drop\n' "$chain" "$e" "$IPT_PREFIX"; done <"$dir/sets/$name" >>"$dir/chainbody.$fam"
                        body+=("-A $M -j $chain") ;;
                    esac
                fi
            done <"$dir/sets.txt"
        }
        : >"$dir/chainbody.$fam"
        section allow
        section custom
        if [[ $mods -eq 1 ]]; then
            # shellcheck disable=SC2086
            [[ ${CFG[BLOCK_SMTP]} == yes ]] && lg "-p tcp -m multiport --dports $(ports_csv ${CFG[SMTP_PORTS]})" "smtp"
            if [[ ${CFG[BLOCK_PORTS]} == yes ]]; then
                # shellcheck disable=SC2086
                [[ -n "${CFG[BLOCK_TCP_PORTS]}" ]] && lg "-p tcp -m multiport --dports $(ports_csv ${CFG[BLOCK_TCP_PORTS]})" "ports"
                # shellcheck disable=SC2086
                [[ -n "${CFG[BLOCK_UDP_PORTS]}" ]] && lg "-p udp -m multiport --dports $(ports_csv ${CFG[BLOCK_UDP_PORTS]})" "ports"
            fi
            if [[ ${CFG[SCAN_GUARD]} == yes ]]; then
                if [[ $use_set -eq 1 && $IPT_HAS_HASHLIMIT -eq 1 && $IPT_HAS_SETTARGET -eq 1 ]]; then
                    local S="${IPT_PREFIX}-scan" seen="ad${fam}-sgseen" d="${CFG[SCAN_GUARD_DESTS_PER_MIN]}" p="${CFG[SCAN_GUARD_PORTS_PER_MIN]}"
                    chains+=("$S")
                    printf '%s %s dynamic\n' "$seen" "$fam" >>"$dir/ipsets.txt"
                    {
                        # shellcheck disable=SC2086
                        [[ -n "${CFG[SCAN_GUARD_EXEMPT_PORTS]}" ]] && printf -- '-A %s -p tcp -m multiport --dports %s -j RETURN\n' "$S" "$(ports_csv ${CFG[SCAN_GUARD_EXEMPT_PORTS]})"
                        printf -- '-A %s -m set --match-set %s dst,dst -j RETURN\n' "$S" "$seen"
                        [[ $log -eq 1 ]] && printf -- '-A %s -p tcp -m hashlimit --hashlimit-above %s/min --hashlimit-burst %s --hashlimit-mode dstport --hashlimit-name ad%sport --hashlimit-htable-expire 300000 -m limit --limit %s/min -j LOG --log-prefix "%s scanguard: " --log-level 6\n' "$S" "$d" "$((d * 2))" "$fam" "$rate" "$pfx"
                        printf -- '-A %s -p tcp -m hashlimit --hashlimit-above %s/min --hashlimit-burst %s --hashlimit-mode dstport --hashlimit-name ad%sport --hashlimit-htable-expire 300000%s\n' "$S" "$d" "$((d * 2))" "$fam" "$verdict"
                        printf -- '-A %s -m hashlimit --hashlimit-above %s/min --hashlimit-burst %s --hashlimit-mode dstip --hashlimit-name ad%shost --hashlimit-htable-expire 300000%s\n' "$S" "$p" "$p" "$fam" "$verdict"
                        printf -- '-A %s -j SET --add-set %s dst,dst\n' "$S" "$seen"
                    } >>"$dir/chainbody.$fam"
                    body+=("-A $M -p tcp --tcp-flags SYN,ACK SYN -j $S")
                else
                    RENDER_NOTES+=("scan guard needs nftables or ipset+hashlimit+SET support - skipped on this host")
                fi
            fi
        fi
        section local
        section block
        if [[ $use_set -eq 0 ]]; then
            chains+=("${IPT_PREFIX}-drop")
            {
                if [[ $log -eq 1 ]]; then
                    local uidopt=""; [[ $loguid -eq 1 ]] && uidopt=" --log-uid"
                    printf -- '-A %s-drop -m limit --limit %s/min --limit-burst 5 -j LOG --log-prefix "%s: " --log-level 6%s\n' "$IPT_PREFIX" "$rate" "$pfx" "$uidopt"
                fi
                printf -- '-A %s-drop -j DROP\n' "$IPT_PREFIX"
            } >>"$dir/chainbody.$fam"
        fi
        {
            printf '# written by abuse-defender %s - do not edit\n*filter\n' "$AD_VERSION"
            local ch
            for ch in "${chains[@]}"; do printf ':%s - [0:0]\n' "$ch"; done
            printf '%s\n' "${body[@]}"
            cat "$dir/chainbody.$fam"
            printf 'COMMIT\n'
        } >"$out"
        rm -f "$dir/chainbody.$fam" "$dir"/chain."$fam".* 2>/dev/null || true
        printf '%s\n' "${chains[@]}" | sed "s/^/$fam /" >>"$dir/chains.txt"
        # jumps
        local hooks=(OUTPUT) h i
        [[ ${CFG[APPLY_FORWARD]} == yes ]] && hooks+=(FORWARD)
        for h in "${hooks[@]}"; do
            if [[ -s "$dir/egress.txt" ]]; then
                while read -r i; do printf '%s %s -o %s -j %s\n' "$fam" "$h" "$i" "$M"; done <"$dir/egress.txt"
            else
                printf '%s %s ! -o lo -j %s\n' "$fam" "$h" "$M"
            fi
        done >>"$dir/jumps.txt"
        unset -f lg section
    done
    sort -u "$dir/ipsets.txt" -o "$dir/ipsets.txt"
}

# Build a complete bundle into DIR (plan + rendered rules + meta). Returns 0 or 1.
bundle_build() {
    local dir=$1 level=0 rc
    rm -rf -- "$dir"; mkdir -p "$dir"
    plan_build "$dir"
    RENDER_NOTES=()
    while :; do
        if [[ $BACKEND == nft ]]; then render_nft "$dir" "$level"; else render_ipt "$dir" "$level"; fi
        if [[ $DRY_RUN -eq 1 && $IS_ROOT -ne 1 ]]; then break; fi
        rc=0
        if [[ $BACKEND == nft ]]; then
            nft -c -f "$dir/ruleset.nft" >"$dir/check.log" 2>&1 || rc=$?
        else
            local f
            for f in 4 6; do
                [[ -f "$dir/rules$f.ipt" ]] || continue
                # --test does not need the ipsets to exist
                ipt_restore "$f" --test --noflush <"$dir/rules$f.ipt" >"$dir/check.log" 2>&1 || { rc=1; break; }
            done
        fi
        [[ $rc -eq 0 ]] && break
        if (( level >= 3 )); then
            err "the rendered ruleset was rejected by the kernel/tooling:"; sed 's/^/    /' "$dir/check.log" >&2 || true
            return 1
        fi
        case $level in
        0) RENDER_NOTES+=("log owner UID (skuid/--log-uid) unsupported - logging without UID") ;;
        1) RENDER_NOTES+=("kernel logging unsupported here - blocked packets are only counted") ;;
        2) RENDER_NOTES+=("optional modules (SMTP/ports/scan guard) are unsupported by this kernel/nft version - skipped") ;;
        esac
        level=$((level + 1))
    done
    {
        printf 'version=%s\nbackend=%s\nnft_family=%s\nipv4=%s\nipv6=%s\nlevel=%s\ncreated=%s\n' \
            "$AD_VERSION" "$BACKEND" "$NFT_FAMILY" "$IPV4_ON" "$IPV6_ON" "$level" "$(now_epoch)"
    } >"$dir/meta"
    printf '%s\n' ${RENDER_NOTES[@]+"${RENDER_NOTES[@]}"} | sort -u | grep . >"$dir/notes.txt" || true
    bundle_hash "$dir" >"$dir/hash"
    return 0
}

bundle_hash() {
    local dir=$1
    (
        cd "$dir" || exit 1
        grep -v '^created=' meta 2>/dev/null || true
        local f
        for f in ruleset.nft rules4.ipt rules6.ipt jumps.txt ipsets.txt sets.txt; do [[ -f $f ]] && cat "$f"; done
        for f in sets/*; do [[ -f $f ]] && { echo "== $f"; cat "$f"; }; done
    ) | cksum | awk '{print $1 "-" $2}'
}

meta_get() { awk -F= -v k="$2" '$1==k {print substr($0, length(k)+2); exit}' "$1/meta" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# Applying / removing rules
# ---------------------------------------------------------------------------
nft_tables_ours() {   # prints "family name" for our tables
    have nft || return 0
    { nft list tables 2>/dev/null || true; } | awk -v n="$NFT_TABLE_NAME" '$1=="table" && $3==n {print $2, $3}'
}

# list jump rules referencing our chains in OUTPUT/FORWARD, as "-A CHAIN spec"
ipt_our_jumps() {
    local fam=$1 h
    for h in OUTPUT FORWARD; do
        { ipt "$fam" -S "$h" 2>/dev/null || true; } | awk -v p="$IPT_PREFIX" '$1=="-A" { for (i=1;i<NF;i++) if ($i=="-j" && index($(i+1),p)==1) { print; next } }'
    done
    return 0
}
ipt_our_chains() { { ipt "$1" -S 2>/dev/null || true; } | awk -v p="$IPT_PREFIX" '$1=="-N" && index($2,p)==1 {print $2}'; }

# delete a rule given as "-A CHAIN spec..." (spec contains no quoted strings)
ipt_delete_rule() {
    local fam=$1 rule=$2
    local -a words
    read -r -a words <<<"$rule"
    words[0]="-D"
    ipt "$fam" "${words[@]}" >/dev/null 2>&1 || true
}

ipt_rule_index() {   # index (1-based) of exact rule "-A CHAIN spec" in CHAIN, 0 if absent
    local fam=$1 chain=$2 rule=$3
    { ipt "$fam" -S "$chain" 2>/dev/null || true; } | awk -v r="$rule" '$1=="-A" { n++; if ($0==r) { print n; found=1; exit } } END { if (!found) print 0 }'
}

# make sure our jumps exist and come before every other rule of the hook chain
ipt_apply_jumps() {
    local dir=$1 fam=$2 line h spec rule idx pos n=0
    local -a wanted=()
    while read -r line; do
        [[ "${line%% *}" == "$fam" ]] || continue
        wanted+=("${line#* }")
    done <"$dir/jumps.txt"
    # insert in reverse order so the final order matches jumps.txt
    local i
    for (( i=${#wanted[@]}-1; i>=0; i-- )); do
        h="${wanted[$i]%% *}"; spec="${wanted[$i]#* }"; rule="-A $h $spec"
        idx="$(ipt_rule_index "$fam" "$h" "$rule")"
        pos="$(printf '%s\n' "${wanted[@]}" | grep -c "^$h ")"
        if [[ $idx -eq 0 ]]; then
            # shellcheck disable=SC2086
            ipt "$fam" -I "$h" 1 $spec
        elif (( idx > pos )); then
            # shellcheck disable=SC2086
            ipt "$fam" -I "$h" 1 $spec
            ipt "$fam" -D "$h" $((idx + 1))
        fi
        n=$((n + 1))
    done
    # remove stale jumps to our chains
    while read -r rule; do
        [[ -n "$rule" ]] || continue
        h="$(awk '{print $2}' <<<"$rule")"; spec="${rule#-A "$h" }"
        if ! printf '%s\n' "${wanted[@]+"${wanted[@]}"}" | grep -Fxq -- "$h $spec"; then
            ipt_delete_rule "$fam" "$rule"
        fi
    done < <(ipt_our_jumps "$fam")
    # remove duplicates of wanted jumps (keep the first occurrence)
    for line in "${wanted[@]+"${wanted[@]}"}"; do
        h="${line%% *}"; spec="${line#* }"
        while [[ "$({ ipt "$fam" -S "$h" 2>/dev/null || true; } | grep -Fxc -- "-A $h $spec" || true)" -gt 1 ]]; do
            idx="$(ipt "$fam" -S "$h" | awk -v r="-A $h $spec" '$1=="-A" {n++; if ($0==r) c++; if ($0==r && c==2) {print n; exit}}')"
            [[ -n "$idx" ]] || break
            ipt "$fam" -D "$h" "$idx"
        done
    done
}

ipset_apply() {
    local dir=$1 sn fam name kind famname maxe cnt existing
    [[ -s "$dir/ipsets.txt" ]] || return 0
    existing="$(ipset list -n 2>/dev/null || true)"
    {
        while read -r sn fam name; do
            famname=inet; [[ $fam == 6 ]] && famname=inet6
            if [[ $name == dynamic ]]; then
                grep -Fxq -- "$sn" <<<"$existing" || printf 'create %s hash:ip,port family %s timeout 600 maxelem 262144\n' "$sn" "$famname"
                continue
            fi
            cnt="$(count_lines "$dir/sets/$name")"; maxe=65536
            (( cnt * 2 > maxe )) && maxe=$((cnt * 2))
            grep -Fxq -- "$sn" <<<"$existing" || printf 'create %s hash:net family %s hashsize 1024 maxelem %s\n' "$sn" "$famname" "$maxe"
            grep -Fxq -- "$sn-n" <<<"$existing" && printf 'destroy %s-n\n' "$sn"
            printf 'create %s-n hash:net family %s hashsize 1024 maxelem %s\n' "$sn" "$famname" "$maxe"
            sed "s/^/add $sn-n /" "$dir/sets/$name"
            printf 'swap %s-n %s\ndestroy %s-n\n' "$sn" "$sn" "$sn"
        done <"$dir/ipsets.txt"
    } >"$dir/ipset.restore"
    ipset restore <"$dir/ipset.restore"
}

ipt_cleanup_stale() {   # remove chains/sets of ours that the bundle does not use
    local dir=$1 fam ch sn
    for fam in 4 6; do
        have "$(ipt_cmd "$fam")" || continue
        if [[ -n "$dir" && -f "$dir/rules$fam.ipt" ]]; then
            ipt_apply_jumps "$dir" "$fam"
        else
            # no rules for this family in the bundle: drop all our jumps
            while read -r ch; do [[ -n "$ch" ]] && ipt_delete_rule "$fam" "$ch"; done < <(ipt_our_jumps "$fam")
        fi
        local -a stale=()
        while read -r ch; do
            [[ -n "$ch" ]] || continue
            if [[ -n "$dir" ]] && grep -Fxq -- "$fam $ch" "$dir/chains.txt" 2>/dev/null; then continue; fi
            stale+=("$ch")
        done < <(ipt_our_chains "$fam")
        for ch in "${stale[@]+"${stale[@]}"}"; do ipt "$fam" -F "$ch" >/dev/null 2>&1 || true; done
        for ch in "${stale[@]+"${stale[@]}"}"; do ipt "$fam" -X "$ch" >/dev/null 2>&1 || warn "could not delete chain $ch (IPv$fam) - still referenced?"; done
    done
    if have ipset; then
        while read -r sn; do
            [[ -n "$sn" ]] || continue
            if [[ -n "$dir" ]] && awk '{print $1}' "$dir/ipsets.txt" 2>/dev/null | grep -Fxq -- "$sn"; then continue; fi
            ipset destroy "$sn" >/dev/null 2>&1 || true
        done < <(ipset list -n 2>/dev/null | grep -E "^(${IPSET_PREFIX4}|${IPSET_PREFIX6})" || true)
    fi
}

nft_remove_all() {
    local fam name
    while read -r fam name; do
        if [[ -n "$name" ]]; then nft delete table "$fam" "$name" >/dev/null 2>&1 || true; fi
    done < <(nft_tables_ours)
}

# apply a bundle directory to the kernel
bundle_apply() {
    local dir=$1 b fam
    b="$(meta_get "$dir" backend)"
    case $b in
    nft)
        nft -f "$dir/ruleset.nft"
        # a family switch (inet <-> ip) leaves the other table behind
        local other=ip; [[ "$(meta_get "$dir" nft_family)" == ip ]] && other=inet
        nft delete table "$other" "$NFT_TABLE_NAME" >/dev/null 2>&1 || true
        ipt_cleanup_stale ""
        ;;
    ipset|iptables)
        [[ $b == ipset ]] && ipset_apply "$dir"
        for fam in 4 6; do
            [[ -f "$dir/rules$fam.ipt" ]] || continue
            ipt_restore "$fam" ${IPT_W[@]+"${IPT_W[@]}"} --noflush <"$dir/rules$fam.ipt" 2>/dev/null ||
                ipt_restore "$fam" --noflush <"$dir/rules$fam.ipt"
        done
        ipt_cleanup_stale "$dir"
        if have nft; then nft_remove_all; fi
        ;;
    *) err "bundle has unknown backend '$b'"; return 1 ;;
    esac
}

teardown_rules() {
    if have nft; then nft_remove_all; fi
    ipt_cleanup_stale ""
    return 0
}

# are the rules of the applied bundle live in the kernel?
rules_live() {
    local dir=$APPLIED_DIR b fam rule h spec idx
    [[ -f "$dir/meta" ]] || return 1
    b="$(meta_get "$dir" backend)"
    case $b in
    nft) nft list table "$(meta_get "$dir" nft_family)" "$NFT_TABLE_NAME" >/dev/null 2>&1 ;;
    *)
        for fam in 4 6; do
            [[ -f "$dir/rules$fam.ipt" ]] || continue
            ipt "$fam" -S "$IPT_MAIN" >/dev/null 2>&1 || return 1
            local pos=0
            # shellcheck disable=SC2094
            while read -r rule; do
                [[ "${rule%% *}" == "$fam" ]] || continue
                rule="${rule#* }"; h="${rule%% *}"; spec="${rule#* }"
                pos=$((pos + 1))
                idx="$(ipt_rule_index "$fam" "$h" "-A $h $spec")"
                [[ $idx -ge 1 ]] || return 1
                # must stay in front of other rules (ufw/docker may insert above us)
                (( idx <= $(grep -c "^$fam $h " "$dir/jumps.txt") )) || return 1
            done <"$dir/jumps.txt"
        done
        ;;
    esac
}

# ---------------------------------------------------------------------------
# /etc/hosts managed block
# ---------------------------------------------------------------------------
hosts_render() {   # stdout: new hosts content
    local enabled=$1 domains_file=$2
    awk -v b="$HOSTS_BEGIN" -v e="$HOSTS_END" '
        $0==b {skip=1; next} $0==e {skip=0; next} skip {next}
        /^127\.0\.0\.1[ \t]+(appclick\.co|pushnotificationws\.com)[ \t]*$/ {next}
        {print}' "$HOSTS_FILE"
    if [[ $enabled == yes && -s "$domains_file" ]]; then
        printf '%s\n' "$HOSTS_BEGIN"
        local d
        while read -r d; do [[ -n "$d" ]] && printf '127.0.0.1 %s\n::1 %s\n' "$d" "$d"; done <"$domains_file"
        printf '%s\n' "$HOSTS_END"
    fi
}

hosts_apply() {   # hosts_apply yes|no
    local enabled=$1 dom new
    [[ -f "$HOSTS_FILE" ]] || return 0
    tmp_init
    dom="$TMP_ROOT/domains"; new="$TMP_ROOT/hosts.new"
    { list_content domains; [[ -f "$USER_DOMAINS_FILE" ]] && validate_domains <"$USER_DOMAINS_FILE" 2>/dev/null; } | awk '!s[$0]++' >"$dom" || true
    hosts_render "$enabled" "$dom" >"$new"
    cmp -s "$new" "$HOSTS_FILE" && return 0
    if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] would update the managed block in ${HOSTS_FILE#"$R"}"; return 0; fi
    mkdir -p "$BACKUP_DIR"
    cp -p -- "$HOSTS_FILE" "$BACKUP_DIR/hosts.bak" 2>/dev/null || true
    # write in place: keeps inode, owner, mode, SELinux label and works on bind mounts
    if ! cat "$new" >"$HOSTS_FILE"; then
        cat "$BACKUP_DIR/hosts.bak" >"$HOSTS_FILE" 2>/dev/null || true
        err "could not write ${HOSTS_FILE#"$R"} (disk full?) - original restored"
        return 1
    fi
    info "updated domain block in ${HOSTS_FILE#"$R"}"
}

# ---------------------------------------------------------------------------
# Persistence (systemd units / cron / OpenRC)
# ---------------------------------------------------------------------------
oncalendar() { case ${CFG[UPDATE_INTERVAL]} in 6h) echo '*-*-* 00/6:00:00' ;; 12h) echo '*-*-* 00/12:00:00' ;; weekly) echo weekly ;; *) echo daily ;; esac; }
cron_spec() {
    local m=$(( RANDOM % 60 )) h=$(( RANDOM % 24 ))
    case ${CFG[UPDATE_INTERVAL]} in 6h) echo "$m */6 * * *" ;; 12h) echo "$m */12 * * *" ;; weekly) echo "$m $h * * 0" ;; *) echo "$m $h * * *" ;; esac
}

persist_install() {
    [[ $DRY_RUN -eq 1 ]] && { info "[dry-run] would install boot/update/ensure scheduling"; return 0; }
    persist_remove quiet
    if is_systemd; then
        mkdir -p "$SYSTEMD_DIR"
        atomic_write "$SYSTEMD_DIR/abuse-defender.service" <<EOF
[Unit]
Description=Abuse Defender - restore outbound abuse-protection rules at boot
Documentation=$AD_URL
DefaultDependencies=no
After=local-fs.target nftables.service netfilter-persistent.service iptables.service ip6tables.service ufw.service firewalld.service
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target
PartOf=nftables.service netfilter-persistent.service firewalld.service
ConditionPathExists=$INSTALL_BIN_REAL

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$INSTALL_BIN_REAL --quiet boot

[Install]
WantedBy=multi-user.target
EOF
        atomic_write "$SYSTEMD_DIR/abuse-defender-ensure.service" <<EOF
[Unit]
Description=Abuse Defender - re-check rules and auto-whitelist
Documentation=$AD_URL
Wants=network-online.target
After=network-online.target abuse-defender.service
ConditionPathExists=$INSTALL_BIN_REAL

[Service]
Type=oneshot
Nice=10
PrivateTmp=yes
NoNewPrivileges=yes
ExecStart=$INSTALL_BIN_REAL --quiet ensure
EOF
        atomic_write "$SYSTEMD_DIR/abuse-defender-ensure.timer" <<EOF
[Unit]
Description=Abuse Defender - periodic rule check

[Timer]
OnBootSec=45s
OnUnitActiveSec=15min
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF
        atomic_write "$SYSTEMD_DIR/abuse-defender-update.service" <<EOF
[Unit]
Description=Abuse Defender - download and apply list updates
Documentation=$AD_URL
Wants=network-online.target
After=network-online.target
ConditionPathExists=$INSTALL_BIN_REAL

[Service]
Type=oneshot
Nice=10
PrivateTmp=yes
NoNewPrivileges=yes
ExecStart=$INSTALL_BIN_REAL --quiet update
EOF
        atomic_write "$SYSTEMD_DIR/abuse-defender-update.timer" <<EOF
[Unit]
Description=Abuse Defender - scheduled list updates

[Timer]
OnCalendar=$(oncalendar)
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable abuse-defender.service >/dev/null 2>&1 || warn "could not enable abuse-defender.service"
        systemctl enable --now abuse-defender-ensure.timer >/dev/null 2>&1 || warn "could not enable abuse-defender-ensure.timer"
        if [[ ${CFG[UPDATE_ENABLED]} == yes ]]; then
            systemctl enable --now abuse-defender-update.timer >/dev/null 2>&1 || warn "could not enable abuse-defender-update.timer"
        fi
        # mark the boot unit active without running it again
        systemctl start --no-block abuse-defender.service >/dev/null 2>&1 || true
        info "systemd units installed (boot restore, 15-min ensure timer$([[ ${CFG[UPDATE_ENABLED]} == yes ]] && echo ", ${CFG[UPDATE_INTERVAL]} update timer"))"
    elif [[ -d "$CRON_D_DIR" ]]; then
        {
            printf '# Abuse Defender schedule (managed - removed by "abuse-defender uninstall")\n'
            printf 'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
            printf '@reboot root %s --quiet boot\n' "$INSTALL_BIN_REAL"
            printf '*/15 * * * * root %s --quiet ensure\n' "$INSTALL_BIN_REAL"
            [[ ${CFG[UPDATE_ENABLED]} == yes ]] && printf '%s root %s --quiet update --jitter 1800\n' "$(cron_spec)" "$INSTALL_BIN_REAL"
        } | atomic_write "$CRON_FILE" 0644
        info "no systemd: installed $CRON_FILE"
    elif [[ -d "$PERIODIC_DIR" ]]; then
        mkdir -p "$PERIODIC_DIR/15min" "$PERIODIC_DIR/daily" "$LOCAL_D_DIR"
        printf '#!/bin/sh\n# abuse-defender (managed)\nexec %s --quiet ensure\n' "$INSTALL_BIN_REAL" | atomic_write "$PERIODIC_DIR/15min/abuse-defender" 0755
        if [[ ${CFG[UPDATE_ENABLED]} == yes ]]; then
            printf '#!/bin/sh\n# abuse-defender (managed)\nexec %s --quiet update --jitter 1800\n' "$INSTALL_BIN_REAL" | atomic_write "$PERIODIC_DIR/daily/abuse-defender" 0755
        fi
        printf '#!/bin/sh\n# abuse-defender (managed)\n%s --quiet boot\n' "$INSTALL_BIN_REAL" | atomic_write "$LOCAL_D_DIR/abuse-defender.start" 0755
        info "OpenRC/Alpine: installed periodic jobs and $LOCAL_D_DIR/abuse-defender.start (run 'rc-update add local default' if not enabled)"
    else
        warn "no systemd, /etc/cron.d or /etc/periodic found - rules will NOT survive a reboot; run 'abuse-defender boot' from your init system"
    fi
    if [[ -d "$R/etc/logrotate.d" ]]; then
        printf '%s {\n    weekly\n    rotate 4\n    compress\n    missingok\n    notifempty\n    copytruncate\n}\n' "${LOG_FILE#"$R"}" |
            atomic_write "$LOGROTATE_FILE" 0644
    fi
}

persist_remove() {
    local quiet=${1:-} u
    if is_systemd; then
        for u in abuse-defender-update.timer abuse-defender-ensure.timer abuse-defender.service abuse-defender-update.service abuse-defender-ensure.service; do
            if [[ -f "$SYSTEMD_DIR/$u" ]]; then
                [[ $quiet == quiet ]] || systemctl disable --now "$u" >/dev/null 2>&1 || true
                [[ $quiet == quiet ]] && { systemctl disable "$u" >/dev/null 2>&1 || true; }
            fi
        done
    fi
    rm -f -- "$SYSTEMD_DIR"/abuse-defender*.service "$SYSTEMD_DIR"/abuse-defender*.timer
    is_systemd && { systemctl daemon-reload >/dev/null 2>&1 || true; }
    rm -f -- "$CRON_FILE" "$PERIODIC_DIR/15min/abuse-defender" "$PERIODIC_DIR/daily/abuse-defender" "$LOCAL_D_DIR/abuse-defender.start"
    [[ $quiet == quiet ]] || rm -f -- "$LOGROTATE_FILE"
    return 0
}

# ---------------------------------------------------------------------------
# Legacy (v1) detection and migration
# ---------------------------------------------------------------------------
legacy_crontab_has() { have crontab && crontab -l 2>/dev/null | grep -Fq "abuse-defender-update.sh"; }
legacy_hosts_has() {   # v1 lines outside our managed block
    [[ -f "$HOSTS_FILE" ]] || return 1
    awk -v b="$HOSTS_BEGIN" -v e="$HOSTS_END" '$0==b {skip=1; next} $0==e {skip=0; next}
        !skip && /^127\.0\.0\.1[ \t]+(appclick\.co|pushnotificationws\.com)[ \t]*$/ {found=1}
        END {exit !found}' "$HOSTS_FILE"
}
legacy_chains_have() {
    have iptables || return 1
    iptables -S 2>/dev/null | grep -Eq -- '^-N abuse-defender-whitelist$' && return 0
    iptables -S abuse-defender-custom 2>/dev/null | grep -Eq -- '^-A abuse-defender-custom -d [0-9./]+ -j DROP$' && return 0
    iptables -S "$IPT_MAIN" 2>/dev/null | grep -Eq -- '^-A abuse-defender -d [0-9./]+ -j DROP$'
}
legacy_detect() {
    [[ -f "$OLD_UPDATE_SCRIPT" ]] || legacy_crontab_has || legacy_hosts_has || legacy_chains_have
}

# import v1 custom-block / whitelist rules so nothing the admin added is lost
legacy_import_rules() {
    have iptables || return 0
    local e n=0
    mkdir -p "$CONF_DIR"
    while read -r e; do
        e="$(normalize_one "$e" block 2>/dev/null)" || continue
        grep -Fxq -- "$e" "$CUSTOM_FILE" 2>/dev/null || { printf '%s\n' "$e" >>"$CUSTOM_FILE"; n=$((n + 1)); }
    done < <(iptables -S abuse-defender-custom 2>/dev/null | awk '$1=="-A" && $3=="-d" && $NF=="DROP" {print $4}')
    while read -r e; do
        e="$(normalize_one "$e" allow 2>/dev/null)" || continue
        grep -Fxq -- "$e" "$WHITELIST_FILE" 2>/dev/null || { printf '%s\n' "$e" >>"$WHITELIST_FILE"; n=$((n + 1)); }
    done < <(iptables -S abuse-defender-whitelist 2>/dev/null | awk '$1=="-A" && $3=="-d" && $NF=="ACCEPT" {print $4}')
    [[ $n -gt 0 ]] && report "imported $n entr$([[ $n -eq 1 ]] && echo y || echo ies) from the v1 custom/whitelist chains"
    return 0
}

# strip our rules from distro persistence files so a saved ruleset never depends on our sets
strip_persisted_rules() {
    local f changed=0
    for f in "$R/etc/iptables/rules.v4" "$R/etc/iptables/rules.v6" "$R/etc/sysconfig/iptables" "$R/etc/sysconfig/ip6tables"; do
        [[ -f "$f" ]] || continue
        grep -Eq -- "(^:${IPT_PREFIX}|^-A ${IPT_PREFIX}| -j ${IPT_PREFIX}| --match-set ad[46]-)" "$f" || continue
        [[ $DRY_RUN -eq 1 ]] && { info "[dry-run] would remove abuse-defender lines from ${f#"$R"}"; continue; }
        mkdir -p "$BACKUP_DIR"
        cp -p -- "$f" "$BACKUP_DIR/$(basename "$f").$(date +%Y%m%d%H%M%S)"
        grep -Ev -- "(^:${IPT_PREFIX}|^-A ${IPT_PREFIX}| -j ${IPT_PREFIX}(-[A-Za-z0-9-]+)?([[:space:]]|$)| --match-set ad[46]-)" "$f" >"$f.ad-new" || true
        cat "$f.ad-new" >"$f"; rm -f -- "$f.ad-new"
        changed=1
        report "removed abuse-defender rules from ${f#"$R"} (backup in ${BACKUP_DIR#"$R"})"
    done
    # nftables persistence: drop our table block from the config if someone saved it
    for f in "$R/etc/nftables.conf" "$R/etc/sysconfig/nftables.conf"; do
        [[ -f "$f" ]] && grep -Eq "^table (inet|ip) $NFT_TABLE_NAME " "$f" || continue
        [[ $DRY_RUN -eq 1 ]] && continue
        mkdir -p "$BACKUP_DIR"; cp -p -- "$f" "$BACKUP_DIR/$(basename "$f").$(date +%Y%m%d%H%M%S)"
        awk -v n="$NFT_TABLE_NAME" '
            !skip && $0 ~ "^table (inet|ip) " n " [{]" { skip=1; depth=0 }
            skip { o=gsub(/[{]/,"{"); c=gsub(/[}]/,"}"); depth+=o-c; if (depth<=0) skip=0; next }
            {print}' "$f" >"$f.ad-new" && cat "$f.ad-new" >"$f"; rm -f -- "$f.ad-new"
        changed=1
    done
    [[ $changed -eq 0 ]] || info "persistence files cleaned"
    return 0
}

legacy_cleanup() {   # remove v1 artefacts that are no longer needed (rules handled by stale cleanup)
    if [[ -f "$OLD_UPDATE_SCRIPT" ]]; then
        rm -f -- "$OLD_UPDATE_SCRIPT"; report "removed old ${OLD_UPDATE_SCRIPT#"$R"}"
    fi
    if legacy_crontab_has; then
        tmp_init
        local cur="$TMP_ROOT/crontab.cur" new="$TMP_ROOT/crontab.new"
        if crontab -l >"$cur" 2>/dev/null; then
            grep -Fv "abuse-defender-update.sh" "$cur" >"$new" || true
            if crontab "$new"; then report "removed the old abuse-defender-update.sh crontab line (other lines kept)"
            else warn "could not rewrite crontab - remove the abuse-defender-update.sh line manually"; fi
        fi
    fi
    strip_persisted_rules
}

# ---------------------------------------------------------------------------
# Self-test, confirmation and rollback
# ---------------------------------------------------------------------------
selftest() {   # prints "name ok|fail" lines
    local gw first_mirror host
    first_mirror="$(awk '{print $1}' <<<"${CFG[MIRRORS]}")"
    host="${first_mirror#https://}"; host="${host%%/*}"
    if have curl; then
        if curl -fsS -o /dev/null --max-time 10 -I "https://$host/" 2>/dev/null; then echo "https-$host ok"; else echo "https-$host fail"; fi
    fi
    if have timeout; then
        if timeout 6 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then echo "tcp-1.1.1.1:443 ok"; else echo "tcp-1.1.1.1:443 fail"; fi
        if [[ $IPV6_ON -eq 1 ]] && ip -6 route show default 2>/dev/null | grep -q .; then
            if timeout 6 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/443' 2>/dev/null; then echo "tcp6-cloudflare:443 ok"; else echo "tcp6-cloudflare:443 fail"; fi
        fi
    fi
    if have getent && have timeout; then
        if timeout 8 getent ahosts "$host" >/dev/null 2>&1; then echo "dns ok"; else echo "dns fail"; fi
    fi
    if have ping; then
        for gw in $(detect_gateways | grep -v '^fe80' | head -n 2); do
            if ping -c 1 -W 2 "$gw" >/dev/null 2>&1; then echo "gw-$gw ok"; else echo "gw-$gw fail"; fi
        done
    fi
    return 0
}

# compare: anything that worked before and fails now is a regression
selftest_regressions() {
    local before=$1 after=$2
    awk 'NR==FNR { b[$1]=$2; next } b[$1]=="ok" && $2!="ok" { print $1 }' "$before" "$after"
}

rollback_rules() {
    if [[ -f "$PREVIOUS_DIR/meta" ]]; then
        if bundle_apply "$PREVIOUS_DIR"; then
            rm -rf -- "$APPLIED_DIR"; cp -a -- "$PREVIOUS_DIR" "$APPLIED_DIR"
            warn "rolled back to the previous rules"
            return 0
        fi
        err "re-applying the previous rules failed - removing all abuse-defender rules"
    fi
    teardown_rules
    rm -rf -- "$APPLIED_DIR"
    warn "rolled back: abuse-defender rules removed"
}

spawn_rollback_watchdog() {   # survives SIGKILL/terminal loss of this process
    local token=$1 secs=$2
    [[ -x "$INSTALL_BIN" ]] || return 0
    printf '%s\n' "$token" >"$RUN_DIR/pending-confirm"
    if have setsid; then
        setsid "$INSTALL_BIN" --quiet _auto-rollback "$token" "$secs" </dev/null >/dev/null 2>&1 9>&- &
    else
        nohup "$INSTALL_BIN" --quiet _auto-rollback "$token" "$secs" </dev/null >/dev/null 2>&1 9>&- &
    fi
    disown 2>/dev/null || true
}

cmd_auto_rollback() {
    local token=${1:-} secs=${2:-60}
    [[ "$secs" =~ ^[0-9]+$ ]] || exit 0
    sleep $((secs + 15))
    [[ -f "$RUN_DIR/pending-confirm" && "$(cat "$RUN_DIR/pending-confirm" 2>/dev/null)" == "$token" ]] || exit 0
    lock_acquire 600
    [[ -f "$RUN_DIR/pending-confirm" && "$(cat "$RUN_DIR/pending-confirm" 2>/dev/null)" == "$token" ]] || exit 0
    rm -f -- "$RUN_DIR/pending-confirm"
    rollback_rules
}

# apply_pipeline CONFIRM(yes|no) : build, apply, test, confirm/rollback, record
apply_pipeline() {
    local want_confirm=$1 new before after reg
    tmp_init
    new="$TMP_ROOT/bundle"
    bundle_build "$new" || return 1
    if [[ -s "$new/notes.txt" ]]; then while read -r l; do warn "$l"; done <"$new/notes.txt"; fi
    if [[ $DRY_RUN -eq 1 ]]; then
        say "----- dry-run: backend=$BACKEND$([[ $BACKEND == nft ]] && echo "/$NFT_FAMILY") $(family_label "$IPV4_ON" "$IPV6_ON") egress=$( [[ -s $new/egress.txt ]] && paste -sd' ' "$new/egress.txt" || echo all) -----"
        say "auto-whitelist:"; sed 's/^/  /' "$new/auto-allow.txt"
        while read -r name fam kind tag; do say "  set $name ($kind): $(count_lines "$new/sets/$name") entries"; done <"$new/sets.txt"
        if [[ -f "$new/ruleset.nft" ]]; then grep -v '^add element' "$new/ruleset.nft"; say "(+ $(grep -c '^add element' "$new/ruleset.nft" || true) element chunks)"; fi
        local f; for f in 4 6; do [[ -f "$new/rules$f.ipt" ]] && { say "--- rules$f.ipt (first 60 lines)"; head -n 60 "$new/rules$f.ipt"; }; done
        [[ -f "$new/jumps.txt" ]] && { say "--- jumps"; cat "$new/jumps.txt"; }
        return 0
    fi

    before="$TMP_ROOT/selftest.before"; after="$TMP_ROOT/selftest.after"
    selftest >"$before"

    mkdir -p "$STATE_DIR"
    rm -rf -- "$PREVIOUS_DIR"
    [[ -f "$APPLIED_DIR/meta" ]] && cp -a -- "$APPLIED_DIR" "$PREVIOUS_DIR"

    if ! bundle_apply "$new"; then
        err "applying rules failed"
        rollback_rules
        return 1
    fi
    rm -rf -- "$APPLIED_DIR"; cp -a -- "$new" "$APPLIED_DIR"

    selftest >"$after"
    reg="$(selftest_regressions "$before" "$after")"
    if [[ -n "$reg" ]]; then
        sleep 3; selftest >"$after"; reg="$(selftest_regressions "$before" "$after")"
    fi
    if [[ -n "$reg" ]]; then
        err "connectivity self-test regressed after applying ($(tr '\n' ' ' <<<"$reg")) - rolling back"
        rollback_rules
        return 1
    fi

    local timeout="${OPT_CONFIRM_TIMEOUT:-${CFG[CONFIRM_TIMEOUT]}}"
    if [[ $want_confirm == yes && $INTERACTIVE -eq 1 && $ASSUME_YES -eq 0 && $OPT_NO_CONFIRM -eq 0 && $timeout -gt 0 ]]; then
        local token ans
        token="$$-$(now_epoch)-$RANDOM"
        PENDING_CONFIRM=1
        spawn_rollback_watchdog "$token" "$timeout"
        say ""
        say "${C_BLD}Open a NEW SSH session now and check that you can still log in."
        say "Type 'yes' within ${timeout}s to keep the new rules (anything else rolls back):${C_OFF}"
        prompt ans "> " "$timeout" || ans=""
        if [[ "${ans,,}" == yes || "${ans,,}" == y ]]; then
            PENDING_CONFIRM=0
            rm -f -- "$RUN_DIR/pending-confirm"
        else
            PENDING_CONFIRM=0
            rm -f -- "$RUN_DIR/pending-confirm"
            rollback_rules
            warn "not confirmed - the previous rules were restored"
            return 1
        fi
    fi
    ok "rules applied: backend=$BACKEND$([[ $BACKEND == nft ]] && echo "($NFT_FAMILY)") $(family_label "$IPV4_ON" "$IPV6_ON") egress=$( [[ -s $APPLIED_DIR/egress.txt ]] && paste -sd' ' "$APPLIED_DIR/egress.txt" || echo all)"
    return 0
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
require_installed() {
    [[ -f "$CONF_FILE" || $DRY_RUN -eq 1 ]] && return 0
    die "Abuse Defender is not installed - run: abuse-defender install"
}

# installed (config exists) and enabled: only then do edits trigger a rule reload
active_install() {
    if [[ -f "$CONF_FILE" && ${CFG[ENABLED]} == yes ]]; then return 0; fi
    [[ -f "$CONF_FILE" ]] || info "not installed yet - change saved; run 'abuse-defender install' to activate"
    return 1
}

require_root() {
    [[ $IS_ROOT -eq 1 ]] || die "run as root (sudo -i)"
}

ensure_dirs() {
    [[ $DRY_RUN -eq 1 ]] && return 0
    mkdir -p "$CONF_DIR" "$STATE_DIR" "$CACHE_DIR" "$RUN_DIR"
    chmod 0755 "$CONF_DIR" 2>/dev/null || true
    [[ -f "$WHITELIST_FILE" ]] || printf '# One IPv4/IPv6 address or CIDR per line. Traffic to these is never blocked.\n' >"$WHITELIST_FILE"
    [[ -f "$CUSTOM_FILE" ]] || printf '# One IPv4/IPv6 address or CIDR per line. Always blocked (unless whitelisted).\n' >"$CUSTOM_FILE"
    [[ -f "$USER_DOMAINS_FILE" ]] || printf '# Extra domains to sinkhole in /etc/hosts (one per line).\n' >"$USER_DOMAINS_FILE"
}

self_source_file() {   # prints a path to a copy of this script suitable for installation
    local s="${BASH_SOURCE[0]:-$0}"
    if [[ -f "$s" && -r "$s" && "$s" != /dev/* && "$s" != /proc/* ]] && grep -q '^AD_VERSION=' "$s"; then
        printf '%s' "$s"; return 0
    fi
    # running from a pipe (bash <(curl ...)): fetch a fresh copy
    tmp_init
    local base out="$TMP_ROOT/abuse-defender.sh"
    for base in ${CFG[MIRRORS]}; do
        if http_get_tracked "$base/abuse-defender.sh" "$out" && bash -n "$out" 2>/dev/null && grep -q '^AD_VERSION=' "$out" &&
            verify_sum "$base" "abuse-defender.sh" "$out"; then
            printf '%s' "$out"; return 0
        fi
    done
    return 1
}

install_binary() {
    local src
    [[ $DRY_RUN -eq 1 ]] && { info "[dry-run] would install $INSTALL_BIN"; return 0; }
    src="$(self_source_file)" || die "could not obtain a copy of the script to install"
    if [[ -f "$INSTALL_BIN" ]] && cmp -s "$src" "$INSTALL_BIN"; then return 0; fi
    mkdir -p "$(dirname -- "$INSTALL_BIN")"
    atomic_write "$INSTALL_BIN" 0755 <"$src"
    info "installed ${INSTALL_BIN#"$R"} (v$(grep -m1 '^AD_VERSION=' "$INSTALL_BIN" | cut -d'"' -f2))"
}

conntrack_note() {
    local max cnt
    max="$(cat "$PROC_DIR/sys/net/netfilter/nf_conntrack_max" 2>/dev/null || true)"
    cnt="$(cat "$PROC_DIR/sys/net/netfilter/nf_conntrack_count" 2>/dev/null || true)"
    if [[ -n "$max" && -n "$cnt" && "$max" =~ ^[0-9]+$ && "$cnt" =~ ^[0-9]+$ ]] && (( cnt * 100 > max * 70 )); then
        warn "conntrack table is ${cnt}/${max} full - busy proxies should raise net.netfilter.nf_conntrack_max"
    fi
    return 0
}

report() { REPORT+=("$*"); info "$*"; }

version_gt() {   # version_gt A B -> 0 when dotted version A is newer than B
    local -a va=() vb=()
    local i x y
    IFS=. read -r -a va <<<"$1"
    IFS=. read -r -a vb <<<"$2"
    for i in 0 1 2 3; do
        x="${va[$i]:-0}"; y="${vb[$i]:-0}"; x="${x//[^0-9]/}"; y="${y//[^0-9]/}"
        (( 10#${x:-0} > 10#${y:-0} )) && return 0
        (( 10#${x:-0} < 10#${y:-0} )) && return 1
    done
    return 1
}
installed_version() { { grep -m1 '^AD_VERSION=' "$INSTALL_BIN" 2>/dev/null || true; } | cut -d'"' -f2; }

# v1 rules that actively drop traffic
legacy_protected() {
    have iptables || return 1
    { iptables -S "$IPT_MAIN" 2>/dev/null || true; } | grep -Eq -- '^-A abuse-defender -d [0-9./]+ -j DROP$'
}

# save every v1 chain, rule and jump (iptables -S format) so a failed migration can put them back
legacy_snapshot() {
    local f=$1
    : >"$f"
    have iptables || return 0
    { iptables -S 2>/dev/null || true; } | awk -v p="$IPT_PREFIX" '
        ($1=="-N" || $1=="-A") && index($2,p)==1 { print; next }
        $1=="-A" && ($2=="OUTPUT" || $2=="FORWARD") { for (i=3;i<NF;i++) if ($i=="-j" && index($(i+1),p)==1) { print; next } }' >"$f"
}

legacy_restore() {   # re-create the v1 protection after a failed migration
    local f=$1 line ch
    [[ -s "$f" ]] && have iptables || return 0
    iptables -S "$IPT_MAIN" >/dev/null 2>&1 && return 0     # still there
    local -a w
    while read -r _ ch; do iptables -N "$ch" >/dev/null 2>&1 || true; done < <(awk '$1=="-N"' "$f")
    while read -r line; do
        read -r -a w <<<"$line"
        iptables "${w[@]}" >/dev/null 2>&1 || true
    done < <(awk '$1=="-A" && $2!="OUTPUT" && $2!="FORWARD"' "$f")
    while read -r line; do
        read -r -a w <<<"$line"
        w[0]="-I"
        iptables "${w[0]}" "${w[1]}" 1 "${w[@]:2}" >/dev/null 2>&1 || true
    done < <(awk '$1=="-A" && ($2=="OUTPUT" || $2=="FORWARD") {a[++n]=$0} END {for (i=n;i>0;i--) print a[i]}' "$f")
    report "migration failed: the previous v1 rules were restored unchanged"
}

# Install or re-install without asking. CONFIRM=yes asks for the interactive keep-rules check.
do_install() {
    local confirm=$1 v1=0 snap=""
    legacy_detect && v1=1
    ensure_dirs
    if [[ $v1 -eq 1 && $DRY_RUN -eq 0 ]]; then
        legacy_import_rules
        tmp_init; snap="$TMP_ROOT/v1-snapshot"; legacy_snapshot "$snap"
    fi
    CFG[ENABLED]=yes
    config_write
    install_binary
    select_backend
    info "backend: $BACKEND$([[ $BACKEND == nft ]] && echo " ($NFT_FAMILY)")$([[ $BACKEND != nft ]] && echo " (iptables $(iptables_variant))"), $(family_label "$IPV4_ON" "$IPV6_ON")"
    local c; while read -r c; do [[ -n "$c" ]] && warn "$c"; done < <(detect_conflicts)
    update_sources || true
    if ! apply_pipeline "$confirm"; then
        [[ -n "$snap" ]] && legacy_restore "$snap"
        err "protection was NOT applied (previous state kept)"
        return 1
    fi
    [[ $DRY_RUN -eq 1 ]] && return 0
    hosts_apply "${CFG[HOSTS_BLOCK]}"
    [[ $v1 -eq 1 ]] && legacy_cleanup
    strip_persisted_rules
    persist_install
    conntrack_note
    return 0
}

cmd_install() {
    require_root
    lock_acquire
    if [[ $INTERACTIVE -eq 1 && $ASSUME_YES -eq 0 ]]; then
        say "This will install Abuse Defender v$AD_VERSION:"
        say "  - script: ${INSTALL_BIN#"$R"}, config: ${CONF_FILE#"$R"}"
        say "  - outbound DROP rules for: ${CFG[CATEGORIES]}${CFG[GEO_COUNTRIES]:+, countries: ${CFG[GEO_COUNTRIES]}}"
        say "  - boot restore + periodic checks + automatic list updates"
        legacy_detect && say "  - replace the old v1 setup (cron script, hosts lines, chains)"
        ask_yes_no "Continue?" y || { info "cancelled"; return 0; }
    fi
    do_install yes || return 1
    [[ $DRY_RUN -eq 1 ]] || ok "Abuse Defender v$AD_VERSION is active. Check with: abuse-defender status"
}

# Replace any older installation (v1 artefacts or an older v2) without asking.
# The new rules are loaded before anything old is removed; on failure the old rules stay.
auto_replace_old() {
    [[ $IS_ROOT -eq 1 && $DRY_RUN -eq 0 ]] || return 0
    local v1=0 v1prot=0 upgrade=0 iv=""
    legacy_detect && v1=1
    [[ $v1 -eq 1 ]] && legacy_protected && v1prot=1
    if [[ -f "$INSTALL_BIN" ]]; then
        iv="$(installed_version)"
        if [[ -z "$iv" ]] || version_gt "$AD_VERSION" "$iv"; then upgrade=1; fi
    fi
    [[ -f "$CONF_FILE" && $CONFIG_OBSOLETE -eq 1 ]] && upgrade=1
    [[ $v1 -eq 1 || $upgrade -eq 1 ]] || return 0
    lock_acquire
    if [[ $v1 -eq 1 ]]; then
        report "found an Abuse Defender v1 setup - replacing it with v$AD_VERSION"
        if [[ $v1prot -eq 1 || -f "$CONF_FILE" ]]; then
            if do_install no; then report "v1 replaced: new rules active, old chains/cron/script/hosts lines removed"
            else report "replacement failed - nothing was removed; see the errors above"; fi
        else
            # leftovers of a v1 setup whose rules were already cleared: just tidy up
            legacy_import_rules
            legacy_cleanup
            [[ -f "$APPLIED_DIR/meta" ]] || ipt_cleanup_stale ""
            hosts_apply "$([[ -f "$CONF_FILE" ]] && echo "${CFG[HOSTS_BLOCK]}" || echo no)"
            report "removed inactive v1 leftovers (no v1 rules were active)"
        fi
    else
        report "found Abuse Defender v${iv:-unknown} - upgrading to v$AD_VERSION"
        if [[ -f "$CONF_FILE" && ${CFG[ENABLED]} == yes ]]; then
            do_install no || report "upgrade failed - the previous rules stay active"
        else
            ensure_dirs; config_write; install_binary
            [[ -f "$CONF_FILE" ]] && persist_install
            report "settings and program files upgraded (protection is disabled)"
        fi
    fi
    lock_release     # the menu runs its actions in subshells that take the lock themselves
    return 0
}

print_report() {
    [[ ${#REPORT[@]} -gt 0 ]] || return 0
    say "${C_BLD}Previous installation replaced:${C_OFF}"
    printf '  - %s\n' "${REPORT[@]}"
}

# Settings checkpoint: when an interactive change is not confirmed (or fails) the rules
# are rolled back - the settings must go back too, or the ensure timer would re-apply them.
CKPT=0
config_checkpoint() {
    tmp_init
    mkdir -p "$TMP_ROOT/ckpt"
    local f
    for f in "$CONF_FILE" "$WHITELIST_FILE" "$CUSTOM_FILE" "$USER_DOMAINS_FILE"; do
        if [[ -f "$f" ]]; then cp -p -- "$f" "$TMP_ROOT/ckpt/$(basename -- "$f")"; else : >"$TMP_ROOT/ckpt/$(basename -- "$f").absent"; fi
    done
    CKPT=1
}
config_rollback() {
    [[ $CKPT -eq 1 && $DRY_RUN -eq 0 ]] || return 0
    local f b
    for f in "$CONF_FILE" "$WHITELIST_FILE" "$CUSTOM_FILE" "$USER_DOMAINS_FILE"; do
        b="$TMP_ROOT/ckpt/$(basename -- "$f")"
        if [[ -f "$b" ]]; then cp -p -- "$b" "$f"; elif [[ -f "$b.absent" ]]; then rm -f -- "$f"; fi
    done
    config_load; apply_runtime_config
    warn "settings restored to their previous values"
}
apply_or_revert() { apply_pipeline "$1" && return 0; config_rollback; return 1; }

cmd_apply() {
    require_root
    require_installed
    lock_acquire
    if [[ ${CFG[ENABLED]} != yes ]]; then
        info "protection is disabled (ENABLED=no) - removing rules"
        [[ $DRY_RUN -eq 1 ]] || { teardown_rules; rm -rf -- "$APPLIED_DIR"; hosts_apply no; }
        return 0
    fi
    select_backend
    apply_pipeline "${1:-yes}" || return 1
    [[ $DRY_RUN -eq 1 ]] && return 0
    hosts_apply "${CFG[HOSTS_BLOCK]}"
    strip_persisted_rules
}

cmd_update() {
    require_root
    require_installed
    if [[ $OPT_JITTER -gt 0 ]]; then sleep $(( RANDOM % OPT_JITTER )); fi
    lock_acquire 900
    if [[ ${CFG[ENABLED]} != yes ]]; then info "protection is disabled - skipping update"; return 0; fi
    select_backend
    UPDATE_CHANGED=0
    update_sources
    if [[ $DRY_RUN -eq 1 ]]; then return 0; fi
    if [[ $UPDATE_CHANGED -eq 1 ]] || ! rules_live; then
        apply_pipeline no || return 1
    else
        info "lists unchanged and rules live - nothing to do"
    fi
    hosts_apply "${CFG[HOSTS_BLOCK]}"
    [[ $UPDATE_FAILED -eq 0 ]] || return 3
}

cmd_ensure() {
    require_root
    [[ -f "$CONF_FILE" ]] || return 0
    lock_acquire 300
    legacy_detect && [[ -f "$INSTALL_BIN" ]] && legacy_cleanup
    # drop settings that no longer exist (IP_FAMILY, MODE, ...) so the notice is shown once
    [[ $CONFIG_OBSOLETE -eq 1 ]] && config_write
    if [[ ${CFG[ENABLED]} != yes ]]; then
        if [[ -n "$(nft_tables_ours 2>/dev/null)" ]] || { have iptables && [[ -n "$(ipt_our_chains 4)" ]]; }; then
            teardown_rules; rm -rf -- "$APPLIED_DIR"; hosts_apply no
        fi
        return 0
    fi
    select_backend
    tmp_init
    local probe="$TMP_ROOT/probe"
    bundle_build "$probe" || return 1
    if [[ -f "$APPLIED_DIR/hash" && "$(cat "$APPLIED_DIR/hash")" == "$(cat "$probe/hash")" ]] && rules_live; then
        hosts_apply "${CFG[HOSTS_BLOCK]}"
        return 0
    fi
    info "rules missing or environment changed (interfaces/gateway/DNS) - re-applying"
    apply_pipeline no || return 1
    hosts_apply "${CFG[HOSTS_BLOCK]}"
    strip_persisted_rules
}

cmd_boot() {
    require_root
    [[ -f "$CONF_FILE" ]] || return 0
    lock_acquire 120
    [[ ${CFG[ENABLED]} == yes ]] || return 0
    if [[ ! -f "$APPLIED_DIR/meta" ]]; then
        info "no applied ruleset yet - the ensure timer will build one once the network is up"
        return 0
    fi
    local b; b="$(meta_get "$APPLIED_DIR" backend)"
    if [[ $b != nft ]]; then
        if have iptables && iptables -w -L -n >/dev/null 2>&1; then IPT_W=(-w); fi
    fi
    if [[ $OPT_SETS_ONLY -eq 1 ]]; then
        [[ $b == ipset ]] && ipset_apply "$APPLIED_DIR"
        return 0
    fi
    bundle_apply "$APPLIED_DIR" || { err "boot restore failed"; return 1; }
    hosts_apply "${CFG[HOSTS_BLOCK]}"
    ok "rules restored from ${APPLIED_DIR#"$R"}"
}

entry_file_edit() {  # entry_file_edit add|del FILE ENTRY
    local op=$1 file=$2 e=$3
    mkdir -p "$(dirname -- "$file")"
    touch "$file"
    if [[ $op == add ]]; then
        grep -Fxq -- "$e" "$file" && { info "$e is already listed"; return 1; }
        [[ $DRY_RUN -eq 1 ]] && { info "[dry-run] would add $e to ${file#"$R"}"; return 1; }
        printf '%s\n' "$e" >>"$file"
    else
        grep -Fxq -- "$e" "$file" || { warn "$e is not in ${file#"$R"}"; return 1; }
        [[ $DRY_RUN -eq 1 ]] && { info "[dry-run] would remove $e from ${file#"$R"}"; return 1; }
        grep -Fxv -- "$e" "$file" | atomic_write "$file" 0644 || true
    fi
    return 0
}

cmd_entries() {   # cmd_entries add|del allow|block ENTRY...
    require_root
    local op=$1 kind=$2; shift 2
    [[ $# -gt 0 ]] || die "missing IP/CIDR"
    lock_acquire
    ensure_dirs
    config_checkpoint
    local file=$CUSTOM_FILE policy=block changed=0 raw e
    [[ $kind == allow ]] && { file=$WHITELIST_FILE; policy=allow; }
    for raw in "$@"; do
        if ! e="$(normalize_one "$raw" "$policy")"; then
            err "rejected '$raw': $({ printf '%s\n' "$raw" | normalize_list any "$policy" 1 2>&1 >/dev/null || true; } | head -n1)"
            continue
        fi
        [[ "$e" != "$raw" && "$e" != "$raw/32" && "$e" != "$raw/128" ]] && info "normalised '$raw' to $e"
        entry_file_edit "$op" "$file" "$e" && { changed=1; ok "$([[ $op == add ]] && echo added || echo removed) $e ($([[ $kind == allow ]] && echo whitelist || echo custom block))"; }
    done
    [[ $changed -eq 1 ]] || return 0
    if active_install; then
        select_backend
        # removing a whitelist entry can cut access: ask for confirmation
        local conf=no; [[ $op == del && $kind == allow ]] && conf=yes
        apply_or_revert "$conf"
    fi
}

cmd_category() {   # category NAME on|off
    require_root
    local name=${1:-} state=${2:-}
    [[ $name =~ ^(bogons|abuse|spamhaus|feodo)$ ]] || die "category must be one of: bogons abuse spamhaus feodo"
    [[ $state =~ ^(on|off)$ ]] || die "usage: category $name on|off"
    lock_acquire
    config_checkpoint
    if [[ $state == on ]]; then config_list_add CATEGORIES "$name"; else config_list_del CATEGORIES "$name"; fi
    config_write
    if active_install; then
        select_backend
        if [[ $state == on ]]; then
            local -a srcs=()
            mapfile -t srcs < <(needed_sources | grep "^$name-" || true)
            [[ ${#srcs[@]} -gt 0 ]] && update_sources "${srcs[@]}"
        fi
        apply_or_revert yes
    fi
}

# ips_in_prefixes FAM LISTFILE < "addr label" lines -> prints the lines whose addr lies
# inside any prefix of LISTFILE (canonical "addr/len" entries of family FAM)
ips_in_prefixes() {
    local fam=$1 list=$2
    if [[ $fam == 4 ]]; then
        awk 'function n(a,  o){ split(a,o,"."); return o[1]*16777216+o[2]*65536+o[3]*256+o[4] }
             NR==FNR { split($1,c,"/"); s=n(c[1]); S[NR]=s; E[NR]=s+2^(32-c[2])-1; m=NR; next }
             { split($1,c,"/"); x=n(c[1]); for (i=1;i<=m;i++) if (x>=S[i] && x<=E[i]) { print; break } }' "$list" -
    else
        awk 'function hv(s,  i,v){ v=0; for(i=1;i<=length(s);i++) v=v*16+index("0123456789abcdef",substr(s,i,1))-1; return v }
             function parse(a,  i,h,t,hn,tn,k,d,hd,tl){ d=index(a,"::")
               if (d) { hd=substr(a,1,d-1); tl=substr(a,d+2); hn=(hd=="")?0:split(hd,h,":"); tn=(tl=="")?0:split(tl,t,":")
                 k=0; for(i=1;i<=hn;i++) G[k++]=hv(h[i]); for(i=0;i<8-hn-tn;i++) G[k++]=0; for(i=1;i<=tn;i++) G[k++]=hv(t[i]) }
               else { split(a,h,":"); for(i=1;i<=8;i++) G[i-1]=hv(h[i]) } }
             function key(p,  i,b,v,r){ r=""; for(i=0;i<8;i++){ b=p-16*i; v=G[i]; if(b<=0) v=0; else if(b<16) v=int(v/2^(16-b))*2^(16-b); r=r v ":" } return r p }
             NR==FNR { split($1,c,"/"); parse(c[1]); L[c[2]+0]=1; K[key(c[2]+0)]=1; next }
             { split($1,c,"/"); parse(c[1]); for (q in L) if (key(q+0) in K) { print; break } }' "$list" -
    fi
}

# what would cut this server off if the country were blocked: gateway, DNS, SSH clients
geo_conflicts() {   # geo_conflicts CC -> prints "addr reason" lines inside the country lists
    local cc=$1 f
    tmp_init
    {
        detect_gateways | grep -v '^fe80' | sed 's/$/ default-gateway/'
        detect_dns | sed 's/%.*//' | grep -v -e '^127\.' -e '^::1$' -e '^fe80' | sed 's/$/ dns-resolver/'
        detect_ssh_clients | sed 's/$/ ssh-client/'
    } 2>/dev/null | { awk -v keep=1 -v want=any -v policy=none -v strict=0 "$AWK_NORMALIZE" 2>/dev/null || true; } | sort -u >"$TMP_ROOT/geo-own" || true
    for f in $(active_fams); do
        [[ -s "$CACHE_DIR/geo-$cc-v$f.txt" ]] || continue
        normalize_list "$f" none 0 <"$CACHE_DIR/geo-$cc-v$f.txt" 2>/dev/null >"$TMP_ROOT/geo-list" || true
        awk -v f="$f" '(f==4 && $1 !~ /:/) || (f==6 && $1 ~ /:/)' "$TMP_ROOT/geo-own" | ips_in_prefixes "$f" "$TMP_ROOT/geo-list"
    done
}

cmd_geo() {   # geo add|remove|list CC
    require_root
    local op=${1:-list} cc=${2:-}
    case $op in
    list) say "countries blocked: ${CFG[GEO_COUNTRIES]:-none}"; return 0 ;;
    add|remove) [[ "${cc,,}" =~ ^[a-z]{2}$ ]] || die "country must be a 2-letter ISO code (e.g. ir)"; cc="${cc,,}" ;;
    *) die "usage: geo add|remove|list [CC]" ;;
    esac
    if [[ $op == remove ]]; then
        lock_acquire
        config_checkpoint
        config_list_del GEO_COUNTRIES "$cc"; config_write
        ok "country $cc removed"
        if active_install; then select_backend; apply_or_revert yes; fi
        return 0
    fi
    # add: download, count, check that we do not cut ourselves off, confirm, apply
    # shellcheck disable=SC2086
    if word_in "$cc" ${CFG[GEO_COUNTRIES]}; then info "country $cc is already blocked"; return 0; fi
    [[ -f "$CONF_FILE" && ${CFG[ENABLED]} == yes ]] || die "install and enable protection first (abuse-defender install)"
    lock_acquire
    config_checkpoint
    select_backend
    local -a srcs=()
    local f n4=0 n6=0 have_data=0
    for f in $(active_fams); do srcs+=("geo-$cc-v$f"); done
    update_sources "${srcs[@]}" || true
    for f in $(active_fams); do
        if [[ -s "$CACHE_DIR/geo-$cc-v$f.txt" ]]; then
            have_data=1
            if [[ $f == 4 ]]; then n4="$(count_lines "$CACHE_DIR/geo-$cc-v4.txt")"; else n6="$(count_lines "$CACHE_DIR/geo-$cc-v6.txt")"; fi
        fi
    done
    [[ $have_data -eq 1 ]] || die "could not download a valid list for '$cc' - country blocking NOT enabled"
    local conflicts
    conflicts="$(geo_conflicts "$cc")"
    if [[ -n "$conflicts" ]]; then
        warn "these addresses this server depends on are inside the '${cc^^}' prefixes:"
        printf '%s\n' "$conflicts" | sed 's/^/    /' >&2
        if [[ $FORCE -eq 0 ]]; then
            die "refusing to block '${cc^^}': it would cut off your gateway/DNS/SSH session (override with --force)"
        fi
        warn "--force given: continuing anyway (the auto-whitelist still exempts these addresses)"
    fi
    local msg v6txt=""
    [[ $IPV6_ON -eq 1 ]] && v6txt=" + $n6 IPv6"
    msg="This blocks ALL outbound traffic to ${cc^^}: $n4 IPv4$v6txt prefixes. Services hosted there become unreachable from this server."
    if [[ $DRY_RUN -eq 1 ]]; then info "[dry-run] $msg"; return 0; fi
    if [[ $ASSUME_YES -eq 0 ]]; then
        if [[ $INTERACTIVE -ne 1 ]]; then die "$msg Re-run with --yes to confirm."; fi
        say "$msg"
        ask_yes_no "Block ${cc^^}?" n || { info "cancelled - nothing changed"; return 0; }
    else
        info "$msg"
    fi
    config_list_add GEO_COUNTRIES "$cc"; config_write
    if apply_or_revert yes; then ok "country ${cc^^} blocked"; else return 1; fi
}

MODULE_KEYS="smtp:BLOCK_SMTP ports:BLOCK_PORTS scanguard:SCAN_GUARD forward:APPLY_FORWARD logging:LOG_BLOCKED hosts:HOSTS_BLOCK stateful:STATEFUL autowhitelist:AUTO_WHITELIST sshprotect:PROTECT_SSH_CLIENT updates:UPDATE_ENABLED"
module_key() { local m; for m in $MODULE_KEYS; do [[ ${m%%:*} == "$1" ]] && { echo "${m#*:}"; return 0; }; done; return 1; }

cmd_module() {   # module NAME on|off  | module (list)
    require_root
    local name=${1:-} state=${2:-} key m
    if [[ -z "$name" ]]; then
        for m in $MODULE_KEYS; do printf '  %-14s %s\n' "${m%%:*}" "${CFG[${m#*:}]}"; done
        return 0
    fi
    key="$(module_key "$name")" || die "unknown module '$name' (one of: $(for m in $MODULE_KEYS; do printf '%s ' "${m%%:*}"; done))"
    [[ $state =~ ^(on|off)$ ]] || die "usage: module $name on|off"
    lock_acquire
    config_checkpoint
    config_set "$key" "$([[ $state == on ]] && echo yes || echo no)"
    config_write
    ok "module $name: $state"
    if [[ $key == UPDATE_ENABLED ]]; then [[ -f "$INSTALL_BIN" ]] && persist_install; return 0; fi
    if [[ $key == HOSTS_BLOCK ]]; then hosts_apply "${CFG[HOSTS_BLOCK]}"; return 0; fi
    if active_install; then select_backend; apply_or_revert yes; fi
}

cmd_set() {   # set KEY VALUE (generic, for automation)
    require_root
    [[ $# -ge 1 ]] || die "usage: set KEY VALUE"
    local key=$1; shift
    lock_acquire
    config_set "$key" "$*"
    config_write
    case $key in
    UPDATE_INTERVAL|UPDATE_ENABLED|LOG_FILE) [[ -f "$INSTALL_BIN" ]] && persist_install; ok "$key=\"$*\"" ;;
    *) ok "$key=\"$*\" (run 'abuse-defender apply' to activate)" ;;
    esac
}

cmd_config() {   # print the effective configuration
    local row
    say "# effective configuration (${CONF_FILE#"$R"}$([[ -f "$CONF_FILE" ]] || echo ", not installed: defaults"))"
    for row in "${CONFIG_SCHEMA[@]}"; do
        schema_split "$row"
        printf '%s="%s"\n' "$SK" "${CFG[$SK]#"$R"}"
    done
}

cmd_enable() {
    require_root
    require_installed
    lock_acquire
    CFG[ENABLED]=yes; config_write
    select_backend
    [[ -d "$CACHE_DIR" ]] || update_sources || true
    apply_pipeline yes && hosts_apply "${CFG[HOSTS_BLOCK]}"
}

cmd_disable() {
    require_root
    require_installed
    lock_acquire
    if [[ $INTERACTIVE -eq 1 ]] && ! ask_yes_no "Remove all abuse-defender rules (settings are kept)?" n; then return 0; fi
    CFG[ENABLED]=no; config_write
    [[ $DRY_RUN -eq 1 ]] && return 0
    teardown_rules; rm -rf -- "$APPLIED_DIR"
    hosts_apply no
    ok "protection disabled (rules removed; settings kept). Re-enable: abuse-defender enable"
}

cmd_uninstall() {
    require_root
    if [[ $ASSUME_YES -eq 0 ]]; then
        [[ $INTERACTIVE -eq 1 ]] || die "uninstall needs --yes when not run interactively"
        ask_yes_no "Completely remove Abuse Defender (rules, timers, hosts entries, files$([[ $OPT_KEEP_CONFIG -eq 1 ]] || echo ", settings"))?" n || { info "cancelled"; return 0; }
    fi
    lock_acquire
    if [[ $DRY_RUN -eq 1 ]]; then
        info "[dry-run] would remove: rules/chains/sets/tables, systemd/cron/OpenRC jobs, hosts block, ${INSTALL_BIN#"$R"}, ${STATE_DIR#"$R"}$([[ $OPT_KEEP_CONFIG -eq 1 ]] || echo ", ${CONF_DIR#"$R"}"), ${LOG_FILE#"$R"}"
        return 0
    fi
    persist_remove
    teardown_rules
    hosts_apply no
    # v1 leftovers too
    legacy_cleanup
    strip_persisted_rules
    rm -f -- "$INSTALL_BIN"
    rm -rf -- "$STATE_DIR" "$RUN_DIR"
    [[ $OPT_KEEP_CONFIG -eq 1 ]] || rm -rf -- "$CONF_DIR"
    LOG_TO_FILE=0
    [[ -n "$LOG_FILE" ]] && rm -f -- "$LOG_FILE" "$LOG_FILE".[0-9]* "$LOG_FILE".*.gz 2>/dev/null
    ok "Abuse Defender removed.$([[ $OPT_KEEP_CONFIG -eq 1 ]] && echo " Settings kept in ${CONF_DIR#"$R"}.")"
}

human_bytes() { awk -v b="${1:-0}" 'BEGIN { split("B KiB MiB GiB TiB",u," "); i=1; while (b>=1024 && i<5) { b/=1024; i++ } printf (i==1?"%d %s":"%.1f %s"), b, u[i] }'; }

counters() {   # prints "tag packets bytes"
    local dir=$APPLIED_DIR b fam
    b="$(meta_get "$dir" backend)"
    case $b in
    nft)
        { nft list table "$(meta_get "$dir" nft_family)" "$NFT_TABLE_NAME" 2>/dev/null || true; } | awk '
            /counter packets/ && /comment "/ { p=0; by=0; for (i=1;i<=NF;i++) { if ($i=="packets") p=$(i+1); if ($i=="bytes") by=$(i+1) }
              c=$0; sub(/.*comment "/,"",c); sub(/".*/,"",c); P[c]+=p; B[c]+=by }
            END { for (c in P) print c, P[c], B[c] }' ;;
    ipset)
        for fam in 4 6; do
            [[ -f "$dir/rules$fam.ipt" ]] || continue
            { ipt "$fam" -nvxL "$IPT_MAIN" 2>/dev/null || true; } | awk '
                /match-set/ && !/LOG/ && $3!="RETURN" { tag="?"; for (i=1;i<=NF;i++) if ($i=="match-set") tag=$(i+1); print tag, $1, $2; next }
                /multiport/ && !/LOG/ && $3!="RETURN" { print "ports/smtp", $1, $2 }'
            { ipt "$fam" -nvxL "${IPT_PREFIX}-scan" 2>/dev/null || true; } | awk '/hashlimit/ && !/LOG/ {print "scanguard", $1, $2}'
        done | awk '{ t=$1; sub(/^ad[46]-/,"",t); P[t]+=$2; B[t]+=$3 } END { for (t in P) print t, P[t], B[t] }' ;;
    iptables)
        for fam in 4 6; do
            [[ -f "$dir/rules$fam.ipt" ]] || continue
            local chn
            while read -r chn; do
                [[ "$chn" == "$fam ${IPT_PREFIX}-"* ]] || continue
                chn="${chn#* }"; [[ $chn == "${IPT_PREFIX}-drop" ]] && continue
                { ipt "$fam" -nvxL "$chn" 2>/dev/null || true; } | awk -v t="${chn#"${IPT_PREFIX}"-}" 'NR>2 {p+=$1; b+=$2} END {print t, p+0, b+0}'
            done <"$dir/chains.txt"
            { ipt "$fam" -nvxL "$IPT_MAIN" 2>/dev/null || true; } | awk 'NR>2 && /multiport/ && !/LOG/ && $3!="RETURN" {print "ports/smtp", $1, $2}'
        done | awk '{ P[$1]+=$2; B[$1]+=$3 } END { for (t in P) print t, P[t], B[t] }' ;;
    esac
}

timer_state() {   # short
    if is_systemd; then
        if [[ -f "$SYSTEMD_DIR/abuse-defender-ensure.timer" ]]; then
            printf 'systemd update:%s ensure:%s' "$(systemctl is-active abuse-defender-update.timer 2>/dev/null || echo inactive)" \
                "$(systemctl is-active abuse-defender-ensure.timer 2>/dev/null || echo inactive)"
        else printf 'none'; fi
    elif [[ -f "$CRON_FILE" ]]; then printf 'cron'
    elif [[ -f "$PERIODIC_DIR/15min/abuse-defender" ]]; then printf 'openrc-periodic'
    else printf 'none'; fi
}

last_update_str() {
    local t; t="$(awk -F= '$1=="time" {print $2}' "$STATE_DIR/last-update" 2>/dev/null || true)"
    if [[ -n "$t" ]]; then
        printf '%s (%s)' "$(date -d "@$t" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$t")" "$(awk -F= '$1=="status" {print $2}' "$STATE_DIR/last-update")"
    else printf 'never'; fi
}

status_line() {   # one line: protected | backend | families | updated | timer
    local prot="${C_RED}NO${C_OFF}" bk="-" famtxt="-"
    if [[ ! -f "$CONF_FILE" ]]; then prot="${C_RED}NO (not installed)${C_OFF}"
    elif [[ ${CFG[ENABLED]} != yes ]]; then prot="${C_YEL}NO (disabled)${C_OFF}"
    elif [[ $IS_ROOT -eq 1 && -f "$APPLIED_DIR/meta" ]] && rules_live 2>/dev/null; then
        prot="${C_GRN}YES${C_OFF}"
    fi
    if [[ -f "$APPLIED_DIR/meta" ]]; then
        bk="$(meta_get "$APPLIED_DIR" backend)"
        [[ $bk == nft ]] && bk="nft/$(meta_get "$APPLIED_DIR" nft_family)"
        famtxt="$(family_label "$(meta_get "$APPLIED_DIR" ipv4)" "$(meta_get "$APPLIED_DIR" ipv6)")"
    fi
    printf 'Protected: %s | backend: %s | %s | updated: %s | timer: %s\n' \
        "$prot" "$bk" "$famtxt" "$(last_update_str)" "$(timer_state)"
}

cmd_status() {
    say "${C_BLD}Abuse Defender v$AD_VERSION${C_OFF}"
    status_line
    if [[ $IS_ROOT -eq 1 ]] && legacy_detect; then say "${C_YEL}Old v1 artefacts present - they are replaced automatically on the next install/menu run.${C_OFF}"; fi
    [[ -f "$APPLIED_DIR/meta" ]] || return 0
    local s="" name fam kind tag
    while read -r name fam kind tag; do
        [[ $kind == block || $kind == custom ]] || continue
        s="$s $tag/v$fam=$(count_lines "$APPLIED_DIR/sets/$name")"
    done <"$APPLIED_DIR/sets.txt"
    say "Ranges     :$s"
    say "Egress     : $( [[ -s $APPLIED_DIR/egress.txt ]] && paste -sd' ' "$APPLIED_DIR/egress.txt" || echo 'all non-loopback interfaces')"
    say "Settings   : categories='${CFG[CATEGORIES]}' geo='${CFG[GEO_COUNTRIES]}'"
    local m line=""
    for m in $MODULE_KEYS; do line="$line ${m%%:*}=${CFG[${m#*:}]}"; done
    say "Modules    :$line"
    [[ "$(meta_get "$APPLIED_DIR" backend)" != nft ]] && say "iptables   : $(iptables_variant)"
    if [[ $IS_ROOT -eq 1 ]]; then
        say ""
        say "Blocked packets per category (since rules were loaded):"
        local p b
        while read -r tag p b; do printf '  %-20s %10s pkts  %s\n' "$tag" "$p" "$(human_bytes "$b")"; done < <(counters | sort)
    fi
    if [[ -s "$APPLIED_DIR/auto-allow.txt" ]]; then
        say ""; say "Auto-whitelisted (AUTO_WHITELIST / PROTECT_SSH_CLIENT):"
        sed 's/^/  /' "$APPLIED_DIR/auto-allow.txt"
    fi
    if [[ -s "$APPLIED_DIR/sets/local_v4" || -s "$APPLIED_DIR/sets/local_v6" ]]; then
        say "Directly connected subnets (exempt from range lists only):"
        cat "$APPLIED_DIR"/sets/local_v* 2>/dev/null | sed 's/^/  /'
    fi
    [[ -s "$APPLIED_DIR/notes.txt" ]] && { say ""; say "Notes:"; sed 's/^/  - /' "$APPLIED_DIR/notes.txt"; }
    if [[ $IS_ROOT -eq 1 ]]; then
        local c; c="$(detect_conflicts)"; [[ -n "$c" ]] && { say ""; say "Environment:"; printf '%s\n' "$c" | sed 's/^/  - /'; }
        conntrack_note
    fi
    return 0
}

cmd_list() {   # list [whitelist|custom|auto|domains|CATEGORY]
    local what=${1:-all} f name fam kind tag
    case $what in
    whitelist) grep -v '^#' "$WHITELIST_FILE" 2>/dev/null || true ;;
    custom) grep -v '^#' "$CUSTOM_FILE" 2>/dev/null || true ;;
    auto) cat "$APPLIED_DIR/auto-allow.txt" 2>/dev/null || true ;;
    domains) list_content domains; grep -v '^#' "$USER_DOMAINS_FILE" 2>/dev/null || true ;;
    all)
        [[ -f "$APPLIED_DIR/sets.txt" ]] || { say "no rules applied yet"; return 0; }
        while read -r name fam kind tag; do
            say "## $name ($kind, $(count_lines "$APPLIED_DIR/sets/$name") entries)"
            cat "$APPLIED_DIR/sets/$name"
        done <"$APPLIED_DIR/sets.txt" ;;
    *)
        local found=0
        for f in "$APPLIED_DIR"/sets/"${what//-/_}"_v[46]; do
            [[ -f "$f" ]] && { cat "$f"; found=1; }
        done
        if [[ $found -eq 0 ]]; then
            for f in 4 6; do list_content "$what-v$f" 2>/dev/null || true; done
        fi ;;
    esac
}

cmd_hits() {   # hits [N]
    local n=${1:-15} src="" f
    [[ "$n" =~ ^[0-9]+$ ]] || n=15
    tmp_init
    local log="$TMP_ROOT/hits"
    : >"$log"
    if have journalctl && journalctl -k -n 1 >/dev/null 2>&1; then
        { journalctl -k -o cat --no-pager -n 200000 2>/dev/null || true; } | grep -F 'AD-DROP' >"$log" || true; src="journalctl -k"
    fi
    if [[ ! -s "$log" ]]; then
        for f in "$R/var/log/kern.log" "$R/var/log/messages" "$R/var/log/syslog"; do
            [[ -r "$f" ]] && { grep -F 'AD-DROP' "$f" >"$log" 2>/dev/null || true; src="$f"; [[ -s "$log" ]] && break; }
        done
    fi
    if [[ ! -s "$log" ]] && have dmesg; then { dmesg 2>/dev/null || true; } | grep -F 'AD-DROP' >"$log" || true; src=dmesg; fi
    if [[ ! -s "$log" ]]; then
        say "No blocked-packet log lines found (LOG_BLOCKED=${CFG[LOG_BLOCKED]}). Counters: abuse-defender status"
        return 0
    fi
    say "Source: $src  ($(count_lines "$log") log lines, rate-limited to ${CFG[LOG_RATE]}/min per rule)"
    top() {
        local title=$1 field=$2
        say ""; say "Top $title:"
        awk -v f="$field" '{ for (i=1;i<=NF;i++) if (index($i, f "=")==1) { print substr($i, length(f)+2); break } }' "$log" |
            sort | uniq -c | sort -rn | head -n "$n" | awk '{printf "  %8d  %s\n", $1, $2}'
    }
    say ""; say "By category:"
    sed -nE 's/.*AD-DROP ?([^:]*):.*/\1/p' "$log" | sort | uniq -c | sort -rn | awk '{printf "  %8d  %s\n", $1, ($2==""?"(generic)":$2)}'
    top "destinations" DST
    top "destination ports" DPT
    top "local users (UID) - who is sending it" UID
    unset -f top
}

SETTINGS_FILES="abuse-defender.conf whitelist.txt custom-block.txt domains.txt"

cmd_export() {   # export [FILE]: settings only (config, whitelist, custom blocks, domains)
    require_root
    local out=${1:-"$R/root/abuse-defender-settings-$(date +%Y%m%d-%H%M%S).tar.gz"}
    [[ -d "$CONF_DIR" ]] || die "nothing to export (not installed)"
    [[ $DRY_RUN -eq 1 ]] && { info "[dry-run] would write $out"; return 0; }
    local root="${R:-/}"
    tar -C "$root" -czf "$out" etc/abuse-defender 2>/dev/null || die "export failed"
    chmod 600 "$out"
    ok "settings exported to $out"
}

cmd_import() {   # import FILE: settings from 'export' (or a v2.0.0 backup)
    require_root
    local file=${1:-}
    [[ -f "$file" ]] || die "usage: import FILE.tar.gz"
    lock_acquire
    tmp_init
    local x="$TMP_ROOT/import" entry name
    mkdir -p "$x"
    # refuse anything unexpected: absolute paths, '..', links, devices, foreign files
    while IFS= read -r entry; do
        [[ $entry == *..* || $entry == /* ]] && die "refusing archive: unsafe path '$entry'"
        case $entry in
        etc|etc/|etc/abuse-defender|etc/abuse-defender/) ;;
        etc/abuse-defender/*)
            name="${entry#etc/abuse-defender/}"
            # shellcheck disable=SC2086
            word_in "$name" $SETTINGS_FILES || die "refusing archive: unexpected file '$entry'" ;;
        var|var/|var/lib|var/lib/|var/lib/abuse-defender|var/lib/abuse-defender/|var/lib/abuse-defender/lists|var/lib/abuse-defender/lists/|var/lib/abuse-defender/lists/*.txt|var/lib/abuse-defender/lists/*.meta) ;;
        *) die "refusing archive: unexpected entry '$entry'" ;;
        esac
    done < <(tar -tzf "$file")
    if tar -tvzf "$file" | awk '{print substr($1,1,1)}' | grep -qv '^[-d]$'; then die "refusing archive: contains links or special files"; fi
    tar -C "$x" -xzf "$file" --no-same-owner etc/abuse-defender 2>/dev/null || die "the archive contains no settings (etc/abuse-defender)"
    local f
    for name in $SETTINGS_FILES; do
        f="$x/etc/abuse-defender/$name"
        [[ -f "$f" ]] || continue
        case $name in
        domains.txt) validate_domains <"$f" >/dev/null || die "invalid domains in the archive" ;;
        whitelist.txt) normalize_list any allow 1 <"$f" >/dev/null || die "invalid entries in whitelist.txt" ;;
        custom-block.txt) normalize_list any block 1 <"$f" >/dev/null || die "invalid entries in custom-block.txt" ;;
        esac
    done
    [[ $DRY_RUN -eq 1 ]] && { ok "[dry-run] archive is valid"; return 0; }
    mkdir -p "$CONF_DIR"
    config_checkpoint
    for name in $SETTINGS_FILES; do
        f="$x/etc/abuse-defender/$name"
        [[ -f "$f" ]] && cp -f -- "$f" "$CONF_DIR/$name"
    done
    config_load; apply_runtime_config; config_write
    ok "settings imported from $file"
    if [[ ${CFG[ENABLED]} == yes && -f "$INSTALL_BIN" ]]; then select_backend; apply_or_revert yes && hosts_apply "${CFG[HOSTS_BLOCK]}"; fi
}

# ---------------------------------------------------------------------------
# doctor: read-only diagnosis (only temporary probe tables/chains are created)
# ---------------------------------------------------------------------------
cmd_doctor() {
    local fails=0 warns=0 t
    d_ok()   { say "  [ OK ] $*"; }
    d_info() { say "  [INFO] $*"; }
    d_warn() { say "  [WARN] $*"; warns=$((warns + 1)); }
    d_fail() { say "  [FAIL] $*"; fails=$((fails + 1)); }
    say "Abuse Defender v$AD_VERSION - doctor"
    say ""; say "System"
    if [[ $IS_ROOT -eq 1 ]]; then d_ok "running as root"; else d_fail "not running as root - most checks need root"; fi
    if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 2) )); then d_ok "bash $BASH_VERSION"
    else d_fail "bash $BASH_VERSION is too old (4.2+ needed)"; fi
    for t in awk sed grep sort cksum mktemp tar; do have "$t" || d_fail "required tool missing: $t"; done
    if have curl; then d_ok "curl available"; elif have wget; then d_ok "wget available (curl preferred)"; else d_fail "neither curl nor wget - lists cannot be downloaded"; fi
    if have ip; then d_ok "iproute2 'ip' available"; else d_fail "'ip' missing - gateway/interface detection impossible"; fi
    if have ss; then d_ok "'ss' available (SSH client detection)"; else d_warn "'ss' missing - connected SSH clients are not auto-whitelisted"; fi
    if have sha256sum; then d_ok "sha256sum available"; else d_warn "sha256sum missing - downloads cannot be checksum-verified"; fi
    if have flock; then d_ok "flock available"; else d_warn "flock missing - a directory lock is used instead"; fi
    if [[ $IS_ROOT -ne 1 ]]; then say ""; say "Summary: $fails failure(s), $warns warning(s)"; unset -f d_ok d_info d_warn d_fail; return 1; fi

    say ""; say "Firewall"
    if have nft; then
        if nft_probe inet; then d_ok "nftables usable (inet family, IPv4+IPv6)"
        elif nft_probe ip; then d_warn "nftables usable for IPv4 only (no inet family)"
        else d_warn "nft installed but not usable (kernel modules/permissions?)"; fi
    else d_info "nft not installed"; fi
    if have iptables; then d_info "iptables: $(iptables -V 2>/dev/null || echo unknown)"; else d_info "iptables not installed"; fi
    if have iptables-legacy-save && have iptables-nft-save; then
        local nl nn
        nl="$({ iptables-legacy-save 2>/dev/null || true; } | grep -c '^-A' || true)"
        nn="$({ iptables-nft-save 2>/dev/null || true; } | grep -c '^-A' || true)"
        if [[ ${nl:-0} -gt 0 && ${nn:-0} -gt 0 ]]; then d_warn "rules exist in BOTH iptables-legacy ($nl) and iptables-nft ($nn) - both are evaluated; harder to debug"; fi
    fi
    if have ipset; then d_info "ipset installed"; fi
    local sel
    if sel="$(select_backend 2>&1 >/dev/null && printf 'backend=%s%s, %s' "$BACKEND" "${NFT_FAMILY:+/$NFT_FAMILY}" "$(family_label "$IPV4_ON" "$IPV6_ON")")"; then
        d_ok "selected: $sel (BACKEND=${CFG[BACKEND]})"
        select_backend >/dev/null 2>&1
        tmp_init
        if bundle_build "$TMP_ROOT/doctor" >/dev/null 2>&1; then
            local lvl; lvl="$(meta_get "$TMP_ROOT/doctor" level)"
            if [[ $lvl == 0 ]]; then d_ok "the kernel accepts the full ruleset (all configured features)"
            else d_warn "ruleset accepted at reduced feature level $lvl:"; sed 's/^/           /' "$TMP_ROOT/doctor/notes.txt"; fi
        else
            d_fail "the rendered ruleset is rejected by the kernel - run 'abuse-defender --dry-run apply' and see the errors"
        fi
    else
        d_fail "no usable backend: ${sel:-unknown error}"
    fi

    say ""; say "Network"
    local egress gws dns gw
    egress="$(detect_egress_ifaces | tr '\n' ' ')"
    if [[ ${CFG[EGRESS_INTERFACES]} == all ]]; then d_info "EGRESS_INTERFACES=all: every non-loopback interface is filtered"
    elif [[ -n "$egress" ]]; then d_ok "uplink interface(s): $egress"
    else d_warn "no default route found - all non-loopback interfaces would be filtered"; fi
    gws="$(detect_gateways | tr '\n' ' ')"
    [[ -n "$gws" ]] && d_info "default gateway(s): $gws (always allowed)"
    for gw in $(detect_gateways | grep -v '^fe80' | head -n 2); do
        if have ping && ping -c 1 -W 2 "$gw" >/dev/null 2>&1; then d_ok "gateway $gw answers ping"
        else d_info "gateway $gw does not answer ping (many providers filter ICMP; not an error)"; fi
    done
    dns="$(detect_dns | grep -v '^127\.' | grep -v '^::1$' | sort -u | tr '\n' ' ' || true)"
    [[ -n "$dns" ]] && d_info "DNS resolvers: $dns(always allowed)"
    local first host
    first="$(awk '{print $1}' <<<"${CFG[MIRRORS]}")"; host="$(host_of "$first")"
    if have getent && getent ahosts "$host" >/dev/null 2>&1; then d_ok "DNS resolution works ($host)"
    elif have getent; then d_fail "cannot resolve $host - DNS problem"; fi
    local base okm=0
    tmp_init
    for base in ${CFG[MIRRORS]}; do
        if http_get "$base/lists/SHA256SUMS" "$TMP_ROOT/doctor-sums" || http_get "$base/abuse-ips.ipv4" "$TMP_ROOT/doctor-sums"; then
            d_ok "mirror reachable: $base"; okm=$((okm + 1))
        else d_warn "mirror unreachable: $base"; fi
    done
    [[ $okm -gt 0 ]] || d_fail "no mirror reachable - updates fail (cached lists keep working); set MIRRORS"
    if ipv6_available; then
        if have ip && ip -6 route show default 2>/dev/null | grep -q .; then d_ok "IPv6 available with a default route"
        else d_info "IPv6 enabled in the kernel but no IPv6 default route"; fi
    else d_info "no IPv6 on this host - only IPv4 is filtered"; fi

    say ""; say "Protection"
    if [[ -f "$CONF_FILE" ]]; then d_ok "installed (config ${CONF_FILE#"$R"})"; else d_warn "not installed - run: abuse-defender install"; fi
    if [[ -f "$INSTALL_BIN" ]]; then
        local iv; iv="$(installed_version)"
        if [[ "$iv" == "$AD_VERSION" ]]; then d_ok "program ${INSTALL_BIN#"$R"} v$iv"
        else d_info "program ${INSTALL_BIN#"$R"} is v${iv:-?}, this script is v$AD_VERSION"; fi
    fi
    if [[ -f "$CONF_FILE" ]]; then
        [[ ${CFG[ENABLED]} == yes ]] && d_ok "protection enabled" || d_warn "protection is disabled (ENABLED=no) - enable it with: abuse-defender enable"
        if [[ -f "$APPLIED_DIR/meta" ]]; then
            if rules_live; then d_ok "rules are loaded in the kernel"
            else d_fail "rules are NOT loaded (another tool removed them?) - run: abuse-defender apply"; fi
            if [[ -f "$TMP_ROOT/doctor/hash" && -f "$APPLIED_DIR/hash" ]] && [[ "$(cat "$TMP_ROOT/doctor/hash")" != "$(cat "$APPLIED_DIR/hash")" ]]; then
                d_warn "gateway/DNS/interfaces/lists changed since the last apply - the ensure timer re-applies within 15 min"
            fi
        elif [[ ${CFG[ENABLED]} == yes ]]; then d_fail "no rules applied yet - run: abuse-defender apply"; fi
        local name age now; now="$(now_epoch)"
        while read -r name; do
            if [[ -f "$CACHE_DIR/$name.txt" ]]; then
                age="$(awk -F= '$1=="fetched" {print $2}' "$CACHE_DIR/$name.meta" 2>/dev/null || true)"
                if [[ -n "$age" && $(( (now - age) / 86400 )) -gt 7 ]]; then d_warn "list $name is $(( (now - age) / 86400 )) days old"
                else d_ok "list $name: $(count_lines "$CACHE_DIR/$name.txt") entries"; fi
            else
                source_info "$name" || true
                if [[ $SRC_BUILTIN -eq 1 ]]; then d_info "list $name: not downloaded yet, built-in copy in use"
                else d_warn "list $name: no data - run: abuse-defender update"; fi
            fi
        done < <(needed_sources)
        if grep -q '^status=partial' "$STATE_DIR/last-update" 2>/dev/null; then d_warn "last update was partial: $(last_update_str)"; fi
    fi
    if legacy_detect; then d_warn "old v1 artefacts present - replaced automatically on the next install/menu run"; fi
    for t in "$R/etc/iptables/rules.v4" "$R/etc/iptables/rules.v6" "$R/etc/sysconfig/iptables" "$R/etc/sysconfig/ip6tables"; do
        if [[ -f "$t" ]] && grep -Eq -- "(-j ${IPT_PREFIX}|--match-set ad[46]-)" "$t"; then d_warn "${t#"$R"} contains abuse-defender rules (removed automatically on the next apply)"; fi
    done

    say ""; say "Scheduling"
    if is_systemd; then
        local u st
        for u in abuse-defender.service abuse-defender-ensure.timer abuse-defender-update.timer; do
            if [[ -f "$SYSTEMD_DIR/$u" ]]; then
                st="$(systemctl is-enabled "$u" 2>/dev/null || echo disabled)"
                if [[ $st == enabled ]]; then d_ok "$u enabled"
                elif [[ $u == abuse-defender-update.timer && ${CFG[UPDATE_ENABLED]} == no ]]; then d_info "$u disabled (UPDATE_ENABLED=no)"
                else d_warn "$u is $st"; fi
            elif [[ -f "$CONF_FILE" ]]; then d_warn "$u missing - run: abuse-defender install"; fi
        done
    elif [[ -f "$CRON_FILE" ]]; then d_ok "cron schedule ${CRON_FILE#"$R"}"
    elif [[ -f "$PERIODIC_DIR/15min/abuse-defender" ]]; then d_ok "OpenRC periodic jobs installed"
    elif [[ -f "$CONF_FILE" ]]; then d_warn "no scheduler: rules do not survive a reboot and lists are not updated"; fi

    say ""; say "Environment"
    local c
    while read -r c; do [[ -n "$c" ]] && d_info "$c"; done < <(detect_conflicts)
    local max cnt
    max="$(cat "$PROC_DIR/sys/net/netfilter/nf_conntrack_max" 2>/dev/null || true)"
    cnt="$(cat "$PROC_DIR/sys/net/netfilter/nf_conntrack_count" 2>/dev/null || true)"
    if [[ "$max" =~ ^[0-9]+$ && "$cnt" =~ ^[0-9]+$ && $max -gt 0 ]]; then
        if (( cnt * 100 > max * 70 )); then d_warn "conntrack table ${cnt}/${max} (>70%) - raise net.netfilter.nf_conntrack_max"
        else d_ok "conntrack table ${cnt}/${max}"; fi
    fi
    say ""
    say "Summary: $fails failure(s), $warns warning(s)"
    unset -f d_ok d_info d_warn d_fail
    [[ $fails -eq 0 ]]
}

cmd_selftest() {
    require_root
    select_backend
    say "Connectivity self-test (what the rollback guard checks):"
    selftest | sed 's/^/  /'
}

cmd_self_update() {
    require_root
    lock_acquire
    tmp_init
    local base out="$TMP_ROOT/new.sh" v
    for base in ${CFG[MIRRORS]}; do
        if http_get_tracked "$base/abuse-defender.sh" "$out" && bash -n "$out" 2>/dev/null && grep -q '^AD_VERSION=' "$out" &&
            verify_sum "$base" "abuse-defender.sh" "$out"; then
            v="$(grep -m1 '^AD_VERSION=' "$out" | cut -d'"' -f2)"
            if [[ -f "$INSTALL_BIN" ]] && cmp -s "$out" "$INSTALL_BIN"; then ok "already up to date (v$v)"; return 0; fi
            [[ $DRY_RUN -eq 1 ]] && { info "[dry-run] would install v$v"; return 0; }
            atomic_write "$INSTALL_BIN" 0755 <"$out"
            ok "installed v$v from $base"
            return 0
        fi
    done
    die "could not download a valid script from any mirror"
}

cmd_validate() {   # validate FILE [4|6|any] [block|allow]
    local file=${1:-} fam=${2:-any} pol=${3:-block}
    [[ -f "$file" ]] || die "usage: validate FILE [4|6|any] [block|allow|none]"
    if normalize_list "$fam" "$pol" 1 <"$file"; then return 0; fi
    return 3
}

usage() {
    cat <<EOF
Abuse Defender v$AD_VERSION - block outbound traffic that causes hosting abuse reports
$AD_URL

Usage: abuse-defender [options] [command] [args]
       Without a command on a terminal the interactive menu opens.

Protection
  install                 install to ${INSTALL_BIN_REAL}, fetch lists, apply, schedule updates
  update                  download + validate lists, apply if changed (used by the timer)
  apply                   rebuild and apply rules from settings + cached lists (no download)
  status                  protection state, counters, auto-whitelist, environment
  doctor                  diagnose backend, kernel features, conflicts, network, timers, lists
  enable | disable        turn protection on/off (settings kept)
  uninstall               remove everything (rules, timers, hosts block, files)

Allow and block
  whitelist <ip/cidr>...  never block these        unwhitelist <ip/cidr>...
  block <ip/cidr>...      always block these       unblock <ip/cidr>...
  list [what]             all | whitelist | custom | auto | domains | <category>

Settings
  category <name> on|off  bogons | abuse | spamhaus | feodo
  geo add|remove|list CC  outbound country blocking, e.g. 'geo add ir' (asks first; --yes to confirm)
  module [name on|off]    smtp ports scanguard forward logging hosts stateful autowhitelist sshprotect updates
  set KEY VALUE           change any setting (see 'config')
  config                  print the effective settings

Tools
  hits [N]                top blocked destinations/ports/UIDs from the kernel log
  export [file]           save settings (config, whitelist, custom blocks, domains)
  import <file>           load settings saved by 'export'
  selftest                run the connectivity checks used by the rollback guard
  self-update             replace the installed program with the latest release
  validate FILE [4|6|any] [block|allow]   check a list file (no root needed)
  menu                    interactive menu (reads answers from stdin when it is not a terminal)
  ensure | boot           used by the timers / boot unit
  version | help

Options
  -y, --yes               assume yes (non-interactive; also skips the keep-rules prompt)
  -n, --dry-run           show what would happen, change nothing
  -q, --quiet             only warnings and errors
      --force             accept lists that shrank a lot; block a country that contains
                          your gateway/DNS/SSH client (not recommended)
      --backend=B         auto | nft | ipset | iptables (this run)
      --confirm-timeout=N seconds to confirm risky changes before auto-rollback
      --no-confirm        apply without the interactive keep-rules prompt
      --keep-config       with uninstall: keep ${CONF_DIR#"$R"}
      --jitter=N          with update: random delay up to N seconds
      --config=FILE       alternative config file
      --no-color          no colours (NO_COLOR is honoured too)

Examples
  bash <(curl -s https://raw.githubusercontent.com/$AD_REPO/main/abuse-defender.sh)
  abuse-defender install --yes
  abuse-defender whitelist 10.10.0.0/16
  abuse-defender --yes geo add ir
  abuse-defender doctor
  abuse-defender uninstall --yes
EOF
}

# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------
MENU_NOTICE_SHOWN=0

# run a command in a subshell: errors and 'die' return to the menu, rollback still works
menu_run() {
    (
        TMP_ROOT=""; LOCK_HELD=0; LOCK_DIR_FALLBACK=""; PENDING_CONFIRM=0
        trap cleanup EXIT
        "$@"
    ) || true
    config_load
    apply_runtime_config
}

# menu_choice VAR MAX : re-prompts until 0..MAX is entered; returns 1 at end of input
menu_choice() {
    local __v=$1 max=$2 ans
    while true; do
        prompt ans "Choose [0-$max]: " || return 1
        ans="${ans//[[:space:]]/}"
        if [[ "$ans" =~ ^[0-9]+$ ]] && (( 10#$ans <= max )); then printf -v "$__v" '%s' "$((10#$ans))"; return 0; fi
        warn "please enter a number between 0 and $max"
    done
}

# menu_ip VAR POLICY : re-prompts until a valid IP/CIDR (empty = cancel)
menu_ip() {
    local __v=$1 policy=$2 ans n
    while true; do
        prompt ans "IP or CIDR (e.g. 192.0.2.10 or 10.8.0.0/16, empty = cancel): " || return 1
        ans="${ans//[[:space:]]/}"
        [[ -n "$ans" ]] || return 1
        if n="$(normalize_one "$ans" "$policy")"; then printf -v "$__v" '%s' "$n"; return 0; fi
        warn "'$ans' is not accepted: $({ printf '%s\n' "$ans" | normalize_list any "$policy" 1 2>&1 >/dev/null || true; } | head -n1 | sed 's/^invalid: //')"
    done
}

menu_header() {
    if [[ -t 1 && $PROMPT_STDIN -eq 0 ]]; then clear 2>/dev/null || true; fi
    local line="+--------------------------------------------------------------+"
    say "$line"
    printf '| %-61s|\n' "Abuse Defender v$AD_VERSION - outbound abuse protection"
    printf '| %-61s|\n' "$AD_URL"
    say "$line"
    status_line
    if [[ $MENU_NOTICE_SHOWN -eq 0 && ${#REPORT[@]} -gt 0 ]]; then print_report; MENU_NOTICE_SHOWN=1; fi
    if [[ $IS_ROOT -eq 1 ]] && legacy_detect 2>/dev/null; then say "${C_YEL}Old v1 artefacts are still present - choose 1 to replace them.${C_OFF}"; fi
}

onoff() { if [[ $1 == yes || $1 == on ]]; then printf 'on '; else printf 'off'; fi; }

menu_categories() {
    local ch c i st
    local cats=(bogons abuse spamhaus feodo)
    local desc=("private/reserved/bogon space (IANA special-purpose)" "curated abuse/honeypot ranges (this project)" "Spamhaus DROP hijacked/criminal netblocks" "abuse.ch Feodo botnet C2 IPs (IPv4 only)")
    while true; do
        say ""; say "Block categories"
        for i in "${!cats[@]}"; do
            st=off
            # shellcheck disable=SC2086
            word_in "${cats[$i]}" ${CFG[CATEGORIES]} && st=on
            printf '  %d) [%s] %-9s %s\n' "$((i + 1))" "$(onoff "$st")" "${cats[$i]}" "${desc[$i]}"
        done
        say "  0) back"
        menu_choice ch 4 || return 0
        [[ $ch -eq 0 ]] && return 0
        c="${cats[$((ch - 1))]}"
        # shellcheck disable=SC2086
        if word_in "$c" ${CFG[CATEGORIES]}; then menu_run cmd_category "$c" off; else menu_run cmd_category "$c" on; fi
    done
}

menu_geo() {
    local ch cc
    while true; do
        say ""; say "Country blocking - currently: ${CFG[GEO_COUNTRIES]:-none}"
        say "  1) add a country"; say "  2) remove a country"; say "  0) back"
        menu_choice ch 2 || return 0
        case $ch in
        0) return 0 ;;
        1|2)
            while true; do
                prompt cc "Two-letter ISO country code (e.g. ir, empty = cancel): " || return 0
                cc="${cc//[[:space:]]/}"; cc="${cc,,}"
                [[ -z "$cc" ]] && break
                if [[ "$cc" =~ ^[a-z]{2}$ ]]; then
                    if [[ $ch == 1 ]]; then menu_run cmd_geo add "$cc"; else menu_run cmd_geo remove "$cc"; fi
                    break
                fi
                warn "'$cc' is not a two-letter country code"
            done ;;
        esac
    done
}

menu_modules() {
    local ch m i key
    local mods=(smtp ports scanguard forward logging hosts stateful autowhitelist sshprotect updates)
    local desc=("block outbound SMTP (ports: ${CFG[SMTP_PORTS]})" "block scan-target ports (tcp ${CFG[BLOCK_TCP_PORTS]}; udp ${CFG[BLOCK_UDP_PORTS]})" "rate-limit port-scan patterns" "also protect forwarded traffic (Docker, VPN clients)" "log blocked packets (rate-limited)" "sinkhole bad domains in /etc/hosts" "allow replies to inbound connections" "auto-allow gateway/DNS/metadata/local subnets" "auto-allow connected SSH clients" "automatic list updates")
    while true; do
        say ""; say "Optional modules"
        for i in "${!mods[@]}"; do
            key="$(module_key "${mods[$i]}")"
            printf '  %2d) [%s] %-13s %s\n' "$((i + 1))" "$(onoff "${CFG[$key]}")" "${mods[$i]}" "${desc[$i]}"
        done
        say "   0) back"
        menu_choice ch "${#mods[@]}" || return 0
        [[ $ch -eq 0 ]] && return 0
        m="${mods[$((ch - 1))]}"; key="$(module_key "$m")"
        if [[ ${CFG[$key]} == yes ]]; then menu_run cmd_module "$m" off; else menu_run cmd_module "$m" on; fi
    done
}

menu_export_import() {
    local ch f
    say ""; say "Export / import settings (config, whitelist, custom blocks, extra domains)"
    say "  1) export to a file"
    say "  2) import from a file"
    say "  0) back"
    menu_choice ch 2 || return 0
    case $ch in
    1) prompt f "File (empty = /root/abuse-defender-settings-<date>.tar.gz): " || return 0
       if [[ -n "$f" ]]; then menu_run cmd_export "$f"; else menu_run cmd_export; fi ;;
    2) while true; do
           prompt f "File to import (empty = cancel): " || return 0
           [[ -z "$f" ]] && break
           if [[ -f "$f" ]]; then menu_run cmd_import "$f"; break; fi
           warn "no such file: $f"
       done ;;
    esac
}

menu_main() {
    INTERACTIVE=1
    local ch ip toggle
    while true; do
        menu_header
        if [[ -f "$CONF_FILE" && ${CFG[ENABLED]} == yes ]]; then toggle="Disable protection (keeps settings)"
        else toggle="Enable protection"; fi
        say ""
        say " Protection"
        say "   1) Install / re-apply protection"
        say "   2) Update lists now"
        say "   3) Status and counters"
        say "   4) $toggle"
        say "   5) Doctor (diagnose problems)"
        say "   6) Preview rules without applying (dry-run)"
        say " Allow and block"
        say "   7) Whitelist an IP/range            8) Remove a whitelisted IP/range"
        say "   9) Block an IP/range               10) Unblock an IP/range"
        say " Settings"
        say "  11) Block categories               12) Country blocking"
        say "  13) Optional modules"
        say " Tools"
        say "  14) Blocked-connections log        15) Show settings"
        say "  16) Export / import settings       17) Uninstall completely"
        say "   0) Exit"
        menu_choice ch 17 || { say ""; return 0; }
        case $ch in
        0) say "Bye."; return 0 ;;
        1) menu_run cmd_install; pause ;;
        2) if [[ -f "$CONF_FILE" ]]; then menu_run cmd_update; else warn "install first (option 1)"; fi; pause ;;
        3) menu_run cmd_status; pause ;;
        4) if [[ ! -f "$CONF_FILE" ]]; then warn "install first (option 1)"
           elif [[ ${CFG[ENABLED]} == yes ]]; then menu_run cmd_disable
           else menu_run cmd_enable; fi; pause ;;
        5) menu_run cmd_doctor; pause ;;
        6) if [[ -f "$CONF_FILE" ]]; then
               ( DRY_RUN=1; menu_run cmd_apply )
           else
               ( DRY_RUN=1; menu_run cmd_install )
           fi; pause ;;
        7) say "Current whitelist:"; cmd_list whitelist | sed 's/^/  /'
           menu_ip ip allow && menu_run cmd_entries add allow "$ip"; pause ;;
        8) say "Current whitelist:"; cmd_list whitelist | sed 's/^/  /'
           menu_ip ip allow && menu_run cmd_entries del allow "$ip"; pause ;;
        9) say "Current custom blocks:"; cmd_list custom | sed 's/^/  /'
           menu_ip ip block && menu_run cmd_entries add block "$ip"; pause ;;
        10) say "Current custom blocks:"; cmd_list custom | sed 's/^/  /'
            menu_ip ip block && menu_run cmd_entries del block "$ip"; pause ;;
        11) menu_categories ;;
        12) menu_geo ;;
        13) menu_modules ;;
        14) menu_run cmd_hits; pause ;;
        15) cmd_config; pause ;;
        16) menu_export_import; pause ;;
        17) menu_run cmd_uninstall; pause ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local -a args=() orig=("$@")
    while [[ $# -gt 0 ]]; do
        case $1 in
        -y|--yes) ASSUME_YES=1 ;;
        -n|--dry-run) DRY_RUN=1 ;;
        -q|--quiet) QUIET=1 ;;
        --force) FORCE=1 ;;
        --backend=*) OPT_BACKEND="${1#*=}"; [[ $OPT_BACKEND =~ ^(auto|nft|ipset|iptables)$ ]] || die "invalid --backend" ;;
        --backend) shift; OPT_BACKEND="${1:-}"; [[ $OPT_BACKEND =~ ^(auto|nft|ipset|iptables)$ ]] || die "invalid --backend" ;;
        --confirm-timeout=*) OPT_CONFIRM_TIMEOUT="${1#*=}"; [[ $OPT_CONFIRM_TIMEOUT =~ ^[0-9]+$ ]] || die "invalid --confirm-timeout" ;;
        --no-confirm) OPT_NO_CONFIRM=1 ;;
        --keep-config) OPT_KEEP_CONFIG=1 ;;
        --sets-only) OPT_SETS_ONLY=1 ;;
        --jitter=*) OPT_JITTER="${1#*=}"; [[ $OPT_JITTER =~ ^[0-9]+$ ]] || die "invalid --jitter" ;;
        --jitter) shift; OPT_JITTER="${1:-0}"; [[ $OPT_JITTER =~ ^[0-9]+$ ]] || die "invalid --jitter" ;;
        --config=*) CONF_FILE="${1#*=}" ;;
        --no-color) C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_OFF="" ;;
        -h|--help) usage; return 0 ;;
        -V|--version) say "abuse-defender $AD_VERSION"; return 0 ;;
        --) shift; args+=("$@"); break ;;
        -*) die "unknown option: $1 (see --help)" ;;
        *) args+=("$1") ;;
        esac
        shift
    done
    set -- ${args[@]+"${args[@]}"}
    local cmd=${1:-}
    [[ $# -gt 0 ]] && shift

    # a newer installed program wins over an older copy that was started by hand
    if [[ $IS_ROOT -eq 1 && -x "$INSTALL_BIN" && "${BASH_SOURCE[0]:-$0}" != "$INSTALL_BIN" && "${BASH_SOURCE[0]:-$0}" != "$INSTALL_BIN_REAL" ]]; then
        local iv; iv="$(installed_version)"
        if [[ -n "$iv" ]] && version_gt "$iv" "$AD_VERSION"; then
            info "a newer version (v$iv) is installed - running it instead of this v$AD_VERSION copy"
            exec "$INSTALL_BIN" ${orig[@]+"${orig[@]}"}
        fi
    fi

    if [[ $cmd == menu && ! -t 0 ]]; then PROMPT_STDIN=1; fi
    if [[ $ASSUME_YES -eq 0 && -t 0 && -t 1 ]] || [[ -z "$cmd" && -r /dev/tty && -t 1 ]] || [[ $cmd == menu ]]; then INTERACTIVE=1; fi

    config_load
    apply_runtime_config

    # replace v1 setups / older versions automatically (new rules first, then removal)
    case $cmd in
    ""|menu|apply|update|enable|block|unblock|whitelist|allow|unwhitelist|unallow|category|geo|module|modules|set|import|restore)
        if [[ $IS_ROOT -eq 1 ]]; then
            auto_replace_old
            if [[ ${#REPORT[@]} -gt 0 ]]; then config_load; apply_runtime_config; fi
            [[ -z "$cmd" || $cmd == menu ]] || print_report
        fi ;;
    esac

    case $cmd in
    "")
        if [[ -t 1 ]] && [[ -r /dev/tty ]]; then require_root; menu_main
        else usage; return 2; fi ;;
    menu) require_root; menu_main ;;
    install) cmd_install ;;
    update) cmd_update ;;
    apply) cmd_apply yes ;;
    ensure) cmd_ensure ;;
    boot) cmd_boot ;;
    status) cmd_status ;;
    doctor) cmd_doctor ;;
    list) cmd_list "$@" ;;
    block) cmd_entries add block "$@" ;;
    unblock) cmd_entries del block "$@" ;;
    whitelist|allow) cmd_entries add allow "$@" ;;
    unwhitelist|unallow) cmd_entries del allow "$@" ;;
    category) cmd_category "$@" ;;
    geo) cmd_geo "$@" ;;
    module|modules) cmd_module "$@" ;;
    set) cmd_set "$@" ;;
    config) cmd_config ;;
    hits) cmd_hits "$@" ;;
    enable) cmd_enable ;;
    disable) cmd_disable ;;
    export|backup) cmd_export "$@" ;;
    import|restore) cmd_import "$@" ;;
    selftest|self-test) cmd_selftest ;;
    self-update) cmd_self_update ;;
    validate) cmd_validate "$@" ;;
    uninstall|remove) cmd_uninstall ;;
    _auto-rollback) cmd_auto_rollback "$@" ;;
    version) say "abuse-defender $AD_VERSION" ;;
    help) usage ;;
    *) die "unknown command: $cmd (see --help)" ;;
    esac
}

if [[ "${AD_LIB:-0}" != 1 ]]; then
    main "$@"
fi
