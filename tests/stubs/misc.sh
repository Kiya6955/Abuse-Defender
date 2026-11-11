#!/usr/bin/env bash
# Multi-call test stub: behaviour depends on the name it is invoked as
# (ip, ss, curl, timeout, getent, ping, systemctl, crontab, dmesg, resolvectl,
# journalctl, ufw, firewall-cmd).
me="$(basename "$0")"
printf '%s %s\n' "$me" "$*" >>"$AD_FAKE/calls.log"
net_ok() { [[ "$(cat "$AD_FAKE/net-state" 2>/dev/null || echo ok)" == ok ]]; }

case $me in
ip)
    case "$*" in
    "-4 route show default") cat "$AD_FAKE/ip/route4" 2>/dev/null ;;
    "-6 route show default") cat "$AD_FAKE/ip/route6" 2>/dev/null ;;
    "-o addr show scope global") cat "$AD_FAKE/ip/addr" 2>/dev/null ;;
    *) exit 0 ;;
    esac ;;
ss)
    case "$*" in
    -Hltnp*) cat "$AD_FAKE/ss/listen" 2>/dev/null ;;
    "-Htn state established"*) cat "$AD_FAKE/ss/est" 2>/dev/null ;;
    esac ;;
curl)
    out="" url="" head=0
    while [[ $# -gt 0 ]]; do
        case $1 in
        -o) out=$2; shift ;;
        -I) head=1 ;;
        -A|--proto|--retry|--retry-delay|--connect-timeout|--max-time|--max-filesize) shift ;;
        http*) url=$1 ;;
        esac
        shift
    done
    if [[ $head -eq 1 || $out == /dev/null ]]; then net_ok && exit 0; exit 7; fi
    [[ -f "$AD_FAKE/www-down" ]] && exit 6
    f="$AD_FAKE/www/${url#https://}"
    [[ -f "$f" ]] || exit 22
    cp "$f" "$out" ;;
timeout)
    shift
    case "$*" in
    *"/dev/tcp/"*|getent*) net_ok ;;
    *) exec "$@" ;;
    esac ;;
getent|ping) net_ok ;;
systemctl)
    case ${1:-} in
    is-active) echo active ;;
    is-enabled) echo enabled ;;
    *) exit 0 ;;
    esac ;;
# host tools that must never leak host state into the tests
resolvectl|journalctl) exit 1 ;;
ufw) echo "Status: inactive" ;;
firewall-cmd) echo "not running"; exit 252 ;;
crontab)
    if [[ ${1:-} == -l ]]; then
        [[ -f "$AD_FAKE/crontab" ]] || { echo "no crontab for root" >&2; exit 1; }
        cat "$AD_FAKE/crontab"
    else
        cp "$1" "$AD_FAKE/crontab"
    fi ;;
dmesg) cat "$AD_FAKE/dmesg" 2>/dev/null ;;
*) echo "misc stub: unknown name $me" >&2; exit 2 ;;
esac
