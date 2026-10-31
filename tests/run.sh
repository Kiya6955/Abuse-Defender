#!/usr/bin/env bash
# Abuse Defender test-suite.
#
# Every test runs the real script inside its own fake root with stubbed
# iptables / ip6tables / iptables-restore / ipset / nft / ip / ss / curl / systemctl /
# crontab / resolvectl / journalctl / ufw binaries (tests/stubs). PATH is reduced to the
# stub directory plus /usr/bin:/bin, /proc is faked, and network/sshd/interfaces/DNS
# of the machine running the tests are never consulted. No root, no kernel changes.
#
#   tests/run.sh                 run everything (JOBS=N parallel jobs, default 4)
#   tests/run.sh NAME...         run selected tests (function names without "test_")
#   KEEP=1 tests/run.sh NAME     keep the temporary directories for inspection
#
# SC2015: "A && ok || bad" is the assertion idiom here; SC2016: literal regexes.
# shellcheck disable=SC2015,SC2016
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SCRIPT="$REPO/abuse-defender.sh"
WORKROOT="$(mktemp -d "${TMPDIR:-/tmp}/ad-tests.XXXXXX")"
[[ ${KEEP:-0} == 1 ]] || trap 'rm -rf -- "$WORKROOT"' EXIT
JOBS="${JOBS:-4}"
SYSPATH="${AD_TEST_SYSPATH:-/usr/bin:/bin}"   # e.g. prepend a dir with mawk as "awk"

PASS=0; FAIL=0; CURRENT=""
ok()   { PASS=$((PASS + 1)); }
bad()  { FAIL=$((FAIL + 1)); printf '    FAIL [%s]: %s\n' "$CURRENT" "$*"; }
assert_eq() { [[ "$1" == "$2" ]] && ok || bad "$3: expected '$2', got '$1'"; }
assert_rc() { [[ "$1" -eq "$2" ]] && ok || bad "$3: exit code $1 (expected $2)"; }
assert_file() { [[ -e "$1" ]] && ok || bad "missing file $1"; }
assert_no_file() { [[ ! -e "$1" ]] && ok || bad "file should not exist: $1"; }
assert_grep() { grep -Eq -- "$2" "$1" 2>/dev/null && ok || bad "${3:-pattern '$2' not found in ${1##*/}}"; }
assert_nogrep() { grep -Eq -- "$2" "$1" 2>/dev/null && bad "${3:-pattern '$2' unexpectedly found in ${1##*/}}" || ok; }
count() { grep -Ec -- "$2" "$1" 2>/dev/null || true; }

# ---------------------------------------------------------------- environment
# new_env BACKEND [flavour]   BACKEND: nft | ipset | iptables ; flavour: systemd | cron | alpine | none
new_env() {
    local backend=$1 flavour=${2:-systemd}
    T="$(mktemp -d "$WORKROOT/t.XXXXXX")"; R="$T/root"; F="$T/fake"
    mkdir -p "$R/etc" "$R/root" "$R/usr/local/sbin" "$R/var/lib" "$R/proc/net" "$R/proc/sys/net/ipv6/conf/all" \
             "$R/run/systemd/resolve" "$R/var/log" "$F/bin" "$F/ip" "$F/ss" "$F/www"
    case $flavour in
    systemd) mkdir -p "$R/run/systemd/system" "$R/etc/systemd/system" "$R/etc/logrotate.d" ;;
    cron) mkdir -p "$R/etc/cron.d" ;;
    alpine) mkdir -p "$R/etc/periodic" "$R/etc/local.d" ;;
    esac
    : >"$R/proc/net/if_inet6"; echo 0 >"$R/proc/sys/net/ipv6/conf/all/disable_ipv6"
    printf '127.0.0.1 localhost\n::1 localhost ip6-localhost\n203.0.113.5 vps1\n' >"$R/etc/hosts"
    printf 'nameserver 127.0.0.53\noptions edns0\n' >"$R/etc/resolv.conf"
    printf 'nameserver 10.0.0.2\nnameserver 2001:4860:4860::8888\n' >"$R/run/systemd/resolve/resolv.conf"
    echo 'default via 172.31.1.1 dev eth0 proto dhcp src 203.0.113.5 metric 100' >"$F/ip/route4"
    echo 'default via fe80::1 dev eth0 proto ra metric 1024 pref medium' >"$F/ip/route6"
    printf '%s\n' '2: eth0    inet 203.0.113.5/32 scope global dynamic eth0' \
        '2: eth0    inet6 2001:db8:1234::5/64 scope global' \
        '3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0' >"$F/ip/addr"
    echo 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=3))' >"$F/ss/listen"
    echo '0 0 203.0.113.5:2222 [::ffff:192.168.1.50]:50123' >"$F/ss/est"
    local s
    for s in ip ss curl timeout getent ping systemctl crontab dmesg resolvectl journalctl ufw firewall-cmd; do
        cp "$HERE/stubs/misc.sh" "$F/bin/$s"
    done
    cp "$HERE/stubs/_ipt_lib.sh" "$F/bin/"
    case $backend in
    nft) cp "$HERE/stubs/nft" "$F/bin/nft"
         cp "$HERE/stubs/iptables" "$F/bin/iptables" ;;   # iptables present too (v1 migration)
    ipset|iptables)
        for s in iptables ip6tables; do cp "$HERE/stubs/iptables" "$F/bin/$s"; done
        for s in iptables-restore ip6tables-restore; do cp "$HERE/stubs/iptables-restore" "$F/bin/$s"; done
        [[ $backend == ipset ]] && cp "$HERE/stubs/ipset" "$F/bin/ipset" ;;
    esac
    chmod +x "$F"/bin/*
    # fake mirrors with the repository content
    local m
    for m in raw.githubusercontent.com/Kiya6955/Abuse-Defender/main cdn.jsdelivr.net/gh/Kiya6955/Abuse-Defender@main; do
        mkdir -p "$F/www/$m/lists/geo"
        cp "$REPO/abuse-defender.sh" "$REPO/abuse-ips.ipv4" "$F/www/$m/"
        cp "$REPO"/lists/*.txt "$REPO/lists/SHA256SUMS" "$F/www/$m/lists/"
        cp "$REPO"/lists/geo/*.txt "$F/www/$m/lists/geo/" 2>/dev/null || true
    done
    : >"$F/calls.log"
}

ad_env() {
    env -i HOME="$T" TERM=dumb NO_COLOR=1 TMPDIR="$T" PATH="$F/bin:$SYSPATH" \
        AD_ROOT="$R" AD_PROC="$R/proc" AD_FAKE="$F" AD_ALLOW_NONROOT=1 \
        SSH_CONNECTION="198.51.100.77 50000 203.0.113.5 2222" "$@"
}
run_ad() { ad_env bash "$SCRIPT" "$@" </dev/null >"$T/out" 2>&1; }
run_ad_input() { local input=$1; shift; printf '%b' "$input" | ad_env bash "$SCRIPT" "$@" >"$T/out" 2>&1; }

snapshot() {   # file tree + content hashes of the fake root, plus firewall state
    (cd "$R" && find . -type f -o -type d | LC_ALL=C sort | while read -r p; do
        if [[ -f "$p" ]]; then printf '%s %s\n' "$p" "$(cksum <"$p" | cut -d' ' -f1)"; else printf '%s/\n' "$p"; fi
    done)
    cat "$F/ipt4.state" "$F/ipt6.state" 2>/dev/null
    cat "$F/nft/tables" 2>/dev/null
    ls "$F/ipset" 2>/dev/null
    cat "$F/crontab" 2>/dev/null
}

write_v1_state() {   # simulate an existing v1 installation (iptables based)
    {
        echo "-N abuse-defender"; echo "-N abuse-defender-custom"; echo "-N abuse-defender-whitelist"
        echo "-A OUTPUT -j abuse-defender-whitelist"; echo "-A OUTPUT -j abuse-defender-custom"; echo "-A OUTPUT -j abuse-defender"
        echo "-A OUTPUT -p tcp --dport 25 -j REJECT"   # a foreign user rule that must survive
        while read -r c; do echo "-A abuse-defender -d $c -j DROP"; done <"$REPO/abuse-ips.ipv4"
        echo "-A abuse-defender-custom -d 203.0.113.99/32 -j DROP"
        echo "-A abuse-defender-whitelist -d 10.8.0.0/16 -j ACCEPT"
    } >"$F/ipt4.state"
    printf '#!/bin/bash\niptables -F abuse-defender\n' >"$R/root/abuse-defender-update.sh"
    printf '15 4 * * * /usr/bin/backup.sh\n0 0 * * * /root/abuse-defender-update.sh\n' >"$F/crontab"
    printf '127.0.0.1 appclick.co\n127.0.0.1 pushnotificationws.com\n127.0.0.1 appclick.co\n127.0.0.1 pushnotificationws.com\n' >>"$R/etc/hosts"
    mkdir -p "$R/etc/iptables"
    printf '*filter\n:INPUT ACCEPT [0:0]\n:abuse-defender - [0:0]\n:abuse-defender-whitelist - [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A OUTPUT -j abuse-defender\n-A OUTPUT -j abuse-defender-whitelist\n-A abuse-defender -d 10.0.0.0/8 -j DROP\nCOMMIT\n' >"$R/etc/iptables/rules.v4"
}

assert_v1_gone() {
    assert_grep "$R/etc/abuse-defender/custom-block.txt" '^203\.0\.113\.99/32$' "v1 custom block imported"
    assert_grep "$R/etc/abuse-defender/whitelist.txt" '^10\.8\.0\.0/16$' "v1 whitelist imported"
    assert_nogrep "$F/ipt4.state" '(-N abuse-defender-(custom|whitelist)|-j abuse-defender-(custom|whitelist)|^-A abuse-defender -d)' "v1 chains/rules/jumps removed"
    assert_grep "$F/ipt4.state" '^-A OUTPUT -p tcp --dport 25 -j REJECT$' "foreign iptables rule kept"
    assert_no_file "$R/root/abuse-defender-update.sh"
    assert_nogrep "$F/crontab" 'abuse-defender-update' "v1 cron line removed"
    assert_grep "$F/crontab" 'backup\.sh' "other cron lines kept"
    assert_eq "$(count "$R/etc/hosts" '^127\.0\.0\.1 appclick\.co$')" 1 "v1 duplicate hosts lines replaced by one managed entry"
    assert_nogrep "$R/etc/iptables/rules.v4" 'abuse-defender' "rules.v4 cleaned"
    assert_grep "$R/etc/iptables/rules.v4" '^-A INPUT -p tcp --dport 22 -j ACCEPT$' "foreign persisted rule kept"
}

RS() { echo "$F/nft/inet_abuse_defender.nft"; }

# ---------------------------------------------------------------- tests
test_list_parsing() {
    # shellcheck disable=SC1090
    (
        AD_LIB=1 source "$SCRIPT"; set +eE; trap - ERR
        r="$(printf '%s\n' 10.1.2.3/8 '  192.0.2.0/24   # comment' '1.2.3.4 ; SBL1' '{"cidr":"1.10.16.0/20","sblid":"S"}' '{"type":"metadata"}' | normalize_list 4 block 1 | tr '\n' ' ')"
        [[ "$r" == "10.0.0.0/8 192.0.2.0/24 1.2.3.4/32 1.10.16.0/20 " ]] || { echo "normalize v4: $r"; exit 1; }
        for b in 010.0.0.1 1.2.3.256 1.2.3.4/33 0.0.0.0/0 127.0.0.1 64.0.0.0/2 '1.2.3' 'a.b.c.d' 1.2.3.4/x; do
            printf '%s\n' "$b" | normalize_list 4 block 1 >/dev/null 2>&1 && { echo "accepted bad v4 '$b'"; exit 1; }
        done
        r="$(printf '%s\n' 2001:0DB8:0000:0000:0000:0000:0000:0001/32 fc00::/7 fd00::/7 ::/128 1:0:0:2:0:0:0:3 2001:678:00b0:0000:0000:0000:0000:0000/46 | normalize_list 6 block 1 | tr '\n' ' ')"
        [[ "$r" == "2001:db8::/32 fc00::/7 fc00::/7 ::/128 1:0:0:2::3/128 2001:678:b0::/46 " ]] || { echo "normalize v6: $r"; exit 1; }
        for b in fe80::1 fe80::/10 ff02::1 ff00::/8 ::1 ::/96 ::/0 2000::/3 gg::1 1::2::3 1:2:3:4:5:6:7:8:9; do
            printf '%s\n' "$b" | normalize_list 6 block 1 >/dev/null 2>&1 && { echo "accepted bad v6 '$b'"; exit 1; }
        done
        printf '%s\n' 10.0.0.0/7 | normalize_list 4 allow 1 >/dev/null 2>&1 && { echo "whitelist accepted /7"; exit 1; }
        r="$(printf '%s\n' '1.2.3.4 gateway' 'bad reason' | awk -v keep=1 -v want=any -v policy=allow -v strict=0 "$AWK_NORMALIZE" 2>/dev/null | tr '\n' '|')"
        [[ "$r" == "1.2.3.4/32 gateway|" ]] || { echo "keep mode: $r"; exit 1; }
        r="$(printf '%s\n' 10.0.0.0/8 10.1.0.0/16 185.235.86.0/24 185.235.87.0/24 192.168.1.0/24 192.168.0.0/24 224.0.0.0/4 233.252.0.0/24 | aggregate4 | tr '\n' ' ')"
        [[ "$r" == "10.0.0.0/8 185.235.86.0/23 192.168.0.0/23 224.0.0.0/4 " ]] || { echo "aggregate4: $r"; exit 1; }
        r="$(printf '%s\n' 2001:db8::/32 2001:db8:1::/48 fc00::/7 fd00:ec2::/64 2001:db8::/32 | aggregate6 | tr '\n' ' ')"
        [[ "$r" == "2001:db8::/32 fc00::/7 " ]] || { echo "aggregate6: $r"; exit 1; }
        r="$(printf 'Example.COM\nfoo..bar\n' | validate_domains 2>/dev/null)"; [[ $? -eq 3 && "$r" == example.com ]] || { echo "domains: $r"; exit 1; }
        version_gt 2.0.1 2.0.0 && ! version_gt 2.0.0 2.0.0 && ! version_gt 1.9.9 2.0.0 && version_gt 10.0 9.9.9 || { echo "version_gt"; exit 1; }
        exit 0
    ) >"$T/lp.out" 2>&1 && ok || bad "$(cat "$T/lp.out")"
}

test_build_lists_check() {
    (cd "$REPO" && PATH="$SYSPATH" bash tools/build-lists.sh --check) >"$T/bl.out" 2>&1 && ok || bad "build-lists --check: $(tail -n 5 "$T/bl.out")"
    # legacy file must stay compatible with v1 cron scripts
    if grep -Evq '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$' "$REPO/abuse-ips.ipv4"; then bad "abuse-ips.ipv4 has non-CIDR lines"; else ok; fi
    if grep -q $'\r\|\t' "$REPO/abuse-ips.ipv4"; then bad "abuse-ips.ipv4 has CR/TAB"; else ok; fi
    assert_nogrep "$REPO/abuse-ips.ipv4" '^(0\.0\.0\.0|127\.)' "legacy list must not contain 0/8 or 127/8"
}

test_cli_basics() {
    run_ad --version; assert_rc $? 0 "--version"; assert_grep "$T/out" '^abuse-defender 2\.'
    run_ad --help; assert_rc $? 0 "--help"; assert_grep "$T/out" 'uninstall'; assert_grep "$T/out" 'doctor'
    run_ad --bogus; assert_rc $? 1 "unknown option"
    run_ad --lang=fa status; assert_rc $? 1 "--lang was removed"
    run_ad frobnicate; assert_rc $? 1 "unknown command"
    run_ad; assert_rc $? 2 "no command without a terminal prints usage"
    printf '1.2.3.0/24\n2001:db8::/32\n' >"$T/l.txt"; run_ad validate "$T/l.txt"; assert_rc $? 0 "validate ok"
    printf '1.2.3.0/24\n999.1.1.1\n' >"$T/l.txt"; run_ad validate "$T/l.txt"; assert_rc $? 3 "validate bad"
    run_ad status; assert_rc $? 0 "status when not installed"; assert_grep "$T/out" 'Protected: NO \(not installed\)'
    run_ad update; assert_rc $? 1 "update refuses when not installed"; assert_grep "$T/out" 'not installed'
    run_ad config; assert_rc $? 0 "config"; assert_grep "$T/out" '^ENABLED="yes"$'
    assert_nogrep "$T/out" '^(IP_FAMILY|MODE|LANGUAGE)=' "removed settings are gone"
    run_ad --family=4 status; assert_rc $? 1 "--family was removed"
    run_ad --no-ipv6 status; assert_rc $? 1 "--no-ipv6 was removed"
    run_ad mode monitor; assert_rc $? 1 "mode command was removed"
    run_ad family 4; assert_rc $? 1 "family command was removed"
    run_ad --help; assert_nogrep "$T/out" 'monitor|family|--family' "help mentions no removed feature"
}

test_install_nft() {
    run_ad --yes install; assert_rc $? 0 "install: $(tail -n 5 "$T/out")"
    assert_file "$R/usr/local/sbin/abuse-defender"
    assert_file "$R/etc/abuse-defender/abuse-defender.conf"
    assert_file "$R/etc/systemd/system/abuse-defender.service"
    assert_grep "$R/etc/systemd/system/abuse-defender-update.timer" 'RandomizedDelaySec='
    assert_file "$R/etc/systemd/system/abuse-defender-ensure.timer"
    local rs; rs="$(RS)"
    assert_grep "$rs" 'oifname \{ "eth0" \} jump egress' "only the uplink is filtered"
    assert_grep "$rs" 'ct state established,related return'
    assert_grep "$rs" 'icmpv6 type \{ nd-router-solicit' "IPv6 neighbour discovery exempt"
    assert_grep "$rs" 'add element inet abuse_defender bogons_v4 \{ 0\.0\.0\.0/8, 10\.0\.0\.0/8'
    assert_grep "$rs" 'bogons_v4 counter drop comment "bogons"'
    assert_nogrep "$rs" 'chain forward' "forward chain off by default"
    local a c l b
    a="$(grep -n 'daddr @allow_v4 return' "$rs" | cut -d: -f1)"; c="$(grep -n 'daddr @custom_v4 counter drop' "$rs" | cut -d: -f1)"
    l="$(grep -n 'daddr @local_v4 return' "$rs" | cut -d: -f1)"; b="$(grep -n 'daddr @bogons_v4 counter drop' "$rs" | cut -d: -f1)"
    [[ -n "$a" && -n "$c" && -n "$l" && -n "$b" && $a -lt $c && $c -lt $l && $l -lt $b ]] && ok || bad "rule order allow($a) < custom($c) < local($l) < bogons($b)"
    local auto="$R/var/lib/abuse-defender/applied/auto-allow.txt"
    assert_grep "$auto" '^172\.31\.1\.1/32 gateway' "gateway auto-whitelisted"
    assert_grep "$auto" '^10\.0\.0\.2/32 dns-resolver' "systemd-resolved upstream DNS auto-whitelisted"
    assert_grep "$auto" '^198\.51\.100\.77/32 ssh-client' "SSH_CONNECTION client auto-whitelisted"
    assert_grep "$auto" '^192\.168\.1\.50/32 ssh-client' "ss-detected SSH client auto-whitelisted"
    assert_grep "$auto" '^169\.254\.169\.254/32 cloud-metadata'
    assert_nogrep "$auto" '^127\.' "loopback resolver must not be listed"
    assert_grep "$R/var/lib/abuse-defender/applied/sets/local_v4" '^172\.17\.0\.0/16$' "docker0 subnet is local"
    assert_grep "$R/var/lib/abuse-defender/applied/sets/local_v6" '^2001:db8:1234::/64$' "connected v6 subnet is local"
    assert_eq "$(count "$R/etc/hosts" 'abuse-defender managed block')" 2 "hosts markers"
    assert_grep "$R/etc/hosts" '^127\.0\.0\.1 appclick\.co$'
    assert_grep "$R/etc/hosts" '^::1 pushnotificationws\.com$'
    assert_grep "$R/etc/hosts" '^203\.0\.113\.5 vps1$' "foreign hosts lines kept"
    run_ad status; assert_rc $? 0 "status"
    assert_grep "$T/out" '^Protected: YES \| backend: nft/inet \| IPv4\+IPv6 \| updated: .* \| timer: systemd' "one-line status"
    assert_grep "$T/out" 'bogons +6 pkts' "counters shown (v4+v6)"
}

test_dry_run_output() {
    local s1 s2; s1="$(snapshot)"
    run_ad --dry-run --yes install; assert_rc $? 0 "dry-run install: $(tail -n 3 "$T/out")"
    assert_grep "$T/out" '^----- dry-run: backend=nft/inet IPv4\+IPv6 egress=eth0 -----$' "dry-run header"
    assert_grep "$T/out" 'set bogons_v4 \(block\): 13 entries' "dry-run lists set sizes"
    assert_grep "$T/out" '^  chain egress \{' "dry-run shows the ruleset"
    assert_grep "$T/out" '172\.31\.1\.1/32 gateway' "dry-run shows the auto-whitelist"
    assert_grep "$T/out" 'element chunks' "dry-run summarises elements"
    s2="$(snapshot)"
    [[ "$s1" == "$s2" ]] && ok || bad "dry-run modified state: $(diff <(echo "$s1") <(echo "$s2") | head)"
    run_ad --yes install >/dev/null
    run_ad --dry-run --yes block 203.0.113.0/24; assert_grep "$T/out" 'would add 203\.0\.113\.0/24'
    assert_nogrep "$R/etc/abuse-defender/custom-block.txt" '203\.0\.113' "dry-run block changed nothing"
    rm -f "$R/proc/net/if_inet6"
    run_ad --dry-run --yes apply; assert_grep "$T/out" 'dry-run: backend=nft/inet IPv4 only \(no IPv6 on this host\)' "IPv6 is skipped automatically"
}

test_idempotent_install() {
    run_ad --yes install || { bad "first install: $(tail -n 5 "$T/out")"; return; }
    local s1; s1="$(snapshot | grep -v -e '/var/lib/abuse-defender/' -e '/var/log/' -e '/run/')"
    cp "$(RS)" "$T/rs1"
    run_ad --yes install; assert_rc $? 0 "second install"
    local s2; s2="$(snapshot | grep -v -e '/var/lib/abuse-defender/' -e '/var/log/' -e '/run/')"
    [[ "$s1" == "$s2" ]] && ok || bad "second install changed files: $(diff <(echo "$s1") <(echo "$s2") | head -n 10)"
    cmp -s "$T/rs1" "$(RS)" && ok || bad "ruleset changed on re-install"
    assert_eq "$(count "$R/etc/hosts" 'appclick')" 2 "hosts entries not duplicated"
    : >"$F/calls.log"
    run_ad ensure; assert_rc $? 0 "ensure"
    assert_nogrep "$F/calls.log" '^nft -f [^-]' "ensure must not reload unchanged rules"
    ad_env nft delete table inet abuse_defender
    run_ad ensure; assert_rc $? 0 "ensure restore"
    assert_file "$(RS)"
    echo 'default via 172.31.1.9 dev eth0' >"$F/ip/route4"
    run_ad ensure; assert_grep "$R/var/lib/abuse-defender/applied/auto-allow.txt" '^172\.31\.1\.9/32 gateway' "ensure follows a gateway change"
}

test_migration_to_nft() {
    write_v1_state
    run_ad status; assert_grep "$T/out" 'Old v1 artefacts present' "legacy setup detected by status"
    run_ad --yes install; assert_rc $? 0 "migrating install: $(tail -n 5 "$T/out")"
    assert_v1_gone
    assert_grep "$R/var/lib/abuse-defender/applied/sets/allow_v4" '^10\.8\.0\.0/16$'
    local nl il
    nl="$(grep -n '^nft -f [^-]' "$F/calls.log" | tail -n1 | cut -d: -f1)"
    il="$(grep -n '^iptables -X abuse-defender$' "$F/calls.log" | head -n1 | cut -d: -f1)"
    [[ -n "$nl" && -n "$il" && $nl -lt $il ]] && ok || bad "nft rules ($nl) must load before v1 chain removal ($il)"
}

test_auto_replace_v1_menu() {
    write_v1_state
    run_ad_input '2\n\n0\n' menu; assert_rc $? 0 "menu on a v1 system: $(tail -n 5 "$T/out")"
    assert_nogrep "$T/out" 'another abuse-defender instance' "the lock is released after the replacement"
    assert_grep "$T/out" 'unchanged \([0-9]+ entries\)' "a locking menu action works right after the replacement"
    assert_grep "$T/out" 'Previous installation replaced:' "replacement is reported"
    assert_grep "$T/out" 'imported 2 entries from the v1 custom/whitelist chains'
    assert_grep "$T/out" 'removed the old abuse-defender-update.sh crontab line'
    assert_grep "$T/out" 'v1 replaced: new rules active'
    assert_nogrep "$T/out" 'Continue\?' "no question was asked"
    assert_file "$(RS)"
    assert_file "$R/usr/local/sbin/abuse-defender"
    assert_v1_gone
    # a second start finds nothing to replace
    run_ad_input '0\n' menu; assert_nogrep "$T/out" 'Previous installation replaced' "replacement happens once"
}

test_auto_replace_v1_failure_keeps_old() {
    write_v1_state
    cp "$F/ipt4.state" "$T/v1.state"
    touch "$F/break-net-on-apply"
    run_ad_input '0\n' menu
    assert_grep "$T/out" 'replacement failed - nothing was removed' "failure reported"
    assert_grep "$F/ipt4.state" '^-A abuse-defender -d 10\.0\.0\.0/8 -j DROP$' "v1 rules still protect after a failed replacement"
    assert_grep "$F/ipt4.state" '^-A OUTPUT -j abuse-defender$' "v1 jump restored"
    assert_no_file "$(RS)"
}

test_auto_replace_v1_leftovers() {
    # v1 "clear rules" was used: empty chains, script and cron line remain
    printf -- '-N abuse-defender\n-N abuse-defender-custom\n-N abuse-defender-whitelist\n-A OUTPUT -j abuse-defender\n' >"$F/ipt4.state"
    printf '#!/bin/bash\n' >"$R/root/abuse-defender-update.sh"
    printf '0 0 * * * /root/abuse-defender-update.sh\n' >"$F/crontab"
    run_ad_input '0\n' menu; assert_rc $? 0 "menu with v1 leftovers"
    assert_grep "$T/out" 'removed inactive v1 leftovers'
    assert_nogrep "$F/ipt4.state" 'abuse-defender' "empty v1 chains removed"
    assert_no_file "$R/root/abuse-defender-update.sh"
    assert_no_file "$R/etc/abuse-defender/abuse-defender.conf"
}

test_upgrade_old_v2() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    sed 's/^AD_VERSION=.*/AD_VERSION="1.9.0"/' "$SCRIPT" >"$R/usr/local/sbin/abuse-defender"
    printf 'IPV6="no"\nLANGUAGE="fa"\nIP_FAMILY="4"\nMODE="monitor"\n' >>"$R/etc/abuse-defender/abuse-defender.conf"
    run_ad --yes whitelist 10.20.0.0/16; assert_rc $? 0 "command on an older install: $(tail -n 3 "$T/out")"
    assert_grep "$T/out" 'found Abuse Defender v1\.9\.0 - upgrading to v2\.'
    assert_eq "$(count "$T/out" 'monitor mode no longer exists')" 1 "one notice about the removed monitor mode"
    assert_grep "$R/usr/local/sbin/abuse-defender" '^AD_VERSION="2\.' "program upgraded"
    assert_nogrep "$R/etc/abuse-defender/abuse-defender.conf" '^(LANGUAGE|IPV6|IP_FAMILY|MODE)=' "obsolete keys dropped"
    assert_grep "$R/etc/abuse-defender/abuse-defender.conf" '^ENABLED="yes"$' "still enabled"
    assert_grep "$R/etc/abuse-defender/whitelist.txt" '^10\.20\.0\.0/16$'
    assert_grep "$(RS)" 'ip6 daddr @bogons_v6' "IPv6 automatic again (old IP_FAMILY=4 ignored)"
    assert_grep "$(RS)" 'bogons_v4 counter drop' "enforced (old MODE=monitor ignored)"
}

test_newer_installed_wins() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    printf '#!/usr/bin/env bash\nAD_VERSION="9.9.9"\necho "newer program ran: $*"\n' >"$R/usr/local/sbin/abuse-defender"
    chmod +x "$R/usr/local/sbin/abuse-defender"
    run_ad status; assert_grep "$T/out" 'newer program ran: status' "an older copy hands over to the newer installed program"
}

test_obsolete_config_keys() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    printf 'IP_FAMILY="6"\nMODE="monitor"\nLANGUAGE="fa"\nIPV6="no"\n' >>"$R/etc/abuse-defender/abuse-defender.conf"
    run_ad status; assert_rc $? 0 "status with obsolete keys"
    assert_eq "$(count "$T/out" 'monitor mode no longer exists - protection is enforced')" 1 "monitor notice printed once"
    assert_nogrep "$T/out" 'unknown key' "obsolete keys are dropped silently"
    run_ad ensure; assert_rc $? 0 "ensure rewrites the config"
    assert_nogrep "$R/etc/abuse-defender/abuse-defender.conf" '^(LANGUAGE|IPV6|IP_FAMILY|MODE)=' "obsolete keys removed from the file"
    run_ad status; assert_nogrep "$T/out" 'monitor mode' "notice is shown only until the config is rewritten"
    assert_grep "$T/out" 'Protected: YES'
}

geo_country() {   # geo_country CC "v4 prefixes" "v6 prefixes": publish a fake country list on both mirrors
    local cc=$1 v4=$2 v6=$3 mm
    for mm in "$F/www/raw.githubusercontent.com/Kiya6955/Abuse-Defender/main" "$F/www/cdn.jsdelivr.net/gh/Kiya6955/Abuse-Defender@main"; do
        mkdir -p "$mm/lists/geo"
        # word splitting is intended: the arguments are space-separated prefix lists
        # shellcheck disable=SC2086
        printf '%s\n' $v4 >"$mm/lists/geo/$cc-v4.txt"
        # shellcheck disable=SC2086
        printf '%s\n' $v6 >"$mm/lists/geo/$cc-v6.txt"
    done
}

test_geo_guard() {
    run_ad --yes geo add ir; assert_rc $? 1 "geo add before install"; assert_grep "$T/out" 'install and enable protection first'
    run_ad --yes install >/dev/null || { bad "install"; return; }
    run_ad geo add ir; assert_rc $? 1 "geo add without --yes and without a terminal is refused"
    assert_grep "$T/out" 'This blocks ALL outbound traffic to IR: [0-9]+ IPv4 \+ [0-9]+ IPv6 prefixes\. Services hosted there become unreachable'
    assert_grep "$T/out" 'Re-run with --yes'
    assert_nogrep "$R/etc/abuse-defender/abuse-defender.conf" '^GEO_COUNTRIES="ir"' "not enabled without confirmation"
    assert_nogrep "$(RS)" 'geo_ir' "no rules without confirmation"
    run_ad --dry-run geo add ir; assert_rc $? 0 "dry-run geo add"; assert_grep "$T/out" '\[dry-run\] This blocks ALL outbound traffic to IR: 1747 IPv4'
    run_ad_input '12\n1\nir\nn\n0\n0\n' menu; assert_grep "$T/out" 'cancelled - nothing changed' "menu: answering no cancels"
    assert_nogrep "$R/etc/abuse-defender/abuse-defender.conf" '^GEO_COUNTRIES="ir"'
    # the default gateway (172.31.1.1) is inside the country -> refused unless --force
    geo_country zz "172.16.0.0/12 5.0.0.0/8" "2a00::/16"
    run_ad --yes geo add zz; assert_rc $? 1 "country containing the gateway refused"
    assert_grep "$T/out" '172\.31\.1\.1/32 default-gateway'
    assert_grep "$T/out" "refusing to block 'ZZ': it would cut off your gateway/DNS/SSH session"
    assert_nogrep "$R/etc/abuse-defender/abuse-defender.conf" 'GEO_COUNTRIES="zz"'
    # the current SSH client (198.51.100.77) is inside the country -> refused
    geo_country yy "198.51.100.0/24" ""
    run_ad --yes geo add yy; assert_rc $? 1 "country containing the SSH client refused"; assert_grep "$T/out" '198\.51\.100\.77/32 ssh-client'
    # an IPv6 DNS resolver (2001:4860:4860::8888) is inside the country -> refused
    geo_country xx "5.0.0.0/8" "2001:4860::/32"
    run_ad --yes geo add xx; assert_rc $? 1 "country containing an IPv6 resolver refused"; assert_grep "$T/out" '2001:4860:4860::8888/128 dns-resolver'
    # --force overrides
    run_ad --yes --force geo add zz; assert_rc $? 0 "--force overrides: $(tail -n 3 "$T/out")"
    assert_grep "$T/out" '--force given'
    assert_grep "$R/etc/abuse-defender/abuse-defender.conf" '^GEO_COUNTRIES="zz"$'
    assert_grep "$R/var/lib/abuse-defender/applied/auto-allow.txt" '^172\.31\.1\.1/32 gateway' "gateway stays exempt"
    # download failure: not enabled
    run_ad --yes geo add qq; assert_rc $? 1 "unknown country"; assert_grep "$T/out" "could not download a valid list for 'qq' - country blocking NOT enabled"
    assert_nogrep "$R/etc/abuse-defender/abuse-defender.conf" 'qq'
    # a clean country with --yes works
    run_ad --yes geo add ir; assert_rc $? 0 "geo add ir --yes"; assert_grep "$T/out" 'country IR blocked'
    assert_grep "$(RS)" 'set geo_ir_v4'
}

test_migration_to_ipset() {
    new_env ipset
    write_v1_state
    run_ad --yes install; assert_rc $? 0 "migrating install (ipset): $(tail -n 5 "$T/out")"
    local st="$F/ipt4.state"
    assert_v1_gone
    assert_eq "$(grep '^-A OUTPUT ' "$st" | head -n1)" "-A OUTPUT -o eth0 -j abuse-defender" "our jump is first in OUTPUT"
    assert_grep "$st" '^-A abuse-defender -o lo -j RETURN$'
    assert_grep "$st" '^-A abuse-defender -m set --match-set ad4-allow dst -j RETURN$'
    assert_grep "$st" '^-A abuse-defender -m set --match-set ad4-bogons dst -j DROP$'
    assert_file "$F/ipset/ad4-bogons"; assert_file "$F/ipset/ad6-bogons"; assert_no_file "$F/ipset/ad4-bogons-n"
    assert_grep "$F/ipt6.state" '^-A abuse-defender -p ipv6-icmp --icmpv6-type 135 -j RETURN$' "NDP exempt on IPv6"
    run_ad --yes apply; assert_rc $? 0 "re-apply"
    assert_eq "$(count "$st" '^-A OUTPUT -o eth0 -j abuse-defender$')" 1 "jump not duplicated"
    ad_env iptables -I OUTPUT 1 -j ACCEPT
    run_ad ensure; assert_rc $? 0 "ensure reorder"
    assert_eq "$(grep '^-A OUTPUT ' "$st" | head -n1)" "-A OUTPUT -o eth0 -j abuse-defender" "ensure restores first position"
    assert_eq "$(count "$st" '^-A OUTPUT -o eth0 -j abuse-defender$')" 1 "still exactly one jump"
}

test_plain_iptables_backend() {
    new_env iptables cron
    run_ad --yes install; assert_rc $? 0 "install (plain iptables): $(tail -n 5 "$T/out")"
    local st="$F/ipt4.state"
    assert_grep "$st" '^-N abuse-defender-bogons$'
    assert_grep "$st" '^-A abuse-defender-bogons -d 10\.0\.0\.0/8 -j abuse-defender-drop$'
    assert_grep "$st" '^-A abuse-defender -d 172\.31\.1\.1/32 -j RETURN$' "gateway allow rule"
    assert_grep "$R/etc/cron.d/abuse-defender" '@reboot root /usr/local/sbin/abuse-defender --quiet boot'
    run_ad status; assert_nogrep "$T/out" 'Old v1' "own plain-iptables chains are not mistaken for v1"
    run_ad --yes category abuse off; assert_rc $? 0 "category off"
    assert_nogrep "$st" 'abuse-defender-abuse' "disabled category chain removed"
}



test_doctor() {
    run_ad doctor; assert_rc $? 0 "doctor before install: warnings only"; assert_grep "$T/out" '\[WARN\] not installed'
    run_ad --yes install >/dev/null || { bad "install"; return; }
    run_ad doctor; assert_rc $? 0 "doctor on a healthy install: $(grep -E 'FAIL' "$T/out" | head -n 3)"
    assert_grep "$T/out" '\[ OK \] rules are loaded in the kernel'
    assert_grep "$T/out" '\[ OK \] the kernel accepts the full ruleset'
    assert_grep "$T/out" '\[ OK \] mirror reachable: https://raw\.githubusercontent\.com'
    assert_grep "$T/out" '\[WARN\] mirror unreachable: https://fastly'
    assert_grep "$T/out" 'Summary: 0 failure'
    ad_env nft delete table inet abuse_defender
    run_ad doctor; assert_rc $? 1 "doctor detects missing rules"; assert_grep "$T/out" 'rules are NOT loaded'
}

test_input_validation() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    run_ad whitelist '1.2.3.4;touch /tmp/x'; assert_nogrep "$R/etc/abuse-defender/whitelist.txt" 'touch' "injection rejected"
    assert_grep "$T/out" 'rejected'
    run_ad whitelist 0.0.0.0/0; assert_nogrep "$R/etc/abuse-defender/whitelist.txt" '^0\.0\.0\.0/0' "whitelisting everything refused"
    run_ad block 127.0.0.1; assert_nogrep "$R/etc/abuse-defender/custom-block.txt" '^127\.' "blocking loopback refused"
    run_ad block fe80::1; assert_nogrep "$R/etc/abuse-defender/custom-block.txt" '^fe80' "blocking link-local v6 refused"
    run_ad block 203.0.113.7/24; assert_grep "$R/etc/abuse-defender/custom-block.txt" '^203\.0\.113\.0/24$' "host bits normalised"
    assert_grep "$(RS)" 'custom_v4 \{ 203\.0\.113\.0/24 \}' "custom block applied"
    run_ad block 203.0.113.0/24; assert_eq "$(count "$R/etc/abuse-defender/custom-block.txt" '^203\.0\.113\.0/24$')" 1 "no duplicate entry"
    run_ad unblock 203.0.113.0/24; assert_nogrep "$R/etc/abuse-defender/custom-block.txt" '^203\.0\.113' "unblock"
    run_ad --yes whitelist 2001:db8:abcd::/48; assert_grep "$R/var/lib/abuse-defender/applied/sets/allow_v6" '^2001:db8:abcd::/48$'
    printf 'ENABLED=yes\nCATEGORIES="bogons $(touch %s/pwned)"\nFOO=bar\n' "$T" >"$R/etc/abuse-defender/abuse-defender.conf"
    run_ad status; assert_no_file "$T/pwned"; assert_grep "$T/out" 'invalid value for CATEGORIES'
    run_ad --yes set MIRRORS 'https://example.com/*'; assert_rc $? 1 "glob characters refused in MIRRORS"
}

test_rollback_on_selftest_failure() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    cp "$(RS)" "$T/before"
    touch "$F/break-net-on-apply"
    run_ad --yes module smtp on; local rc=$?
    [[ $rc -ne 0 ]] && ok || bad "apply should fail when connectivity regresses"
    assert_grep "$T/out" 'rolling back'
    rm -f "$F/break-net-on-apply"; echo ok >"$F/net-state"
    cmp -s "$T/before" "$(RS)" && ok || bad "previous ruleset not restored"
    new_env nft
    touch "$F/break-net-on-apply"
    run_ad --yes install
    assert_no_file "$(RS)"
    assert_grep "$T/out" 'NOT applied'
}

test_render_fallback_levels() {
    echo 'flags skuid' >"$F/nft-reject"
    run_ad --yes install; assert_rc $? 0 "install with old nft"
    assert_nogrep "$(RS)" 'skuid' "falls back to logging without UID"
    assert_grep "$(RS)" 'log prefix'
    printf 'flags skuid\nlog prefix\nupdate @sg\n' >"$F/nft-reject"
    run_ad --yes module scanguard on; assert_rc $? 0 "scan guard on unsupported nft"
    assert_nogrep "$(RS)" 'scanguard' "unsupported optional module skipped, base protection kept"
    assert_grep "$(RS)" 'bogons_v4 counter drop'
}

test_modules() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    run_ad --yes module smtp on; assert_grep "$(RS)" 'tcp dport \{ 25 \} counter drop comment "smtp"'
    run_ad --yes set SMTP_PORTS "25 465 587"; run_ad --yes apply
    assert_grep "$(RS)" 'tcp dport \{ 25, 465, 587 \} counter drop'
    run_ad --yes set SMTP_PORTS '25; drop'; assert_grep "$T/out" 'invalid value'
    run_ad --yes module ports on; assert_grep "$(RS)" 'tcp dport \{ 23, 135, 139, 445 \}'
    run_ad --yes module scanguard on; assert_grep "$(RS)" 'meta nfproto ipv4 update @sg_port_v4 \{ tcp dport limit rate over 60/minute burst 120 packets \} counter drop'
    assert_grep "$(RS)" 'meta nfproto ipv6 update @sg_port_v6'
    assert_grep "$(RS)" 'tcp dport \{ 53, 80, 443, 853 \} return'
    run_ad --yes module forward on; assert_grep "$(RS)" 'type filter hook forward priority 0'
    run_ad --yes module logging off; assert_nogrep "$(RS)" 'log prefix'
    run_ad --yes module hosts off; assert_nogrep "$R/etc/hosts" 'appclick'
    run_ad --yes module hosts on; assert_grep "$R/etc/hosts" 'appclick'
}

test_update_logic() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    local m="$F/www/raw.githubusercontent.com/Kiya6955/Abuse-Defender/main" mm
    echo '10.0.0.0/8' >"$m/lists/bogons-v4.txt"
    run_ad update; assert_grep "$T/out" 'checksum mismatch'
    assert_eq "$(grep -c . "$R/var/lib/abuse-defender/lists/bogons-v4.txt")" 13 "good copy kept"
    for mm in "$m" "$F/www/cdn.jsdelivr.net/gh/Kiya6955/Abuse-Defender@main"; do
        printf '10.0.0.0/8\n300.1.1.1/8\n' >"$mm/lists/abuse-v4.txt"
        (cd "$mm" && sha256sum lists/abuse-v4.txt >lists/SHA256SUMS)
    done
    run_ad update; assert_grep "$T/out" 'abuse-v4 rejected'
    assert_grep "$R/var/lib/abuse-defender/lists/abuse-v4.txt" '^102\.0\.0\.0/8$' "last good abuse list kept"
    touch "$F/www-down"
    run_ad update; assert_grep "$T/out" 'download failed on all mirrors'
    assert_grep "$T/out" 'unreachable \(curl exit 6\) - skipping it for this run' "dead mirrors are skipped"
    assert_file "$(RS)"
    rm -f "$F/www-down"
    mkdir -p "$m/lists/geo"
    seq 1 100 | awk '{print "5." $1 ".0.0/16"}' >"$R/var/lib/abuse-defender/lists/geo-zz-v4.txt"
    printf '5.1.0.0/16\n' >"$m/lists/geo/zz-v4.txt"
    for mm in "$m" "$F/www/cdn.jsdelivr.net/gh/Kiya6955/Abuse-Defender@main"; do rm -f "$mm/lists/SHA256SUMS"; done
    run_ad --yes set GEO_COUNTRIES zz; run_ad update; assert_grep "$T/out" 'shrank from 100 to 1'
    run_ad --force update; assert_eq "$(grep -c . "$R/var/lib/abuse-defender/lists/geo-zz-v4.txt")" 1 "--force accepts"
}

test_fresh_offline_install() {
    touch "$F/www-down"
    run_ad --yes install; assert_rc $? 0 "offline install uses built-in lists: $(tail -n 3 "$T/out")"
    assert_grep "$(RS)" 'bogons_v4 \{ 0\.0\.0\.0/8'
    assert_grep "$(RS)" 'abuse_v4 \{ 25\.0\.0\.0/8'
}

test_legacy_list_fallback() {
    local mm
    for mm in "$F/www/raw.githubusercontent.com/Kiya6955/Abuse-Defender/main" "$F/www/cdn.jsdelivr.net/gh/Kiya6955/Abuse-Defender@main"; do
        rm -rf "$mm/lists"
        echo '198.51.100.0/24' >"$mm/abuse-ips.ipv4"
    done
    run_ad --yes install; assert_rc $? 0 "install with only the legacy list published"
    assert_grep "$R/var/lib/abuse-defender/lists/abuse-v4.txt" '^198\.51\.100\.0/24$' "legacy abuse-ips.ipv4 used"
}

test_no_ipv6_host() {
    rm -f "$R/proc/net/if_inet6"; : >"$F/ip/route6"
    run_ad --yes install; assert_rc $? 0 "install without IPv6"
    assert_nogrep "$(RS)" 'ip6 daddr|ipv6_addr|icmpv6' "no IPv6 rules"
    new_env ipset
    rm -f "$R/proc/net/if_inet6"
    run_ad --yes install; assert_rc $? 0 "install without IPv6 (ipset)"
    assert_nogrep "$F/ipt6.state" 'abuse-defender' "nothing in ip6tables"
}

test_no_default_route() {
    : >"$F/ip/route4"; : >"$F/ip/route6"
    run_ad --yes install; assert_rc $? 0 "install without default route"
    assert_grep "$(RS)" 'oifname != "lo" jump egress' "falls back to all non-lo interfaces"
    assert_grep "$T/out" 'no default-route interface'
}

test_alpine_and_none() {
    new_env nft alpine
    run_ad --yes install; assert_rc $? 0 "alpine install"
    assert_file "$R/etc/periodic/15min/abuse-defender"; assert_file "$R/etc/local.d/abuse-defender.start"
    run_ad --yes uninstall; assert_no_file "$R/etc/periodic/15min/abuse-defender"; assert_no_file "$R/etc/local.d/abuse-defender.start"
    new_env nft none
    run_ad --yes install; assert_rc $? 0 "install without scheduler"; assert_grep "$T/out" 'NOT survive a reboot'
}

test_uninstall_clean() {
    local be
    for be in nft ipset; do
        new_env "$be"
        echo "-A OUTPUT -d 192.0.2.1/32 -j REJECT" >"$F/ipt4.state"
        printf '15 4 * * * /usr/bin/backup.sh\n' >"$F/crontab"
        mkdir -p "$R/etc/iptables"; printf '*filter\n-A INPUT -i lo -j ACCEPT\nCOMMIT\n' >"$R/etc/iptables/rules.v4"
        local before; before="$(snapshot)"
        run_ad --yes install >/dev/null || { bad "install ($be): $(tail -n 5 "$T/out")"; continue; }
        run_ad --yes whitelist 10.9.0.0/16 >/dev/null
        run_ad --yes module scanguard on >/dev/null
        run_ad uninstall; assert_rc $? 1 "uninstall without --yes when non-interactive must refuse"
        run_ad --yes uninstall; assert_rc $? 0 "uninstall ($be)"
        local after; after="$(snapshot)"
        [[ "$before" == "$after" ]] && ok || bad "uninstall ($be) left changes: $(diff <(echo "$before") <(echo "$after") | head -n 12)"
    done
}

test_v1_only_uninstall() {
    write_v1_state
    run_ad --yes uninstall; assert_rc $? 0 "uninstall of a v1-only setup"
    assert_nogrep "$F/ipt4.state" 'abuse-defender' "v1 chains removed"
    assert_nogrep "$F/crontab" 'abuse-defender' "v1 cron removed"
    assert_nogrep "$R/etc/hosts" 'appclick' "v1 hosts lines removed"
    assert_no_file "$R/root/abuse-defender-update.sh"
}

test_export_import() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    run_ad --yes block 198.18.5.0/24 >/dev/null
    run_ad --yes module smtp on >/dev/null
    run_ad export "$T/s.tgz"; assert_rc $? 0 "export"; assert_file "$T/s.tgz"
    tar -tzf "$T/s.tgz" >"$T/list"; assert_nogrep "$T/list" 'var/lib' "export contains settings only"
    run_ad --yes unblock 198.18.5.0/24 >/dev/null
    run_ad --yes module smtp off >/dev/null
    run_ad --yes import "$T/s.tgz"; assert_rc $? 0 "import: $(tail -n 3 "$T/out")"
    assert_grep "$R/etc/abuse-defender/custom-block.txt" '^198\.18\.5\.0/24$'
    assert_grep "$R/etc/abuse-defender/abuse-defender.conf" '^BLOCK_SMTP="yes"$'
    assert_grep "$(RS)" 'comment "smtp"' "imported settings applied"
    mkdir -p "$T/evil/etc"; echo x >"$T/evil/etc/passwd"
    tar -C "$T/evil" -czf "$T/evil.tgz" etc/passwd
    run_ad --yes import "$T/evil.tgz"; assert_rc $? 1 "evil archive refused"; assert_grep "$T/out" 'refusing archive'
    mkdir -p "$T/evil2/etc/abuse-defender"; echo x >"$T/evil2/etc/abuse-defender/evil.sh"
    tar -C "$T/evil2" -czf "$T/evil2.tgz" etc/abuse-defender
    run_ad --yes import "$T/evil2.tgz"; assert_rc $? 1 "unknown file in settings archive refused"
}

test_hits() {
    cat >"$F/dmesg" <<'EOF'
[100.1] AD-DROP bogons: IN= OUT=eth0 SRC=203.0.113.5 DST=10.1.2.3 LEN=60 PROTO=TCP SPT=40000 DPT=445 UID=1001 GID=1001
[100.2] AD-DROP bogons: IN= OUT=eth0 SRC=203.0.113.5 DST=10.1.2.4 LEN=60 PROTO=TCP SPT=40001 DPT=445 UID=1001 GID=1001
[100.3] AD-DROP abuse: IN= OUT=eth0 SRC=203.0.113.5 DST=25.1.1.1 LEN=60 PROTO=TCP SPT=40002 DPT=22 UID=0 GID=0
EOF
    run_ad hits 5; assert_rc $? 0 "hits"
    assert_grep "$T/out" '2  bogons'; assert_grep "$T/out" '1  abuse'; assert_grep "$T/out" '2  445'; assert_grep "$T/out" '2  1001'
}

test_disable_enable() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    run_ad --yes disable; assert_rc $? 0 "disable"
    assert_no_file "$(RS)"; assert_nogrep "$R/etc/hosts" 'appclick'
    run_ad status; assert_grep "$T/out" 'Protected: NO \(disabled\)'
    run_ad ensure; assert_no_file "$(RS)"
    run_ad --yes enable; assert_rc $? 0 "enable"; assert_file "$(RS)"
}

test_geo() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    run_ad --yes geo add IR; assert_rc $? 0 "geo add: $(tail -n 3 "$T/out")"
    assert_grep "$(RS)" 'set geo_ir_v4'; assert_grep "$(RS)" 'comment "geo-ir"'
    run_ad --yes geo add 'i;' ; assert_rc $? 1 "bad country code refused"
    run_ad --yes geo remove ir; assert_nogrep "$(RS)" 'geo_ir'
}

test_menu_flow() {
    local input='1\ny\nyes\n\n'          # 1 install -> Continue? y -> keep rules? yes -> Enter
    input+='99\n7\n999.1.1.1\n10.9.0.0/16\n\n'  # bad choice, whitelist with an invalid then a valid IP
    input+='13\n1\nyes\n0\n'             # modules -> toggle smtp -> confirm -> back
    input+='11\n3\nyes\n0\n'             # categories -> toggle spamhaus -> confirm -> back
    input+='12\n1\nir\ny\nyes\n0\n'      # country -> add ir -> confirm block -> keep rules -> back
    input+='6\n\n'                       # dry-run preview
    input+='5\n\n'                       # doctor
    input+='3\n\n'                       # status
    input+='15\n\n'                      # show settings
    input+='4\ny\n\n'                    # disable -> confirm
    input+='4\nyes\n\n'                  # enable -> keep rules
    input+='0\n'
    run_ad_input "$input" --confirm-timeout=5 menu; assert_rc $? 0 "menu session: $(tail -n 5 "$T/out")"
    cp "$T/out" "$T/menu.out"
    local m="$T/menu.out" c="$R/etc/abuse-defender/abuse-defender.conf"
    assert_grep "$m" '^\+-+\+$' "header box"
    assert_grep "$m" '^Protected: YES \| backend: nft/inet \| IPv4\+IPv6 \| updated: ' "status line after install"
    assert_grep "$m" '^   4\) Disable protection \(keeps settings\)$' "enable/disable is item 4"
    assert_grep "$m" '^   4\) Enable protection$' "item 4 turns into Enable when disabled"
    assert_grep "$m" '^  16\) Export / import settings       17\) Uninstall completely$' "contiguous numbering up to 17"
    assert_grep "$m" 'Choose \[0-17\]: ' "prompt range"
    assert_nogrep "$m" 'Mode \(|IP family|Mirrors and other settings|monitor' "removed menu items are gone"
    assert_grep "$m" 'please enter a number between 0 and 17' "invalid menu choice re-prompts"
    assert_grep "$m" "'999\.1\.1\.1' is not accepted" "invalid IP re-prompts"
    assert_grep "$R/etc/abuse-defender/whitelist.txt" '^10\.9\.0\.0/16$' "whitelist via menu"
    assert_grep "$c" '^BLOCK_SMTP="yes"$' "module via menu"
    assert_grep "$c" '^CATEGORIES="bogons abuse spamhaus"$' "category via menu"
    assert_grep "$m" 'This blocks ALL outbound traffic to IR' "country confirmation shown"
    assert_grep "$c" '^GEO_COUNTRIES="ir"$' "country via menu"
    assert_grep "$m" 'dry-run: backend=nft/inet IPv4\+IPv6 egress=eth0' "preview via menu"
    assert_grep "$m" 'Summary: [0-9]+ failure' "doctor via menu"
    assert_grep "$m" '^MIRRORS="https://' "show settings via menu (read-only)"
    assert_grep "$m" 'protection disabled' "disable via menu"
    assert_grep "$c" '^ENABLED="yes"$' "enabled again via menu"
    assert_file "$(RS)"
    assert_grep "$(RS)" 'set geo_ir_v4'
    assert_grep "$m" 'Bye\.' "clean exit"
    # end of input never loops forever
    run_ad_input '7\n' menu; assert_rc $? 0 "menu exits at end of input"
    # a 'no' at the keep-rules prompt rolls back rules and setting
    cp "$(RS)" "$T/rs.before"
    run_ad_input '13\n2\nno\n0\n0\n' --confirm-timeout=5 menu
    assert_grep "$T/out" 'not confirmed - the previous rules were restored'
    cmp -s "$T/rs.before" "$(RS)" && ok || bad "rules not rolled back after 'no'"
    assert_grep "$c" '^BLOCK_PORTS="no"$' "the unconfirmed setting is reverted too"
    assert_grep "$T/out" 'settings restored to their previous values'
}

test_menu_uninstall() {
    run_ad --yes install >/dev/null || { bad "install"; return; }
    run_ad_input '17\nn\n\n0\n' menu; assert_file "$R/usr/local/sbin/abuse-defender"; assert_grep "$T/out" 'cancelled'
    run_ad_input '17\ny\n\n0\n' menu; assert_no_file "$R/usr/local/sbin/abuse-defender"; assert_no_file "$(RS)"
}

# ---------------------------------------------------------------- runner
ALL=(list_parsing build_lists_check cli_basics install_nft dry_run_output idempotent_install migration_to_nft
     auto_replace_v1_menu auto_replace_v1_failure_keeps_old auto_replace_v1_leftovers upgrade_old_v2 newer_installed_wins
     obsolete_config_keys geo_guard migration_to_ipset plain_iptables_backend doctor input_validation
     rollback_on_selftest_failure render_fallback_levels modules update_logic fresh_offline_install
     legacy_list_fallback no_ipv6_host no_default_route alpine_and_none uninstall_clean v1_only_uninstall
     export_import hits disable_enable geo menu_flow menu_uninstall)
run_one() {   # runs in a background subshell; results go to files
    local name=$1
    CURRENT=$name; PASS=0; FAIL=0
    new_env nft
    "test_$name" >"$WORKROOT/res.$name.log" 2>&1
    echo "$PASS $FAIL" >"$WORKROOT/res.$name.cnt"
}


run_tests() {
    local name p f TP=0 TF=0
    SEL=("$@"); [[ ${#SEL[@]} -gt 0 ]] || SEL=("${ALL[@]}")

    for name in "${SEL[@]}"; do
        declare -F "test_$name" >/dev/null || { echo "unknown test: $name"; exit 2; }
        run_one "$name" &
        while [[ $(jobs -rp | wc -l) -ge $JOBS ]]; do wait -n 2>/dev/null || sleep 0.5; done
    done
    wait

    for name in "${SEL[@]}"; do
        read -r p f <"$WORKROOT/res.$name.cnt" 2>/dev/null || { p=0; f=1; echo "    FAIL [$name]: test crashed"; }
        TP=$((TP + p)); TF=$((TF + f))
        printf '%-36s %s\n' "$name" "$([[ $f -eq 0 ]] && echo ok || echo FAILED)"
        [[ $f -eq 0 ]] || cat "$WORKROOT/res.$name.log"
    done
    echo
    echo "passed assertions: $TP, failed: $TF"
    [[ $TF -eq 0 ]]
}

# AD_TEST_LIB=1: only define the helpers (used to capture example output)
[[ ${AD_TEST_LIB:-0} == 1 ]] || run_tests "$@"
