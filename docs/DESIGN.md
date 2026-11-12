# Abuse Defender 2 - design notes

This document explains how the rules are laid out, why they are ordered the way they
are, what keeps an administrator from being locked out, and how updates stay atomic.
It is written for reviewers and contributors; users want the README.

## 1. Goals and non-goals

Goals, in priority order:

1. **Never lock the admin out and never break the host's own networking** (SSH, DNS,
   default gateway, cloud metadata, IPv6 neighbour discovery, Docker/VPN interfaces).
2. **Never leave a window without protection** during updates, re-applies or migration
   from v1, and never fall back to "no protection" when a download fails.
3. **Only touch what we own.** No global flushes, no rewriting of other tools' rules.
4. **Idempotent and reversible.** Running any command twice changes nothing the second
   time; `uninstall` restores the machine to its previous state.
5. Work on every common VPS distribution (Debian/Ubuntu, RHEL/Alma/Rocky/Fedora, Arch,
   Alpine), with nftables, iptables-nft, iptables-legacy, with or without systemd.

Non-goals: inbound firewalling, deep-packet inspection, replacing ufw/firewalld.

## 2. Components

```
abuse-defender.sh            single self-contained bash script (also the installed binary)
  /usr/local/sbin/abuse-defender            installed copy
  /etc/abuse-defender/abuse-defender.conf   KEY="value" config (parsed, never sourced)
  /etc/abuse-defender/whitelist.txt         user allow list (IPv4/IPv6 CIDRs)
  /etc/abuse-defender/custom-block.txt      user block list
  /etc/abuse-defender/domains.txt           extra domains for the hosts sinkhole
  /var/lib/abuse-defender/lists/            last-known-good copies of every downloaded list
  /var/lib/abuse-defender/applied/          the bundle currently loaded in the kernel
  /var/lib/abuse-defender/previous/         the bundle before that (rollback target)
  /var/log/abuse-defender.log               log (+ logrotate snippet)
  systemd: abuse-defender.service (boot restore), abuse-defender-ensure.timer (15 min),
           abuse-defender-update.timer (daily + 1h random delay)
  fallbacks: /etc/cron.d/abuse-defender, or Alpine /etc/periodic + /etc/local.d
lists/                         curated lists (commented) + country lists built from RIR data + SHA256SUMS
abuse-ips.ipv4                 legacy list derived from lists/, consumed by v1 installs
tools/build-lists.sh           validation/aggregation/rebuild of derived files (uses the script as a library)
tests/run.sh + tests/stubs/    test-suite with fake iptables/nft/ipset/ip/ss/curl/systemctl
```

## 3. Backends

`BACKEND=auto` picks, after **probing the running kernel** (a throw-away table/chain
is created and deleted, so "binary installed but module missing" is detected):

| Order | Backend | Data structure | Atomic update |
|---|---|---|---|
| 1 | `nft` | own table `inet abuse_defender` (or `ip` if the kernel has no IPv6) with interval sets | one `nft -f` file: `add table; delete table; table {...}; add element ...` is a single transaction |
| 2 | `ipset` | `hash:net` sets `ad4-*`/`ad6-*` + chain `abuse-defender` in the `filter` table | sets are filled under a temporary name and `ipset swap`ped; the chain is replaced with `iptables-restore --noflush` (atomic per table) |
| 3 | `iptables` | one chain per category with one rule per CIDR | `iptables-restore --noflush` (atomic per table) |

nftables is preferred because our table is completely separate: `ufw reload`,
Docker restarts, `iptables-save > rules.v4` or `firewall-cmd --reload` (nft backend)
never touch it, and a DROP in any base chain is final in nftables, so other tables'
ACCEPT rules cannot bypass it. iptables-nft vs. iptables-legacy does not matter to the
nft backend; for the iptables backends the variant is reported in `status`.

## 4. Rule layout and ordering

Only packets **leaving through an uplink interface** are filtered. With
`EGRESS_INTERFACES=auto` these are the interfaces that hold a default route (IPv4 or
IPv6). Traffic to `docker0`, `br-*`, `wg0`, `tailscale0`, a provider's private VLAN on
`eth1`, etc. never reaches the provider's public network and is not touched. If no
default route is found the tool falls back to "every interface except `lo`" and warns.

```
 OUTPUT hook (and FORWARD hook if APPLY_FORWARD=yes)
   └─ oifname in {uplinks}  ──jump──►  egress chain   (iptables: chain "abuse-defender")
                                         │
   1  -o lo ............................... RETURN   (iptables only; nft never jumps for lo)
   2  ct state established,related ........ RETURN   replies to inbound sessions (SSH, panels)
   3  udp 68 -> 67 (DHCPv4) ............... RETURN   255.255.255.255 is inside 240/4
   4  ICMPv6 RS/NS/NA/MLD, DHCPv6 ......... RETURN   IPv6 must keep working
   5  daddr in allow set .................. RETURN   whitelist.txt + gateways + DNS + cloud metadata + SSH clients
   6  daddr in custom set ................. LOG(rate-limited) + DROP
   7  optional: SMTP ports, scan-target ports ........ LOG + DROP
   8  optional: TCP SYN -> scanguard chain ........... (see §7)
   9  daddr in local set .................. RETURN   directly connected subnets
  10  daddr in <category> sets ............ LOG(rate-limited) + DROP   bogons, abuse, spamhaus, feodo, geo-XX
                                         │
   falls off the end → back to OUTPUT, the user's own rules continue normally
```

Why this order:

* Whitelist (5) wins over everything, deterministically. v1 relied on the accidental
  order of three `-I OUTPUT` calls.
* Custom blocks (6) are above the connected-subnet exemption (9) so an admin can block
  a neighbour in the same subnet.
* Port rules (7, 8) are above the connected-subnet exemption because scanning the
  neighbours in your own provider /24 is a classic report trigger.
* We use `RETURN`, never `ACCEPT`: allowed traffic still passes through the user's own
  OUTPUT rules (ufw, custom rules), we only ever *remove* traffic.
* For the iptables backends the jump is kept at position 1 of OUTPUT/FORWARD
  (ufw's `ufw-track-output` ACCEPTs new connections, so being below it would be useless).
  `ensure` puts it back on top if ufw/Docker inserted rules above it.

Counters: every DROP rule has a counter (nft `counter ... comment "<category>"`, iptables
per-rule counters), shown per category by `abuse-defender status`.

Logging: a separate rule with `limit rate N/minute` logs `AD-DROP <category>:` with the
**owning UID** (`log flags skuid` / `--log-uid`) so `abuse-defender hits` can show which
local user/app produced the blocked traffic. If the kernel or nft version cannot do UID
logging, logging, or an optional module, the renderer retries at a lower feature level
(`nft -c` / `iptables-restore --test` decide) and records a note instead of failing.

**IPv6 is automatic.** IPv4 is always protected. IPv6 sets and rules are added only when
the host has working IPv6 (`/proc/net/if_inet6` present, `disable_ipv6` not set) and the
backend can filter it (nftables `inet` family, or ip6tables); otherwise the IPv6 parts
(sets, ICMPv6/DHCPv6 exemptions, scan-guard sets) are simply not rendered.

## 5. Safety model (what can lock you out, and why it does not)

| Risk | Mitigation |
|---|---|
| SSH replies to a client in a private range (VPN, provider LAN, Tailscale) | conntrack `ESTABLISHED,RELATED` return; current SSH client IPs (`SSH_CONNECTION` + `ss`) auto-whitelisted |
| Provider gateway in RFC1918/CGNAT (Hetzner `172.31.1.1`, Oracle `10.0.0.1`) | default gateways auto-whitelisted |
| DNS resolver in a blocked range (AWS VPC+2, Alibaba `100.100.2.136`) | `/etc/resolv.conf`, systemd-resolved upstreams and `resolvectl` resolvers auto-whitelisted; documented cloud DNS IPs in `lists/cloud-allow-*` |
| Metadata services (`169.254.169.254`, AWS `fd00:ec2::254`, GCP `fd20:ce::254`, Alibaba `100.100.100.200`) | `lists/cloud-allow-*` |
| Docker bridges / private VLAN / VPN interfaces | only uplink interfaces are filtered; connected subnets exempt from range lists |
| Loopback | `lo` never filtered; lists may not contain `127.0.0.0/8` or `::1` (validator) |
| IPv6 neighbour discovery / link-local gateway | `fe80::/10` and `ff00::/8` can never be listed (validator), ICMPv6 ND/MLD returned early |
| DHCP lease renewal | DHCPv4/DHCPv6 returned early |
| A bad rule set | `nft -c`/`iptables-restore --test` before applying; feature fallbacks |
| A rule set that breaks connectivity anyway | connectivity self-test before and after (HTTPS to the first mirror, TCP 1.1.1.1:443 / IPv6, DNS lookup, ping gateway). Anything that worked before and fails after → automatic rollback |
| The admin's own SSH breaks in a way the self-test cannot see | interactive changes ask the admin to open a **new** SSH session and type `yes` within 60 s (`--confirm-timeout`). No answer, Ctrl+C, a lost terminal (SIGHUP) or a crash → rollback. A detached watchdog process (`_auto-rollback`) performs the rollback even if the main process is SIGKILLed |
| Whitelisting/blocking everything by typo | allow entries must be ≥ /8 (v4) or ≥ /16 (v6); block entries ≥ /4 or ≥ /7 |
| Busy proxy: conntrack table full | warning when `nf_conntrack_count` > 70 % of `nf_conntrack_max`; `STATEFUL=no` documented |

Rollback restores the previous bundle (or removes everything if there was none) with
the same atomic mechanism as an apply.

## 6. Update flow

```
timer ──► update --quiet
          lock (flock /run/abuse-defender/lock, mkdir fallback)
          for each needed list:
            for each mirror (raw.githubusercontent.com, cdn/fastly/gcore.jsdelivr.net, ...):
              curl -fsSL --proto =https --retry 2 --connect-timeout 10 --max-time 120 --max-filesize 50M
              verify sha256 against <mirror>/lists/SHA256SUMS (when the file is listed there)
              mismatch → next mirror (jsDelivr caches can lag behind GitHub)
            external feeds (Spamhaus, abuse.ch, ipverse, ipdeny) fetched from their origin
            parse + validate every line (strict for our lists, ≤5 % junk for third-party)
            normalise (host bits), dedupe, aggregate
            sanity: minimum size per list; refuse if it lost more than half of its entries (--force accepts)
            ok → atomically replace /var/lib/abuse-defender/lists/<name>.txt
            fail → keep last good copy (or built-in copy) and exit 3 at the end
          if anything changed or rules are missing → build bundle → apply (atomic) → self-test
```

Lists are never applied partially: the new bundle is built completely in a temp dir,
checked, then loaded in one transaction. A failed download can never remove protection.

Signatures: the lists come from the same repository and transport as the script itself
(`bash <(curl ...)`), so a signature on the lists alone would not raise the bar against a
compromised repository. SHA256SUMS protects against truncated/corrupted or mixed-version
CDN responses. The download locations are a fixed internal list (GitHub raw first, then
jsDelivr hosts, because some networks block raw.githubusercontent.com); they are not a
setting.

## 7. Scan guard

Netscan reports are triggered by *many distinct destinations on one port* (horizontal
scan) or *many ports on one destination* (vertical scan) in a short time. The scan guard
tracks recently seen `(destination, port)` pairs in a dynamic set with a 10-minute
timeout; only a **new** pair is counted, against two per-key rate limits:

* per destination port: `SCAN_GUARD_DESTS_PER_MIN` new destinations/minute (default 60, burst ×2)
* per destination IP: `SCAN_GUARD_PORTS_PER_MIN` new ports/minute (default 30)

Ports in `SCAN_GUARD_EXEMPT_PORTS` (53, 80, 443, 853 by default) are never limited:
a proxy legitimately opens thousands of connections to many hosts on 443. Requires
nftables dynamic sets, or ipset + `hashlimit` + `SET`; skipped with a note otherwise.

## 8. Persistence and coexistence

* `abuse-defender.service` (oneshot, `DefaultDependencies=no`, after
  `nftables/netfilter-persistent/iptables/ip6tables/ufw/firewalld`, before
  `network-pre.target`) re-loads the last applied bundle at boot, no network needed.
  `PartOf=nftables.service netfilter-persistent.service firewalld.service` re-applies
  when one of those is restarted (they may flush everything).
* `abuse-defender-ensure.timer` (every 15 min) rebuilds the bundle from current
  gateway/DNS/interfaces; reloads only if it changed or the rules disappeared
  (`firewall-cmd --reload`, `nft flush ruleset`, cloud-init rewriting `/etc/hosts`).
* We never write our rules into `/etc/iptables/rules.v4`, `/etc/sysconfig/iptables` or
  `/etc/nftables.conf`. If they get saved there (v1 did `iptables-save > rules.v4`, a
  user may run `netfilter-persistent save`), our lines are stripped (with a backup) so a
  boot-time restore never depends on ipsets that do not exist yet.

## 9. Migration from v1

v1 state: chains `abuse-defender`, `abuse-defender-custom`, `abuse-defender-whitelist`
with unconditional `-I OUTPUT` jumps, `/root/abuse-defender-update.sh`, a root crontab
line, duplicated `127.0.0.1 appclick.co` lines, and a full `iptables-save` in rules.v4.

1. Entries of `abuse-defender-custom` / `abuse-defender-whitelist` are imported into
   `custom-block.txt` / `whitelist.txt` (nothing the admin added is lost).
2. The new rules are loaded **first** (nft table, or the `abuse-defender` chain is
   atomically re-filled by `iptables-restore --noflush`).
3. Only then the v1 jumps and chains are removed, the cron line is filtered out of the
   crontab (other lines untouched; a failing `crontab -l` never wipes it), the update
   script and the stray hosts lines are deleted, and rules.v4 is cleaned.

`abuse-ips.ipv4` keeps working for v1 installs that are never migrated: plain IPv4 CIDRs,
one per line, derived from `lists/bogons-v4.txt` + `lists/abuse-v4.txt` (without
`0.0.0.0/8`, because v1 has no `lo` exception).

### Automatic replacement of older installations

Whenever the menu starts, or a command that changes settings or rules runs (as root),
`auto_replace_old` looks for v1 artefacts (chains with DROP rules, the update script, its
crontab line, the hosts lines) and for an older v2 (installed program with a lower
`AD_VERSION`). Without asking it:

1. imports the v1 custom/whitelist entries and takes an `iptables -S` snapshot of the
   v1 chains and jumps;
2. runs the normal install (program, config, lists, atomic apply with self-test - no
   interactive keep-rules prompt, because the new rules are strictly less restrictive
   than v1's unconditional drops);
3. only on success removes the v1 chains/jumps, cron line, script, hosts lines and the
   abuse-defender lines in rules.v4; on failure the snapshot is replayed so the v1
   protection is back exactly as it was;
4. prints a summary of what was imported and removed (in the menu: under the header).

A v1 setup whose rules had already been cleared is only tidied up (nothing is
installed). A newer installed program always wins: an older copy started by hand
`exec`s the installed one instead of downgrading it.

### Country blocking guard

`geo add <cc>` first downloads the country lists (repository `lists/geo/<cc>-v{4,6}.txt`
when present - only `ir` is pre-built -, otherwise ipverse/country-ip-blocks, then
ipdeny), validates them like every other list, and then, before changing anything:

1. checks the default gateways, DNS resolvers and connected SSH clients against the
   country prefixes (IPv4 by integer range, IPv6 by masked-prefix lookup) and refuses
   with the offending addresses listed (`--force` overrides; those addresses remain in the
   allow set, so the override cannot cut them off either);
2. prints how many IPv4/IPv6 prefixes will be blocked and that services hosted there
   become unreachable, and asks for confirmation (menu) or requires `--yes` (CLI);
3. only then adds the code to `GEO_COUNTRIES` and applies through the normal
   self-test / keep-rules / checkpoint path.

If no valid list can be downloaded, the code is not added. `geo add` needs an installed
and enabled setup.

### Settings checkpoint

Interactive changes (whitelist removal, categories, modules, country, import) checkpoint the settings files first. If the change is rolled back - self-test
regression, "no"/timeout at the keep-rules prompt, Ctrl+C - the settings are restored
too; otherwise the 15-minute ensure timer would silently re-apply the unconfirmed change.

## 10. Menu

The menu is a loop (no recursion) over grouped sections; every action runs in a
subshell, so an error or `die` returns to the menu while the EXIT trap of that subshell
still performs any pending rollback. Numeric choices, IP/CIDR input and country codes
are validated and asked again until they are valid; an empty answer cancels; end of
input exits. Items are numbered 1-17 without gaps; item 4 toggles between "Disable
protection (keeps settings)" and "Enable protection". Settings are shown read-only
(item 15); module tuning keys (port lists, scan-guard thresholds, ...) are edited in the
config file or with `abuse-defender set KEY VALUE`. The explicit `menu` command reads answers from stdin
when it is not a terminal, which is how the test-suite drives it. Colours are used only
on a terminal and never when `NO_COLOR` is set.

## 11. Domain sinkhole

`lists/domains.txt` + `/etc/abuse-defender/domains.txt` are written as
`127.0.0.1 name` / `::1 name` into one marker-delimited block in `/etc/hosts`. The file is
rewritten in place (keeps inode, owner, SELinux label, works on bind mounts), only when
the content changes, and the block is removed completely on `disable`/`uninstall`.
This only affects programs that use the system resolver (glibc/musl, Go's resolver, Xray
with no own DNS); see docs/xray-routing.md for the application-level complement.
