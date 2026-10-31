<h1 align="center">Abuse Defender</h1>

<div align="center">
    <a href="https://t.me/savechannelkiya6955"> 
        <img src="https://img.shields.io/badge/TelegramChannel-%230577B8?logo=telegram" alt="Telegram channel"/> 
    </a>
    <a href="https://github.com/Kiya6955/Abuse-Defender"> 
        <img src="https://img.shields.io/github/stars/Kiya6955/Abuse-Defender?style=flat" alt="GitHub stars"/> 
    </a>
    <a href="https://github.com/Kiya6955/Abuse-Defender/releases/latest"> 
        <img src="https://img.shields.io/github/release/Kiya6955/Abuse-Defender.svg" alt="Latest release"/> 
    </a>
</div>

**Abuse Defender** stops a Linux server from sending the traffic that gets VPS accounts
suspended: "netscan" to private/reserved address space, connections to honeypot and
sensor networks, outbound spam on port 25 and port-scan patterns. It is made for proxy
servers (Xray/V2Ray/sing-box, OpenVPN, WireGuard) whose users can make the server
connect anywhere, but works on any server.

It adds **outbound rules only** - it never blocks incoming traffic and never touches
firewall rules it did not create.

## Quick start

```bash
bash <(curl -s https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-defender.sh)
```

Run as root and choose **1) Install / re-apply protection**. The script installs itself
to `/usr/local/sbin/abuse-defender`, downloads the lists, applies the rules, asks you to
open a new SSH session and type `yes` to keep them, and schedules boot restore and
daily updates. Afterwards just run `abuse-defender` to get the menu again.

If `raw.githubusercontent.com` is blocked where you are, use the jsDelivr mirror:

```bash
bash <(curl -fsSL https://cdn.jsdelivr.net/gh/Kiya6955/Abuse-Defender@main/abuse-defender.sh)
```

**Upgrading from the old version:** run the same command. An older installation
(v1 chains, `/root/abuse-defender-update.sh`, its cron line, the duplicated
`/etc/hosts` lines, or an older v2) is detected and replaced automatically, without
questions: your manual whitelist/block entries are imported, the new rules are loaded
first, and only then is the old setup removed. A summary of what was imported and
removed is printed. If the new rules cannot be applied, the old ones stay in place.

## The menu

```
+--------------------------------------------------------------+
| Abuse Defender v2.0.0 - outbound abuse protection            |
| https://github.com/Kiya6955/Abuse-Defender                   |
+--------------------------------------------------------------+
Protected: YES | backend: nft/inet | IPv4+IPv6 | mode: enforce | updated: 2026-10-31 12:00 (ok) | timer: systemd update:active ensure:active

 Protection
   1) Install / re-apply protection
   2) Update lists now
   3) Status and counters
   4) Doctor (diagnose problems)
   5) Preview rules without applying (dry-run)
 Allow and block
   6) Whitelist an IP/range            7) Remove a whitelisted IP/range
   8) Block an IP/range                9) Unblock an IP/range
 Settings
  10) Block categories                11) Country blocking
  12) Optional modules                13) IP family (both / IPv4 / IPv6)
  14) Mode (enforce / monitor)        15) Mirrors and other settings
 Tools
  16) Blocked-connections log         17) Export / import settings
  18) Enable / disable protection     19) Uninstall completely
   0) Exit
```

Every input is validated and asked again if it is wrong; Ctrl+C at any point leaves the
server in a consistent state (unconfirmed changes are rolled back).

## Commands (for scripts and automation)

```bash
abuse-defender install --yes            # install/upgrade without questions
abuse-defender status                   # protection, counters, auto-whitelist
abuse-defender doctor                   # diagnose backend, conflicts, network, timers, lists
abuse-defender update                   # fetch lists now (the timer does this daily)
abuse-defender whitelist 10.8.0.0/16    # never block this (e.g. your VPN subnet)
abuse-defender block 203.0.113.0/24     # always block this
abuse-defender unblock 203.0.113.0/24
abuse-defender mode monitor             # only count/log what would be blocked
abuse-defender mode enforce
abuse-defender family 4                 # IPv4 only (both | 4 | 6)
abuse-defender geo add ir               # block outbound traffic to Iran
abuse-defender category spamhaus on     # Spamhaus DROP list
abuse-defender module smtp on           # block outbound port 25
abuse-defender module scanguard on      # rate-limit port-scan behaviour
abuse-defender hits                     # who/what was blocked (kernel log)
abuse-defender --dry-run apply          # show the rules without applying them
abuse-defender export | import FILE     # save / load your settings
abuse-defender config                   # print all settings
abuse-defender set KEY VALUE            # change any setting
abuse-defender disable | enable
abuse-defender uninstall --yes          # remove everything
abuse-defender --help
```

Exit codes: `0` ok, `1` error, `2` usage, `3` update partially failed (old lists kept).
`doctor` exits `1` when it finds a failure.

## Features

| Feature | Default | Notes |
|---|---|---|
| `bogons` category | on | IANA special-purpose IPv4/IPv6 space (RFC 1918, CGNAT, link-local, documentation, benchmarking, multicast, reserved 240/4, ULA, ...) |
| `abuse` category | on | curated ranges of report senders / honeypots (`lists/abuse-v4.txt`; see the risky entries in [lists/SOURCES.md](lists/SOURCES.md)) |
| `spamhaus` category | off | Spamhaus DROP (hijacked/criminal netblocks), fetched from spamhaus.org |
| `feodo` category | off | abuse.ch Feodo Tracker botnet C2 IPs (IPv4) |
| Country blocking | off | `geo add ir` (any ISO code), built from RIR delegation data |
| `smtp` module | off | blocks outbound TCP 25 (`SMTP_PORTS` to add 465/587) |
| `ports` module | off | blocks outbound TCP 23,135,139,445 and UDP 137,138 |
| `scanguard` module | off | drops new connections when a port gets > 60 new destinations/min or a host > 30 new ports/min (80/443/53/853 exempt) |
| `forward` module | off | also protect Docker containers, WireGuard/OpenVPN clients, NAT |
| `logging` | on | rate-limited kernel log with the sending UID → `abuse-defender hits` |
| `hosts` | on | sinkholes `appclick.co`, `pushnotificationws.com` (+ your own) in `/etc/hosts` |
| Monitor mode | off | `mode monitor`: count and log (`AD-MON`) what would be dropped, drop nothing |
| IP family | both | see the table below |
| Auto updates | daily | systemd timer (or cron) with random delay, mirrors, checksums |
| Doctor | - | read-only diagnosis: backend and kernel features, conflicts, gateway/DNS/mirrors, timers, stale lists |
| Export / import | - | config, whitelist, custom blocks and extra domains in one archive |

Settings live in `/etc/abuse-defender/abuse-defender.conf` (documented, every key
validated, never executed). After editing it by hand run `abuse-defender apply`.

### Try before enforcing: monitor mode

```bash
abuse-defender mode monitor     # nothing is dropped; matches are counted and logged as AD-MON
abuse-defender hits             # which destinations/ports/users would have been blocked
abuse-defender mode enforce     # when you are happy
```

Logging needs `LOG_BLOCKED=yes` (default) and kernel support; otherwise only the
per-category counters in `status` are available.

### IP family modes

| `IP_FAMILY` | What is filtered | Not supported / caveats |
|---|---|---|
| `both` (default) | IPv4, and IPv6 when the host has working IPv6 | On a host without IPv6 it silently runs as IPv4 only (shown in the status line). With nftables, IPv6 needs the `inet` table family; very old kernels fall back to IPv4 only. |
| `4` | IPv4 only | IPv6 traffic is not filtered at all, including misrouted IPv6 to ULA/documentation space. |
| `6` | IPv6 only | IPv4 traffic is not filtered at all. Refused on a host without working IPv6. The `feodo` category has no IPv6 data and the `abuse` list currently has no IPv6 entries, so only bogons, custom blocks, Spamhaus v6, country v6 and the port modules apply. |

The scan guard works for IPv4 and IPv6 with nftables or ipset; with plain iptables it
is skipped for both families.

## How it keeps you safe (lock-out protection)

Blocking private ranges blindly can cut a server off from its own gateway, DNS or
metadata service, or drop the replies of your SSH session. Abuse Defender prevents that:

- **Only the uplink is filtered** - interfaces with a default route. Docker bridges,
  WireGuard, Tailscale and private VLANs are not touched.
- **Replies always pass** (`ESTABLISHED,RELATED`), as do DHCP and IPv6 neighbour
  discovery. Link-local and multicast IPv6 can never be blocked.
- **Auto-whitelist**: default gateways (e.g. Hetzner `172.31.1.1`), DNS resolvers
  (including systemd-resolved upstreams), cloud metadata/DNS/NTP endpoints (AWS, GCP,
  Azure, Oracle, Alibaba, DigitalOcean, ...), directly connected subnets, and the IPs of
  connected SSH clients. `abuse-defender status` lists every auto-whitelisted address.
- **Atomic changes**: rules are built completely, checked (`nft -c` /
  `iptables-restore --test`) and loaded in one transaction. A failed download never
  removes protection; the last good list is kept.
- **Self-test + rollback**: connectivity (HTTPS, TCP, DNS, gateway) is tested before and
  after every change; if something that worked stops working, the previous rules come
  back automatically. In the menu you must type `yes` within 60 s from a **new** SSH
  session, otherwise (or on Ctrl+C / lost connection) the rules and the changed setting
  both roll back.
- **Coexists** with ufw, firewalld, Docker, netfilter-persistent: own nftables table
  (or own chains/ipsets), never a global flush; a 15-minute check re-applies the rules
  if another tool removed them.

Details: [docs/DESIGN.md](docs/DESIGN.md).

## FAQ

**My provider's DNS/gateway is in 10.x / 100.64.x / 172.16.x - will it break?**
No. Gateways, resolvers from `/etc/resolv.conf`/systemd-resolved and known cloud
endpoints are whitelisted automatically. For any other internal service run
`abuse-defender whitelist <ip-or-cidr>`.

**Docker / Kubernetes?** Containers talking to each other or to the host are not
affected (not the uplink). Containers' internet traffic is *forwarded*, not output -
enable `abuse-defender module forward on` to filter it too. The same applies to
WireGuard/OpenVPN servers that NAT their clients.

**Tailscale / ZeroTier / WireGuard (100.64.0.0/10, 10.x)?** Traffic inside the tunnel
uses the tunnel interface and is not filtered. If you set `EGRESS_INTERFACES=all`, also
whitelist the overlay subnet.

**Which backend is used?** nftables when available (Debian 10+, Ubuntu 20.04+, RHEL 8+,
Fedora, Arch, Alpine), otherwise ipset + iptables, otherwise plain iptables (OpenVZ/LXC).
Force one with `abuse-defender set BACKEND nft|ipset|iptables` or `--backend=`.
`abuse-defender doctor` shows what works on your kernel.

**Xray/V2Ray?** Abuse Defender works in the kernel for every process. Add Xray routing
rules as a second layer: [docs/xray-routing.md](docs/xray-routing.md).

**Torrents?** Not reliably blockable by IP/port. Use Xray's `"protocol": ["bittorrent"]`
routing rule (see the Xray document) and the scan guard.

**Busy proxy - conntrack table full?** `status` and `doctor` warn above 70 % of
`nf_conntrack_max`; raise `net.netfilter.nf_conntrack_max` or set `STATEFUL=no`.

**Without systemd?** A file in `/etc/cron.d` is used; on Alpine/OpenRC `/etc/periodic`
and `/etc/local.d` (run `rc-update add local default`).

## Uninstall

```bash
abuse-defender uninstall          # asks for confirmation
abuse-defender uninstall --yes    # non-interactive; --keep-config keeps /etc/abuse-defender
```

Removes rules, chains, sets, the nftables table, systemd units/cron jobs, the hosts
block, the installed script, state, log and settings (and any v1 leftovers).

## Contributing / reporting ranges

See [CONTRIBUTING.md](CONTRIBUTING.md). Send ranges with evidence via
[Telegram](https://t.me/Kiya6955Contactbot); news on the
[channel](https://t.me/savechannelkiya6955). Security issues: [SECURITY.md](SECURITY.md).
Changes: [CHANGELOG.md](CHANGELOG.md). List sources: [lists/SOURCES.md](lists/SOURCES.md).
