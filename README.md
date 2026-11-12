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

It adds **outbound DROP rules only** - it never blocks incoming traffic and never touches
firewall rules it did not create. IPv4 is always protected; IPv6 is protected
automatically when the server has working IPv6 and skipped safely when it does not.

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
Protected: YES | backend: nft/inet | IPv6: yes | updated: 2026-10-31 12:00 (ok) | timer: systemd update:active ensure:active

 Protection
   1) Install / re-apply protection
   2) Update lists now
   3) Status and counters
   4) Disable protection (keeps settings)
   5) Doctor (diagnose problems)
   6) Preview rules without applying (dry-run)
 Allow and block
   7) Whitelist an IP/range            8) Remove a whitelisted IP/range
   9) Block an IP/range               10) Unblock an IP/range
 Settings
  11) Block categories               12) Country blocking
  13) Optional modules
 Tools
  14) Blocked-connections log        15) Show settings
  16) Export / import settings       17) Uninstall completely
   0) Exit
```

- **1** installs, or re-applies after you edited files by hand.
- **4** switches between *Disable protection* (removes every rule, keeps all settings)
  and *Enable protection*. Use it if you want the server unprotected for a while.
- **5** checks the backend, kernel features, conflicts (ufw, firewalld, Docker),
  gateway/DNS/mirror reachability, timers and list freshness.
- **6** shows exactly which rules would be loaded, without changing anything.
- **11-13** turn categories, countries and modules on and off; every change is applied
  with the self-test and the keep-rules prompt.
- **15** prints all effective settings (read-only).

Every input is validated and asked again if it is wrong; Ctrl+C at any point leaves the
server in a consistent state (unconfirmed changes are rolled back).

## Commands (for scripts and automation)

```bash
abuse-defender install --yes            # install/upgrade without questions
abuse-defender status                   # protection, counters, auto-whitelist
abuse-defender doctor                   # diagnose backend, conflicts, network, timers, lists
abuse-defender update                   # fetch lists now (the timer does this daily)
abuse-defender disable                  # remove all rules, keep settings
abuse-defender enable
abuse-defender whitelist 10.8.0.0/16    # never block this (e.g. your VPN subnet)
abuse-defender unwhitelist 10.8.0.0/16
abuse-defender block 203.0.113.0/24     # always block this
abuse-defender unblock 203.0.113.0/24
abuse-defender category spamhaus on     # bogons | abuse | spamhaus | feodo
abuse-defender module smtp on           # smtp ports scanguard forward logging hosts ...
abuse-defender --yes geo add ir         # block outbound traffic to a country
abuse-defender geo remove ir
abuse-defender hits                     # who/what was blocked (kernel log)
abuse-defender --dry-run apply          # show the rules without applying them
abuse-defender config                   # print all settings
abuse-defender export | import FILE     # save / load your settings
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
| Country blocking | off | `geo add <cc>`, asks for confirmation, refuses countries that contain your gateway/DNS/SSH client (see below) |
| `smtp` module | off | blocks outbound TCP 25 (`SMTP_PORTS` in the config file to add 465/587) |
| `ports` module | off | blocks outbound TCP 23,135,139,445 and UDP 137,138 |
| `scanguard` module | off | drops new connections when a port gets > 60 new destinations/min or a host > 30 new ports/min (80/443/53/853 exempt) |
| `forward` module | off | also protect Docker containers, WireGuard/OpenVPN clients, NAT |
| `logging` | on | rate-limited kernel log with the sending UID → `abuse-defender hits` |
| `hosts` | on | sinkholes `appclick.co`, `pushnotificationws.com` (+ your own) in `/etc/hosts` |
| IPv6 | automatic | filtered when the host has working IPv6 and the backend supports it, skipped otherwise |
| Auto updates | daily | systemd timer (or cron) with random delay, mirrors, checksums |
| Doctor | - | read-only diagnosis: backend and kernel features, conflicts, gateway/DNS/mirrors, timers, stale lists |
| Export / import | - | config, whitelist, custom blocks and extra domains in one archive |

Settings live in `/etc/abuse-defender/abuse-defender.conf` (documented, every key
validated, never executed). After editing the file by hand run `abuse-defender apply`.

### Country blocking

`abuse-defender geo add <cc>` (menu 12) blocks **all** outbound traffic to a country:

- **Data**: only `ir` (Iran) is pre-built in this repository (`lists/geo/`, rebuilt weekly
  from the five RIR delegation files). Any other ISO code is fetched on demand: first
  from this repository (if it is ever added there), then from
  [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks) (also built
  from RIR delegation data), then from [ipdeny.com](https://www.ipdeny.com/). Every
  download goes through the same validation as the other lists.
- **Confirmation**: before anything changes it shows the number of IPv4/IPv6 prefixes
  and that services hosted in that country become unreachable, and asks (menu) or
  requires `--yes` (CLI).
- **Self-protection**: it refuses a country whose prefixes contain your default
  gateway, a DNS resolver or the IP of a connected SSH client, and says which one.
  `--force` overrides this (not recommended; those addresses stay whitelisted anyway).
- **Download failure**: if no valid list can be downloaded for the code, nothing is
  enabled and the command fails with an error.

RIR data says where an address block is registered, not where it is used.

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

**Can I see the rules before they are applied?** Yes: menu 6 or
`abuse-defender --dry-run apply`. To run without protection for a while use
`abuse-defender disable` (menu 4); `enable` brings everything back.

**Docker / Kubernetes?** Containers talking to each other or to the host are not
affected (not the uplink). Containers' internet traffic is *forwarded*, not output -
enable `abuse-defender module forward on` to filter it too. The same applies to
WireGuard/OpenVPN servers that NAT their clients.

**Tailscale / ZeroTier / WireGuard (100.64.0.0/10, 10.x)?** Traffic inside the tunnel
uses the tunnel interface and is not filtered. If you set `EGRESS_INTERFACES=all` in the
config file, also whitelist the overlay subnet.

**My server has no IPv6.** Nothing to do: IPv6 rules are skipped automatically and the
status line shows `IPv6: no (not available)`.

**Which backend is used?** nftables when available (Debian 10+, Ubuntu 20.04+, RHEL 8+,
Fedora, Arch, Alpine), otherwise ipset + iptables, otherwise plain iptables (OpenVZ/LXC).
`abuse-defender doctor` shows what works on your kernel; `BACKEND=` in the config file
forces one.

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
abuse-defender uninstall          # asks for confirmation (menu 17)
abuse-defender uninstall --yes    # non-interactive; --keep-config keeps /etc/abuse-defender
```

Removes rules, chains, sets, the nftables table, systemd units/cron jobs, the hosts
block, the installed script, state, log and settings (and any v1 leftovers).

## Contributing / reporting ranges

See [CONTRIBUTING.md](CONTRIBUTING.md). Send ranges with evidence via
[Telegram](https://t.me/Kiya6955Contactbot); news on the
[channel](https://t.me/savechannelkiya6955). Security issues: [SECURITY.md](SECURITY.md).
Changes: [CHANGELOG.md](CHANGELOG.md). List sources: [lists/SOURCES.md](lists/SOURCES.md).
