# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-31

Complete rewrite. The one-liner
`bash <(curl -s https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-defender.sh)`
still opens the menu.

### Added
- New interactive menu (main interface): header box, one-line status (protected,
  backend, IPv4/IPv6, mode, last update, timer), grouped sections, validated input with
  re-prompt, loop based, Ctrl+C safe. Every feature is reachable from it.
- Non-interactive CLI for scripts: `install update apply status doctor list block
  unblock whitelist unwhitelist category geo module family mode set config hits enable
  disable export import selftest self-update validate uninstall menu`, with `--yes
  --dry-run --quiet --force --family --backend --confirm-timeout --no-confirm`.
- nftables backend (own table `inet abuse_defender`), ipset backend and plain iptables
  fallback, chosen automatically after probing the running kernel.
- IPv6 protection (IANA IPv6 special-purpose bogons) that never touches link-local,
  multicast or neighbour discovery; `IP_FAMILY=both|4|6` (both / IPv4 only / IPv6 only).
- Monitor mode (`mode monitor`): count and log what would be blocked, drop nothing.
- `doctor`: read-only diagnosis of backend and kernel features, iptables-legacy/nft
  mix, ufw/firewalld/Docker, gateway/DNS/mirror reachability, timers, stale lists.
- `export` / `import` of settings (config, whitelist, custom blocks, extra domains).
- Safety net: established/related traffic, DHCP and ICMPv6 ND always pass; default
  gateways, DNS resolvers, cloud metadata endpoints, connected subnets and current SSH
  clients are auto-whitelisted and listed in `status`.
- Only uplink (default-route) interfaces are filtered; Docker bridges, WireGuard,
  Tailscale and private VLANs are left alone. Optional `forward` module for routed traffic.
- Connectivity self-test with automatic rollback, plus an interactive "type yes within
  60 s" confirmation backed by a detached watchdog. A rolled-back change also restores
  the settings that caused it.
- Config file `/etc/abuse-defender/abuse-defender.conf` (parsed, never executed),
  `whitelist.txt`, `custom-block.txt`, `domains.txt`.
- systemd boot unit + 15-minute ensure timer + daily update timer with random delay;
  cron and Alpine/OpenRC fallbacks.
- Mirror fallback (raw.githubusercontent.com, cdn/fastly/gcore.jsdelivr.net) with
  unreachable mirrors skipped, SHA256SUMS verification, strict list validation, shrink
  protection, last-known-good cache, built-in fallback lists, log file with logrotate.
- Optional modules: outbound SMTP block, scan-target port block, scan guard
  (rate-limits horizontal/vertical scan patterns), country blocking (`geo add ir`),
  Spamhaus DROP and abuse.ch Feodo categories, rate-limited logging with the sending
  UID and `abuse-defender hits`.
- docs/DESIGN.md, docs/xray-routing.md, tests with stubbed firewall tools (run in
  parallel, independent of the host), GitHub Actions (lint, tests, real-kernel job,
  weekly country-list refresh as a pull request).

### Changed
- Lists moved to `lists/` with comments and sources (`lists/SOURCES.md`, including a
  section that flags risky entries); `abuse-ips.ipv4` is now derived from them and stays
  v1-compatible.
- `240.0.0.0/24` → `240.0.0.0/4` (whole reserved block); `0.0.0.0/8` added to bogons.
- UK MoD entries (AS203665 commit) replaced by the full RIPE allocation `195.130.0.0/19`,
  which also covers the MoD prefixes that are actually routed.
- `/etc/hosts` entries live in one managed block (`127.0.0.1` and `::1`), no duplicates.
- The user interface is English only.

### Fixed
- Duplicate `/etc/hosts` lines on every run; recursion into the menu; unquoted
  variables; no input validation; `read` without `-r`.
- Updates flushed the chain before downloading, leaving the server unprotected (or
  unprotected forever when the download failed).
- "Clear rules" left chains and jumps behind; crontab could be wiped on error.
- Stray TAB in `233.252.0.0/24`.

### Upgrade notes (v1 → v2)
- Nothing to do: running the one-liner (or any `abuse-defender` command that changes
  settings) replaces a v1 setup automatically and prints what was done. The entries of
  `abuse-defender-custom` / `abuse-defender-whitelist` are imported into the new text
  files, the new rules are loaded **first**, then the v1 jumps/chains,
  `/root/abuse-defender-update.sh`, its crontab line (other lines are kept), the
  duplicated hosts lines and the abuse-defender lines in `/etc/iptables/rules.v4` are
  removed (a backup is kept in `/var/lib/abuse-defender/backup/`). If the new rules
  cannot be applied, the v1 rules are kept or restored unchanged.
- The chain name `abuse-defender` is reused by the iptables backends; the `-custom` and
  `-whitelist` chains no longer exist (replaced by sets).
- v1 servers that are never upgraded keep working: their cron script still downloads
  `abuse-ips.ipv4`, which remains a plain IPv4 CIDR list.

## [1.x]

Original menu script: blocked `abuse-ips.ipv4` with one iptables rule per range,
manual whitelist/block chains, iptables-persistent, optional cron update.
