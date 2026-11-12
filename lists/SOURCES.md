# List sources and rationale

Every entry in this directory must be traceable to a primary or reputable source.
Nothing is added from guesswork. Facts below were checked on **2026-10-31**.

| File | Category | Maintained how |
|---|---|---|
| `bogons-v4.txt`, `bogons-v6.txt` | `bogons` (default on) | curated |
| `abuse-v4.txt`, `abuse-v6.txt` | `abuse` (default on) | curated by the maintainer |
| `cloud-allow-v4.txt`, `cloud-allow-v6.txt` | always-allowed infrastructure | curated |
| `domains.txt` | hosts sinkhole | curated |
| `geo/<cc>-v4.txt`, `geo/<cc>-v6.txt` | `geo add <cc>` | `tools/build-lists.sh --geo` (weekly CI) |
| `SHA256SUMS` | integrity of every published file | `tools/build-lists.sh` |
| `../abuse-ips.ipv4` | legacy list for v1 installs | `tools/build-lists.sh` |

## ⚠ Risky entries - review before relying on them

These maintainer-curated entries in `abuse-v4.txt` are kept unchanged, but they block
**live, legitimate networks**. If your users need any of these destinations, either
whitelist the specific range (`abuse-defender whitelist <cidr>`) or turn the whole
category off (`abuse-defender category abuse off`).

| Entry | What it is (RIR/RIPEstat, 2026-10-31) | Collateral risk |
|---|---|---|
| **102.0.0.0/8** | An entire AFRINIC /8: about 89 % allocated/assigned, at least 51 % routed by African ISPs (Telecom Egypt AS8452, Maroc Telecom AS6713, MTN Nigeria AS29465, Airtel Kenya AS36926, Telkom SA AS5713, ...) | **Very high** - blocks a large part of Africa's eyeball and business networks |
| **195.137.167.0/24** | Beh Pardakht Mellat, an Iranian payment processor (AS210695), routed | **High** - breaks Iranian payment gateways (shops, WHMCS) running on or through the server |
| **25.0.0.0/8** | UK Ministry of Defence legacy block; the /8 is unrouted but four more-specifics with "NCSC" netnames are announced by AS209242 | **Medium** - also used as overlay address space by LogMeIn Hamachi (secondary source only) |
| **216.218.185.0/24** | Hurricane Electric address space (ARIN), routed inside 216.218.128.0/17 by AS6939 | **Medium/unknown** - hosting/transit customers may sit here; purpose of this /24 not verifiable |
| **206.191.152.0/24** | Internap / SingleHop hosting (ARIN), routed as 206.191.152.0/23 by AS32475 | **Medium/unknown** - hosted customers may sit here; purpose of this /24 not verifiable |

## bogons

* IANA IPv4 Special-Purpose Address Registry:
  https://www.iana.org/assignments/iana-ipv4-special-registry/ (CSV:
  `iana-ipv4-special-registry-1.csv`). Every prefix with *Globally Reachable = False*
  is listed, except `127.0.0.0/8` (loopback never leaves the host; the validator
  refuses it). `0.0.0.0/8` was **added** (missing in v1).
* IANA IPv4 Address Space Registry: https://www.iana.org/assignments/ipv4-address-space/
  - `240/8`..`255/8` are "Reserved - Future use" → `240.0.0.0/4` **replaces** v1's
  `240.0.0.0/24` (which covered only 1/4096 of the reserved space).
* `233.252.0.0/24` (MCAST-TEST-NET, RFC 6676) from v1 is kept as a comment only: it is
  inside `224.0.0.0/4`. v1's copy also contained a stray TAB.
* Globally reachable special-purpose prefixes (`192.0.0.9/32`, `192.0.0.10/32`,
  `192.31.196.0/24` AS112, `192.52.193.0/24` AMT, `192.175.48.0/24`) are **not** blocked,
  except the first two which sit inside `192.0.0.0/24` that v1 already blocked (no
  server uses PCP/TURN anycast).
* IPv6: IANA IPv6 Special-Purpose Address Registry
  https://www.iana.org/assignments/iana-ipv6-special-registry/ . Listed: `::/128`,
  `::ffff:0:0/96`, `100::/64`, `100:0:0:1::/64` (RFC 9780), `2001:2::/48`,
  `2001:10::/28`, `2001:db8::/32`, `3fff::/20` (RFC 9637), `5f00::/16` (RFC 9602),
  `fc00::/7`. Not listed (and refused by the validator where noted): `::1` (refused),
  `fe80::/10` (refused - link-local gateways, NDP), `ff00::/8` (refused - NDP/MLD),
  `64:ff9b::/96` (globally reachable NAT64), `64:ff9b:1::/48` (provider NAT64 on
  IPv6-only VPS), Teredo/6to4 and all globally reachable assignments.

Cloud caveats (handled by the auto-whitelist, see README "FAQ"):
`169.254.0.0/16` holds every major cloud's metadata service; `100.64.0.0/10` holds
Alibaba Cloud metadata and DNS; `172.16.0.0/12` holds Hetzner Cloud's gateway
`172.31.1.1` and Docker bridges; `10.0.0.0/8` holds AWS VPC resolvers (VPC+2) and Oracle
Cloud subnets; `fc00::/7` holds AWS `fd00:ec2::/…` and GCP `fd20:ce::254` endpoints.

## cloud-allow

| Address | Use | Source |
|---|---|---|
| 169.254.169.254 | AWS IMDS | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html |
| fd00:ec2::254 | AWS IMDS (IPv6, Nitro) | same |
| 169.254.169.123, fd00:ec2::123 | AWS Time Sync | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configure-ec2-ntp.html |
| 169.254.169.253, fd00:ec2::253 | AWS Route 53 Resolver | https://docs.aws.amazon.com/vpc/latest/userguide/AmazonDNS-concepts.html |
| 169.254.169.254, fd20:ce::254 | Google Compute Engine metadata | https://docs.cloud.google.com/compute/docs/metadata/querying-metadata |
| 169.254.169.254 | Azure IMDS | https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service |
| 169.254.169.254 | Oracle Cloud IMDS and VCN resolver | https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm , https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/dns.htm |
| 100.100.100.200 | Alibaba Cloud ECS metadata | https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata |
| 100.100.2.136, 100.100.2.138 | Alibaba Cloud default DNS | https://www.alibabacloud.com/help/en/vpc/user-guide/overview-5 |
| 169.254.169.254 | DigitalOcean metadata | https://docs.digitalocean.com/products/droplets/how-to/retrieve-droplet-metadata/ |

Azure's `168.63.129.16` is public address space (not blocked by any list), so it needs
no entry. Hetzner Cloud's gateway `172.31.1.1`
(https://docs.hetzner.com/cloud/servers/static-configuration/) is covered by default
gateway detection. Tencent Cloud documents only a hostname for its metadata service,
so no IP is listed.

## abuse (curated by the maintainer)

Ownership/routing checked with RIR RDAP (https://rdap.org/) and RIPEstat
(https://stat.ripe.net/, `prefix-overview`, `routing-status`, `routing-history`).

| Entry | Owner (RIR) | Routed on 2026-10-31 | Notes |
|---|---|---|---|
| 25.0.0.0/8 | UK Ministry of Defence, legacy (RIPE) | /8 not announced; 25.25.25.0/24, 25.26.27.0/24, 25.129.196.0/23, 25.129.198.0/23 announced by AS209242 (netnames "NCSC") | LogMeIn Hamachi also assigns 25.x addresses (not verified from a primary source) |
| 45.14.174.0/24 | CloudKleyer Frankfurt (RIPE) | no (AS209242 until 2024-07) | |
| 102.0.0.0/8 | AFRINIC | ~89 % allocated/assigned, ≥51 % routed (AS8452, AS6713, AS29465, AS36926, AS5713, …) | **heavy collateral: blocks large parts of Africa** |
| 103.29.38.0/24 | Shyam Spectra (APNIC, IN) | no | |
| 103.49.99.0/24 | Beijing Zhong Bang Telecom (APNIC, CN) | no (AS4808 until 2020) | |
| 103.58.50.0/24, 103.58.82.0/24 | National Informatics Centre Services (APNIC, IN) | no (AS9829 until 2019/2020) | |
| 114.208.187.0/24 | China TieTong (APNIC, CN) | no | |
| 185.235.86.0/24, 185.235.87.0/24 | Criteo Europe infra (RIPE) | no (AS44788 until 2025-10) | aggregated to /23 |
| 195.130.0.0/19 | UK Ministry of Defence, UK-MOD-960823 (RIPE) | 195.130.3/6/11-15.0/24 announced by AS2856 (BT) | see AS203665 below |
| 195.137.167.0/24 | Beh Pardakht Mellat (RIPE, IR), AS210695 | yes | **Iranian payment processor - blocks a payment gateway** |
| 206.191.152.0/24 | Internap / SingleHop (ARIN) | yes, in 206.191.152.0/23 (AS32475) | purpose of this /24 not verifiable |
| 216.218.185.0/24 | Hurricane Electric (ARIN) | yes, in 216.218.128.0/17 (AS6939) | purpose of this /24 not verifiable |

**AS203665**: RIPE RDAP (https://rdap.db.ripe.net/autnum/203665) - "UKMOD", UK Ministry of
Defence. RIPEstat shows it has never originated a prefix. v1's commit "add AS203665"
added seven pieces of `195.130.0.0/19` (`195.130.0.0/23`, `.2.0/24`, `.4.0/23`, `.7.0/24`,
`.8.0/23`, `.10.0/24`, `.16.0/20`), all of which are unrouted, while the MoD prefixes that
*are* routed (`195.130.3.0/24`, `.6.0/24`, `.11-15.0/24`, via BT AS2856) were missing.
The whole allocation `195.130.0.0/19` (RIPE inetnum UK-MOD-960823) is now listed, which
covers both.

## Optional threat feeds (fetched from their origin at update time, never re-hosted)

| Category | URL | Format | Terms |
|---|---|---|---|
| `spamhaus` | https://www.spamhaus.org/drop/drop_v4.json (fallback `drop.txt`), https://www.spamhaus.org/drop/drop_v6.json | NDJSON `{"cidr":...}` / `CIDR ; SBLnnn` | https://www.spamhaus.org/drop/terms/ - free for use in firewalls, no redistribution licence → not re-hosted in this repo. EDROP is merged into DROP; `drop_v6.txt` no longer exists |
| `feodo` | https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt | one IP per line, `#` comments | https://abuse.ch/terms-of-use/ (CC0). Currently only a handful of entries |

Not included: Emerging Threats `compromised-ips.txt` - the licence covering that file
could not be verified, and listing changing compromised hosts is a poor fit for an
outbound filter.

## geo (country lists)

Built by `tools/build-lists.sh --geo` from the five RIR *delegated-extended* statistics
files (records with status `allocated` or `assigned`):

* https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
* https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
* https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest
* https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest
* https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest

For countries not pre-built here the client falls back to
https://github.com/ipverse/country-ip-blocks (CC0, same RIR data) and then to
https://www.ipdeny.com/ (redistribution permitted per https://www.ipdeny.com/copyright.php).
Note that RIR data says where a block is *registered*, not where it is used.

## domains

`appclick.co`, `pushnotificationws.com`: carried over unchanged from v1 (maintainer's list).
