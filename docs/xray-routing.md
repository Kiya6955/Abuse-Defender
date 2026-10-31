# Xray / V2Ray routing: the application-level complement

Abuse Defender works in the **kernel** (nftables/iptables): every packet that leaves the
server's uplink is checked, no matter which program sent it - Xray, a panel, a cron job,
a compromised PHP script. Xray `routing` works inside **Xray**: it sees the domain
(after sniffing) and the protocol of each proxied connection, and can close it before
any packet is sent. Use both:

| | Abuse Defender (kernel) | Xray routing (application) |
|---|---|---|
| Covers | all processes on the host (+ Docker/VPN with `APPLY_FORWARD=yes`) | only traffic proxied by Xray |
| Matches | destination IP/port, scan behaviour | IP, domain, port, sniffed protocol (BitTorrent) |
| Feedback to the client | packet silently dropped (connection times out) | connection closed immediately |

### Example configuration

Verified against the current Xray-core documentation
(https://xtls.github.io/en/config/routing.html and
https://xtls.github.io/en/config/outbounds/blackhole.html, Xray-docs-next main branch,
checked 2026-10-31). Merge the relevant parts into your existing config.

```json
{
  "inbounds": [
    {
      "tag": "in",
      "port": 443,
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "ip": ["geoip:private"], "outboundTag": "block" },
      { "protocol": ["bittorrent"], "outboundTag": "block" },
      { "port": "25", "outboundTag": "block" },
      { "domain": ["geosite:category-ir"], "outboundTag": "block" },
      { "ip": ["geoip:ir"], "outboundTag": "block" }
    ]
  }
}
```

Notes:

* The **first** outbound is the default, so `direct` must stay first.
* `protocol: ["bittorrent"]` only works when **sniffing is enabled** on the inbound.
  BitTorrent detection is best-effort; encrypted BitTorrent is not recognised. That is
  why Abuse Defender does not try to block torrents by port (ports are arbitrary) and
  the scan guard module limits the *pattern* that gets reported instead.
* `geoip:private` covers RFC 1918, CGNAT, link-local, loopback etc. - the same idea as
  Abuse Defender's `bogons` category.
* `port` accepts a number or a string such as `"25,465,587"` or ranges `"1000-2000"`.
  Blocking 465/587 also blocks legitimate mail clients of your users; port 25 is the
  one that gets abuse reports.
* `geoip:ir` in the geoip.dat shipped with current Xray releases (XTLS/Xray-rules-dat,
  "Lite" edition) is an alias of `in-ir`, a list designed for "direct connection from
  Iran" use, **not** strict geolocation. If you need strict country data use a full
  geoip file, or use Abuse Defender's `geo add ir`, which is built from the RIR
  delegation statistics.
* Since Xray-core v25.8 (commit of 2025-08-16) the `"type": "field"` key and
  `routing.domainMatcher` were removed. **Older cores** (some panels still bundle them)
  require `"type": "field"` in every rule - add it if your Xray is older.
* `domainStrategy: "IPIfNonMatch"` resolves a domain to IP only when no domain rule
  matched, so the `geoip:` rules also catch domains that point to private/IR addresses.
