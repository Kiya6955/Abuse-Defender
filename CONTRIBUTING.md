# Contributing

Thanks for helping! Contact: Telegram https://t.me/Kiya6955Contactbot ·
channel https://t.me/savechannelkiya6955

## Proposing an IP range

Ranges are only accepted with **evidence**. Send (Telegram or a pull request):

1. The CIDR(s), IPv4 or IPv6.
2. Why it triggers abuse reports - e.g. the abuse e-mail you received (remove your own
   IP/customer data), the honeypot/telescope operator's own documentation, or an
   RIR/IANA reference for reserved space.
3. Ownership: the RIR record (https://rdap.org/ip/<address>) and, if routed, the origin
   AS (https://stat.ripe.net/).

Please do not send ranges copied from unknown lists, whole providers or whole
countries (that is what the optional `geo` module is for).

In a pull request:

- edit `lists/abuse-v4.txt` / `lists/abuse-v6.txt` (one CIDR per line, a `#` comment
  with owner and reason), add the source to `lists/SOURCES.md`;
- keep `builtin_list()` in `abuse-defender.sh` in sync (the build checks this);
- run `tools/build-lists.sh` - it validates, aggregates and rebuilds
  `abuse-ips.ipv4` and `lists/SHA256SUMS`;
- **never** hand-edit `abuse-ips.ipv4`: old (v1) installs parse it with a plain shell
  loop, so it must stay a bare IPv4 CIDR list without comments, blank lines or tabs.

## Code changes

```bash
bash -n abuse-defender.sh
shellcheck -s bash abuse-defender.sh tools/build-lists.sh tests/run.sh tests/stubs/*
bash tests/run.sh               # fake root, stubbed iptables/nft/ipset; JOBS=N for parallelism
bash tools/build-lists.sh --check
```

Rules of thumb: quote everything, no `eval`, no sourcing of data files, every change to
the kernel must go through the bundle/apply/rollback path, and the tool must never
modify rules it did not create. Test idempotency (run twice) and `uninstall`.
