# Security policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems (for example a way
to inject commands through a list or config value, a lock-out scenario, or a way to
make the tool disable protection).

Report privately via:

- GitHub: *Security* tab → *Report a vulnerability* (private advisory), or
- Telegram: https://t.me/Kiya6955Contactbot

Include the version (`abuse-defender --version`), distribution, backend
(`abuse-defender status`) and steps to reproduce. You will get an answer as soon as the
maintainer can; fixes are released as a new version and noted in CHANGELOG.md.

## Scope and trust model

- The script runs as root. Everything it downloads (lists, checksums, the script itself
  for `install` / `self-update`) comes from this repository through HTTPS mirrors. The
  `SHA256SUMS` file protects against corrupted or inconsistent downloads, not against
  a compromised repository - review changes before running `self-update` on critical
  systems.
- Third-party feeds (Spamhaus, abuse.ch, ipverse, ipdeny) are parsed as data only:
  every line must be a valid CIDR, broad ranges and loopback/link-local/multicast are
  refused, and nothing from a feed is ever executed or interpolated into a shell command.
- The config file is parsed as `KEY="value"` with a per-key whitelist regex; it is never
  sourced.
- Settings archives (`import`) are only accepted if they contain nothing but the
  expected settings files, and every list in them passes validation.
