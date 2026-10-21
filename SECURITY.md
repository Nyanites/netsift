# Security policy

NetSift parses traffic from networks that may be hostile, so we treat any problem reading
a packet or capture file as a security issue.

## Reporting a vulnerability

Please **don't open a public issue**. Report it privately through GitHub instead:
**Security → Report a vulnerability** on this repository.

Include your NetSift version, your operating system, what you did and, if you can, a capture
that reproduces the problem. Please remove anything sensitive first; never send a key log
for traffic that isn't yours to share.

We aim to reply within a few days and to fix confirmed issues in the next release.

## How NetSift protects you

- **Captures are only read.** NetSift never sends, replays or modifies traffic.
- **Hostile packets are contained.** Every dissector is bounds-checked, and the parsers for
  TLS, QUIC, HTTP/2, HPACK and QPACK are fuzzed with random and mutated traffic. A packet
  that can't be read is marked malformed; the rest of the capture still loads.
- **Nothing leaves your machine.** No telemetry, no account, no update pings. The only
  network traffic NetSift causes is a browser you launch yourself from the 🔑 menu.
- **Key logs stay local.** TLS secrets are read from the file you choose and never copied
  anywhere. Treat key logs like passwords: anyone with one can decrypt that traffic.
- **Least privilege.** Live capture uses your operating system's packet capture permissions
  (the `access_bpf` group on macOS, `CAP_NET_RAW` on Linux); NetSift never asks for root.
- **Releases are verified.** Releases are built by GitHub Actions from the public source and
  published with SHA-256 checksums and signed build provenance; the installer checks the
  checksum before installing.
