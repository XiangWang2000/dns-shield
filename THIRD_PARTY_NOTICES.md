# Third-party data notices

## 1Hosts Lite

DNS Shield packages a deterministic hashed representation of the 1Hosts Lite DNS blocklist.

- Project: `badmojr/1Hosts`
- Source revision: `7a4588e87bcf7e86e0b8169d391b8422bd3c5d36`
- Source date: `2026-09-03`
- Source file: `Lite/domains.wildcards`
- Source URL: <https://raw.githubusercontent.com/badmojr/1Hosts/7a4588e87bcf7e86e0b8169d391b8422bd3c5d36/Lite/domains.wildcards>
- Source SHA-256: `6d6e4a087e501696b2996b888fd220590335b6bfc2ee375046abe74b95b45d9f`
- License: Mozilla Public License 2.0
- License text: [third_party/licenses/1Hosts-MPL-2.0.txt](third_party/licenses/1Hosts-MPL-2.0.txt)

DNS Shield's `active.bin` is generated from that exact source using `tools/build_blocklist.py`. It contains sorted FNV-1a 64-bit hashes rather than readable domain strings. The preparation and verification manifests preserve the corresponding source and artifact identities.
