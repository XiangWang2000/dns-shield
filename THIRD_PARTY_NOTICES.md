# Third-party data notices

## 1Hosts Lite

DNS Shield packages a deterministic hashed representation of the 1Hosts Lite DNS blocklist.

- Project: `badmojr/1Hosts`
- Source revision: `273a6bcdcc3585bc47f1ebb6823db05ec5b7b409`
- Source file: `Lite/domains.wildcards`
- Source URL: <https://raw.githubusercontent.com/badmojr/1Hosts/273a6bcdcc3585bc47f1ebb6823db05ec5b7b409/Lite/domains.wildcards>
- Source SHA-256: `a3e143b2fcddd38fa5a9095548d176391b1cc791135b4248b3d1c9ebaa253634`
- License: Mozilla Public License 2.0
- License text: [third_party/licenses/1Hosts-MPL-2.0.txt](third_party/licenses/1Hosts-MPL-2.0.txt)

DNS Shield's `active.bin` is generated from that exact source using `tools/build_blocklist.py`. It contains sorted FNV-1a 64-bit hashes rather than readable domain strings. The preparation and verification manifests preserve the corresponding source and artifact identities.
