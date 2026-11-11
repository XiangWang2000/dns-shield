# Third-party data notices

DNS Shield 1.5.0 packages a compiled domain blocklist derived from 1Hosts Lite and AdGuard DNS Filter. The application source is licensed separately under [Apache License 2.0](LICENSE).

## 1Hosts Lite

- Project: `badmojr/1Hosts`
- Source revision: `7a4588e87bcf7e86e0b8169d391b8422bd3c5d36`
- Source date: `2026-09-03`
- Source file: `Lite/domains.wildcards`
- Source URL: <https://raw.githubusercontent.com/badmojr/1Hosts/7a4588e87bcf7e86e0b8169d391b8422bd3c5d36/Lite/domains.wildcards>
- Source SHA-256: `6d6e4a087e501696b2996b888fd220590335b6bfc2ee375046abe74b95b45d9f`
- License: Mozilla Public License 2.0
- License text: [1Hosts MPL 2.0](third_party/licenses/1Hosts-MPL-2.0.txt)

## AdGuard DNS Filter

- Project: `AdguardTeam/AdGuardSDNSFilter`
- Source revision: `bef5669f914c1d2419e732feeefde79fcdca0eab`
- Source date: `2026-11-05`
- Source file: `Filters/filter.txt`
- Source URL: <https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/bef5669f914c1d2419e732feeefde79fcdca0eab/Filters/filter.txt>
- Source SHA-256: `2bfb2cb0e71439de8d0cbbd44cb91716561d6ef7592026ea5d26718b19400ee3`
- License: GNU General Public License version 3
- License text: [AdGuard DNS Filter GPL 3.0](third_party/licenses/AdGuard-DNS-Filter-GPL-3.0.txt)

## Combined blocklist and source

On 2026-11-11, DNS Shield combined these snapshots by taking simple AdGuard domain block rules and applying simple AdGuard exceptions to the added domains. The merge excludes AdGuard additions already covered by the 1Hosts Lite input or the built-in matcher. Advanced AdGuard rules are outside the merge. The resulting `active.bin` stores 247,497 sorted FNV-1a 64-bit domain hashes.

The combined blocklist data is distributed under GNU GPL version 3. The original 1Hosts Lite input is available under MPL 2.0 and is additionally provided under GPL version 3 for use in the combined blocklist under MPL 2.0 section 3.3.

Download `blocklist-source.zip` next to the APK on the matching [GitHub release](https://github.com/XiangWang2000/dns-shield/releases). It contains the unmodified pinned inputs, the canonical merged domain text, build tools, manifests, and license texts. The source and artifact contracts are [active_blocklist_source.json](tools/active_blocklist_source.json) and [active_blocklist_production.json](tools/active_blocklist_production.json).
