# Domain blocking policy

DNS Shield keeps domain policy separate from the VPN lifecycle so precedence and matcher behavior can be tested without opening a tunnel.

## Decision order

`CompositeDomainMatcher` applies this order:

1. Normalize the queried domain with `lowercase().trim()`.
2. Allow blank and `unknown` values without invoking policy components.
3. Check `DomainAllowlist`; an allowlist hit bypasses every blocker.
4. Ask each `DomainMatcher` in order and stop at the first blocking result.
5. Allow the domain when no blocker matches.

The service-level `blockDecisionCache` remains outside this composition and caches the final policy decision using both the normalized domain and the exact published policy assembly.

## Current allowlist semantics

`ExactDomainAllowlist` matches only the normalized domain stored in the set. Allowing `example.com` does not allow `sub.example.com`, `lookalike-example.com`, or any parent domain.

This conservative behavior is intentional. Parent-domain traversal, Public Suffix safeguards, user-managed persistence, and policy replacement must be designed and tested separately.

## Policy assembly and fallback

`DomainPolicyAssembler` always includes `BuiltInDomainMatcher`. When a compiled blocklist file is configured, the assembler loads and validates it before adding `CompiledBlocklistMatcher` after the built-in matcher.

The assembly result exposes one of three states:

- `NotConfigured`: no compiled blocklist was requested; built-in rules remain active.
- `Loaded(entryCount)`: the compiled blocklist was validated and joined to the policy.
- `Rejected(reason)`: loading or validation failed; the optional compiled matcher is omitted and built-in rules remain active.

The assembler catches recoverable `Exception` failures only. Fatal JVM errors are not converted into fallback states. A rejected optional list is logged for diagnostics and never disables built-in DNS protection.

## Runtime blocklist source

`RuntimeDomainPolicy` reserves one app-private candidate path:

```text
<filesDir>/blocklists/active.bin
```

When that path does not exist, the optional compiled blocklist is treated as `NotConfigured` and the file loader is not called. When the path exists, it is passed to `DomainPolicyAssembler`; empty, malformed, unreadable, non-file, and unsorted artifacts are therefore surfaced as `Rejected` rather than silently ignored.

The runtime source does not create directories, copy a bundled asset, download a list, or replace files.

## Atomic policy publication

`ReloadableDomainPolicy` stores one complete `DomainPolicyAssembly` in an atomic reference. DNS readers therefore observe either the previous matcher and status or the replacement matcher and status; they never observe a partially updated policy.

`DnsVpnService` assembles and installs runtime policy on each tunnel start, including starts reached through `ACTION_RESTART`. The installation callback clears DNS responses, in-flight requests, and block decisions before the replacement assembly is published. Missing or rejected artifacts still publish a built-in-only fallback assembly.

Every DNS query snapshots the same `DomainPolicyAssembly` used for its block decision. DNS cache keys, in-flight keys, block-decision keys, and current-state checks use assembly identity, so a query that started under an old policy cannot populate or satisfy cache entries for a newer publication. Resolver changes remain separated by their resolver generation.

Installers are serialized, while domain lookups remain lock-free and delegate through the snapshot matcher.

## Current scope

Runtime policy is now wired into `DnsVpnService`, but the repository still does not include a production blocklist, bundled asset, remote update flow, atomic file replacement, UI, user-managed allowlist, or Room schema change. With no `active.bin` present, shipped behavior remains the existing built-in matcher only.
