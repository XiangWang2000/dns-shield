# Domain blocking policy

DNS Shield keeps domain policy separate from the VPN lifecycle so precedence and matcher behavior can be tested without opening a tunnel.

## Decision order

`CompositeDomainMatcher` applies this order:

1. Normalize the queried domain with `lowercase().trim()`.
2. Allow blank and `unknown` values without invoking policy components.
3. Check the Room-backed user rules; the most-specific match returns ALLOW or BLOCK before any other policy component.
4. Check `DomainAllowlist`; an allowlist hit bypasses every blocker.
5. Ask each `DomainMatcher` in order and stop at the first blocking result.
6. Allow the domain when no blocker matches.

The service-level `blockDecisionCache` remains outside this composition and caches the final policy decision using both the normalized domain and the exact published policy assembly.

## Exact allowlist semantics

`ExactDomainAllowlist` matches only the normalized domain stored in the set. Allowing `example.com` does not allow `sub.example.com`, `lookalike-example.com`, or any parent domain.

This exact-only component is separate from user rules, which can explicitly include subdomains and are described below.

## Room-backed user rules

The `user_domain_rules` Room table stores ALLOW or BLOCK rules with an exact-domain or include-subdomains scope. Rules are retained across app restarts. The unique key is `(domain, includeSubdomains)`, so a domain can have one rule for each scope. The UI asks for confirmation before changing the action of an existing rule with the same domain and scope; revision checks prevent a stale edit from replacing a newer rule.

User rules are normalized to lowercase ASCII domain names. A rule that includes subdomains must pass the Public Suffix List check, so a public suffix cannot be selected as a parent rule. The most-specific matching domain wins; for the same domain, an exact rule takes precedence over its include-subdomains rule for the apex. A matching ALLOW bypasses the exact allowlist and every blocker, while a matching BLOCK overrides them.

## Bounded parent-domain matching

`ParentDomainMatcher` extends an exact matcher without blindly walking to the top-level domain. It checks the queried name first, then asks a required `RegistrableDomainResolver` for the effective TLD plus one boundary and checks parents only through that boundary.

For `ads.api.example.co.uk`, a resolver result of `example.co.uk` permits these candidates:

```text
ads.api.example.co.uk
api.example.co.uk
example.co.uk
```

It never asks the exact matcher about `co.uk` or `uk`. The resolver contract applies both the ICANN and PRIVATE sections of the Public Suffix List so private suffixes such as `github.io` also remain protected.

A missing, blank, malformed, or unrelated resolver result keeps matching exact-only. `ParentDomainMatcher` has no unsafe fallback that assumes the last two labels are registrable.

`CompiledPublicSuffixList` implements the resolver contract from the deterministic production artifact packaged as `app/src/main/assets/public_suffix.bin`. The artifact identity is verified during routine repository verification and by a real-main-asset Android instrumentation test.

`DomainPolicyAssembler` applies bounded parent traversal only to a validated `CompiledBlocklistMatcher`. `BuiltInDomainMatcher` is not wrapped because its existing suffix, contains, and label behavior is intentionally preserved, and `CompositeDomainMatcher` is not wrapped so an exact allowlist entry cannot silently become a subdomain allowlist.

The registrable-domain resolver is supplied lazily. The provider is not invoked when no compiled blocklist is configured and is not invoked until a configured blocklist has loaded and passed sorted-artifact validation. If the resolver is unavailable or its provider throws a recoverable `Exception`, the validated compiled matcher remains active in exact-only mode.

## Policy assembly and fallback

`DomainPolicyAssembler` always includes `BuiltInDomainMatcher`. When a compiled blocklist file is configured, the assembler loads and validates it before adding the compiled matcher after the built-in matcher.

The assembly result exposes one of three compiled-blocklist states:

- `NotConfigured`: no compiled blocklist was requested; built-in rules remain active.
- `Loaded(entryCount)`: the compiled blocklist was validated and joined to the policy, either exact-only or parent-aware depending on resolver availability.
- `Rejected(reason)`: loading or validation failed; the optional compiled matcher is omitted and built-in rules remain active.

Compiled-blocklist loading catches recoverable `Exception` failures only. Fatal JVM errors are not converted into fallback states. Resolver-provider failures are isolated after blocklist validation, so they do not convert a valid compiled blocklist into `Rejected`.

## Runtime blocklist source

`RuntimeDomainPolicy` reserves one app-private candidate path:

```text
<filesDir>/blocklists/active.bin
```

In production, a missing private file selects the verified `active.bin` packaged in the APK. Direct callers that do not provide a bundled loader still receive `NotConfigured`, preserving the policy component's optional-source contract. When the private path exists, it takes precedence and is passed to `DomainPolicyAssembler`; empty, malformed, unreadable, non-file, and unsorted overrides are surfaced as `Rejected` rather than silently ignored, and they do not trigger Public Suffix loading.

The runtime source does not create directories, download a blocklist, or replace files. Production blocklist updates occur only through a reviewed APK release.

## Atomic policy publication

`ReloadableDomainPolicy` stores one complete `DomainPolicyAssembly` in an atomic reference. DNS readers therefore observe either the previous matcher and status or the replacement matcher and status; they never observe a partially updated policy.

`DnsVpnService` assembles and installs runtime policy on each tunnel start, including starts reached through `ACTION_RESTART`. It includes the current Room rule snapshot; saving or deleting a rule while the VPN is running requests a policy reload. One lazy `ProductionBlocklistAssetLoader` and one lazy `PublicSuffixResolverOwner` belong to the service instance. The production blocklist bytes and resolver are verified once and reused by later policy reloads in the same service lifecycle. With no valid compiled blocklist, the resolver owner is never touched.

The installation callback clears DNS responses, in-flight requests, and block decisions before the replacement assembly is published. Missing or rejected blocklists still publish a built-in-only fallback assembly. A Public Suffix load rejection keeps a valid compiled blocklist exact-only.

Every DNS query snapshots the same `DomainPolicyAssembly` used for its block decision. DNS cache keys, in-flight keys, block-decision keys, and current-state checks use assembly identity, so a query that started under an old policy cannot populate or satisfy cache entries for a newer publication. Upstream resolver changes remain separated by their resolver generation.

Installers are serialized, while domain lookups remain lock-free and delegate through the snapshot matcher.

## Current scope

The production APK packages a pinned, verified 247,497-entry compiled blocklist derived from 1Hosts Lite and simple AdGuard DNS Filter rules and the reviewed Public Suffix artifact used for bounded parent matching. The app includes a UI for Room-backed exact and include-subdomains ALLOW/BLOCK rules; the repository does not ship a runtime remote-update flow for the packaged blocklist. A private app-files `active.bin` remains an explicit local override; without one, the packaged production list is active by default.
