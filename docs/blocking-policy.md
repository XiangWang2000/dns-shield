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

This conservative behavior is intentional. User-managed persistence and any future parent-aware allowlist semantics remain separate reviewed policy changes.

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

`DnsVpnService` assembles and installs runtime policy on each tunnel start, including starts reached through `ACTION_RESTART`. One lazy `ProductionBlocklistAssetLoader` and one lazy `PublicSuffixResolverOwner` belong to the service instance. The production blocklist bytes and resolver are verified once and reused by later policy reloads in the same service lifecycle. With no valid compiled blocklist, the resolver owner is never touched.

The installation callback clears DNS responses, in-flight requests, and block decisions before the replacement assembly is published. Missing or rejected blocklists still publish a built-in-only fallback assembly. A Public Suffix load rejection keeps a valid compiled blocklist exact-only.

Every DNS query snapshots the same `DomainPolicyAssembly` used for its block decision. DNS cache keys, in-flight keys, block-decision keys, and current-state checks use assembly identity, so a query that started under an old policy cannot populate or satisfy cache entries for a newer publication. Upstream resolver changes remain separated by their resolver generation.

Installers are serialized, while domain lookups remain lock-free and delegate through the snapshot matcher.

## Current scope

The production APK packages a pinned, verified 102,972-entry 1Hosts Lite compiled blocklist and the reviewed Public Suffix artifact used for bounded parent matching. The repository still does not ship a runtime remote-update flow, user-managed allowlist persistence, blocking-policy UI, or Room schema change. A private app-files `active.bin` remains an explicit local override; without one, the packaged production list is active by default.
