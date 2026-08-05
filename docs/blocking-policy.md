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

It never asks the exact matcher about `co.uk` or `uk`. The resolver contract must apply both the ICANN and PRIVATE sections of the Public Suffix List so private suffixes such as `github.io` also remain protected.

A missing, blank, malformed, or unrelated resolver result keeps matching exact-only. `ParentDomainMatcher` has no unsafe fallback that assumes the last two labels are registrable.

The bounded matcher is not yet added to `DomainPolicyAssembler`; compiled blocklist decisions therefore remain exact-domain only until a reviewed Public Suffix resolver is available.

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

Runtime policy is wired into `DnsVpnService`, and a bounded parent-domain matcher now exists as a pure Kotlin component. The repository still does not include a Public Suffix resolver, production blocklist, bundled asset, remote update flow, atomic file replacement, UI, user-managed allowlist, or Room schema change. With no `active.bin` present, shipped behavior remains the existing built-in matcher only.
