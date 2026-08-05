# Domain blocking policy

DNS Shield keeps domain policy separate from the VPN lifecycle so precedence and matcher behavior can be tested without opening a tunnel.

## Decision order

`CompositeDomainMatcher` applies this order:

1. Normalize the queried domain with `lowercase().trim()`.
2. Allow blank and `unknown` values without invoking policy components.
3. Check `DomainAllowlist`; an allowlist hit bypasses every blocker.
4. Ask each `DomainMatcher` in order and stop at the first blocking result.
5. Allow the domain when no blocker matches.

The service-level `blockDecisionCache` is intentionally outside this composition and remains responsible for caching the final policy decision once this layer is wired into the VPN.

## Current allowlist semantics

`ExactDomainAllowlist` matches only the normalized domain stored in the set. Allowing `example.com` does not allow `sub.example.com`, `lookalike-example.com`, or any parent domain.

This conservative behavior is intentional. Parent-domain traversal, Public Suffix safeguards, user-managed persistence, and policy-generation invalidation must be designed and tested separately before runtime integration.

## Policy assembly and fallback

`DomainPolicyAssembler` always includes `BuiltInDomainMatcher`. When a compiled blocklist file is configured, the assembler loads and validates it before adding `CompiledBlocklistMatcher` after the built-in matcher.

The assembly result exposes one of three states:

- `NotConfigured`: no compiled blocklist was requested; built-in rules remain active.
- `Loaded(entryCount)`: the compiled blocklist was validated and joined to the policy.
- `Rejected(reason)`: loading or validation failed; the optional compiled matcher is omitted and built-in rules remain active.

The assembler catches recoverable `Exception` failures only. Fatal JVM errors are not converted into fallback states. Runtime callers may record the status for diagnostics, but must not treat a rejected optional list as a reason to disable built-in DNS protection.

## Runtime blocklist source

`RuntimeDomainPolicy` reserves one app-private candidate path:

```text
<filesDir>/blocklists/active.bin
```

When that path does not exist, the optional compiled blocklist is treated as `NotConfigured` and the file loader is not called. When the path exists, it is passed to `DomainPolicyAssembler`; empty, malformed, unreadable, non-file, and unsorted artifacts are therefore surfaced as `Rejected` rather than silently ignored.

The runtime source does not create directories, copy a bundled asset, download a list, replace files, or install policy into the VPN service. Those lifecycle operations remain separate reviewed changes.

## Atomic policy publication

`ReloadableDomainPolicy` stores one complete `DomainPolicyAssembly` in an atomic reference. DNS readers therefore observe either the previous matcher and status or the replacement matcher and status; they never observe a partially updated policy.

`install()` accepts a `beforePublish` callback. Runtime integration must use that callback to increment the service policy generation and clear DNS, in-flight, and block-decision caches before the replacement matcher becomes visible. If invalidation throws, the previous assembly remains installed and the failure is propagated.

Installers are serialized, while domain lookups remain lock-free and delegate through the currently published matcher.

## Current scope

The policy components, assembler, runtime file resolver, and reloadable publisher are pure Kotlin and are not wired into `DnsVpnService` yet. This document does not introduce a production blocklist, bundled asset, remote update flow, UI, or Room schema change.
