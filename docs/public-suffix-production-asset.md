# Production Public Suffix asset packaging

The production Public Suffix resolver is still not connected to DNS blocking policy. This document describes the guarded step used to move the already reviewed compact artifact from `build/` into the Android main asset source set without changing resolver behavior.

## Pinned production identity

`tools/public_suffix_production.json` is the source of truth. The current reviewed artifact is:

```text
artifact size: 153,740 bytes
artifact SHA-256: 401b3ed16ed28eb9a8362a93f8f054462fa16bdce26a0e7eaa6c5a3cb5a6eb70
normalized size: 144,382 bytes
normalized SHA-256: 72d07fea544b74d920be2394d4c5fbb38dd3f5f3ccac299e27809009bac1c550
rules: 9,950 exact / 281 wildcard / 8 exception
source revision: e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20
```

Do not copy a similarly named binary into `app/src/main/assets` by hand. Hashes or benchmark JSON are evidence of identity, not substitutes for the reviewed binary bytes.

## Install a verified candidate

Generate or restore the pinned outputs first so these files exist:

```text
build/public-suffix.normalized.dat
build/public-suffix.bin
```

Then run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-public-suffix-asset.ps1
```

The installer performs two gates before creating the destination:

1. `verify_public_suffix_production.py` validates the pinned source identity, normalized bytes, artifact size/SHA, deterministic regeneration, artifact header and production rule counts.
2. The candidate copy is staged beside the final destination and `verify_public_suffix_asset.py` independently verifies the exact artifact contract that an APK-packaged asset must satisfy: size, SHA-256, format header, embedded normalized-source SHA-256 and rule counts.

Only a candidate that passes both gates is moved to:

```text
app/src/main/assets/public_suffix.bin
```

The command is safe to rerun. If the destination already exists and matches the production contract, the installer exits successfully without rewriting it. If an existing destination does not match the contract, the installer refuses to overwrite it so an unknown binary cannot be silently replaced.

Custom input/output paths are available through `-Normalized`, `-Artifact`, and `-Destination`, but the default path is the one expected by `PublicSuffixAssetLoader.ASSET_NAME`.

## Why installation is separate from runtime wiring

Adding a reviewed binary to the main asset source set changes APK contents and package size, but it should not yet change DNS behavior. `PublicSuffixResolverOwner`, `ParentDomainMatcher`, `DomainPolicyAssembler`, and `DnsVpnService` remain separate concerns.

After the exact production asset is checked in, the next packaging PR should verify the checked-in bytes during repository verification and exercise `PublicSuffixResolverOwner.fromAssets()` against the real main asset. Only after that packaging step is independently verified should a later behavior-change PR connect the resolver to parent-domain matching.
