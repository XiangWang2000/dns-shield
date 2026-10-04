# R02 user-rule assembly validation (#65)

Base: main `1dbd49df6a788a894c1e3e65e1b5357bb211f569`.

Cause: valid private `active.bin` and no-provider assembly branches omitted `userRules` when calling `DomainPolicyAssembler`. The new five-path matrix failed before the fix at the private-file ALLOW assertion. The fix only passes the existing rules through those two branches.

## Checks

- `RuntimeDomainPolicyTest.userRulesApplyAcrossEveryRuntimeAssemblyPath`: fail before / pass after. Matrix: valid private, bundled, corrupt private falling back to bundled, both providers rejected, no provider. Checks ALLOW over compiled/built-in blockers, BLOCK, exact BLOCK priority at apex and includeSubdomains ALLOW below it.
- Entire `RuntimeDomainPolicyTest`: PASS.
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1`: PASS. First full run failed because this old reused worktree did not yet have main's locked native submodule; initialized recorded revisions and reran successfully. No dependency version change.
- Android 10 ASUS_Z01RD, serial `JCAZB7604377HFP`, isolated `.d07test`: `LiveUserDomainRuleTunInstrumentedTest,UserDomainRulePersistenceInstrumentedTest`, **OK (2 tests)**, 1.141s. Real TUN BLOCK -> ALLOW -> cached positive -> BLOCK verifies live policy reload discards the cached answer; Room reopen/removal/exact/subdomain/undo tests pass. This service test uses the packaged provider; the private/no-provider paths are covered by the deterministic JVM matrix, not claimed as separate device cases.
- APK SHA256: `66873837426BFE853885501847D72F1D9049CCB79D429889BF9C60D9A150E35B`.
- `git diff --check`: PASS. CRLF retained.

Ignored logs: `captures/r02-final-verify.log` (missing native dependency), `captures/r02-final-verify-submodule-ready.log` (PASS), `captures/r02-d07-device-build.log`, `captures/r02-android10-rules-reload.txt`. Common final candidate remains #72. No automatic merge/release.