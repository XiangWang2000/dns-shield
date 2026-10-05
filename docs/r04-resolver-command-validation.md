# R04 resolver command ordering validation

## Cause and change

Independent ViewModel IO jobs could write/read/send A after a later B request, leaving Room/UI and the service on different resolvers. Resolver mutations now enter a process-scoped FIFO synchronously at API entry. All accepted Room writes run in submission order even if a UI waiter is cancelled. Revisions fence dispatch and application; they do not discard legitimate selection when an unrelated edit/delete follows. Service UPDATE waits for a FIFO barrier, reads Room's current active row rather than trusting the intent ID, and applies it only while its revision remains current on the existing Main lifecycle actor. Legacy intents without a revision receive a token. Unchanged active rows do not reset service DNS state.

Fallback requests publish a nonblocking requested-allow guard at submission. New strict requests reject subsequent plaintext sends/registrations without waiting for Room or socket IO. Socket cleanup runs on IO; existing send/write lock remains authoritative for already-entered sends. Older queued ALLOW cannot reopen the requested strict guard. Durable setting mutations remain FIFO. No main-thread socket close or SharedPreferences commit was introduced.

## Validation (2026-10-05)

Focused command/fence tests: 13/13, zero failures/errors (`ResolverCommandOrderingTest` 9 and `DnsPlaintextFallbackFenceTest` 4). Controlled barriers cover A/B/A, selection plus unrelated fallback edit, stale UI delete snapshot with DB fallback, delayed service active read, legacy refresh, cancelled waiter, failing command followed by successful mutation, and strict requested while Room worker is blocked with runtime initially allowing plaintext. The strict regression checks rejection before releasing Room, plus a late old allow setter and TCP registration/cleanup.

Commands with Android Studio JBR:

```powershell
.\gradlew.bat :app:testDebugUnitTest --tests '*ResolverCommandOrderingTest' --tests '*DnsPlaintextFallbackFenceTest'
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

Full verify passed (`captures/r04-strict-fifo-final-verify.log`). Preserve the earlier `captures/r04-fifo-final-verify.log`: reused worktree lacked locked native submodules (undefined hev-socks5-tunnel), then `git submodule update --init --recursive` restored recorded dependency revisions; no dependency upgrade. Existing allNetworks warnings in related D09 code are separate from this slice; no new warning observed here.

Independent review caught the queued strict-fence regression before commit; the requested guard and before-barrier assertions above resolve it. Pure JVM ordering tests do not claim actual Android service wiring or real upstream selection was tested. That cross-module device acceptance remains #72. No merge or release is authorized by this result.
