# Local admission of a proven pre-dispatch failure

The Tenderplan attempt `sd_9ced15e3298344a1bc29078d7c42e42c` committed an intent and an `UNCERTAIN` event. Its sealed worker did not commit `DISPATCH_CLAIMED`. The reviewed, byte-pinned worker protocol requires that claim before credential access or provider entry. This explains this one historical failure; it does not change its recorded outcome or authorize another request.

`tenderplan_no_dispatch_evidence.py` accepts only the separately reviewed proof registered as `tpnd_20260914_9ced15e3298344a1bc29078d7c42e42c_v1`. Admission verifies the proof's exact file and record hashes, eight execution artifacts, every sealed archive member, the original controller attempt and the native event chain. Supplying a new hash or re-signing a different proof cannot add an acceptance. The diagnostic sidecar is not read as authority.

The explicit local operation upgrades native V2 to V3 and controller V7 to V8. Each store receives an append-only typed receipt. Original attempts, events, cards, decisions, account transition, consumed authorization and terminal counters are preserved. Ordinary status and calls without a scope pin continue to report `BLOCKED_UNCERTAIN`.

For a fresh proposal, the new `expected_source_reconciliation_set_sha256` binds both the older failed-closed receipt and the new non-dispatch receipt, plus the full native admission set. Controller, Source Lab where applicable, and native writer fences still enforce current file/snapshot pins, one running attempt, unresolved history and review backpressure. The old Tenderplan-only pin keeps its original scope. The new pin is not an execution authorization.

## Local procedure

1. In the admitted runtime, use `scripts/run_source_discovery_once.py tenderplan-reconcile-no-dispatch` with the accepted proof, provenance path map and exact controller file/snapshot/native file hashes. The CLI uses that runtime's bound controller path. The default is a preview; neither store changes.
2. Review the deterministic preview and its hash. Apply additionally requires `--apply`, `--expected-preview-sha256` and `--confirm-local-reconciliation`. This local confirmation does not authorize provider or credential access.
3. Save the resulting mixed and native set hashes. Use the mixed hash with a newly prepared source proposal and freshly read controller/native pins. Old consumed requests remain unusable.
4. Provider execution, credentials, Yandex activation, CRM writes, messages and scheduling retain their own existing authority requirements.

The native receipt commits before the controller receipt. If the second commit fails, controller history remains blocked and native calls without the exact admission pin remain blocked. Re-read the current native file hash and repeat the same reviewed preview to finish the local operation. Do not replace databases, rewrite history or manufacture a new proof to recover. An exact completed re-apply is inert.

## Verification

The integration tests exercise stable read-only preview, exact apply, immutable raw history, forged proof/provenance, wrong and stale pins, old-run replay, unrelated uncertainty, schema tampering, missing-file races, rollback, interruption between stores, current-pin idempotence, and a chronological mixed V2/V3/V8 history followed by a fresh Yandex reservation. Synthetic acceptance registry entries are confined to tests; no test receipt is installed as operational trust.

This change is a local admission mechanism. A successful new provider response and imported useful records are separate acceptance evidence.
