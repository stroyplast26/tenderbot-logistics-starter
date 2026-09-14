# Manual acknowledgement of an uncertain read

An operator may acknowledge one reviewed read-only failure to prepare a new
request. The old request remains `UNCERTAIN`; unknown provider/credential counts
remain null. An acknowledgement grants no execution or automatic retry authority.

This path applies only to a native account-transition queue with the exact
`INTENT -> DISPATCH_CLAIMED -> UNCERTAIN` chain, no cards or decisions, one intended
request, zero writes/contact/spend, and bounded response/record caps. It does not
classify a claimed request as no-dispatch or failed-closed. Native V3 and controller
V8 schemas and historical rows remain unchanged.

## Two immutable artifacts

1. `tenderplan_read_failure_ack.<set_sha256>.json`, beside the native queue,
   contains the exact historical operation/intent/event digests, controller
   attempt digest, independently reviewed owner-grant and execution evidence
   pins, terminal/diagnostic pins and unchanged unknown counters.
2. `source_read_failure_context.<context_sha256>.json`, beside the controller,
   binds that set to the existing typed reconciliation set, actual controller
   attempt rows, native store identity and both file/path identities.

Builders receive evidence pins from a trusted, separately reviewed operator
composition. Self-consistent submitted JSON is not independent evidence. Creation
is exclusive and idempotent only for identical bytes. No mutable registry is read.
The consumer receives the exact context digest from a separate approved proposal;
the mere presence of either artifact has no effect.

Initial database file hashes in the context describe the observation at creation.
They do not freeze all future database contents. Current hashes are checked again
when making and reserving each new proposal; historical rows and file identities
must continue to match. Replacement of either database invalidates the context.

## Admission and fences

`expected_source_reconciliation_set_sha256` can select the exact context. A
genuinely absent context follows the legacy exact reconciliation-pin check. A
present invalid context always fails closed. Both artifact handles deny Windows
write/delete sharing for the duration of the controller/native fences.

The controller compares actual fenced native acknowledgements with the exact
controller references and excludes overlap with existing typed reconciliations.
It reports separate `reconciled_uncertain_count` and
`acknowledged_read_failure_count`; raw state counters are never reduced. Only
these validated sets affect `blocking_uncertain_count` in the explicitly scoped
snapshot. Raw/default checks still block on every `UNCERTAIN`.

The acknowledged native set is propagated through intake readiness and native
reservation using `expected_read_failure_ack_set_sha256`. Reservation revalidates
the artifact and history transactionally and refuses any existing run ID. A
durable new intent remains subject to the ordinary one-shot worker claim and
separate execution authority. Any additional unresolved attempt blocks admission.

V8 raw history validation permits historical uncertainty beside a subsequent
attempt; it still rejects multiple running attempts. This only makes retained
history readable. It does not open the raw admission gate. Older schemas retain
their prior structural restrictions.

## Verification

`test_tenderplan_read_failure_ack.py`, `test_source_read_failure_context.py` and
`test_source_read_failure_integration.py` cover native/controller binding,
unchanged history, immutable artifact handles, malformed or stale inputs,
substitution between checks and reservation, default denial, one fresh attempt
and blocking on a subsequent failure. Test evidence and credentials are synthetic;
passing these tests does not establish a successful provider response.
