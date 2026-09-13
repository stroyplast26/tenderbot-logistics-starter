# Yandex: defer incomplete local research

An inspected batch can contain useful decisions and unresolved research. An
explicit research deferral releases that batch's WIP slot while preserving its
`NEEDS_RESEARCH` decisions, every resolution and queue event, and the original
request accounting. It does not qualify the unresolved candidates or turn their
decisions into approval or rejection.

The controller records a separate immutable deferral. The attempt remains
physically `READY_FOR_REVIEW`; status reports `DEFERRED_LOCAL` and counts deferred
batches separately from normal closures. Normal closure and deferral exclude
each other. The exact V6 schema extends V5 and supports existing V4 controllers
through one explicit atomic migration. Routine reads do not prepare the schema.

Every candidate must have a recorded latest resolution, with at least one
`NEEDS_RESEARCH`. Unreviewed, held, or claimed items cannot be deferred. The
receipt binds the original batch and an ordered manifest of latest decisions
and queue heads. The controller and Source Lab are locked together while that
manifest is validated and the deferral is committed. Source Lab is not written.
Any later drift blocks subsequent source checks and reservations for explicit
reconciliation. Reopening or changing a deferred batch is not provided by this
operation.

## Operator procedure

Deploy the reviewed compatible controller, bridge and their dependencies to
every runtime that operates the same state before applying V6. Preserve exact
backups of the existing controller and Source Lab, including a consistent
snapshot of any active SQLite journal. Do not restore an old controller over
later activity. Use the existing canonical controller path explicitly; a missing
file is rejected and no replacement database is created.

Preview is the default and performs no state migration:

```powershell
.\.venv\Scripts\python.exe -B scripts/defer_yandex_review_batch.py `
  --state-path <existing-controller-path> `
  --attempt-id <reviewed-existing-attempt-id>
```

Review the batch receipt, decision digest, counts and unresolved IDs against
trusted local evidence. Apply uses those same reviewed pins, plus an attributable
actor, reason, evidence reference and stable idempotency key:

```powershell
.\.venv\Scripts\python.exe -B scripts/defer_yandex_review_batch.py `
  --state-path <existing-controller-path> `
  --attempt-id <reviewed-existing-attempt-id> `
  --apply --confirm-local-deferral `
  --expected-receipt-sha256 <reviewed-batch-receipt-hash> `
  --expected-decisions-sha256 <reviewed-decision-manifest-hash> `
  --actor <operator> --reason <why-research-is-deferred> `
  --evidence-ref <local-evidence-reference> `
  --idempotency-key <stable-operation-key>
```

An exact replay does not add another receipt. Changed pins or conflicting replay
inputs are rejected. After apply, verify the separate deferral count, freed WIP,
unchanged Source Lab history and original accounting. This operation performs no
provider request, secret lookup, CRM write, message, or scheduling change. A new
source request still needs its own authority and all normal admission checks.
