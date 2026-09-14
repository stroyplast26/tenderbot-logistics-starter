# TenderPlan response failure diagnostics

When an HTTP response fails validation, the worker now reports a fixed rule and
field category, the stage (`PROJECTION` or `BATCH`), and the bounded numeric
observations available at failure time. For example, an unsupported field in a
tender produces `TENDER_FIELD_UNSUPPORTED`; its actual name and value are never
included. An unexpected internal exception produces
`UNCLASSIFIED_INTERNAL_FAILURE` without parsing its message.

## Data and compatibility

The detail contains the existing run, intent and request digest bindings. HTTP
status and body byte length describe the response actually observed by the
worker. Provider count, returned count and projected count are populated only
when observed and validated; `null` means unavailable. A count inconsistency may
therefore retain both conflicting numbers. These observations are diagnostic
metadata, not provider request counters or execution receipts.

No response body or body digest, token, credential reference, query, URL,
provider string, unknown field name, exception text or traceback is stored in
the detail. Its schema accepts only fixed enums and bounded integers.

Successful worker messages and legacy errors retain their V1 protocols and
exact field sets. Errors carrying a detail use the separate
`tenderplan-read-only-worker-error-v2` envelope. The parent verifies its exact
schema and run/intent/request bindings. Invalid or foreign details remain
`WORKER_OUTPUT_INVALID` uncertainty.

The existing diagnostic V1 schema and records are unchanged. Supplementary
details are written into a separate path-bound SQLite sidecar next to the native
queue, after native `UNCERTAIN` is committed. Both diagnostic writes are
independent and best effort. A failed write cannot replace the native outcome.
Supplementary records are immutable, hash chained and bound to the native
uncertain event. Identical replay is idempotent; conflicting data is rejected.

## Read a recorded detail

```powershell
python scripts/show_tenderplan_response_failure.py --help
```

The command accepts the native queue path and run ID. It opens existing files
read-only, verifies their bindings, and returns only safe diagnostic metadata.
Missing supplementary evidence is reported as unavailable; reading it does not
create a database. It does not retrieve credentials or call the provider.

## Operational boundary

All retry, automatic schedule, live release and reconciliation authorization
flags remain false. No admission, authority, no-dispatch, controller or queue
state-transition logic is changed by these diagnostics.

This change cannot reconstruct details of earlier responses that were not
retained. In particular, the 2026-09-14 attempt with
`WORKER_RESPONSE_VALIDATION` remains unresolved. Local tests of this change do
not authorize another provider call or activate the dependent Yandex job.
Any future worker must be rebuilt and admitted with its exact new source pins;
previously approved bundles are not modified by this change.
