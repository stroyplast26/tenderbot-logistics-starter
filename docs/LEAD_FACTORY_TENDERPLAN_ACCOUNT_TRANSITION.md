# Tenderplan: local transition between two accounts

An unresolved request from a previous account must remain unresolved in its
original history. It must not be reassigned to a newly verified account. This
change introduces one explicit local transition for an existing V1 queue with
exactly one terminal `UNCERTAIN` operation, no cards, and no decisions.

The migration preserves the original metadata, store identity, operation and
event rows. It adds one immutable transition record and a recognized V2 schema.
The transition pins the entire old operation/event content, its run ID, the
original and current locations, the owner's confirmation of different accounts,
and the new account's pinned connection profile. The old account's provider ID
remains unknown. This is not automatic account discovery or general migration.

The V2 ledger can reserve only intents bound to the new registration. Only the
exact frozen old operation is excluded from the new account's unresolved count.
A new `INTENT`, `DISPATCH_CLAIMED`, or `UNCERTAIN` still blocks another request.
The old operation cannot be replayed or extended. Global counts continue to
include the old uncertainty; the preflight reports current-account counts
separately. Removing the transition, changing its contents, using another path,
or opening V2 with the old validator fails closed.

## Preview and application

Use the repository's CPython 3.11 environment. The CLI defaults to read-only
preview and accepts only an existing file. It neither moves files nor creates an
empty replacement queue. Obtain the expected hashes from trusted local evidence,
not from an unreviewed input requesting its own admission.

```powershell
.\.venv\Scripts\python.exe scripts/prepare_tenderplan_account_transition.py `
  --store <existing-queue-path> `
  --expected-store-sha256 <verified-original-file-hash> `
  --expected-origin-path-sha256 <original-path-binding> `
  --expected-store-identity-sha256 <original-store-identity> `
  --legacy-run-id <frozen-old-run-id> `
  --profile <verified-new-connection-profile> `
  --expected-profile-sha256 <trusted-profile-file-hash> `
  --owner-confirmation-sha256 <digest-of-owner-account-confirmation>
```

Read-only preview is not an authority or a reservation. An approved local apply
uses the same inputs plus `--apply --confirm-local-transition`. The CLI preserves
an exact `.before-account-transition.bak` without overwriting it. The store
revalidates the expected original bytes and complete V1 ledger under an exclusive
SQLite transaction before adding the transition. A precommit fault rolls back;
a second transition is rejected. The backup remains historical evidence, not an
alternative active queue. Do not restore it over an active ledger after new work.

The migration has no provider, vault, CRM, scheduling, contact, or search action.
It does not close Source Discovery WIP, renew exhausted authority, reset budgets,
or authorize a new API request. Deploy the reviewed code to the intended runtime
before applying its state format; do not use `run-one` as a migration probe.

## Connection and worker checks

The profile validator reads the exact pinned receipt of a successful historical
GET `/api/info/firm`, with one attempt, zero searches and Windows credential
readback. It validates the strict schema and checksum without accessing a secret.
The checksum is not a provider signature: its fingerprint must come from trusted
local execution evidence. This proves the recorded firm connection, not current
search entitlement.

At dispatch, the worker gets the active connection from the same transaction
that claims the intent. It rereads and validates the pinned profile before
Credential Manager. `LastWritten` is checked on the same credential structure as
the bearer, before copying the secret: the write time must fall within the
recorded fresh-slot write/readback/GET window. This detects slot rewrites after
verification. It trusts that recorded sequence, the local clock and evidence; it
is not cryptographic proof of PAT identity or protection against a local admin.

New uncertainty diagnostics use a fixed filename containing the transition hash
in the current queue directory, and reference the original store/intent through
the existing diagnostic bindings. The legacy diagnostic file is preserved.
Diagnostics remain best effort and never authorize a retry or change the durable
native `UNCERTAIN` outcome.

## Validation boundaries

Offline coverage includes exact history preservation, invalid schema/path/proof,
atomic rollback, concurrent reservations, replay rejection, current-account
uncertainty, profile replacement, credential rewrites, isolated diagnostics and
unchanged common WIP. Tests use synthetic accounts and contained/mock transports.
Passing these checks does not establish a live search, automatic collection,
commercial qualification, or a manager handoff.
