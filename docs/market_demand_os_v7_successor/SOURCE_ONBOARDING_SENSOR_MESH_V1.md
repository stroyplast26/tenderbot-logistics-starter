# Source Onboarding & Sensor Mesh v1

Status: `NON_RATIFYING_OFFLINE_IMPLEMENTATION`

Version: `0.9.0`

This successor specification does not modify or ratify the immutable MDOS v7
package. It grants no authority for external reads, credentials, contact,
publication, advertising spend, Source Lab writes, or Bitrix writes.

## 1. Goal

Connect many acquisition and demand-discovery services through one controlled
grammar. A provider is not a lead source by itself: every account exposes
separate, versioned capabilities with an exact purpose, source role, effect
class, terms, operation contract, quota, cost, retention, validity, and
dependency family.

The first executable stage registers these facts and runs deterministic
synthetic/read-only preflight across many providers. It produces observations
and receipts, not leads, GDOs, consent, contact permission, or CRM commands.

## 2. Existing reusable boundaries

- `lead_factory/source_adapter.py` already owns page authorization, cursor,
  quota, idempotency, STOP, uncertain-result reconciliation, and a JIT external
  read fence for one in-memory runtime session.
- `lead_factory/mdos_v7/source_read_ledger.py` now owns local cross-process
  reservation, dispatch-intent, checkpoint, outcome, idempotency, and cumulative
  quota custody in one explicitly configured canonical SQLite file. With an
  explicitly injected monotonic anchor it also owns a recoverable anchor
  outbox, rollback detection, durable reconciliation quarantine, governed quota
  epochs, rights-neutral continuation migration, stream incidents and repair,
  controlled vault-key lifecycle, and the authoritative latest runtime-
  continuation head.
- `lead_factory/mdos_v7/source_runtime_vault.py` owns staged AES-256-GCM
  custody for adapter cursor, quota, receipt, and pending-reservation state.
  Raw cursor and page contents remain encrypted; SQLite projections contain
  only bounded digests and opaque key references. It can rewrap a complete
  verified inventory to a successor key, prove the sealed inventory to the
  ledger, and activate a governed repaired or migrated generation.
- `lead_factory/mdos_v7/durable_read_sensor.py` composes that ledger with the
  exact read-only sensor. It permits one adapter boundary call only after a new
  reservation and dispatch intent are durable. Its anchored-vault path binds an
  exact encrypted generation to the ledger outcome before activation and can
  restore the next local fixture position without restarting page one. It also
  drives exact registry/capability revision migration without a provider call
  and durably quarantines a ledger-bound generation that disappeared locally.
  Its repair state machine resumes by stable repair identity across INTENT,
  atomic PREPARED+physical-base fence, ledger BIND, vault ACTIVATE, and ledger
  RESOLVED cuts; callers never supply a randomized PREPARED descriptor or raw
  cursor.
- `lead_factory/source_wave1_contracts.py` already defines fixture-only
  contracts for TenderPlan, Saby Trade, DOM.RF public projects, and Kontur
  Client Search.
- `lead_factory/source_wave1_ingest.py` already has a separate prepare/commit
  boundary into Source Lab and human qualification review.
- `lead_factory/tenderplan_shadow_canary.py` provides a default-off, one-request
  TenderPlan search boundary. Its live-admission fence is currently hard-coded
  to deny before credential resolution or network dispatch. A PAT alone cannot
  open that fence. A future call requires a separate signed live permit bound
  to the exact search policy, last-moment STOP control, and durable uncertain-
  request recovery. The boundary pins the exact HTTPS host and search path,
  disables redirects and retries, bounds the response, and retains only one
  digest/count observation. It does not create a live permit, persist raw
  tenders, or feed Source Lab/CRM.
- `lead_factory/tenderplan_live_authority.py` verifies three exact signed
  envelopes and binds the one-shot TenderPlan request, query-policy digest,
  auth-reference digest, passport, mapping, contract, epoch, nonce, validity,
  skew, and read cut. The shared signed protocol deliberately produces only
  `live_release_eligible=False` evidence, so its final admission method always
  denies; it is not a self-issued live permit.
- `lead_factory/tenderplan_one_shot_guard.py` is a separate path-bound SQLite
  one-shot journal. Its standalone dispatch method is hard default-off before
  intent mutation or callbacks. Offline state-machine tests prove durable
  intent-before-entry, one winner, reconcile-only restart, and tamper checks;
  an external monotonic rollback anchor and atomic STOP lease remain required
  before any sealed live composition.
- `lead_factory/tenderplan_isolated_transport.py` is a second independently
  default-off transport foundation. On Windows it creates the worker
  suspended, assigns a one-process kill-on-close Job Object, resumes it, then
  transfers the PAT through anonymous stdin. Parent-side bounded output,
  caller-specific byte revalidation, forced kill/reap, fixed TLS host/path,
  and no proxy/retry/redirect defend a future one-shot call. The worker still
  requires signed one-use admission/nonce/STOP/query-policy IPC binding before
  its network fence may be changed.
- `lead_factory/tenderplan_owner_canary.py`,
  `scripts/run_tenderplan_owner_canary.py`, and the separate
  `TenderPlanOwnerCanaryTransport` provide one owner-invoked diagnostic read.
  The runner durably creates a sealed `INTENT` before child entry; the contained
  worker verifies that exact record, resolves the registered PAT inside the Job
  Object, performs at most one no-retry request, and returns only bound hashes
  and counts. Raw provider data and the PAT do not cross back to the parent.
  This narrow manual path does not feed Source Lab/CRM, cannot be scheduled,
  and keeps both `automatic_schedule_eligible=False` and
  `live_release_eligible=False`.
- `lead_factory/tenderplan_read_only_projection.py`,
  `lead_factory/tenderplan_read_only_crypto.py`,
  `lead_factory/tenderplan_read_only_diagnostics.py`,
  `lead_factory/tenderplan_read_only_store.py`,
  `lead_factory/tenderplan_read_only_transport.py`, and
  `lead_factory/tenderplan_read_only_intake.py` provide a second, separate
  owner-invoked manual contour for local review. It durably commits an exact
  intent, atomically appends a single-winner `DISPATCH_CLAIMED` event before
  PAT resolution/network, performs one contained no-retry `page=0` read,
  strictly validates the complete page, minimizes to at most five cards,
  encrypts every card inside
  the worker, and appends only ciphertext envelopes to a path-bound new-store
  SQLite schema. A human may append only local `KEEP`, `DISMISS`, or `HOLD`
  decisions. It has no pagination, scheduler, Source Lab/CRM bridge, message,
  bid, contact, spend, or provider-write path and keeps
  `automatic_schedule_eligible=False` and `live_release_eligible=False`.
  Provider numeric values remain canonical strings marked
  `UNVERIFIED_PROVIDER_SEMANTICS`; date, price, region, and status units are not
  promoted to verified business semantics. Per-card AES-256-GCM keys are
  locally DPAPI-wrapped for the current Windows user. This is a local canary,
  not a non-exportable HSM or destruction claim. Display expires after 30 days,
  while verified key erasure across SQLite remnants and backups remains an
  explicit live-release blocker.
  The diagnostic module is a separate fixed-path, append-only, new-store-only
  schema v1 sidecar. Only strict stage/outcome enums and existing digest
  bindings may be written, and only after the main queue has committed
  `UNCERTAIN`. Query/query digest, auth reference, PAT, URL, HTTP/body/provider
  material, ciphertext, exception text, and traceback have no field. The main
  queue and transport never read this sidecar for authority: missing, corrupt,
  conflicting, or rolled-back diagnostics cannot permit retry, reconciliation,
  scheduling, or release. `LEGACY_DETAIL_UNAVAILABLE` records only that an
  older uncertainty predates diagnostics; it does not reconstruct a cause.
  Without an external monotonic anchor, restoring an older canonical sidecar
  at the same path is not detectable, so the sidecar is neither completeness
  evidence nor a rollback-proof audit log.
- `lead_factory/tenderplan_windows_credential.py` and
  `scripts/import_tenderplan_pat_windows.py` provide owner-invoked, one-time
  Windows Credential Manager provisioning only. A fresh opaque auth reference
  and non-secret PREPARING registration are durably reserved before
  `CredWriteW`; exact readback is required before the registration becomes
  VERIFIED, and repeats or uncertain state fail closed. The plaintext source
  file is retained until a separate owner-authorized removal. No general or
  scheduled runtime token resolver is exported. Only the separate manual
  owner-canary worker resolves the PAT inside its already-contained process.
  This is not an HSM, non-exportable-secret, HA, external rollback, rotation,
  or live-readiness claim. A future automated worker successor still requires
  signed one-use admission and current STOP.
- `lead_factory/mdos_v7/avito_shadow_lab.py` already separates Avito listing,
  messenger, promotion, collaboration, and advertising capabilities.

The sensor mesh composes above these boundaries. It must not add another HTTP
runtime or write directly to Source Lab. Existing Wave 1 page records are not
automatically sensor-safe: a separate allowlisted, privacy-reviewed projection
must turn them into digest-only observations before reuse by the mesh.

### 2.1 Concrete signed-boundary implementation map

- `lead_factory/mdos_v7/signed_authority.py` defines the shared canonical
  Ed25519 envelope, pinned trust bundle, historical verification cut, and fresh
  challenge-bound inclusion verification.
- `lead_factory/mdos_v7/source_read_anchor_boundary.py` provides
  `PinnedSignedSourceReadExternalAnchor`, the signed CAS/readback adapter
  injected into `SourceReadLedger`.
- `lead_factory/mdos_v7/source_read_authority_boundary.py` provides
  `PinnedSignedSourceReadApprovalAuthorityV1`, the signed approval/readback
  adapter used by the representative continuation-rotation path.
- `lead_factory/mdos_v7/signed_authority_policy_transition.py` provides a
  path-bound append-only offline custody for predecessor-signed approval and
  anchor trust-bundle successors/revocations, plus independently governed
  approval and anchor clock-skew transitions.
- `lead_factory/mdos_v7/source_read_policy_bound_composition.py` reconstructs
  both exact current trust roots from that verified custody, rejects bundles
  without the required runtime capabilities, and installs one shared
  store/path/generation/head fence inside the exact signed adapters.
- `lead_factory/mdos_v7/signed_challenge_replay.py` provides the optional
  durable local challenge reservation used by both signed adapters before
  transport entry; the legacy bounded in-process window remains the default.
- `lead_factory/mdos_v7/source_read_ledger_v4_rehearsal.py` provides a bounded
  verification-only v3 manifest and deterministic receipt for opening a
  separate empty v4 store. It transfers no rows, rights, or authority.
- `lead_factory/mdos_v7/source_read_ledger_v4_bootstrap.py` creates only a new
  empty schema-v4 ledger plus a separate canonical sealed sidecar bound to the
  exact policy composition. Existing, partial, copied, stale, or tampered
  paths are not adopted or overwritten.
- `lead_factory/mdos_v7/offline_foundation_manifest.py` and
  `scripts/verify_mdos_v7_offline_foundation.py` provide the fixed local
  file/schema/live-guard allowlist and the single `--full` verification entry
  point. This manifest is an integrity checklist, not a release signature.
- `lead_factory/mdos_v7/runtime_vault_kms_boundary.py` provides the configured
  exported-key adapter and `RuntimeVaultKmsKeyLifecycleCustodyAdapter`.
  `SourceRuntimeVault.open_existing_with_kms_boundary(...)` is the explicit
  canary entry point that requires those exact adapters and verifies authority
  alignment before plaintext verification.

These surfaces are imported from their concrete modules. The package-root
`lead_factory.mdos_v7` export remains intentionally limited to the default-deny
authority helpers so importing the package does not eagerly load optional
cryptographic boundaries or imply live authority.

## 3. Registry grammar

Each registry snapshot contains:

- provider and opaque account identity;
- dependency family and account status;
- atomic capability and exact `READ`, `WRITE`, `CONTACT`, `SPEND` effects;
- source role (`DISCOVERY`, `TRIGGER`, `INTENT`, `RFQ`, `OUTCOME`);
- terms, licence, operation-contract, mapping, security-review, and approval
  evidence digests;
- allowed data class and purpose;
- storage/derivation/export/training/contact flags, retention and cache TTL;
- request, record, byte, cost, and freshness ceilings;
- validity and review/expiry state;
- optional trial entitlement with tariff, cancellation deadline, disabled
  auto-renew assertion, and maximum financial commitment.

Permissions never transfer between capabilities, accounts, products, purposes,
or providers. Five adapters backed by one provider remain one dependency family.

## 4. Read-only sensor contract

```text
Governed RegistrySnapshot
    -> exact READ capability selection
    -> deterministic bounded SensorPlan
    -> durable batch + full-budget reservation
    -> one-shot dispatch-intent winner
    -> caller-injected fixture/replay boundary
    -> rollback-coupled encrypted PREPARED runtime generation
    -> atomic page/observation/checkpoint/quota outcome
    -> recoverable external-anchor intent / CAS / acknowledgement
    -> exact vault activation
    -> optional rights-neutral registry/capability migration
    -> durable stream incident
    -> anchored repair intent / physical-base CAS
    -> atomic encrypted PREPARED + repair fence / ledger acknowledgement
    -> vault activation / governed incident resolution
    -> anchored writer-epoch transition / vault registration acknowledgement
    -> controlled full-inventory key rewrap/retirement
    -> uncertain hold and reconciliation-only recovery
    -> optional later prepare-only Source Lab handoff
```

A sensor observation contains only opaque subject/object references, source
role, stable provider revision, observed time, field/evidence digests, and
provenance. Raw contact data, credentials, arbitrary provider payloads, and
vendor-controlled error text are excluded.

An uncertain dispatch creates a sealed conservative reservation for the full
page budget. That reservation continues to consume global, dependency-family,
and capability capacity until an exact reconciliation is applied. The sensor
reconciliation API accepts the exact adapter runtime and a typed recovered
page, calls the adapter reconciliation itself, and advances the checkpoint
exactly once; it never trusts a caller-constructed page receipt.

The durable coordinator deliberately dispatches one binding and one page per
unit. A brand-new reservation receives a process-local, one-shot winner grant;
replays and reopened operations never receive one. Any operation found in
`RESERVED`, `DISPATCH_INTENT`, `UNCERTAIN`, or `QUARANTINED` state after restart
is fail-closed. A verified encrypted continuation may reconstruct only the
exact local replay or pending state; it never grants a new provider call. If
the ledger, anchor, vault generation, operation-recovery proof, command, or
checkpoint differs, the result remains `RECONCILE_ONLY` or
`RUNTIME_REHYDRATION_REQUIRED`, never a restart from page one.

## 5. Parallelism and control

The portfolio may schedule many providers in one batch, but remains bounded by:

- global and per-dependency-family operation/record/byte limits;
- exact per-capability quota and validity;
- one governed quota epoch at a time, with cumulative conservative counters;
  transition requires no unresolved operation, exact policy continuity, an
  external separation-of-duties authorization, and an anchored event;
- deterministic priority and fair allocation;
- one checkpoint chain per account/capability stream;
- no hidden partial success or cursor advancement;
- stop-on-conflict, stale terms, schema drift, quota breach, duplicate stable
  identity, privacy violation, or uncertain result;
- zero `WRITE`, `CONTACT`, `SPEND`, publication, message, and Bitrix effects.

Provider volume is diagnostic. It cannot improve rank without downstream
unique human-accepted GDO and, later, authoritative Paid/contribution evidence.

## 6. Initial local portfolio

The first preflight covers only locally evidenced capabilities:

| Provider | Current evidence | Executable stage |
| --- | --- | --- |
| TenderPlan | Wave 1 sealed fixture, hard default-off signed shadow boundary, owner-only digest/count canary, and separate encrypted local review queue | one manual no-retry read may queue at most five encrypted cards for human review; no raw import, Source Lab/CRM feed, schedule, or live release |
| Saby Trade | Wave 1 sealed fixture contract | existing source-specific offline replay; sensor-safe projection still required |
| DOM.RF public projects | Wave 1 sealed fixture contract | existing source-specific offline replay; sensor-safe projection still required |
| Kontur Client Search | Wave 1 sealed fixture contract | existing source-specific offline replay; sensor-safe projection still required |
| Avito | local reference specifications and synthetic capability pack | synthetic sensor/preflight |
| Website/Source Lab | existing signed intake and review queue | existing boundary; not reimplemented |

Every other service starts as `PROPOSED` or `UNPROVEN` until its account,
terms/licence, technical operation, trial exposure, data lifecycle, and local
fixture are supplied. A trial subscription alone does not prove a read right.

## 7. Deliberate limits

- No general or scheduled runtime credential resolver is configured. Windows
  Credential Manager provisioning prepares local same-user custody. The only
  resolver is inside the separate owner-canary worker, after Job containment
  and exact durable-INTENT verification. The signed provider transports and
  both production network fences remain hard default-off. Possession of a PAT
  is insufficient to schedule reads. Automated admission still requires a
  separately ratified live-successor signer, durable consume-once nonce,
  external monotonic rollback anchor, atomic STOP lease, and exact sealed
  composition.
- The TenderPlan owner-canary result is a digest/count capability observation,
  not a tender import or lead. Raw values are not persisted or returned to the
  parent, and Source Lab, Bitrix, contact, spend, and external-write effects
  remain zero.
- The manual canary is exactly one no-retry request with at most five sampled
  identity digests and no Source Lab or CRM write. Credentials stay in Windows
  Credential Manager and must never be pasted into chat, code, documentation,
  fixtures, or test output. It keeps `automatic_schedule_eligible=False` and
  `live_release_eligible=False`.
- The separate encrypted review intake is also exactly one owner-invoked,
  no-retry request. It validates a durable intent before PAT/network access and
  returns only ciphertext envelopes to the parent. The queue contains no query,
  PAT, raw response, contact fields, or plaintext card. It supports only local
  per-item review and remains outside the sensor mesh. Its 30-day display gate
  is not secure-erasure evidence; DPAPI wrapping is neither HSM custody nor a
  non-exportable/destroy guarantee. Both eligibility flags remain false.
- `READ_ONLY_API` remains behind the existing unratified default-deny authority
  fence.
- The registry evidence is caller-supplied digest evidence until a persistent
  signed governance registry is connected.
- Factory-origin reservation and receipt attestations prevent public-dataclass
  replacement inside the current process. They are not durable signatures and
  do not prove that an external provider authored the data.
- The external monotonic anchor, quota authority, and continuation-rotation
  authority are injected interfaces. Migration, stream-repair, vault-lifecycle,
  key-retirement, and absence-observation boundaries are also explicit. The
  repository contains deterministic offline fixtures, not production remote
  anchors, KMS custody, backup authorities, or owner-signing services. Without
  the required configured boundaries the ledger remains local-only and vault
  activation is denied.
- A transport-neutral signed-boundary foundation is present but remains
  `live_release_eligible=False`. It uses exact canonical JSON, three distinct
  Ed25519 principals for immutable approvals, deployment-pinned trust bundles,
  and a separate active-signer current-head inclusion bound to an unpredictable
  challenge. Historical receipts are checked at their stored consumption cut;
  they are never made "fresh" by reusing their own timestamp.
  An offline governed custody now records predecessor-signed approval and
  anchor trust-bundle successors/revocations and separate changes to their
  `maximum_clock_skew_seconds`. A policy-bound composition can now construct
  the exact approval and anchor adapters from one verified head; its fence
  reopens and verifies that store before nonce reservation and every transport
  method, and permanently quarantines the composition after an observed
  mismatch. This is not an authenticated deployment, distribution, or
  revocation service, does not hot-swap an existing ledger pin, and has no
  external rollback authority. A byte-for-byte same-path rollback to the
  expected head that was not observed by the process remains indistinguishable
  without an external monotonic authority. Production trust-bundle rollout,
  revocation propagation, clock-skew rollout, and rollback authority remain
  explicit live-release blockers.
- The signed ledger composition is deliberately representative rather than
  complete: it covers the external anchor and continuation rotation through an
  anchored `AUTH_INTENT`, authoritative readback, and atomic business/approval
  acknowledgement. Quota epochs, migration, repair, absence, and key-lifecycle
  governance still use the offline authority contracts and therefore remain
  live-release blockers. Ledger schema v4 is a storage-layout break and a
  new-store boundary; no automatic v3-to-v4 data migration is claimed. The
  separate `SOURCE_READ_LEDGER_PROTOCOL_VERSION` remains the
  `source-read-ledger-v3` wire/domain label for compatibility; it must not be
  interpreted as permission to open a schema-v3 store with the schema-v4 code.
  Because this repository does not embed the canonical v3 schema and semantic
  mapping, the manual rehearsal is verification-only: it allowlists the exact
  supplied v3 schema, proves a bounded source manifest, creates a separate
  empty v4 store, transfers no data or authority, and keeps both manifest and
  receipt `live_release_eligible=False`. A reviewed full export, semantic
  mapping, import, and reconciliation remain live-release blockers.
  The separate bootstrap path creates only a new empty v4 ledger and an
  exclusive canonical sidecar bound to the exact policy head, trust bundles,
  independent skews, ledger path, store identity, schema and fingerprint. It
  never adopts an existing or partial store and performs no business-data or
  authority migration.
- The legacy/default signed anchor and approval fixtures retain a bounded
  in-process replay window of 4096 challenges. When explicitly configured, the
  durable local replay store commits a challenge before transport and rejects
  replay after restart without that fixed in-memory cap. It is still
  single-file SQLite custody with no high availability, external monotonicity,
  or compaction protocol; production and high-volume challenge custody remain
  live-release blockers.
- The signed KMS boundary is likewise an opt-in canary. It verifies signed
  lifecycle heads, independent signed retirement approval, exact CAS readback,
  response-loss replay, signer/data-key separation, and local-vs-authority key
  state before plaintext verification. Its configured provider still exports
  32-byte encryption and audit keys into Python; it is not a non-exportable HSM
  API, does not prove physical destruction, and does not make the vault live-
  release eligible.
- The offline foundation manifest verifies a fixed workspace-relative file
  allowlist, exact SHA-256 values, schema pins, live guards and a pinned local
  toolchain. `python scripts/verify_mdos_v7_offline_foundation.py --full` runs
  its fixed pytest, Ruff, format and compile commands with package indexes and
  conventional network proxies disabled. It does not grant a hard network
  sandbox. The manifest is locally resealable and therefore is neither a
  publisher signature nor an independent release attestation.
- SQLite integrity and quota custody still require one configured canonical
  file. This is not a distributed quota service. Rollback protection applies
  only when the same ledger is connected to its pinned external anchor.
- The encrypted runtime vault requires an explicit keyring; it never discovers
  keys or credentials. Controlled A→B retirement first fences new work, rewraps
  the complete verified dependency inventory, anchors the exact seal, performs
  external custody CAS/readback, and only then accepts B-only reopen. A stale
  A writer and old vault snapshot are rejected. This is an offline lifecycle
  protocol, not a production KMS implementation.
- A successor key is only a candidate until the ledger has anchored its exact
  writer-epoch transition, the vault has registered that candidate under the
  transition proof, and the ledger has anchored the registration ACK. The
  unresolved transition is a global dispatch hold. Every later PREPARED,
  operation, and last-moment boundary authorization binds the finalized writer
  epoch, so restoring a pre-registration vault cannot make A authoritative
  again after B was finalized.
- Cancelling an incomplete routine retirement never rolls an append-only
  writer epoch back. A stale request cancelled before successor registration
  leaves A as the exact finalized writer under the newly anchored writer head.
  Once B registration is acknowledged and B is finalized, cancellation leaves
  B as the only permitted encryption writer while A is retained for decryption
  and may be retried for retirement through the `SUCCESSOR_ALREADY_ACTIVE`
  path. Re-authorizing A after that point would require a distinct governed
  writer epoch or new key identity; it is not part of this slice.
- A routine retirement that reached local SEAL but did not obtain the anchored
  retirement intent may be cancelled only through append-only vault and ledger
  acknowledgements proving that the external custody CAS is still unchanged.
  Compromise containment never has this return-to-service cancellation path.
- Controlled pre-destruction compromise containment is fail-closed and may
  proceed only from a clean, aligned, final vault/ledger head. Detection is
  anchored before alignment or SoD calls. If a read hold, stream incident,
  stale containment state, unavailable key, or whole-vault rollback already
  exists, detection becomes a permanent global fence: no retirement/custody
  authority is minted and no new read is allowed. Autonomous compromise
  recovery is not claimed, and no path may cancel such a fence back to the
  compromised key.
- Production key destruction additionally requires an independently durable,
  encrypted successor replica/backup attestation and a restore drill. The
  ledger stores commitments, not replacement ciphertext; after vault loss it
  can prove divergence but cannot recreate cursor/runtime plaintext.
- A custody CAS that entered the external boundary before a later compromise
  fence cannot be recalled by the local ledger. Production custody therefore
  needs a monotonic compromise-generation precondition; this offline slice
  treats such an in-flight completion as quarantined evidence, never as an
  authorization to resume reads.
- The offline vault performs a non-creating local absence observation, but that
  observation is not an independent owner approval. Production quarantine and
  repair require a separately authenticated SoD authority with deterministic
  readback.
- Vault history is deliberately bounded and append-only. There is not yet an
  anchored compaction/archive protocol or a production-scale incremental
  verifier, so long-running high-volume operation remains blocked before the
  per-slot generation ceiling or retirement-inventory ceiling is approached.
- Signed anchor and approval adapters keep the bounded 4,096-challenge replay
  set only on their legacy/default path. An explicitly configured durable
  replay store reserves before transport, persists across restart, and fails
  closed at its configured capacity without silently dropping history. It does
  not replace the reviewed HA or externally monotonic nonce custody still
  required for production/high-volume use.
- Quota-epoch and key-rotation authorities must replay the exact same approval
  after a crash between authority return and local commit. The current abstract
  boundary records this operational requirement but does not ship a production
  availability/idempotency service.
- Expired authorization creates a durable ledger quarantine disposition,
  retains the complete uncertain quota hold, and permits only reconciliation or
  governed operator handling.
- If an openable canonical vault loses or diverges from the exact encrypted
  generation for an already final anchored ledger head, the coordinator
  records an append-only stream incident and never rereads the page. Complete
  whole-file absence is narrower: `open_existing` refuses to create genesis,
  so startup remains globally fail-closed with zero dispatch, but this slice
  cannot append a per-stream incident without a separately pinned non-creating
  backup/custody observer. Repair requires an exact encrypted recovery source,
  a new PREPARED generation, anchored repair binding, vault activation proof,
  and a second external approval. Digest-only ledger state cannot manufacture
  a raw cursor.
- The executable offline repair path is intentionally narrower: it may recover
  only from the exact ledger-authorized, state-equivalent physical ACTIVE
  predecessor (including the state-preserving one-step rollback of a
  ledger-bound migration or rekey). A prior page, empty vault, deeper rollback,
  or unavailable predecessor creates no repair intent or vault fence and
  remains under the existing full hold until an independently attested
  encrypted-backup import protocol exists.
- A registry/capability revision may inherit an open continuation only through
  the factory-derived migration checkpoint, exact prior anchored head, exact
  encrypted PREPARED target, full old/new registry rights profiles, external
  separation-of-duties receipt, anchored lineage CAS, and vault activation.
  The current migration is deliberately rights-neutral: provider, account,
  stream, authorization and receipt, content binding, quota epoch/policy,
  purpose, privacy, retention, source-contract semantics, sensor limits, and
  cursor position must remain exact. Authorization, content, quota, or stream
  changes require a new governed stream; mixed historical authority is not
  supported.
- Time is required to be canonical and non-decreasing inside the ledger, but a
  trusted external wall-clock/monotonic-time authority is not connected.
- Sensor output is not automatically committed to Source Lab and never reaches
  Gold, the GDO queue, Bitrix, contact, advertising, or spend.
- Service-specific mapping accuracy and commercial usefulness still require
  bounded observed pilots and independent outcomes.

## 8. Gate for automated or production reads

The owner-only TenderPlan canary above is a bounded diagnostic exception, not
evidence that this gate has passed. It cannot schedule another request or
promote its result into the sensor mesh. For each automated account and atomic
operation the owner must provide or approve:

1. provider/account and dependency-family identity;
2. exact product/tariff and trial start/end/cancellation deadline;
3. terms/licence and data-lifecycle evidence;
4. authentication reference held outside this code;
5. operation contract/schema and quota;
6. allowed data class, purpose, region/product scope, retention, and exclusions;
7. a small operation/record/byte cap and human owner;
8. a synthetic fixture and expected mapping before a read canary;
9. a production-operated monotonic anchor with stable store identity, CAS,
   recovery procedure, availability, and rollback response;
10. an external vault keyring and custody process, including rotation,
    retirement, encrypted successor backup, restore drill, incident response,
    compromise fence, and approved key-destruction evidence;
11. exact SoD authorities for quota epochs, continuation rekey/migration,
    stream repair, and key lifecycle, with deterministic idempotent readback
    after partial failure;
12. a successful offline restart drill proving page N+1, uncertain recovery,
    anchor recovery, quarantine, and zero duplicate boundary calls;
13. the implemented rights-neutral procedure for a registry/capability-only
    revision, and a separate new-stream procedure for authorization, content,
    quota, purpose, privacy, or contract changes;
14. an independently durable encrypted recovery source for every continuation
    that must survive key retirement or local vault loss.
15. real authenticated transports for the signed anchor, approval authority,
    and KMS boundary, plus a reviewed trusted clock and CSPRNG challenge source;
16. a rehearsed ledger v3-to-v4 rollout, governed trust-bundle and signer-key
    rotation, durable signed-evidence export, monitoring, and restore drills.

Only after those facts pass registry, policy, security, and adapter preflight
may a separately authorized automated process enable one bounded external
read.

## 9. Acceptance for the offline mesh slice

This slice is accepted only when executable tests prove all of the following:

- two accounts and two independent READ capabilities of the same provider can
  coexist without inheriting one another's rights;
- provider-family ceilings aggregate across accounts and capabilities;
- plan order does not change fair round-robin allocation or content hashes;
- the sensor accepts only an exact projection of one sealed canonical registry
  snapshot and one exact adapter authorization/receipt pair;
- stale, unverified, non-READ, paid, contact-capable, write-capable, mismapped,
  partially projected, or caller-resealed bindings fail before dispatch;
- an uncertain page does not move the checkpoint and permits only
  reconciliation, never an automatic retry;
- a pre-dispatch reservation and dispatch-intent are durably committed before
  the only possible adapter boundary call;
- competing coordinators against the same canonical ledger can produce only
  one dispatch winner for a semantic source position;
- after any crash or post-intent ambiguity, the next action is
  `RECONCILE_ONLY` or `RUNTIME_REHYDRATION_REQUIRED`, never a blind retry;
- an accepted or uncertain runtime mutation is encrypted before its rollback
  fence returns, then bound to the exact ledger outcome and external anchor
  before it becomes restorable;
- a fresh process restores the exact active continuation and can produce page
  N+1 while the page-N boundary call count remains one;
- PREPARED-only, historical, wrong-key, wrong-command, wrong-checkpoint,
  wrong-operation, stale-anchor, copied-vault, and copied-ledger states fail
  closed before decryption, activation, or dispatch;
- controlled key retirement rewraps every exact dependency, anchors the sealed
  inventory, admits one custody-CAS winner, supports crash resume, and permits
  B-only reopen while stale A writers and prior vault snapshots fail closed;
- writer-epoch transition admits one A→B or A→C CAS winner, blocks dispatch
  until vault registration is acknowledged and anchored, pins the finalized
  epoch in every operation and encrypted generation, and rechecks it inside
  the one-shot STOP fence immediately before provider entry;
- cancellation before successor registration preserves A as the exact active
  writer but advances its anchored writer head; subsequent A PREPARED,
  activation, restart, and page N+1 must bind that non-genesis head;
- if routine retirement is cancelled after local SEAL but before custody CAS,
  the append-only cancellation is anchored and acknowledged by both stores,
  releases only the retirement fence, leaves B as the sole writer epoch, and
  keeps A available for controlled decryption but permanently stale for
  writes; a retry retires A against the already-active B writer without
  advancing the writer epoch again;
- compromise detection fences new work before containment dependencies are
  consulted; a non-clean stream remains under full-hold permanent quarantine
  and cannot reach vault BEGIN or external custody CAS in this slice;
- an authorization expiry produces an append-only quarantine event and keeps
  the full operation/record/byte hold;
- snapshot, request-key, idempotency-key, or quota-epoch rotation cannot create
  a second dispatch or reset completed/pending quota custody;
- an exact rights-neutral registry/capability migration preserves checkpoint
  position and performs zero provider calls across PREPARED, ledger-bind,
  ACTIVATE, restart, replay, and competing-writer cuts;
- migration rejects any authorization, content, purpose, privacy, contract,
  quota, provider/account/stream, sensor-policy, or unrelated-capability rights
  drift; a ledger-bound target whose ciphertext is missing is durably
  quarantined without a provider call;
- stream repair authorizes and anchors the exact repair id, target position,
  and eligible physical ACTIVE predecessor before any vault fence; PREPARED and
  that fence commit atomically, and the incident cannot clear until the ledger
  verifies an exact vault activation acknowledgement plus a second governed
  completion receipt;
- response loss between repair intent, the atomic PREPARED/fence commit, ledger
  acknowledgement, vault activation, and ledger completion is recovered by
  unique factory readback from the anchored repair id/proof; recovery never
  asks a caller to reproduce a randomized envelope digest;
- an empty, missing, deeper-rollback, prior-page, or otherwise state-changing
  physical predecessor fails before repair SoD, PREPARED, fence, custody, or
  provider effects, while the original stream incident and full quota hold
  remain durable;
- page output contains only the allowlisted digest envelope and no raw payload,
  contact identifier, credential, cursor token, or provider error text;
- the sealed result recomputes page, observation, checkpoint, usage, and global
  zero-effect totals and cannot be forged by replacing a public dataclass;
- actual `SourceAdapterRuntime` plus exact `FixturePageBoundary` is exercised in
  at least one integration test; mocks alone are insufficient;
- a trust-bundle successor is authorized only by the exact predecessor bundle,
  cannot reactivate a revoked key or reuse a principal across approval and
  anchor boundaries, and is recovered through exact replay, CAS, and readback;
- approval and anchor clock-skew transitions are authorized and advanced
  independently, while stale, replayed, cross-boundary, or forged transitions
  fail closed and every result remains `live_release_eligible=False`;
- the v3-to-v4 rehearsal verifies an allowlisted bounded v3 manifest, creates
  only a separate empty v4 store, rejects tamper/overwrite/alias/future-schema
  states, and proves that no business data, rights, or authority were moved;
- configured durable challenge custody reserves before transport, survives
  restart and response loss, and rejects same-boundary and cross-boundary
  replay while retaining `live_release_eligible=False`;
- policy-bound composition uses the exact current approval and anchor bundles,
  independent skews and runtime capabilities; stale/copy/tamper states fail
  before nonce reservation or transport, and an observed mismatch permanently
  quarantines that composition;
- new-store bootstrap creates only an empty schema-v4 ledger and its exclusive
  sidecar, binds the exact ledger and policy identities through readback, and
  rejects existing, partial, copied, resealed, stale, or forged states;
- the canonical offline-foundation manifest rejects missing, extra, unsafe,
  duplicated, changed, schema-divergent or live-eligible entries and runs only
  its fixed local verification command set;
- no code path writes Source Lab, the experiment ledger, Bitrix, contacts a
  person, publishes content, spends money, reads credentials, or opens network.
