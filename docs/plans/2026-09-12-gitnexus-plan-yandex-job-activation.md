# GitNexus Engineering Plan

> Task: Implement an audited, local-only activator that converts one exact inert Yandex draft into a native-authority-compatible manual job without making a provider request.
> Evidence verified at commit `43a06711c16654f638718b84ab4430ba320e7583`; repo-local GitNexus workspace index is fresh at that commit after `analyze --index-only --pdg`. The global MCP registry reported an older commit and is non-load-bearing.
> Evidence provenance schema 2; global dirty digest `0a9c85780067d9afcd0764f307b60891e3cee927ee11eaeb5ec7826d10fd82cd`; cited-path manifest 17 sorted entries; exact generated plan path excluded.

## 1. Objective

- [verified] Add `source yandex-activate` as a strictly local transition from `PREPARED_NOT_ACTIVATED` to an exact native Yandex job. It must create no credential read, HTTP, reservation, spend, CRM/outbox/contact action, schedule, or automatic `run-one`.
- [inferred] The command should consume one content-addressed evidence bundle from a fixed trusted state path, validate owner/reviewer/readiness separation and bindings, install the exact request plus retention pin, and publish the root live pin only as the final commit point.
- [inferred] A successful activation should return `ACTIVATED_AWAITING_EXPLICIT_RUN_ONE`, `authority_verified=true`, `launch_allowed=false`, and safe hashes only; a provider read remains a separate command and confirmation.

## 2. Current Behaviour

- [verified] `prepare_inactive_yandex_job` creates only `request.draft.json`, an empty `request.sqlite`, and an empty `dispatch-claims`; its result explicitly denies launch and lists five missing gates (`lead_factory/radar_yandex_job_preparer.py:30-82`, `lead_factory/radar_yandex_job_preparer.py:218-252`, `tests/test_lead_factory_radar_yandex_job_preparer.py:98-203`).
- [verified] A draft is immutable, tied to one deterministic UUID/idempotency key, exact query/region, current connection and runtime hashes, and expires after six hours (`lead_factory/radar_yandex_job_preparer.py:398-494`, `lead_factory/radar_yandex_job_preparer.py:497-570`).
- [verified] Native authority currently reads `request-activation.json`, then exact `request.json`, and validates path, hash, limits, journal/claims identities, code hashes, receipts, roles, readiness, time, and expiry before returning `_ManualData` (`lead_factory/radar_yandex_connection_authority.py:132-226`).
- [verified] `verify_manual_grant` is not a neutral validation probe: it creates and retains a grant in `_GRANTS` (`lead_factory/radar_yandex_connection_authority.py:349-360`).
- [verified] The launcher exposes `yandex-prepare/status/purge`, but no activation route. Direct Python is provenance-gated only for `run-one` and `yandex-prepare` (`scripts/run_source_discovery_once.py:58-72`, `scripts/run_source_discovery_once.py:160-218`, `scripts/run_source_discovery_once.py:268-322`).
- [verified] The Windows launcher has an exact allowlist, fixed argument validation, ambient credential scrubbing, exact repo-local Python bootstrap, and a marker set only after bootstrap (`scripts/run_safe_lead_flow.ps1:1-80`, `scripts/run_safe_lead_flow.ps1:162-228`).
- [verified] The present ACL helper intentionally accepts only the three-file inert job layout and rejects `request.json` and `retention-activation.json`; it must not be weakened (`scripts/check_yandex_state_acl.ps1:196-334`).

## 3. Relevant Architecture

- [verified] Trusted state is derived from the actual OS profile rather than `HOME`/`USERPROFILE`; canonical reads reject relative paths, reparses, duplicate JSON keys, oversized inputs, and identity changes (`lead_factory/radar_yandex_pilot_authority.py:51-85`, `lead_factory/radar_yandex_pilot_authority.py:95-189`).
- [verified] Runtime fingerprints include every `lead_factory/*.py` plus an explicit launcher/helper list. Adding the activator changes the fingerprint automatically; adding a PowerShell helper requires adding it to `_LAUNCHER_FILES` (`lead_factory/radar_yandex_connection_authority.py:28-73`).
- [verified] The live request schema is exact and permits one request, 49 kopecks maximum/reserve, and 24-hour raw retention. Owner scope binds policy, journal path and identities, workspace, claims, and connection (`lead_factory/radar_yandex_connection_authority.py:146-218`).
- [verified] Per-job `retention-activation.json` is a maintenance/privacy binding only. It has precedence over root/archive candidates, and an invalid preferred pin cannot fall back; exactly one unique matching hash is required (`lead_factory/radar_yandex_maintenance.py:109-159`).
- [verified] The root `request-activation.json` is the live permission consumed by native authority (`lead_factory/radar_yandex_connection_authority.py:132-145`). Therefore `request.json` and retention pin can exist inertly before the root pin.
- [verified] The documented local trust boundary does not defend against a malicious process running as the same OS user or whole-state rollback (`lead_factory/radar_yandex_connection_authority.py:1-7`, `docs/RADAR_YANDEX_PERMANENT_CONNECTION.md:208-210`).

## 4. GitNexus Findings

- [graph] Repo-local `status` at `43a0671` reported `Status: up-to-date`; the branch label in index metadata is older but the indexed and current commits are identical. The global resource registry reported `a4d48c3`/22 commits behind, so only repo-local CLI outputs are used as load-bearing graph evidence.
- [graph] `query Yandex-activation-evidence --repo . --limit 8` located `_verify_request`, the existing activation tests, and the preparer as the primary path.
- [graph] `context _verify_request --repo .` shows direct use by `_verified_data`, which feeds freshness, grant issuance, source check, and accounted execution. `impact _verify_request --direction upstream --depth 3 --repo .` returned 12 impacted symbols, one affected process, `risk: LOW`, `epistemic: exact`; source validation still governs the change.
- [graph] `impact Function:scripts/run_source_discovery_once.py:main --direction upstream --depth 3 --include-tests --repo .` returned `risk: HIGH`, 17 upstream impacts, and 15 direct dependents. Every direct dependent is in the file entry plus `tests/test_lead_factory_safe_lead_flow_launcher.py` and `tests/test_lead_factory_source_discovery_control.py`; both complete modules are mandatory regression targets.
- [graph] `context _retention_activation --file lead_factory/radar_yandex_maintenance.py --repo .` found one direct caller, `_open_bound_journal`; the source confirms preferred-per-job fail-closed precedence.
- [graph] `context _write_new --file lead_factory/radar_yandex_job_preparer.py --repo .` found one direct caller, `_prepare_core`; its exclusive-create, fsync, identity, and cleanup pattern is the publication model for new stable artifacts.
- [graph] Cluster/process resources were read for the deep plan but came from the stale global registry. The exact repo-local flow extraction is known to be truncated, so the plan relies on direct impacts plus source and test reads rather than claiming complete process coverage.

## 5. Statement-Level PDG Findings

- [graph] `pdg_query(mode=controls,target=_verify_request,limit=100)` returned 28 control edges. Fail-closed branches cover inactive pin, path/hash mismatch, scope, expiry, limits, policy, journal identities, code hashes, separation of duties, readiness, and receipt freshness at `lead_factory/radar_yandex_connection_authority.py:138-225`.
- [graph] Unified PDG impact anchored at line 211 returned `risk: UNKNOWN`, 12 upstream-dependent statements, no unresolved local block projections, and truncation by depth. This is not a safety clearance; the relevant statements were source-verified at `lead_factory/radar_yandex_connection_authority.py:132-226`.
- [verified] `_verify_request` reads the connection and root pin before the job, validates all structural/evidence bindings, creates `_VerifiedData`, then advances the journal's monotonic clock before its final expiry denial (`lead_factory/radar_yandex_connection_authority.py:132-226`, `lead_factory/radar_yandex_pilot_authority.py:509-520`).
- [inferred] Candidate validation must use the same core rules without issuing a grant. Any journal/SQLite mutation or failure must occur before publishing the root pin.
- [inferred] Publication ordering is a safety invariant: evidence/draft checks → exact `request.json` → candidate native validation → exact per-job retention pin → complete revalidation → root pin last → post-publication readback. No rollback may delete a published root pin.
- [graph] `explain(target=_verify_request)` returned zero persisted taint findings, with explicit caveats for closure, property, and implicit flows; absence is not evidence of safety.

## 6. Proposed Changes

### `lead_factory/radar_yandex_connection_authority.py`

- [verified] Refactor existing `_verify_request` so its root-pin reader delegates to one new private validator that accepts an already-read exact pin and performs the current request/receipt/journal/code checks without creating a grant.
- [inferred] The activator will call that same validator after publishing inert `request.json` and before root activation; `_verify_request`, `_verified_data`, `verify_manual_grant`, and all runtime callers retain their public behavior.
- [inferred] Add `scripts/check_yandex_activation_acl.ps1` to `_LAUNCHER_FILES`; keep the complete sorted code hash contract.

### `lead_factory/radar_yandex_job_activator.py` (new)

- [inferred] Add `activate_prepared_yandex_job(job_id, expected_draft_sha256, expected_scope_sha256, evidence_sha256, *, confirmation)` and a bounded sanitized `YandexJobActivationError`.
- [inferred] Resolve only canonical paths under `_STATE_ROOT`. Evidence must be the exact file `activation-evidence/<job_id>/<evidence_sha256>.json`; no caller-supplied path, query, region, folder ID, time, receipt JSON, or credential is accepted.
- [inferred] Require an exact versioned evidence-bundle wrapper binding `job_id`, `draft_sha256`, `scope_sha256`, and the three existing strict nested receipts. The bundle's bytes must hash to the CLI digest. It is consumed, never created or modified, by the activator.
- [inferred] Require owner and readiness timestamps at or after draft creation; permit independent code review within the native verifier's 24-hour pre-draft window so exact-code review can precede draft creation; require every receipt timestamp at or before the single pinned activation time.
- [inferred] Reuse the preparer's intrinsic `_load_published` validation for draft, policy, code, connection, journal and claims. Recheck expected draft/scope hashes explicitly and do not extend expiry or recreate the journal.
- [inferred] Canonically project the bundle receipts into the existing strict `radar-yandex-manual-request-v1` manifest; preserve draft request, policy, limits, identities, action, endpoint and forbidden effects unchanged.
- [inferred] Publish each stable file through a same-directory exclusive stage, file fsync, exact readback/identity check, and no-replace rename. Exact existing bytes are replay; different bytes are conflict.
- [inferred] Support safe exact retry from four states: draft only, request installed, retention pin installed, or fully active. Once a retention pin exists, reuse its exact activation bytes/time rather than minting a new value.
- [inferred] Reject any root pin for another job, even if expired. Rotation/revocation is a separate explicitly confirmed future operation.
- [inferred] Before root publication, repeat source hashes, ACL, connection, evidence bundle, request, journal policy/identity/zero accounting, and empty claims checks. Publish `request-activation.json` last.
- [inferred] After root publication, re-read and run native `_verify_request` without `verify_manual_grant`; a late uncertainty returns `YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED` and never removes/replaces the pin.
- [inferred] Return only job/draft/scope/request/policy/activation hashes, expiry, created/replayed booleans, and explicit zero-effect flags.

### `scripts/check_yandex_activation_acl.ps1` (new)

- [inferred] Derive the trusted OS profile internally and accept only canonical lower-case UUID, evidence SHA-256, and a fixed phase enum; never accept a filesystem path or read credential/evidence contents.
- [inferred] Reuse the existing exact owner/current-SID+SYSTEM ACL model. Validate fixed evidence directories/file and exact phase layouts: draft (`draft/sqlite/claims`), request partial, retention-ready (`+request.json+retention-activation.json`), and active (`+root request-activation.json`). Reject reparses, unexpected job entries, stage residue, non-empty claims, or wrong inheritance.
- [inferred] Keep `check_yandex_state_acl.ps1` unchanged so preparer replay remains an inert-layout proof.

### `scripts/run_source_discovery_once.py`

- [verified] Extend `_parser` and existing `main` with `yandex-activate`; add it to `_LOCAL_YANDEX_COMMANDS`, launcher-marker gating, dispatch, and the sanitized local-only exception group.
- [inferred] Accept exactly `job-id`, expected draft SHA, expected scope SHA, evidence SHA, and a boolean final-activation confirmation; never echo values in failures.

### `scripts/run_safe_lead_flow.ps1`

- [verified] Add one exact allowlisted route and fixed-order nine-token activation contract. Include `yandex-activate` in the post-bootstrap marker set while preserving pre-bootstrap ambient key scrubbing.
- [inferred] Reject count/order/case/UUID/SHA/confirmation errors before child dispatch with only `SAFE_LEAD_FLOW_FAILED`.

### Tests and documentation

- [verified] Extend native authority, launcher/source CLI, preparer, and maintenance regressions at the existing located test modules. Add a dedicated activator suite.
- [verified] Replace the runbook's “future activator” GAP with exact evidence placement, activation, check, and run-one separation; retain the one-source-at-a-time and 30,000-ruble monthly boundary (`docs/SAFE_LEAD_FLOW_LAUNCH_RUNBOOK.md:1-27`, `docs/SAFE_LEAD_FLOW_LAUNCH_RUNBOOK.md:450-475`, `docs/RADAR_YANDEX_PERMANENT_CONNECTION.md:75-119`).

## 7. Implementation Sequence

1. Run fresh GitNexus impact for `_verify_request`, `_verified_data`, `_code_files`, `_parser`, and `main` immediately before their edits; stop and report any new HIGH/CRITICAL production impact.
2. Extract the supplied-pin native validator inside `radar_yandex_connection_authority.py`, preserving root-pin runtime order and grant semantics. Add focused authority tests before adding the activator.
3. Implement the separate activation ACL helper and its parser/negative/phase-layout tests. Do not change the inert helper.
4. Implement the activator's strict input/bundle schemas, canonical path derivation, draft reuse, exact request projection, exclusive publication/replay, revalidation, and root-pin-last state machine.
5. Add fault-injection and concurrency tests for every partial boundary before integrating the command surface.
6. Add the Python CLI route and safe Windows launcher route with exact argument grammar and sanitized output; update every direct `main` consumer regression.
7. Update maintenance and preparer cross-boundary tests to prove retention precedence, active-layout separation, and that an active job can never be replayed as an inert draft.
8. Update both runbooks with the fixed evidence path/schema, six-hour operating window, no-rotation v1 rule, activation output, and separate provider-read confirmation.
9. Run targeted tests, complete modern Lead Factory regression, Ruff, byte compilation, Windows PowerShell 5.1 parsers, bootstrap `-CheckOnly`, and read-only ACL probes.
10. Run `detect-changes --scope all`; review every changed symbol/process, then commit. Re-index exact commit, obtain independent exact-head security/code acceptance, and merge normally. Only after final merge/code freeze create a new real draft and evidence; never activate a pre-change draft.

## 8. Test Strategy

### New activator suite

- Exact bundle + exact inert draft → request and identical retention/root pin bytes → native verifier accepts → no grant, credential, HTTP, reservation, spend, CRM, outbox, contact, or schedule.
- Missing/extra/tampered bundle fields; digest mismatch; wrong job/draft/scope/code/connection/folder binding; reviewer equals owner/author; duplicate authors; non-ACCEPT; suspended billing; unverified API; unavailable credential → zero root activation.
- Owner/readiness before draft; any receipt after activation; expired draft; code/connection drift; non-empty journal/accounting/claims; wrong identity → fail closed before root pin.
- Failure before stable request → own stage cleaned; failure after request → inert partial retained and exact retry completes; failure after retention → exact pin bytes reused; failure/readback uncertainty after root → reconciliation required and pin preserved.
- Two concurrent identical invocations → one creation and one exact replay; different evidence/request/pin → conflict with no overwrite.
- Existing root pin for another job → conflict with no automatic expiry-based replacement.
- Exceptions, stderr, traceback locals, and JSON never contain query, region, folder, paths, identity labels, evidence contents, or credential markers.

### Existing regression suites

- [verified] Native negative matrix and all runtime file hashes: `tests/test_lead_factory_radar_yandex_connection.py:535-635`.
- [verified] Expiry/clock and cross-process claim winner: `tests/test_lead_factory_radar_yandex_connection.py:787-837`.
- [verified] Draft immutability, drift, races, partial cleanup, and ACL isolation: `tests/test_lead_factory_radar_yandex_job_preparer.py:206-543`.
- [verified] Retention-pin precedence and no fallback: `tests/test_lead_factory_radar_yandex_maintenance.py:27-100`.
- [verified] Exact launcher allowlist, direct-Python marker, and malformed input rejection: `tests/test_lead_factory_safe_lead_flow_launcher.py:69-140`, `tests/test_lead_factory_safe_lead_flow_launcher.py:346-500`, `tests/test_lead_factory_safe_lead_flow_launcher.py:680-752`.
- [verified] Source CLI native check/maintenance and sanitization: `tests/test_lead_factory_source_discovery_control.py:314-569`.

### Verification commands

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_lead_factory_radar_yandex_job_activator.py tests/test_lead_factory_radar_yandex_job_preparer.py tests/test_lead_factory_radar_yandex_connection.py tests/test_lead_factory_radar_yandex_maintenance.py tests/test_lead_factory_safe_lead_flow_launcher.py tests/test_lead_factory_source_discovery_control.py
$Modern = Get-ChildItem -LiteralPath tests -Filter 'test_lead_factory_*.py' | Where-Object Name -ne 'test_lead_factory_legacy_canary_guard.py' | ForEach-Object FullName
.\.venv\Scripts\python.exe -m pytest -q @Modern
.\.venv\Scripts\ruff.exe check lead_factory/radar_yandex_connection_authority.py lead_factory/radar_yandex_job_activator.py scripts/run_source_discovery_once.py tests/test_lead_factory_radar_yandex_job_activator.py tests/test_lead_factory_radar_yandex_connection.py tests/test_lead_factory_safe_lead_flow_launcher.py tests/test_lead_factory_source_discovery_control.py
.\.venv\Scripts\python.exe -I -B -m py_compile lead_factory/radar_yandex_connection_authority.py lead_factory/radar_yandex_job_activator.py scripts/run_source_discovery_once.py
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap_python_runtime.ps1 -CheckOnly
node .gitnexus/run.cjs detect-changes --scope all --repo .
```

- [verified] The repo-local runtime currently exists as CPython 3.11.9 with pytest 9.0.2 and Ruff 0.15.17; 120 modern Lead Factory test files are discoverable excluding the legacy config-dependent canary.
- [inferred] Parse `run_safe_lead_flow.ps1`, `check_yandex_state_acl.ps1`, and the new activation helper with the Windows PowerShell 5.1 parser; run the new helper against synthetic phase fixtures and the root-only real read-only probe.

## 9. Risk and Impact Analysis

- [graph] `scripts/run_source_discovery_once.py:main` is HIGH impact with 15 direct dependents. Compatibility requires additive routing, unchanged existing outputs, and complete launcher/source test modules.
- [verified] `_verify_request` guards every provider path through `_verified_data`; a validation-order regression can move key/HTTP access ahead of authority. Preserve its entry interface and rerun the full native connection suite (`lead_factory/radar_yandex_connection_authority.py:229-247`, `lead_factory/radar_yandex_connection_authority.py:353-383`).
- [inferred] Filesystem and SQLite cannot share one transaction. Root pin is therefore the only commit point; all mutable journal checks must finish before it, and post-pin failure cannot be rolled back automatically.
- [inferred] `threading.RLock` is insufficient across processes. Correctness must derive from exclusive no-replace publication and exact-byte convergence.
- [verified] A per-job retention pin changes maintenance precedence. Invalid or mismatched preferred bytes intentionally block maintenance rather than falling back (`lead_factory/radar_yandex_maintenance.py:109-159`).
- [verified] Adding any Python production file changes current code hashes. No draft created before the final exact commit can be activated (`lead_factory/radar_yandex_connection_authority.py:41-73`, `lead_factory/radar_yandex_job_preparer.py:478-493`).
- [inferred] The six-hour draft window couples owner confirmation, readiness observation, evidence bundling, and activation. Independent exact-code review should be completed immediately before the real draft.
- [assumed] V1 evidence provenance trusts the existing single-Windows-user operator boundary and content-addressed local artifacts; it does not add public-key signatures. This limitation must be explicit before real activation.
- [verified] One job is capped at 49 kopecks, but no unified multi-source monthly spend ledger exists; this work must not authorize a second paid source or relax the 30,000-ruble portfolio cap (`docs/SAFE_LEAD_FLOW_LAUNCH_RUNBOOK.md:7-16`).
- [inferred] Automatic rotation of an old root pin is excluded. A later rotation feature must prove old accounting/retention and receive separate confirmation.

## 10. Files Expected to Change

| File | Symbols | Reason |
| ---- | ------- | ------ |
| `lead_factory/radar_yandex_connection_authority.py` | `_code_files`, `_verify_request` plus one new private supplied-pin validator | Share native validation without grant creation; hash the new helper. |
| `lead_factory/radar_yandex_job_activator.py` | new module entrypoint and internal state machine | Consume exact evidence and publish request/retention/root pin safely. |
| `scripts/check_yandex_activation_acl.ps1` | new script | Verify fixed evidence and transitional/active layouts without weakening draft ACL. |
| `scripts/run_source_discovery_once.py` | `_parser`, `main` | Add the local activation route, marker gate, dispatch, and sanitized failure. |
| `scripts/run_safe_lead_flow.ps1` | script allowlist/dispatch/validation blocks | Add fixed-order activation command and marker eligibility. |
| `tests/test_lead_factory_radar_yandex_job_activator.py` | new tests | State machine, evidence, races, failures, sanitization, and zero-effect proof. |
| `tests/test_lead_factory_radar_yandex_connection.py` | existing authority tests | Prove shared validation preserves runtime and issues no grant for candidate checks. |
| `tests/test_lead_factory_radar_yandex_job_preparer.py` | existing preparer/ACL tests | Preserve inert helper and active-job separation. |
| `tests/test_lead_factory_radar_yandex_maintenance.py` | existing retention tests | Prove newly emitted per-job pin works with strict precedence. |
| `tests/test_lead_factory_safe_lead_flow_launcher.py` | existing launcher tests | Account for HIGH-impact allowlist/main consumers and exact argument rejection. |
| `tests/test_lead_factory_source_discovery_control.py` | existing source CLI tests | Preserve all existing command outputs and local/provider effect reporting. |
| `docs/SAFE_LEAD_FLOW_LAUNCH_RUNBOOK.md` | activation sections | Document the supported local activation sequence and remaining live-read gate. |
| `docs/RADAR_YANDEX_PERMANENT_CONNECTION.md` | operator commands/layout | Document fixed evidence bundle, exact pins, replay, and no-rotation rule. |

## 11. Reusable Implementation Context

```yaml
implementation_context:
  task_summary: >-
    Add a safe local yandex-activate transition that consumes one exact fixed-path evidence bundle,
    installs a native-compatible one-request job, and publishes the root activation pin last without
    reading credentials or contacting Yandex.
  acceptance_criteria:
    - Exact draft and content-addressed evidence bundle are required and revalidated.
    - Existing native authority accepts the installed request without a grant being created by the activator.
    - Root pin is last, no-replace, replayable, and never automatically rolled back or rotated.
    - No credential, HTTP, reservation, spend, CRM, outbox, contact, schedule, or automatic run-one occurs.
    - All existing launcher/source/native/maintenance behavior remains compatible.

  evidence_provenance:
    schema_version: 2
    head_commit: '43a06711c16654f638718b84ab4430ba320e7583'
    generated_plan_path: 'docs/plans/2026-09-12-gitnexus-plan-yandex-job-activation.md'
    global_dirty_digest:
      algorithm: 'sha256'
      canonicalization: 'gitnexus-evidence-provenance-v2 NUL-framed UTF-8 records'
      value: '0a9c85780067d9afcd0764f307b60891e3cee927ee11eaeb5ec7826d10fd82cd'
    cited_path_manifest:
      - path: 'docs/RADAR_YANDEX_PERMANENT_CONNECTION.md'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:d5d58a8837d272fe697673dd708b3a323fcb1faa0e6188b9f5f293686b944f3a'
        index_digest: 'sha256:d5d58a8837d272fe697673dd708b3a323fcb1faa0e6188b9f5f293686b944f3a'
        worktree_digest: 'sha256:d5d58a8837d272fe697673dd708b3a323fcb1faa0e6188b9f5f293686b944f3a'
        untracked_digest: absent
      - path: 'docs/SAFE_LEAD_FLOW_LAUNCH_RUNBOOK.md'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:c95069b905222a2052894862a6aaec05a161fb1968710cb41d6b664dfa5ba332'
        index_digest: 'sha256:c95069b905222a2052894862a6aaec05a161fb1968710cb41d6b664dfa5ba332'
        worktree_digest: 'sha256:c95069b905222a2052894862a6aaec05a161fb1968710cb41d6b664dfa5ba332'
        untracked_digest: absent
      - path: 'lead_factory/radar_yandex_connection_authority.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:49db958005291a426d8cf4c484c16709d8db99b6941af9923eaa34eb036974b3'
        index_digest: 'sha256:49db958005291a426d8cf4c484c16709d8db99b6941af9923eaa34eb036974b3'
        worktree_digest: 'sha256:49db958005291a426d8cf4c484c16709d8db99b6941af9923eaa34eb036974b3'
        untracked_digest: absent
      - path: 'lead_factory/radar_yandex_job_activator.py'
        object_kind: {head: absent, index: absent, worktree: absent, untracked: absent}
        state: absent
        rename_from: null
        rename_to: null
        head_digest: absent
        index_digest: absent
        worktree_digest: absent
        untracked_digest: absent
      - path: 'lead_factory/radar_yandex_job_preparer.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:ec5650296dda256afd1be8247b16ceda3fac45923ab1f74d8bdce53502b17fc0'
        index_digest: 'sha256:ec5650296dda256afd1be8247b16ceda3fac45923ab1f74d8bdce53502b17fc0'
        worktree_digest: 'sha256:ec5650296dda256afd1be8247b16ceda3fac45923ab1f74d8bdce53502b17fc0'
        untracked_digest: absent
      - path: 'lead_factory/radar_yandex_maintenance.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:8c7e8c9bdeae989a0f0059ef6de7aad658710df25061698d9ff2224624a66953'
        index_digest: 'sha256:8c7e8c9bdeae989a0f0059ef6de7aad658710df25061698d9ff2224624a66953'
        worktree_digest: 'sha256:8c7e8c9bdeae989a0f0059ef6de7aad658710df25061698d9ff2224624a66953'
        untracked_digest: absent
      - path: 'lead_factory/radar_yandex_pilot_authority.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:1341e2784788963b0e80b7e94da0b098b9f7f3f5a988eaa886593f4c9a878cdb'
        index_digest: 'sha256:1341e2784788963b0e80b7e94da0b098b9f7f3f5a988eaa886593f4c9a878cdb'
        worktree_digest: 'sha256:1341e2784788963b0e80b7e94da0b098b9f7f3f5a988eaa886593f4c9a878cdb'
        untracked_digest: absent
      - path: 'scripts/check_yandex_activation_acl.ps1'
        object_kind: {head: absent, index: absent, worktree: absent, untracked: absent}
        state: absent
        rename_from: null
        rename_to: null
        head_digest: absent
        index_digest: absent
        worktree_digest: absent
        untracked_digest: absent
      - path: 'scripts/check_yandex_state_acl.ps1'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:b14da69600b2288478716b64a3c49307be90839b01e1c53c7a64555f2d9baa57'
        index_digest: 'sha256:b14da69600b2288478716b64a3c49307be90839b01e1c53c7a64555f2d9baa57'
        worktree_digest: 'sha256:b14da69600b2288478716b64a3c49307be90839b01e1c53c7a64555f2d9baa57'
        untracked_digest: absent
      - path: 'scripts/run_safe_lead_flow.ps1'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:dd86082ded19d39151feca41d91b7ed3d9ed121ab7e2da4ea2b0fd27bbb82d02'
        index_digest: 'sha256:dd86082ded19d39151feca41d91b7ed3d9ed121ab7e2da4ea2b0fd27bbb82d02'
        worktree_digest: 'sha256:dd86082ded19d39151feca41d91b7ed3d9ed121ab7e2da4ea2b0fd27bbb82d02'
        untracked_digest: absent
      - path: 'scripts/run_source_discovery_once.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:7c97a88e97f6394c650be38330b84b119e4d6593fec8a8cf2a10d1858d370d10'
        index_digest: 'sha256:7c97a88e97f6394c650be38330b84b119e4d6593fec8a8cf2a10d1858d370d10'
        worktree_digest: 'sha256:7c97a88e97f6394c650be38330b84b119e4d6593fec8a8cf2a10d1858d370d10'
        untracked_digest: absent
      - path: 'tests/test_lead_factory_radar_yandex_connection.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:7ba65eedd821557e3403ac6b16335275d4b6596dee3ffa0f026fef904d142e5c'
        index_digest: 'sha256:7ba65eedd821557e3403ac6b16335275d4b6596dee3ffa0f026fef904d142e5c'
        worktree_digest: 'sha256:7ba65eedd821557e3403ac6b16335275d4b6596dee3ffa0f026fef904d142e5c'
        untracked_digest: absent
      - path: 'tests/test_lead_factory_radar_yandex_job_activator.py'
        object_kind: {head: absent, index: absent, worktree: absent, untracked: absent}
        state: absent
        rename_from: null
        rename_to: null
        head_digest: absent
        index_digest: absent
        worktree_digest: absent
        untracked_digest: absent
      - path: 'tests/test_lead_factory_radar_yandex_job_preparer.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:086c46473094489d9b74c624a4899276d67288459fddc13fcc8d41edb1e6df78'
        index_digest: 'sha256:086c46473094489d9b74c624a4899276d67288459fddc13fcc8d41edb1e6df78'
        worktree_digest: 'sha256:086c46473094489d9b74c624a4899276d67288459fddc13fcc8d41edb1e6df78'
        untracked_digest: absent
      - path: 'tests/test_lead_factory_radar_yandex_maintenance.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:b4bb5413adc7de5db38ba8726a742e5e5b74dd84d3d068b632f6245302ef918f'
        index_digest: 'sha256:b4bb5413adc7de5db38ba8726a742e5e5b74dd84d3d068b632f6245302ef918f'
        worktree_digest: 'sha256:b4bb5413adc7de5db38ba8726a742e5e5b74dd84d3d068b632f6245302ef918f'
        untracked_digest: absent
      - path: 'tests/test_lead_factory_safe_lead_flow_launcher.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:d5084ecf1bef55eb7569176ba11e72f23dca967923ba9eb6ef5aef72001d90bf'
        index_digest: 'sha256:d5084ecf1bef55eb7569176ba11e72f23dca967923ba9eb6ef5aef72001d90bf'
        worktree_digest: 'sha256:d5084ecf1bef55eb7569176ba11e72f23dca967923ba9eb6ef5aef72001d90bf'
        untracked_digest: absent
      - path: 'tests/test_lead_factory_source_discovery_control.py'
        object_kind: {head: regular, index: regular, worktree: regular, untracked: absent}
        state: clean
        rename_from: null
        rename_to: null
        head_digest: 'sha256:35c8773696bf06ae847a1f9e52bf7fd039dc39259662ad994565a42279403aa1'
        index_digest: 'sha256:35c8773696bf06ae847a1f9e52bf7fd039dc39259662ad994565a42279403aa1'
        worktree_digest: 'sha256:35c8773696bf06ae847a1f9e52bf7fd039dc39259662ad994565a42279403aa1'
        untracked_digest: absent

  primary_symbols:
    - symbol: '_verify_request'
      file: 'lead_factory/radar_yandex_connection_authority.py'
      lines: '132-226'
      role: 'Native live request verifier and ordering oracle.'
    - symbol: '_load_published'
      file: 'lead_factory/radar_yandex_job_preparer.py'
      lines: '398-494'
      role: 'Intrinsic exact inert draft verifier reused by the activator.'
    - symbol: 'main'
      file: 'scripts/run_source_discovery_once.py'
      lines: '268-425'
      role: 'HIGH-impact shared CLI dispatch and sanitized output boundary.'
    - symbol: '_retention_activation'
      file: 'lead_factory/radar_yandex_maintenance.py'
      lines: '109-159'
      role: 'Per-job retention-pin precedence contract.'

  related_symbols:
    - symbol: '_verified_data'
      relationship: 'CALLS _verify_request'
      relevance: 'Normalizes native verifier failures.'
    - symbol: 'verify_manual_grant'
      relationship: 'CALLS _verified_data'
      relevance: 'Must not be used by activation validation because it registers a grant.'
    - symbol: '_write_new'
      relationship: 'publication pattern used by _prepare_core'
      relevance: 'Exclusive write/fsync/identity pattern.'
    - symbol: '_observe_bound_time'
      relationship: 'called by native verification'
      relevance: 'Journal mutation must occur before root pin.'

  execution_path:
    - 'Launcher scrubs credentials, validates fixed args, runs bootstrap, then sets the non-secret marker.'
    - 'CLI dispatches job id and expected hashes only to the local activator.'
    - 'Activator verifies code, ACL, connection, inert draft, journal/claims, and content-addressed evidence.'
    - 'Activator installs exact request.json and validates it with the shared supplied-pin native validator.'
    - 'Activator installs the identical per-job retention pin, revalidates all bindings, then installs root pin last.'
    - 'Post-read verification returns hashes and zero-effect flags; run-one remains separate.'

  pdg_constraints:
    - description: 'Receipt acceptance is jointly controlled by owner scope, role separation, exact code map, readiness, and timestamps.'
      affected_statements:
        - 'lead_factory/radar_yandex_connection_authority.py:194'
        - 'lead_factory/radar_yandex_connection_authority.py:211'
        - 'lead_factory/radar_yandex_connection_authority.py:219'
      implementation_consequence: 'Use the native validator; do not duplicate or weaken receipt predicates.'
    - description: 'Journal clock observation occurs only after structural validation and before final expiry denial.'
      affected_statements:
        - 'lead_factory/radar_yandex_connection_authority.py:222'
        - 'lead_factory/radar_yandex_connection_authority.py:224'
        - 'lead_factory/radar_yandex_pilot_authority.py:509'
      implementation_consequence: 'Perform candidate validation and all possible SQLite failure before root activation.'

  architectural_patterns:
    - pattern: 'Canonical JSON + SHA-256 + exact-key schemas'
      example_location: 'lead_factory/radar_yandex_pilot_authority.py:_canonical/_read/_object'
      usage_guidance: 'Reject duplicate/extra keys and bind exact bytes, not parsed equivalence alone.'
    - pattern: 'Exclusive stage and identity-aware cleanup'
      example_location: 'lead_factory/radar_yandex_job_preparer.py:_write_new/_cleanup_stage'
      usage_guidance: 'Never replace stable artifacts; exact bytes replay, differences conflict.'
    - pattern: 'Root activation as explicit authority pin'
      example_location: 'lead_factory/radar_yandex_connection_authority.py:_verify_request'
      usage_guidance: 'Publish root pin only after all inert artifacts and checks succeed.'

  files_to_modify:
    - file: 'lead_factory/radar_yandex_connection_authority.py'
      symbols: ['_code_files', '_verify_request']
      intended_change: 'Share supplied-pin validation without changing grant/runtime semantics; hash new helper.'
    - file: 'lead_factory/radar_yandex_job_activator.py'
      symbols: ['new activation entrypoint and state machine']
      intended_change: 'Consume fixed evidence and install exact job/pins with safe replay.'
    - file: 'scripts/check_yandex_activation_acl.ps1'
      symbols: ['new fixed-scope script']
      intended_change: 'Validate evidence and transition layouts.'
    - file: 'scripts/run_source_discovery_once.py'
      symbols: ['_parser', 'main']
      intended_change: 'Add local activation route and sanitized result handling.'
    - file: 'scripts/run_safe_lead_flow.ps1'
      symbols: ['allowlist, dispatch, argument validation, marker set']
      intended_change: 'Add exact nine-token activation invocation.'
    - file: 'tests/test_lead_factory_radar_yandex_job_activator.py'
      symbols: ['new tests']
      intended_change: 'Prove evidence, atomicity, replay, races, failures, and zero effects.'
    - file: 'tests/test_lead_factory_radar_yandex_connection.py'
      symbols: ['existing native authority tests']
      intended_change: 'Prove shared validator compatibility and no grant issuance.'
    - file: 'tests/test_lead_factory_radar_yandex_job_preparer.py'
      symbols: ['existing preparer and ACL tests']
      intended_change: 'Preserve inert helper and active-job separation.'
    - file: 'tests/test_lead_factory_radar_yandex_maintenance.py'
      symbols: ['existing retention tests']
      intended_change: 'Accept activator retention pin and preserve no-fallback semantics.'
    - file: 'tests/test_lead_factory_safe_lead_flow_launcher.py'
      symbols: ['existing launcher/main tests']
      intended_change: 'Cover HIGH-impact new route and malformed args.'
    - file: 'tests/test_lead_factory_source_discovery_control.py'
      symbols: ['existing source CLI tests']
      intended_change: 'Preserve local/provider effects and existing outputs.'
    - file: 'docs/SAFE_LEAD_FLOW_LAUNCH_RUNBOOK.md'
      symbols: ['activation operator flow']
      intended_change: 'Replace future-activator GAP with safe exact procedure.'
    - file: 'docs/RADAR_YANDEX_PERMANENT_CONNECTION.md'
      symbols: ['activation layout and commands']
      intended_change: 'Document evidence, replay, pins, and separate run-one.'

  tests:
    - file: 'tests/test_lead_factory_radar_yandex_job_activator.py'
      scenarios:
        - 'Exact bundle → activate → native verifier accepts, zero external effects.'
        - 'Each evidence/binding/time/identity drift → no root pin.'
        - 'Failures at request/retention/root boundaries → safe cleanup, replay, or reconciliation.'
        - 'Concurrent equal/different inputs → convergence or conflict without overwrite.'
        - 'Private sentinels → absent from output, error strings, contexts, and production locals.'
    - file: 'tests/test_lead_factory_radar_yandex_connection.py'
      scenarios:
        - 'Existing root verifier behavior unchanged.'
        - 'Supplied-pin candidate validation creates no grant and performs no provider access.'
    - file: 'tests/test_lead_factory_safe_lead_flow_launcher.py'
      scenarios:
        - 'Direct Python activation without marker → denied before state access.'
        - 'Exact marker/args → one local dispatch.'
        - 'Malformed order/count/UUID/SHA/confirmation → rejected before child.'
    - file: 'tests/test_lead_factory_radar_yandex_maintenance.py'
      scenarios:
        - 'Emitted per-job pin is preferred; corruption never falls back.'

  verification_commands:
    - '.\.venv\Scripts\python.exe -m pytest -q tests/test_lead_factory_radar_yandex_job_activator.py tests/test_lead_factory_radar_yandex_job_preparer.py tests/test_lead_factory_radar_yandex_connection.py tests/test_lead_factory_radar_yandex_maintenance.py tests/test_lead_factory_safe_lead_flow_launcher.py tests/test_lead_factory_source_discovery_control.py'
    - "$Modern = Get-ChildItem -LiteralPath tests -Filter 'test_lead_factory_*.py' | Where-Object Name -ne 'test_lead_factory_legacy_canary_guard.py' | ForEach-Object FullName; .\.venv\Scripts\python.exe -m pytest -q @Modern"
    - '.\.venv\Scripts\ruff.exe check lead_factory/radar_yandex_connection_authority.py lead_factory/radar_yandex_job_activator.py scripts/run_source_discovery_once.py tests/test_lead_factory_radar_yandex_job_activator.py tests/test_lead_factory_radar_yandex_connection.py tests/test_lead_factory_safe_lead_flow_launcher.py tests/test_lead_factory_source_discovery_control.py'
    - '.\.venv\Scripts\python.exe -I -B -m py_compile lead_factory/radar_yandex_connection_authority.py lead_factory/radar_yandex_job_activator.py scripts/run_source_discovery_once.py'
    - 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap_python_runtime.ps1 -CheckOnly'
    - 'node .gitnexus/run.cjs detect-changes --scope all --repo .'

  risks:
    - 'Shared CLI main has HIGH impact and 15 direct dependents.'
    - 'Root pin is irreversible inside this command after publication; late uncertainty requires reconciliation.'
    - 'Cross-process races require no-replace filesystem CAS, not an in-process lock.'
    - 'Evidence authenticity is limited to the existing trusted single-user local boundary in v1.'
    - 'Any final code change invalidates earlier drafts and evidence code maps.'

  assumptions:
    - 'Before implementation, recheck HEAD, clean tree, fresh exact local index, and no unexpected HIGH/CRITICAL production impact.'
    - 'Before a real activation, verify the user accepts the documented trusted-operator threat model; otherwise add signed evidence as a separate design.'
    - 'Before a real activation, recheck that no root active pin exists and the old journal has no in-flight/UNCERTAIN attempt.'
    - 'Complete independent exact-code review immediately before the new real draft so the six-hour evidence window is practical.'

  open_questions:
    - 'Cryptographic evidence signing and trusted reviewer/readiness public keys are deferred until multi-user or automated activation.'
    - 'Root-pin rotation/revocation is a separate explicitly authorized feature; v1 refuses it.'
    - 'A unified monthly spend ledger is required before onboarding a second paid source.'

  avoid:
    - 'Do not repeat full repository discovery.'
    - 'Do not weaken or repurpose check_yandex_state_acl.ps1.'
    - 'Do not call verify_manual_grant from the activator.'
    - 'Do not accept query, region, folder, credential, receipt JSON, time, or filesystem path from activation argv.'
    - 'Do not create owner/reviewer/readiness evidence inside the activator.'
    - 'Do not overwrite, replace, extend, auto-delete, auto-rotate, or auto-revoke a stable request or pin.'
    - 'Do not create a real draft until implementation, exact tests, independent review, merge, and code freeze are complete.'
```

## 12. Assumptions and Open Questions

- [assumed] The first manual pilot accepts the codebase's existing trusted single-Windows-user operator boundary. The activator proves exact local consistency and content addressability, not a cryptographic external signature. Reconfirm this before consuming real evidence.
- [verified] The actual read-only ACL root probe succeeds under Windows PowerShell 5.1, and no current root live pin was observed during planning. [assumed] Recheck both immediately before activation because external state can change.
- [assumed] Independent reviewer evidence can be finalized on the exact code map before the draft; owner and readiness evidence will be captured after draft creation and before activation.
- [assumed] No existing Yandex request is in-flight or `UNCERTAIN`. Check native accounting before any future rotation; v1 activation refuses a different root pin regardless.
- [inferred] Signed evidence, root-pin rotation/revocation, and a unified multi-source monthly spend ledger are adjacent follow-ups, explicitly outside this bounded activator.
- [verified] Real query, region, idempotency key, owner identity/source receipt, implementation author IDs, independent `ACCEPT`, billing/API/credential observation, bundle hash, and final activation confirmation are human/external inputs and must not be inferred by code.

## 13. Definition of Done

- A new exact activation route exists only behind the safe launcher and fixed argument grammar.
- The activator consumes but never creates one content-addressed fixed-path evidence bundle and rejects all binding, timestamp, role, code, connection, journal, claims, ACL, and expiry mismatches.
- The emitted `request.json` is accepted by the same native validation core as runtime; candidate validation creates no grant.
- `request.json` and per-job retention pin are inert before the root pin; root pin is published last via no-replace semantics.
- Exact replay is byte/time stable once retention exists; conflicting or cross-job state is never overwritten.
- Every injected failure before root leaves either no stable artifact or an exact resumable inert partial; every late failure preserves the root pin and reports reconciliation.
- Outputs and exceptions expose no query, region, folder, local path, identities, evidence contents, or credential material and report zero external effects.
- Targeted and complete modern Lead Factory tests, Ruff, byte compilation, Windows PowerShell 5.1 parsing, bootstrap check, ACL probes, and non-partial GitNexus `detect-changes` pass.
- Exact-head independent security/code review accepts the final code, the branch merges normally, and no real draft/activation/provider read occurs as part of implementation.
