# Market & Demand OS v7 delivery overlay

This directory is a non-normative execution overlay for the immutable package
AK-MDOS-V7 7.1.0-rc.1, bound to package root
d4da97bd47ed1bf76a52826a852e3a158611d18adf32a901b814a864e862d97e.

Nothing here changes the contract, schemas, requirements or acceptance statuses in
docs/market_demand_os_v7. The normative registries remain the release authority.

Files:

- gap-inventory.json records observed implementation, known gaps and gate blockers.
- delivery-backlog.json is the dependency-ordered executable G0-G2 backlog.
- implementation-trace-overlay.json links selected requirements to design, actual
  code, local tests and evidence, while keeping planned bindings visibly separate.
- g2-motion-profiles.json defines the three requested near-money motions as local
  fixture/shadow profiles only. Its high-intent inbound profile also carries the
  non-normative owner P0 privacy contract for website attribution.

Status rule: no entry in this overlay may be treated as higher than
IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED until an owner-appointed independent verifier
re-runs the exact state and signs the evidence. Empty evidence_refs and
planned_evidence_refs are intentionally different: a planned path is not evidence.

The implemented local slices are bound to these evidence reports:

- G0 consent/suppression: reports/market_demand_os_v7/g0-suppression-evidence.json,
  SHA256 76bef7507d53a4977b2642002b38f6af9bbb20bf3c17ed30b96338714e018b6b;
- G1 Raw-to-Reconciliation plus durable local projection outbox:
  reports/market_demand_os_v7/g1-shadow-evidence.json, SHA256
  0f2cfe49202f21df782a68c3c891607282494e37e9bc79128946177e6ce3565f;
- G1 split-payment shadow slice:
  reports/market_demand_os_v7/g1-split-payment-shadow-evidence.json, SHA256
  610df6f5c9e0883624353750104d356faf787e5aa3f72ca890a357025a117172;
- G2 durable shadow outbox: reports/market_demand_os_v7/g2-outbox-evidence.json,
  SHA256 a1e3560215d4f7e418ea6a8a24f92d3fd125d63f705e49268c0037b45f7fef49;
- privacy-safe inbound attribution:
  reports/market_demand_os_v7/g2-inbound-attribution-shadow-evidence.json, SHA256
  6b0c5c94d1e8aa7dff7208c1f10c53701d0e108716049c06dc4c9a9559ffd3b9;
- G2 near-money proposal preflight:
  reports/market_demand_os_v7/g2-motion-preflight-evidence.json, SHA256
  7fd0675ade007c763a54bb15ac15d34207bddc707780280601a50e0e6ab920bb;
- fail-closed owner ratification/access preflight:
  reports/market_demand_os_v7/g2-owner-preflight-evidence.json, SHA256
  76b7c622da7ee3caa2a6cf100f52378ede94d77a29453d08ff9689863c4faf9f;
- Python egress boundary inventory:
  reports/market_demand_os_v7/g2-manual-egress-evidence.json, SHA256
  5bee2b36e88e78ab736bedf6532c59dae8f57ef1f0486e19356bbe3b64b79716.

G0 observed 5 ledger records, 23 immutable delivery receipts, two persisted contact
DENY effects, zero external/transport effects and exact restore. G1 observed 30 ledger
records, 111 immutable delivery receipts, one projection, one immutable shadow
CONTRACT_SIGNED CRM claim, zero external effects and exact restore. The CRM fact reads
CONTRACT_SIGNED_AWAITING_PAYMENT, while the effective application status remains
FULFILLED because canonical local payment/order/fulfilment truth has precedence. The
separate split-payment shadow slice observed 43 ledger records, 163 immutable delivery
receipts, two distinct installments converging to one terminal
payment truth, exact replay and exact restore with zero external effects. This is a
local contribution only: AT-COM-06 remains NOT_CLAIMED. The outbox reached
SHADOW_COMMITTED with one exact command, claim, attempt and terminal receipt; three
delivery attempts converged to one projection effect, with zero DLQ, transport,
external or live effects. Inbound attribution reconciled as RECONCILED_ATTRIBUTED,
kept its private payload separate, included no raw private values and caused zero
external effects. The two executable motion preflights ended
READY_PROPOSAL_EFFECT_DENIED with no created commercial truth or external effect.
The owner preflight remained NOT_RATIFIED, reported artifact_bytes_verified=false and
artifact_resolution_present=false, and could not mutate authority. It now embeds a
privacy-safe CAPTURED_NOT_RATIFIED owner-intent summary: an inactive aluminium-window
Moscow-Oblast/no-install shadow hypothesis, review-queue limits 5/1/1, Bank API as a
future preference and an opaque Dima role proposal with no self-review or release,
payment, policy, arbitration or independent-verifier authority. The egress
inventory covered 49 Python boundary modules and 40 registered manual operations,
found zero unknown signature modules and observed zero transport attempts or effects.
These remain local implementation-team evidence, not independent verification.

pytest.ini pins official discovery to tests/. The current
reports/market_demand_os_v7/test-summary.json (SHA256
93c2bccdabfdaa177e9cc658525ad281ad7ac3bf0317c5cd3cc999bd125527a7) records the
safe full run: 1240 passed tests, 594 passed subtests, four collection warnings and
552.65 seconds. The owner/CRM/handoff regression passed 110 tests in 53.70 seconds;
Ruff was clean across MDOS, tests, evidence runners and all 49 inventoried Python
egress boundary modules. The earlier unconstrained discovery remains explicitly
invalid evidence: legacy diagnostics attempted failed EIS reads and vendored imports
failed; no successful external read was observed.

Inbound attribution is privacy-minimised: analytics uses path-only navigation,
classified referrer, allowlisted UTM, deterministic source hierarchy and Metrika
presence flags. PII, request text and raw lawfully supplied Metrika identifiers stay
in a separate private plane; form-to-Bitrix correlation is opaque. This is an owner
delivery requirement, not an amendment or completion claim for the normative P0 set.
origin_channel is the captured WEBSITE_FORM/UNKNOWN channel field; the hierarchy
determines source_class and never rewrites origin_channel.

Local owner-artifact byte resolution now revalidates the exact 18 manifest/envelope/
content bindings from a sealed local root and rejects traversal, indirection, swapped,
missing, extra, stale or sensitive bytes. Actual owner artifacts are absent, so this
control intentionally leaves the packet NOT_RATIFIED. Deterministic unsigned verifier
handoff tooling can bind the current profile, trace overlay and all nine reports as
READY_FOR_INDEPENDENT_REVIEW, but that status is input readiness only: the handoff is
not a signed verdict, carries all 36 P0 nonclaims, grants no authority and does not
satisfy DLV-G2-150. The current content-addressed bundle is
outputs/market_demand_os_v7/verification_handoff/verification-handoff-
518220707f35b92bddfcf2a6f9eb38f4936e0f49fe5d059721b92eaec44ae707.json;
its build was APPLIED, exact rerun was REPLAY and explicit validation was VALID.

Current live authority is zero. active_beachhead_profile and ratification are null;
external read, write, contact, spend, routing and live Bitrix actions remain blocked.
The local append-only consent/suppression controls and durable shadow outbox close
their bounded implementation gaps only. The code-level Python egress inventory does
not control manual/operator browser or phone actions, does not ratify dynamic-domain
classes and is not a global organizational egress control. The broad owner intent is
captured, but the unsigned owner packet is NOT_RATIFIED; the proposed first cell is
inactive and its 5/1/1 values are review-queue limits, not production capacity
evidence. The exact Bank API provider/format and real Bitrix tenant/category/pipeline/
stage mapping remain unknown. Production legal basis, exact owner signatures,
external Bitrix readback/transport, credentials, segregation of duties and independent
verification remain absent. Fixture/shadow results are non-KPI and do not prove market
performance. None of the 36 normative P0 requirements is claimed complete.
