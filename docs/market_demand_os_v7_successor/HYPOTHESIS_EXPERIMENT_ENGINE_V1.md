# Hypothesis & Experiment Engine v1

Status: `NON_RATIFYING_OFFLINE_DESIGN`

Version: `0.2.0`

This document is a successor implementation specification. It does not modify,
ratify, activate, or supersede the immutable MDOS v7.1 RC1 package. It grants no
authority for external reads, writes, contact, advertising, spend, or Bitrix.

## 1. Objective

The engine lets AlumKomplekt test many acquisition and demand-discovery methods
in parallel while preserving one common evidence, moderation, capacity, and
learning loop. The core is vendor-neutral: a platform is a collection of
versioned capabilities, not a special lead type.

The operational objective is incremental unique human-accepted GDO delivered to
a bounded work queue. Cleared Paid and contribution are downstream scale proof;
views, listings, clicks, chats, messages, forms, and replies are diagnostics.

## 2. Universal grammar

```text
World observations and owner ideas
        -> proposal-only hypothesis generator
        -> immutable HypothesisVersion registry
        -> preregistered ExperimentPlan and frozen cohort
        -> policy/legal/capacity/budget gates
        -> SensorAdapter or PrivilegedActionAdapter
        -> execution receipts and independent outcomes
        -> causal/shadow analysis
        -> KEEP_TESTING | REVISE | STOP | SIGNAL_CANDIDATE | COMMERCIAL_CANDIDATE
        -> immutable learning memory and new proposals
```

`SIGNAL_CANDIDATE` and `COMMERCIAL_CANDIDATE` produced by this offline layer
are recommendations only. They never constitute canonical KPI evidence,
production proof, ratification, or live authority.

## 3. Core records

### PlatformCapabilityVersion

A capability is bound to provider, account reference, surface, operation,
direction, effect class, subject kinds, source roles, terms evidence, dependency
family, quota, cost, validity, and maturity status. Effect classes are `READ`,
`WRITE`, `CONTACT`, and `SPEND`. Permission for one capability never transfers
to another capability on the same platform.

### TrialEntitlement

Records trial start/end, tariff, renewal policy, cancellation deadline, maximum
commitment, credential reference, owner, and cancellation/renewal evidence. The
default renewal policy is deny unless explicitly approved.

### ExplorationMandate

An owner-approved bounded envelope: products, regions, motions, providers,
capabilities, effect classes, total and per-method spend, contact count, human
review capacity, validity, exclusions, and automatic pause conditions. It is a
policy basis, not a substitute for an exact just-in-time PermitDecision.

### HypothesisVersion

An immutable falsifiable statement containing cohort, intervention, comparator,
causal mechanism, primary outcome, guardrails, maturity horizon, assumptions,
falsification rule, required capabilities, evidence, author provenance, parent
version, and novelty fingerprint.

### TreatmentVersion and ExperimentPlan

The plan freezes eligibility, exclusions, denominator, randomization unit,
interference cluster, treatment/control variants, assignment probabilities,
holdout, primary metric, guardrails, analysis method, minimum/maximum sample,
outcome window, budget, contact and capacity caps, stopping rules, and exact
capability/mandate bindings before assignments are made.

### Assignment, ExecutionReceipt, Outcome

Assignment is deterministic for the frozen cluster and logs its probability.
Receipt binds the exact assignment, capability, permit, request and provider
acknowledgement without storing credentials or raw PII. Outcomes come from
independent human GDO adjudication, cleared payment, fulfilment, loss, complaint,
suppression, or other authoritative evidence; the model's own score is not a
label.

### ExperimentAnalysis and LearningDecision

Analysis preserves intention-to-treat, delayed outcomes, censoring, duplicate
GDO controls, denominator, uncertainty, guardrails, and data-quality findings.
The decision is one of `KEEP_TESTING`, `REVISE`, `STOP`, `SIGNAL_CANDIDATE`, or
`COMMERCIAL_CANDIDATE`, with scope, expiry, evidence, and reason codes. A
negative decision remains immutable; the same method family cannot be silently
relaunched under a new plan identifier. A materially changed retry must bind
the stopped fingerprint, human-approved change rationale, and new evidence.

### PortfolioAllocation

Allocates a bounded exploration share, money, contacts, and review/sales WIP
across simultaneous experiments. Legal, suppression, quality, capacity, and
global kill switches are hard constraints and never reward terms.

## 4. State machines

```text
Hypothesis:
PROPOSED -> SCREENED -> PREREGISTERED -> OFFLINE -> SHADOW -> CANARY
         -> MATURING -> SIGNAL_VALIDATED -> COMMERCIAL_PROVEN
         -> REVISE | INCONCLUSIVE | STOPPED | RETIRED

Capability:
PROPOSED -> TERMS_REVIEWED -> OFFLINE_VERIFIED -> READ_CANARY
         -> ACTION_CANARY -> BOUNDED_ACTIVE
         -> SUSPENDED_REVIEW | EXPIRED | RETIRED

External action:
PROPOSED -> APPROVED | DENIED | EXPIRED -> RESERVED -> DISPATCHED
         -> ACKNOWLEDGED | FAILED | UNCERTAIN -> RECONCILED
```

The initial executable slice supports only proposal, preregistration, offline,
shadow, analysis recommendation, pause, revise, and stop. It has zero transport
calls and cannot enter live capability or external-action states.

## 5. Separation of duties

- An AI or human may propose a hypothesis.
- A policy authority validates capability, mandate, legal purpose, budget, and
  capacity.
- A human approves any envelope that could later permit write/contact/spend.
- A privileged executor accepts only a typed assignment and an exact current
  permit immediately before dispatch.
- An independent reviewer decides Gold.
- Authoritative systems confirm payment and fulfilment.
- An evaluator cannot promote its own model or enlarge its envelope.

The engine may automatically generate, deduplicate, rank, simulate, and pause.
It may not automatically widen audiences, increase budgets, create consent,
contact people, publish content, spend money, accept Gold, or declare production
proof.

## 6. Avito capability map

Avito is an acceptance example, not a special core type:

| Surface | Capability | Effect | Initial status |
| --- | --- | --- | --- |
| Our item listing | `LISTING_PUBLISH` / `LISTING_UPDATE` | `WRITE` | proposal/shadow only |
| Listing promotion | `LISTING_PROMOTE` | `SPEND` | proposal/shadow only |
| Existing inbound chat | `MESSENGER_INBOUND_OBSERVE` | `READ` | reference only |
| Reply in existing chat | `RESPOND_INBOUND` | `CONTACT` | manual canary candidate |
| Third-party listing | `THIRD_PARTY_LISTING_OBSERVE` | `READ` | discovery only |
| New collaboration approach | `INITIATE_COLLABORATION_CONTACT` | `CONTACT` | unproven/manual only |
| Advertising account | `ADS_CREATE`, `ADS_BUDGET_MUTATE`, `ADS_ACTIVATE`, `ADS_STATS_OBSERVE` | `WRITE`, `SPEND`, `READ` | shadow only |
| Calls/orders/statistics | outcome observations | `READ` | reference only |

A third-party seller listing is a discovery/trigger observation, not buyer
intent, consent, GDO, or permission to contact. A collaboration message is a
separate experiment and legal purpose. The locally preserved Messenger OpenAPI
documents sending into an existing chat ID; it does not itself prove the right
or technical capability to initiate arbitrary chats from third-party listings.

## 7. Offline acceptance cases

1. One platform exposes multiple capabilities whose permissions do not leak.
2. A hypothesis can be proposed when a required action capability is unproven,
   but preregistration/execution fails closed.
3. Assignment is deterministic by canonical account/object cluster and logs the
   exact probability; one cluster cannot enter treatment and control.
4. The plan contains one frozen primary metric, control/holdout, denominator,
   maturity, budget, contact, capacity, guardrails, and stop rules.
5. Views, chats, or replies alone cannot produce a scale recommendation.
6. Duplicate GDO and cross-source observations count once.
7. A guardrail breach or capacity/budget exhaustion produces an automatic pause
   or stop recommendation, never more external action.
8. Shadow analysis never claims production proof or enables live authority.
9. Negative results are append-only and block unchanged silent relaunch.
10. Records contain no credentials or raw PII and all external-effect counters
    remain zero.

## 8. First implementation boundary

The first implementation consists of:

- a pure deterministic hypothesis/experiment domain module;
- a caller-path-only append-only offline ledger;
- a deterministic proposal-only portfolio allocator for trials, money,
  contacts, human-review capacity, exploration reserve, and dependency risk;
- an Avito shadow pack demonstrating inbound, discovery, collaboration-contact,
  promotion, and advertising as separate capabilities;
- targeted adversarial tests proving zero I/O, deterministic replay, immutable
  evidence, authority separation, and no live promotion.

Source Lab, the hot/GDO gate, the bounded GDO queue, Bitrix shadow, and future
privileged adapters remain separate bounded contexts. Integration occurs only
through typed, content-addressed records.

## 9. Deliberate limits of the first executable slice

- There is no continuous AI proposal scheduler yet; the engine validates and
  evaluates typed hypotheses supplied by a caller.
- There are no real platform credentials, adapters, messages, publications,
  advertising spend, or Bitrix writes.
- Capability, terms, seed, privacy, trial, and owner attestations are still
  caller-supplied digests until authoritative signed registries are connected.
- Synthetic fixtures can populate audit memory but are never learning-, KPI-,
  commercial-proof-, portfolio-, release-, or scale-eligible.
- The observed-outcome bridge that may later unlock a bounded canary is not yet
  implemented; negative learning can already stop or constrain future work.
