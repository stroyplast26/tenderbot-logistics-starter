# APP-LF-PLATFORM-ARCHITECTURE — целевая платформа Lead Factory

**Application ID:** `APP-LF-PLATFORM-ARCHITECTURE`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Архитектурные принципы

**LF-PLT-001.** Архитектура является contract-first, event-driven, evidence-first,
capacity-aware и fail-closed. Внешний side effect не является побочным действием
аналитики: он всегда отдельная команда с authority, idempotency и reconciliation.

**LF-PLT-002.** Логические границы обязательны с первой версии; физическое
разбиение на процессы/сервисы выполняется только по latency, reliability, ownership
или scale evidence. «Без экономии» не требует преждевременных микросервисов.

**LF-PLT-003.** Допустим production-grade modular monolith с изолированными модулями,
durable queues и ports/adapters. Модуль можно вынести в сервис без изменения
domain command/event contract.

**LF-PLT-004.** Vendor-neutral core: Bitrix, OpenRouter, Apify, ScrapeGraphAI,
Яндекс, Авито и поставщики данных подключаются адаптерами. Ни один vendor payload,
ID или SDK не становится канонической domain model.

## 2. Пять плоскостей

```text
┌──────────────────────────────── CONTROL PLANE ───────────────────────────────┐
│ Contract/Schema Registry · Policy/Permits · Config/Flags · Source/Model      │
│ Registry · Method Portfolio · Capacity Allocation · Release/Rollback · STOP │
└────────────────────────────────────┬─────────────────────────────────────────┘
                                     │ typed commands / policies
┌──────────────────────────────── DATA PLANE ──────────────────────────────────┐
│ Adapters → Raw Capture → Event Store → Identity/Evidence Graph → Funnel      │
│ Cases → Gold Gate → Commercial Spine → Outbox/CRM/Channels                   │
└────────────────────────────────────┬─────────────────────────────────────────┘
                                     │ immutable events/projections
┌────────────────────────── INTELLIGENCE PLANE ────────────────────────────────┐
│ Demand Intelligence · Document AI · Research Planner · Method Lab · NBA      │
└────────────────────────────────────┬─────────────────────────────────────────┘
                                     │ evaluations/proposals, no direct effects
┌─────────────────────────── EVALUATION PLANE ─────────────────────────────────┐
│ Quality Audit · Experiments · Forecast · Economics · Capacity Digital Twin   │
│ Drift/Calibration · Traceability · SLO/Error Budgets · Outcome Reporting     │
└────────────────────────────────────┬─────────────────────────────────────────┘
                                     │ human decisions/tasks
┌──────────────────────────────── HUMAN PLANE ─────────────────────────────────┐
│ Review Console · Bitrix · Sales · Estimator · Production · Owner/Auditor     │
└──────────────────────────────────────────────────────────────────────────────┘

Trust plane: identity, RBAC/SoD, legal, privacy, secrets, audit, retention,
encryption, backup/recovery and incident response cross every plane.
```

**LF-PLT-005.** Intelligence/Evaluation Plane не имеет прямой authority к внешним
адаптерам. Proposal превращается в действие только Control Plane командой.

**LF-PLT-006.** Human Plane не редактирует Event Store. Ручное решение создаётся
как signed/versioned command с actor, evidence и reason.

## 3. Contract, schema и configuration registry

**LF-PLT-REG-001.** Любой runtime decision связан с exact:

- contract package/version/hash;
- domain/event/command schema versions;
- policy and qualification profile;
- source passport/mapping/licence;
- method/experiment version;
- model/prompt/eval profile;
- capacity snapshot;
- code/release/deployment revision.

**LF-PLT-REG-002.** Registry append-only. Новая версия не меняет смысл исторического
события. Deprecated schema имеет migration/upcaster и sunset policy.

**LF-PLT-REG-003.** Unknown/unregistered version обрабатывается fail-closed;
«использовать последнюю» без exact binding запрещено.

## 4. Command model

**LF-PLT-CMD-001.** Любая изменяющая состояние операция использует command envelope:

```text
command_id
command_type + schema_version
aggregate_type + aggregate_id + expected_version
actor_id + actor_role
authority/permit reference
idempotency_key
correlation_id + causation_id
issued_at + expires_at/deadline
contract/policy/method/model bindings
payload_hash + evidence references
```

**LF-PLT-CMD-002.** Command validation проходит в порядке:

```text
schema → identity/version → authority → legal/data scope → suppression
→ freshness/evidence → capacity/WIP → budget/rate → aggregate invariants
→ durable decision/effect intent
```

Первый hard failure прекращает выполнение без partial domain change.

**LF-PLT-CMD-003.** Optimistic concurrency использует `expected_version`.
Concurrent conflicting commands не разрешаются last-write-wins.

## 5. Event model и CQRS

**LF-PLT-EVT-001.** Принятое domain change создаёт immutable event envelope:

```text
event_id + event_type + schema_version
aggregate_type + aggregate_id + aggregate_version
occurred_at + recorded_at
actor + authority
correlation_id + causation_id
contract/policy/method/model/source versions
payload_hash + evidence refs
```

**LF-PLT-EVT-002.** Event Store является канонической историей. Graph, dashboards,
queues и CRM mapping — rebuildable projections. Внешний платёжный/CRM факт хранится
как observed event плюс reconciliation state, не как слепо доверенный update.

**LF-PLT-EVT-003.** Ordering гарантируется на aggregate, но глобальный порядок не
предполагается. Cross-aggregate workflow использует saga/process manager.

**LF-PLT-EVT-004.** Transport может быть at-least-once. Exactly-once business effect
достигается idempotency, unique constraints, inbox/outbox и remote correlation;
заявлять exactly-once network delivery запрещено.

## 6. Sagas и внешние эффекты

**LF-PLT-SAGA-001.** Длительные процессы — CRM projection, dealer assignment,
estimate handoff, campaign canary, source paging — реализуются saga с:

- explicit states;
- deadlines/timeouts;
- retry/backoff;
- compensation либо manual recovery;
- reconciliation;
- terminal disposition;
- replay-safe commands.

**LF-PLT-SAGA-002.** Transactional outbox фиксируется в одной транзакции с domain
event. Удаление из outbox до typed acknowledgement/read-back запрещено.

**LF-PLT-SAGA-003.** Remote timeout считается `UNKNOWN`, а не failure/success;
перед retry выполняется correlation/read reconciliation.

## 7. State и storage profiles

**LF-PLT-STO-001.** Data classes разделяются:

- immutable domain/event ledger;
- content-addressed evidence/blob vault;
- bitemporal graph/claims;
- transactional operational state/outbox/inbox;
- rebuildable search/index/vector projections;
- analytics/feature/experiment datasets;
- secrets/credentials вне domain storage.

**LF-PLT-STO-002.** Embedding/vector store является retrieval projection и не
владеет identity, permission, evidence или qualification fact.

**LF-PLT-STO-003.** Production storage обязан доказать transaction isolation,
concurrent writers, backup/restore, integrity checks, encryption/access controls,
retention и point-in-time recovery для заявленного scale tier.

**LF-PLT-STO-004.** SQLite допускается для offline/stage/bounded single-writer,
если gates зелёные. Multi-worker/live scale требует storage profile, доказавший
конкурентность и recovery; выбор технологии оформляется ADR, не скрытой миграцией.

## 8. Capacity Digital Twin

**LF-PLT-CAP-001.** `Capacity Digital Twin` хранит time-stamped возможности:

- source/capture throughput;
- enrichment/AI tokens and latency;
- reviewer/sales minutes;
- estimator slots по complexity;
- production m²/тип системы/смена;
- delivery/region constraints;
- dealer assignment capacity;
- active quote/order/claim load.

**LF-PLT-CAP-002.** Twin использует сценарии `base/high/low/failure`, stochastic
service times и фактические queue distributions. Простое деление дневного лимита
на среднее время недостаточно.

**LF-PLT-CAP-003.** Перед scale выполняется discrete-event либо эквивалентная
simulation с observed distributions; затем controlled load test. Simulation не
заменяет live evidence.

**LF-PLT-CAP-004.** Admission controller выдаёт slot до AGCO handoff. Utilization,
queue age и error budget создают backpressure/priority downgrade, а не потерю данных.

## 9. Policy-as-code

**LF-PLT-POL-001.** Policy Engine принимает typed facts и возвращает:

```text
ALLOW / DENY / REVIEW / DEFER
+ reason codes
+ matched rules/versions
+ missing evidence
+ capacity/budget reservation
+ decision TTL
```

**LF-PLT-POL-002.** Hard rules — legal, suppression, authority, identity conflict,
tampered evidence, capacity unavailable, invalid contract/schema — не могут быть
переопределены AI score или человеком без отдельного exception workflow.

**LF-PLT-POL-003.** Exception является narrower, time-bound, actor-bound,
purpose-bound, имеет two-person approval для high-risk и не изменяет исходное правило.

**LF-PLT-POL-004.** Policy change проходит unit/property/adversarial/replay tests
на историческом ledger и оценивает, какие ранее принятые decisions изменились бы.

## 10. Deployment и scale tiers

**LF-PLT-SCL-001.** Scale tiers:

- `T0_OFFLINE` — fixtures/replay, 0 external authority;
- `T1_SHADOW` — разрешённые reads, 0 commercial writes;
- `T2_BOUNDED_CANARY` — sealed cohort/quota/time;
- `T3_CONTROLLED_PRODUCTION` — один proven method/funnel;
- `T4_MULTI_METHOD_GCO10` — несколько methods, GCO10 proof;
- `T5_RESILIENT_OPERATION` — tested fallback и disaster recovery.

**LF-PLT-SCL-002.** Tier вычисляется для exact deployment manifest. Изменение
contract/code/schema/policy/model/source/capacity может отозвать tier.

**LF-PLT-SCL-003.** Horizontal workers partition by aggregate/source while preserving
aggregate ordering. Autoscaling подчиняется external quotas, cost, backpressure и
human/estimator/production capacity.

## 11. SLO, error budgets и observability

**LF-PLT-SLO-001.** Для каждого critical flow фиксируются SLI/SLO:

- capture freshness;
- end-to-end processing latency;
- first human response;
- Gold review/estimate latency;
- queue age/backlog;
- duplicate/invalid/measurement gap;
- external delivery/reconciliation;
- model calibration/drift;
- availability и recovery.

**LF-PLT-SLO-002.** Safety/legal/data loss имеет zero error budget. Для latency/
availability допускается versioned error budget. При исчерпании budget feature
freeze/scale stop приоритетнее новой функциональности.

**LF-PLT-SLO-003.** Каждый command/event/external call имеет correlation trace,
structured reason/error, latency, attempt, cost и redacted payload reference.
Metrics без trace-to-evidence не используются для приёмки.

**LF-PLT-SLO-004.** Alerts являются actionable: owner, severity, runbook, deadline
и suppression/dedup. Alert storm не должен скрывать первый critical signal.

## 12. Recovery и continuity

**LF-PLT-REC-001.** Для каждого state class задаются RPO/RTO, backup frequency,
restore order, dependency map и owner. Значения утверждаются до соответствующего tier.

**LF-PLT-REC-002.** Restore никогда не оживляет старый permit, cursor, lease,
writer/source-read epoch или queued side effect. После restore внешние полномочия 0
до reconciliation и нового epoch/permit.

**LF-PLT-REC-003.** Регулярно проверяются:

- corrupted/partial backup;
- point-in-time restore;
- loss of source/model/CRM;
- duplicate/reordered events;
- poisoned queue;
- clock skew;
- network partition/timeout;
- operator error and credential revocation.

## 13. Architecture fitness functions

**LF-PLT-FIT-001.** CI/acceptance автоматически проверяет:

- dependency boundaries между contexts;
- все external effects проходят ports/policy/outbox;
- domain modules не импортируют vendor SDK напрямую;
- command/event schemas backward compatible либо имеют migration;
- requirement→test→evidence traceability;
- manifest hashes и release bindings;
- no secret/PII leakage в logs/evidence/model payloads;
- deterministic replay ключевых decisions.

**LF-PLT-FIT-002.** Performance/load/recovery tests привязаны к scale tier и
production-like distributions; microbenchmark не заменяет end-to-end proof.

## 14. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-PLT-01` | Intelligence пытается вызвать adapter напрямую. | Dependency/permission gate блокирует. |
| `AT-PLT-02` | Два concurrent command с одной expected version. | Один commit, второй conflict. |
| `AT-PLT-03` | Outbox timeout после remote create. | Reconcile; дубль не создаётся. |
| `AT-PLT-04` | Projection удалена. | Rebuild из Event Store даёт тот же digest. |
| `AT-PLT-05` | Unknown schema/policy/model version. | Fail-closed, 0 side effect. |
| `AT-PLT-06` | AI/vector store недоступен. | Deterministic/manual degradation, ledger цел. |
| `AT-PLT-07` | Restore старого snapshot. | Все external authority 0; epoch продвинут. |
| `AT-PLT-08` | Queue duplicated/reordered. | Один domain effect, valid aggregate order. |
| `AT-PLT-09` | Capacity stale/zero. | Admission blocked; raw intake preserved. |
| `AT-PLT-10` | Policy exception шире запроса/истекла. | Reject. |
| `AT-PLT-11` | Error budget исчерпан. | Scale/feature gate закрыт. |
| `AT-PLT-12` | Vendor adapter меняет domain payload. | Contract test/mapping rejects drift. |
| `AT-PLT-13` | Replay exact ledger/release. | Decisions/evidence digests воспроизводимы. |
| `AT-PLT-14` | Load 150% planned GCO with failure injection. | Backpressure без loss/duplicate/unsafe effect. |

