# APP-MDOS-REFERENCE-ARCHITECTURE — целевая система

**Application ID:** `APP-MDOS-REFERENCE-ARCHITECTURE`  
**Версия:** `1.1.0`

## 1. Карта системы

```text
SOURCE POLICY PLANE
  permits · licence · purpose · consent · retention · quotas
                         │
                         v
EVENT SIGNAL MESH → RAW/EVIDENCE LAKE → DOCUMENT INTELLIGENCE
                         │                  │
                         └──── claims/provenance ────┐
                                                     v
        BITEMPORAL MARKET WORLD MODEL / KNOWLEDGE GRAPH
 Account · Person/Role · Object/Site · InstalledAsset · Product/Offer
 Interaction · Evidence · DemandUnit · Relationship · Outcome
                         │
                         v
 DEMAND INTELLIGENCE & ORCHESTRATION ENGINE
 resolution · fusion · critic · timing · research · motion state
                         │
                         v
 SELECTIVE DECISION + PORTFOLIO OPTIMIZER
 legal · Gold profile · capacity · incremental contribution · abstain
                         │
                         v
 JOURNEY / ACTION CONTROL → BITRIX24 / PEOPLE / ADS / PARTNERS
                         │
                         v
 BANK/PAYMENT PROOF + ORDER/FULFILMENT LEDGERS → CAUSAL OUTCOME LEARNING
                         └─────────────────────────────↺
```

**MDOS-ARC-001.** Архитектура разделена на control, data, intelligence, decision,
execution, outcome и assurance planes. Модель не совмещает чтение недоверенного
контента с привилегированным внешним действием.

**MDOS-ARC-002.** Bounded contexts имеют versioned contracts и не делят внутренние
таблицы напрямую:

1. `SourcePolicyAndEntitlement`;
2. `CaptureAndLineage`;
3. `DocumentIntelligence`;
4. `IdentityAndRelationship`;
5. `MarketWorldModel`;
6. `ProductCapabilityAndPromise`;
7. `DemandResolution`;
8. `MotionAndJourney`;
9. `DecisionAndPortfolio`;
10. `CRMProjectionAndWork`;
11. `OrderPaymentFulfilment`;
12. `ExperimentAndLearning`;
13. `AssuranceAndOperations`.

## 2. Event and evidence substrate

**MDOS-EVT-001.** Любое событие имеет immutable ID, type/schema version, producer,
subject refs, `event_time`, `observed_time`, correlation/causation, source revision,
payload hash, data class, purpose, trace ID и idempotency key.

**MDOS-EVT-002.** Transport может быть at-least-once; business effect обязан быть
idempotent. Outbox/inbox, retry, dead-letter, replay и reconciliation обязательны.

**MDOS-EVT-003.** Raw capture предшествует parsing/AI, content-addressed и не
изменяется. Новая parser/model/schema revision создаёт новые claims и lineage.

**MDOS-EVT-004.** Event/profile mappings совместимы по смыслу с CloudEvents,
OpenTelemetry, OpenLineage и W3C PROV, но конкретный vendor не обязателен.

## 3. World model и identity

**MDOS-KG-001.** Каждый claim хранит valid time, recorded/system time, source,
evidence span/coordinates, producer/model/prompt/schema, probability/uncertainty,
TTL, contradiction links, purpose и authoritative class.

**MDOS-KG-002.** Нельзя переписывать прошлое новой ревизией. Отчёт и prediction
воспроизводятся `as-of` по event/valid time и exact artifact digests.

**MDOS-KG-003.** Identity resolution использует strong identifiers и вероятностные
comparison features. Результат имеет три зоны: `AUTO_LINK`, `REVIEW`, `REJECT`;
thresholds versioned, merge обратим, source records сохраняются.

**MDOS-KG-004.** Совпадение одного email/телефона/названия/адреса/embedding не даёт
автоматический account/person/object merge. Cluster split/unmerge сохраняет lineage
и пересчитывает зависимые DemandUnit/attribution.

**MDOS-KG-005.** Graph хранит не только project relations, но account ownership,
buying group, supplier/partner/referral, interaction sequence, installed assets,
product fit, channel protection и commercial outcomes.

## 4. Product, offer and capacity truth

**MDOS-CAP-001.** Product/offer eligibility рассчитывается из versioned capability,
не из LLM знания: система, геометрия, стекло/фурнитура, КМ/КМД, certification,
lead-time, minimum order, delivery, montage/service route и гарантия.

**MDOS-CAP-002.** Capacity snapshot включает estimator minutes, engineering, line/
shift, coating/glass constraints, delivery slots, dealer acceptance/service and WIP.
Stale/zero capacity блокирует обещание и GDO acceptance, но не наблюдение/research.

**MDOS-CAP-003.** Expected contribution учитывает выручку, прямые материалы,
производство, логистику, acquisition, расчёт/engineering minutes, переделки,
рекламации, credit/payment risk и opportunity cost дефицитной мощности.

## 5. Motion and journey runtime

**MDOS-JRN-001.** Motion state derives from events; UI/CRM stage является проекцией.
Переход требует guard, evidence, actor, time и reason; backdating и manual override
аудируются.

**MDOS-JRN-002.** `Journey` описывает последовательность research, wait, human task,
content, channel, routing и stop actions. Interaction/open/click не разрешает новый
канал и не создаёт коммерческий факт.

**MDOS-JRN-003.** `NextBestActionProposal` содержит motion/case, цель, expected
incremental value, uncertainty, eligibility, legal/source permit, content/offer
version, capacity snapshot, expiry и required approver.

**MDOS-JRN-004.** Исполненное действие создаёт `ActionAssignment` с policy version,
eligibility cohort, assignment probability/propensity, channel, human/agent actor,
permit, timestamp и cost. Без этого результат не используется как causal label.

## 6. Storage and projections

**MDOS-STO-001.** Logical stores:

- immutable raw/evidence object store;
- append-only event store;
- operational state store;
- bitemporal graph/search index;
- point-in-time feature/label store;
- policy/consent/suppression ledger;
- model/prompt/eval/release registry;
- Bitrix24/BI read models.

Физическое объединение допустимо, логическое ownership и access policy — нет.

**MDOS-STO-002.** Bitrix24 получает только accepted work: Company/Contact/Account,
один Deal на distinct commercial DemandUnit, Activities/tasks и outcome projections.
Raw market observations, anonymous sessions и unadjudicated claims в CRM не пишутся.

**MDOS-STO-003.** Existing Account повторно не создаётся Lead на каждый ответ.
Interaction становится Activity; Deal создаётся при distinct DemandUnit/RFQ.

**MDOS-STO-004.** PaymentProof, OrderRecord и FulfilmentRecord reconciles с CRM.
Расхождение создаёт QualityConflict; CRM status, счёт, договор или human decision
не могут самостоятельно подтвердить cleared payment.

**MDOS-STO-005.** При отсутствии 1С/ERP canonical outcome plane состоит из трёх
раздельных append-only реестров: `PaymentProofLedger` (банк/провайдер/подписанная
выписка), `OrderRegistry` и `FulfilmentLedger`. Bitrix24 проецирует их состояния,
но не является writer платёжной истины. Будущий ERP подключается adapter-ом через те
же schemas, idempotency и reconciliation.

## 7. Resilience and observability

**MDOS-OPS-001.** Все read/write/AI/action pipelines имеют trace, metrics, logs,
SLO, queue depth, age, retry, DLQ, backpressure, circuit breaker и kill switch.

**MDOS-OPS-002.** AI outage переводит систему в deterministic/manual degradation;
raw ingestion, source expiry, suppression и commercial truth продолжают работать.

**MDOS-OPS-003.** Source outage/degradation создаёт freshness incident, пересчитывает
coverage/concentration и отзывают зависимые decisions после TTL.

**MDOS-OPS-004.** Release binds contract, schema, code, config, policy, source map,
prompt/model, dataset, test/evidence, capacity and rollback digests. Deployed digest
mismatch блокирует/откатывает production scope.

## 8. Acceptance

| ID | Сценарий | Ожидаемый результат |
|---|---|---|
| `AT-ARC-01` | Один source event повторно доставлен трижды. | Три deliveries, один business effect, полный trace. |
| `AT-ARC-02` | Source исправил дату/участника задним числом. | Новая claim revision; старый as-of отчёт воспроизводим. |
| `AT-ARC-03` | Similar company name и общий телефон. | REVIEW до multi-feature evidence; auto-merge запрещён. |
| `AT-ARC-04` | Ошибочный merge разделён. | Source records, DemandUnit и attribution пересчитаны с lineage. |
| `AT-ARC-05` | Raw page переобработана новой моделью. | Новый claim set; raw hash неизменен; оба producer versions видимы. |
| `AT-ARC-06` | CRM показывает PAID, а банковского/платёжного proof нет. | Payment conflict/quarantine; KPI не растёт. |
| `AT-ARC-07` | Accepted existing account прислал второй RFQ. | Activity + новый distinct Deal; duplicate Company/Lead не создаётся. |
| `AT-ARC-08` | Capacity snapshot просрочен. | Promise/GDO/action blocked; research допускается. |
| `AT-ARC-09` | AI provider недоступен. | Deterministic/manual path; raw/event/legal ledgers сохранены. |
| `AT-ARC-10` | Deployed policy digest отличается от release. | Incident + automatic pause/rollback. |
| `AT-ARC-11` | Contract/invoice/акт указан как authoritative payment. | Outcome schema reject; только claim/conflict. |
| `AT-ARC-12` | Valid PaymentProof связан с неизвестным OrderRecord. | Reconciliation conflict; KPI блокируется. |
| `AT-ARC-13` | Bitrix Deal изменён после банковской оплаты. | Projection обновляется; canonical PaymentProof неизменен. |
| `AT-ARC-14` | ACCEPTED_GDO не содержит GoldAcceptance reference. | DemandUnit schema rejects transition. |
| `AT-ARC-15` | External assignment содержит DENY/expired PermitDecision. | Execution blocked before side effect. |
