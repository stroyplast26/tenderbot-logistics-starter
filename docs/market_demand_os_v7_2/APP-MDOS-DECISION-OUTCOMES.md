# APP-MDOS-DECISION-OUTCOMES — решение, экономика и обучение

**Application ID:** `APP-MDOS-DECISION-OUTCOMES`  
**Версия:** `1.1.0`

## 1. Decision contract

**MDOS-DEC-001.** `DecisionRecord` связывает exact DemandUnit assessment, motion
profile, evidence snapshot, policy/legal decision, capacity/economics snapshot,
eligible actions, uncertainty, human acceptance и expiry.

**MDOS-DEC-002.** Приоритет не равен вероятности покупки. Portfolio optimizer
максимизирует ожидаемый incremental contribution под hard legal/quality/capacity,
WIP, SLA, concentration, fairness и exploration constraints.

**MDOS-DEC-003.** Неопределённость не маскируется ожидаемым значением. Decision
показывает probability/range, risk/coverage zone, missing evidence, downside и
reason for abstain/research/reject.

**MDOS-DEC-004.** Human override требует role, reason, evidence, scope, TTL и outcome
adjudication. Нельзя override law, suppression, payment truth, audit integrity,
non-waivable safety или отсутствие capacity.

## 2. Outcome ledger

**MDOS-OUTC-001.** Канонические outcomes:

- received `RFQ` and `ReadyPackage`;
- accepted estimate/proposal;
- distinct `ClearedPaidOrder`;
- fulfilment: OTIF, defect/rework/claim, warranty/service;
- contribution margin and cash timing;
- second independent paid order/Repeat;
- lost/no-decision/supplier-selected/cancelled with reason/evidence.

**MDOS-OUTC-002.** Outcome содержит demand/account/order identity, event/recorded
time, source system, authoritative class, amount/currency, cost components, motion,
original/latest/influence/action/routing attribution and reconciliation state.

**MDOS-OUTC-003.** Quote, invoice, signed contract, verbal approval или CRM WON без
cleared payment не являются PaidOrder. Split payment, correction, remake, warranty
replacement и duplicate deal не являются Repeat.

## 3. Attribution and causal experiment ledger

**MDOS-EXP-001.** Для каждого intervention фиксируются eligibility cohort, unit of
randomization, treatment/control, assignment probability, policy/offer/content,
time, interference cluster, capacity, cost, outcome window и analysis plan.

**MDOS-EXP-002.** Raw channel attribution и causal incrementality хранятся отдельно.
Last-touch, CRM source или model-selected cohort не доказывают uplift.

**MDOS-EXP-003.** При возможности используется randomized/preregistered design.
Observational uplift требует causal assumptions, overlap/balance diagnostics,
sensitivity and conservative uncertainty; иначе маркируется directional evidence.

**MDOS-EXP-004.** Exploration ограничена legal/safety/capacity. Contextual bandit или
adaptive policy допускается после offline policy evaluation, bounded regret/risk,
logged propensities, holdout и kill switch; hard constraints не становятся reward.

## 4. Economics

**MDOS-ECO-001.** Unit economics считаются на `DemandUnit/Order/Account cohort`, а не
на form/contact. Минимальный набор: gross/contribution margin, cash cycle, acquisition,
qualification/estimator/engineering minutes, logistics, rework/claim, fulfilment,
repeat and opportunity cost.

**MDOS-ECO-002.** Source/motion/offer scale разрешён только если conservative lower
bound incremental contribution положителен либо owner утвердил ограниченный learning
investment с stop-loss и сроком.

**MDOS-ECO-003.** National coverage не предполагается. Region×product×fulfilment
cell имеет отдельные demand, margin, service/capacity, p50/p90 SLA и loss assumptions.

## 5. GDO10 evidence profile

**MDOS-G10-001.** Evaluation cohort и denominator фиксируются до окна. Повторная
квалификация, revisions, duplicates, routed copies и один объект по нескольким
источникам не увеличивают count.

**MDOS-G10-002.** Day считается successful, если создано ≥10 accepted GDO,
которые прошли evidence/legal/capacity/human gates до cut-off и имеют next action.
Backfill после дня не меняет historical day, а фиксирует late evidence отдельно.

**MDOS-G10-003.** Итоговый bundle содержит 30 daily snapshots, raw/event digests,
motion/source breakdown, dedupe audit, reviewer decisions, WIP/SLA/capacity,
downstream maturation and reproducible query/code/release digests.

**MDOS-G10-004.** Надёжность требует не менее трёх independent demand motions либо
approved concentration exception с tested failover. Несколько adapters одной
dependency family не считаются диверсификацией.

**MDOS-G10-005.** `PROVEN_GDO10` автоматически приостанавливается при legal breach,
tampered evidence, unknown writer, critical schema/model/source drift, capacity
overload либо невозможности воспроизвести daily counts.

**MDOS-G10-006.** Единственный счётчик GDO строится из immutable `GoldAcceptance`
со статусом `ACCEPTED` и уникальным scope fingerprint внутри sealed cohort. CRM Deal,
ручная таблица, model score и mutable stage не являются счётчиком.

**MDOS-G10-007.** Review выполняет назначенный человек, который принимает конкретную
работу и не является автором AI claim. ИИ может подготовить evidence bundle и
рекомендацию, но не заполняет reviewer decision и не меняет cut-off задним числом.

**MDOS-G10-008.** При конфликте identity/scope/evidence/capacity/economics/permit
GoldAcceptance переводится в `REVOKED` либо блокируется; dependent count и release
автоматически пересчитываются с audit trail.

**MDOS-G10-009.** Cleared payment связывается с DemandUnit через `PaymentProof` и
distinct `OrderRecord`; duplicate provider event, split payment или correction одного
order не создают новый paid client/repeat.

## 6. PC10 evidence profile

**MDOS-PC10-001.** PC10 активируется отдельной owner ratification; до неё все UI/
reports обязаны показывать `NOT_ACTIVE/NOT_PROVEN`, а не прогноз или обещание.

**MDOS-PC10-002.** `NewPayingClient` — новый canonical Account без исторического
cleared paid order, получивший первый distinct cleared payment. Несколько юрлиц одной
закупочной группы требуют adjudication; несколько контактов/счетов не увеличивают count.

**MDOS-PC10-003.** Proof: ≥300 NewPayingClient за 30 рабочих дней, ≥10 в 24 днях,
positive conservative contribution after fulfilment, fraud/duplicate/payment audit,
capacity and cash-flow proof, plus mature repeat/claim monitoring. Это не выводится
из GDO volume арифметически без наблюдаемой conversion distribution.

## 7. Metrics hierarchy

**MDOS-MET-001.** Board metrics: incremental contribution, cleared paid accounts,
repeat/retention, cash conversion, fulfilment quality, GDO→Paid and time-to-value.

**MDOS-MET-002.** Operating metrics: GDO by motion, RFQ readiness, time-to-first-
human, estimator/engineering SLA, WIP age, capacity utilization, dealer accept,
source freshness and conflict queue.

**MDOS-MET-003.** Intelligence metrics: precision/recall at capacity, calibration,
risk-coverage, false-hot/missed-paid, lead-time advantage, evidence completeness,
ER/extraction quality, drift and cost per incremental GDO/Paid.

**MDOS-MET-004.** Activity metrics: pages, records, forms, clicks, sends and AI calls
не допускаются как North Star и всегда показываются ниже outcome metrics.

## 8. Acceptance

| ID | Сценарий | Ожидаемый результат |
|---|---|---|
| `AT-DEC-01` | Highest propensity case имеет отрицательную margin. | Не выбран; hard economics constraint. |
| `AT-DEC-02` | Manager выбрал только лучшие accounts. | Conversion не называется causal uplift без assignment ledger. |
| `AT-DEC-03` | Quote accepted, payment отсутствует. | 0 PaidOrder/PC10. |
| `AT-DEC-04` | Старый клиент оплатил новый объект. | Repeat/expansion, не NewPayingClient. |
| `AT-DEC-05` | 300 GDO получены за 30 дней, но только 18 successful days. | GDO10 gate fails. |
| `AT-DEC-06` | Один object попал из Яндекса, 2ГИС и TenderPlan. | Один GDO; три source roles/claims. |
| `AT-DEC-07` | Campaign увеличила forms, holdout Paid одинаков. | Scale blocked/revise. |
| `AT-DEC-08` | Adaptive policy не логирует propensity. | Causal/adaptive production blocked. |
| `AT-DEC-09` | Fulfilment claims сделали contribution negative. | Commercial proof revoked/reopened. |
| `AT-DEC-10` | PC10 не ратифицирован. | Dashboard показывает NOT_ACTIVE/NOT_PROVEN. |
| `AT-DEC-11` | CRM/менеджер пометил PAID без банковского PaymentProof. | 0 cleared payment; conflict/quarantine. |
| `AT-DEC-12` | Один provider payment event пришёл повторно. | Один idempotent outcome; Paid/PC10 не удваивается. |
| `AT-DEC-13` | ACCEPTED_GDO не имеет GoldAcceptance/fingerprint. | Schema reject; daily count не растёт. |
| `AT-DEC-14` | Human reviewer принимает AI claim без evidence/permit. | Acceptance denied and audited. |
| `AT-DEC-15` | Второй платёж — доплата по тому же order. | Тот же PaidOrder; 0 RepeatOrder/NewPayingClient. |
