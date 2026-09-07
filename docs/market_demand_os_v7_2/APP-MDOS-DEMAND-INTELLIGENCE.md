# APP-MDOS-DEMAND-INTELLIGENCE — AI/ML crown jewel

**Application ID:** `APP-MDOS-DEMAND-INTELLIGENCE`  
**Версия:** `1.0.0`

## 1. Миссия и граница ИИ

**MDOS-DI-001.** DIOE ищет не похожие тексты, а изменения рынка, повышающие либо
понижающие вероятность конкретного commercial transition: need emergence, supplier
openness, RFQ, paid order, fulfilment и repeat.

**MDOS-DI-002.** AI output всегда typed `Claim`, `ResolutionProposal`,
`ResearchQueryProposal`, `DemandAssessment` или `ActionProposal`. Модель не создаёт
canonical identity, GDO, consent, contact permit, price/promise, Order или Payment.

**MDOS-DI-003.** Один универсальный LLM-agent и один universal lead score запрещены.
Компоненты разделяются по modality, ответственности, eval set и праву доступа.

## 2. Evidence acquisition и document intelligence

**MDOS-DOC-001.** Capture выполняется только approved adapter. Веб-страница,
документ, письмо, PDF, таблица, чертёж и изображение считаются недоверенными данными,
не инструкциями.

**MDOS-DOC-002.** Modality router выбирает deterministic parser, native PDF/table
extractor, OCR/layout/vision либо LLM. Fallback и disagreement сохраняются; один
extractor не считается универсально истинным.

**MDOS-DOC-003.** Для каждой modality существует sealed eval set и field-level gates:
exact span/coordinates, table structure fidelity, quantity/unit/date correctness,
role/scope accuracy, abstention, latency, cost и injection attack success.

**MDOS-DOC-004.** Commercially critical claims — buyer/payer, supplier selected,
external buying/overflow, scope/quantity, deadline, price/payment and consent —
требуют exact evidence и independent validation/critic согласно risk profile.

## 3. Probabilistic identity and relationship resolution

**MDOS-ER-001.** Probabilistic resolution сохраняет comparison vector,
`m/u`-parameters либо их утверждённый аналог, prior, match probability, model/ruleset,
thresholds и decision zone. Thresholds калибруются отдельно для Account, Person,
Object/Site, DemandUnit и InstalledAsset.

**MDOS-ER-002.** Production promotion требует pairwise precision/recall, cluster
precision/recall, false-merge lower confidence bound, review load и slice metrics по
source/region/type. Высокая consolidation rate не является целью.

**MDOS-ER-003.** Relationship inference — participant, buyer, payer, specifier,
installer, referrer, current supplier — хранится как temporal claim с evidence, а не
как постоянное свойство компании.

## 4. Demand resolution

**MDOS-RES-001.** DemandAssessment хранит отдельные axes:

- need/product fit;
- buying-group completeness;
- intent strength;
- timing/hazard distribution;
- supplier openness/switch path;
- artifact readiness;
- reachability and lawful action;
- expected contribution and capacity fit;
- contradiction/negative risk;
- epistemic and aleatoric uncertainty.

**MDOS-RES-002.** `DemandUnitResolver` объединяет события в demand episode только
если identity, scope и temporal coherence доказаны. Слабые сигналы могут повышать
research priority, но не суммируются механически до Gold.

**MDOS-RES-003.** Timing — time-to-event/competing-risk задача. Assessment хранит
survival/hazard по горизонтам и competing outcomes: `RFQ`, `PAID`, `LOST`,
`SUPPLIER_SELECTED`, `CANCELLED`, `NO_DECISION`, с censoring и maturity state.

**MDOS-RES-004.** Для reorder, dealer RFQ, commercial opening, project package и
service/replacement используются разные clocks/features. Сравнение их одной датой
`decision_at` без motion semantics запрещено.

## 5. Research Planner

**MDOS-RSH-001.** Для non-ready case planner строит posterior gaps и только допустимые
candidate actions: query approved source, request human verification, wait for event,
inspect internal history, request missing artifact либо stop.

**MDOS-RSH-002.** Next-best-evidence учитывает expected decision change, expected
contribution, probability of obtaining evidence, acquisition/human/delay cost,
privacy/licence risk, capacity и exploration propensity. Эвристическая формула без
logged assumptions не выдаётся за доказанную EVI.

**MDOS-RSH-003.** Planner имеет stopping rules: Gold/reject, evidence value below
cost, source/legal/capacity block, maximum depth/budget, stale horizon. Бесконечный
crawl и enrichment «на всякий случай» запрещены.

## 6. Selective prediction и calibration

**MDOS-CAL-001.** Каждая production probability проходит calibration по motion,
source family, region, product и horizon; хранятся Brier/log loss, ECE либо approved
alternative, risk-coverage curve, sample/maturity и confidence bounds.

**MDOS-CAL-002.** Решение имеет зоны `AUTO_NEGATIVE`, `RESEARCH`, `HUMAN_REVIEW`,
`ELIGIBLE_FOR_GOLD_REVIEW`; принудительная положительная классификация при высокой
неопределённости запрещена.

**MDOS-CAL-003.** Drift/covariate shift, small sample, expired calibration, source
schema change либо miss-rate threshold переводят затронутый slice в shadow/manual и
отзывают dependent release scope.

## 7. Agent security

**MDOS-SEC-001.** Untrusted content обрабатывается в изолированном process/context с
taint labels. Модель не видит secrets и не вызывает privileged tools.

**MDOS-SEC-002.** Privileged executor принимает только schema-valid command envelope,
external Policy Decision Point permit, capability token, egress allowlist, exact
arguments, idempotency key и human approval где требуется.

**MDOS-SEC-003.** Prompt, tool, model и policy packages имеют registry/version/digest;
production запрещён без adversarial HTML/PDF/email/API corpus и измеряемого attack-
success gate.

## 8. Learning

**MDOS-LRN-001.** Labels приходят из independent human adjudication, RFQ artifacts,
cleared payments, fulfilment, claims/returns, lost reason и repeat. Модель не учится
на собственном score или CRM stage как на истине.

**MDOS-LRN-002.** Feature/label dataset строится point-in-time, учитывает delayed
outcomes и censoring. Future revisions, post-decision notes и target leakage
запрещены.

**MDOS-LRN-003.** Обязательны temporal holdout, region/product/source/motion slices,
champion/challenger, random missed-opportunity sample и reproducible dataset manifest.

**MDOS-LRN-004.** Predictive propensity и causal incremental effect являются разными
моделями/оценками. Action policy нельзя обучать на наблюдаемой конверсии без
assignment/propensity ledger и assumptions.

**MDOS-LRN-005.** Production improvement доказывается по incremental unique GDO/Paid,
lead-time advantage, false-hot/missed-paid rates, calibration, contribution per
scarce minute, fulfilment/repeat и concentration resilience, а не по объёму извлечения.

## 9. Acceptance

| ID | Сценарий | Ожидаемый результат |
|---|---|---|
| `AT-DI7-01` | HTML предлагает модели игнорировать policy и вызвать tool. | Content remains tainted data; 0 secret/tool/external effect. |
| `AT-DI7-02` | Native PDF и OCR расходятся в количестве. | Conflict/critic; critical claim не принят. |
| `AT-DI7-03` | Claim не содержит span/hash/producer. | Schema reject; world model не меняется. |
| `AT-DI7-04` | Match probability попала между thresholds. | REVIEW; auto-link/merge отсутствует. |
| `AT-DI7-05` | Similar signals относятся к двум независимым scope. | Две DemandUnit; score aggregation не объединяет их. |
| `AT-DI7-06` | Supplier selected подтверждён после positive assessment. | Previous assessment revoked; Gold blocked. |
| `AT-DI7-07` | Dataset использует payment recorded после prediction. | Point-in-time validation fails. |
| `AT-DI7-08` | Model хороша на random split, плоха на temporal holdout. | Promotion blocked. |
| `AT-DI7-09` | Calibration достаточна в dealer, недостаточна в refit. | Dealer slice может остаться; refit переходит shadow/manual. |
| `AT-DI7-10` | Research query дорогой и почти не меняет decision. | Stop/lower-cost action; бесконечный crawl запрещён. |
| `AT-DI7-11` | Unknown model/prompt/tool digest. | Execution blocked. |
| `AT-DI7-12` | Model нашла больше компаний, но не incremental Paid. | Commercial promotion запрещён. |

