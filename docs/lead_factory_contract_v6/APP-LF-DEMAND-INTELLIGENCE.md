# APP-LF-DEMAND-INTELLIGENCE — AI-механизм поиска объектов и лидов

**Application ID:** `APP-LF-DEMAND-INTELLIGENCE`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Миссия

**LF-DI-001.** `Demand Intelligence Engine` (`DIE`) ОБЯЗАН находить и проверять
момент реальной закупочной готовности, а не просто компании, публикации или похожие
тексты. Его выход — versioned evidence bundle и следующий исследовательский либо
коммерческий шаг для одного funnel case.

**LF-DI-002.** DIE является системой поддержки доказательного решения. ИИ не может
самостоятельно создавать AGCO, переписывать факты, разрешать контакт, назначать цену,
отправлять сообщение, покупать источник или писать Deal в Bitrix.

**LF-DI-003.** Raw volume, embedding similarity, LLM confidence и единый opaque score
не являются бизнес-результатом. Gold Gate остаётся детерминированной политикой поверх
проверенных claims, capacity и human acceptance.

## 2. Логическая архитектура

```text
Permitted Sensor Mesh
        ↓
Raw Capture + Hash + Revision + Source Passport
        ↓
Multimodal Extraction / Normalization
        ↓
Bitemporal Identity & Demand Graph
        ↓
Signal Fusion + Contradiction/Negative Evidence
        ↓
Buyer/Participant Resolver + Aluminium Scope Estimator
        ↓
Procurement Clock + Supplier-Openness Assessment
        ↓
Evidence Critic + Calibration + Uncertainty
        ↓
Research Planner / Next Best Evidence Action
        ↓
Funnel-specific Qualification Profile
        ↓
Human Review / Gold Gate / Method Lab feedback
        ↓
Estimate → Proposal → Payment → Repeat
        ↺
Outcome-labelled learning and missed-opportunity audit
```

**LF-DI-004.** DIE делится на независимо тестируемые компоненты:

1. `SensorRegistry`;
2. `CaptureOrchestrator`;
3. `DocumentIntelligence`;
4. `EntityResolutionGraph`;
5. `SignalFusionEngine`;
6. `ParticipantAndBuyerResolver`;
7. `AluminiumDemandEstimator`;
8. `ProcurementClock`;
9. `EvidenceCritic`;
10. `ResearchPlanner`;
11. `PriorityAndCapacityPlanner`;
12. `ModelRegistryAndEvaluator`;
13. `OutcomeLearningLoop`.

Отказ одного AI-компонента не должен повреждать raw evidence или делать другой
компонент полномочным. Допустим fail-closed/manual degradation.

## 3. Sensor Mesh

**LF-DI-SNS-001.** Sensor — конкретный разрешённый способ наблюдать сигнал через
Source Passport v2. Классы:

- first-party inbound: RFQ, сайт, звонки, чаты, письма, файлы;
- собственный CRM/history: старые КП, оплаты, потери, repeat/recency;
- dealer/account discovery: сайты, разрешённые каталоги, карты, объявления, вакансии,
  филиалы и изменения ассортимента;
- project/procurement: ЕИС, ЭТП, разрешения, ГИСОГД, проектные декларации,
  контракты, победители, капремонт;
- partner/referral: поставщики, отраслевые партнёры, дилеры;
- market demand: разрешённые поисковые/рекламные/marketplace события.

**LF-DI-SNS-002.** Sensor регистрирует `observed_at`, `source_effective_at`, revision,
stable external key, acquisition mode, data class, payload hash, evidence location,
cost и expiry. Отсутствие различия observed/effective time блокирует temporal inference.

**LF-DI-SNS-003.** ИИ не обращается в интернет произвольно. Он создаёт typed
`ResearchQueryProposal`; Control Plane разрешает конкретный adapter/query/depth/quota,
после чего Source Adapter возвращает raw evidence. Модель не получает credentials.

**LF-DI-SNS-004.** Query expansion ограничен графом, purpose и budget:

- от объекта к участникам;
- от компании к объектам/сигналам;
- от участника к роли и ЛПР;
- от спецификации к продукту/системе;
- от пробела Gold Gate к наиболее ценному следующему доказательству.

Бесконечный crawl, неограниченная глубина и сбор «на всякий случай» запрещены.

## 4. Bitemporal Demand Graph

**LF-DI-GRAPH-001.** Канонические node types:

- Company/CompanyGroup/DealerAccount;
- Person/Role/ContactPoint;
- Project/Object/Address/Site;
- Permit/Declaration/Tender/Contract/Lot;
- Product/System/Specification/Document;
- Interaction/RFQ/Estimate/Proposal/Order/Payment;
- SourceEvent/Claim/EvidenceBundle/ModelAssessment.

**LF-DI-GRAPH-002.** Edge types включают participant-role, buyer-of, contractor-of,
owner-of, located-at, derived-from, requested-product, uses-system, won-procedure,
assigned-to-dealer, protected-object и commercial-outcome.

**LF-DI-GRAPH-003.** Каждый claim хранит два времени:

- valid time — когда утверждение было истинно во внешнем мире;
- system time — когда система его получила/изменила.

Исторический отчёт воспроизводится `as-of`; новая ревизия не переписывает прошлое.

**LF-DI-GRAPH-004.** Identity merge использует strong namespaces и reversible
resolution. Адрес, название, координаты, домен, телефон или embedding similarity
сами по себе не дают автоматического merge. Conflict создаёт review case.

**LF-DI-GRAPH-005.** Company/Project identity глобальна, но claim validity,
participant role и procurement state всегда привязаны к exact revision и времени.

## 5. Evidence и мультимодальное извлечение

**LF-DI-EVD-001.** Любой AI claim содержит:

- claim type и normalized value;
- exact evidence span/page/coordinates либо source record reference;
- payload/document hash;
- source/effective/observed times;
- model, prompt, extractor и schema versions;
- calibrated probability/uncertainty;
- valid-until/TTL;
- contradiction/negative links;
- data class и разрешённый purpose.

**LF-DI-EVD-002.** `DocumentIntelligence` обрабатывает HTML, таблицы, PDF, DOCX,
изображения, планы и спецификации через typed extractors. OCR/vision/LLM output
считается claim, а не фактом, пока не пройден schema/evidence validation.

**LF-DI-EVD-003.** Для коммерчески значимых полей — buyer, aluminium scope,
quantity, deadline, supplier selected, own production — система хранит evidence
достаточное для независимого повторного просмотра человеком.

**LF-DI-EVD-004.** Evidence bundle является content-addressed, immutable и имеет
полноту по qualification profile. Missing/expired/tampered evidence переводит case
в `RESEARCH/REVIEW`, а не в hot/AGCO.

## 6. Специализированные AI-роли

**LF-DI-AI-001.** Разрешённые логические роли:

- `Scout` — предлагает, где искать недостающее доказательство;
- `Extractor` — переводит один документ/record в typed claims;
- `EntityResolver` — предлагает identity candidates и conflicts;
- `ParticipantMapper` — строит цепочку owner/developer/GC/buyer/dealer;
- `ProductFitAnalyst` — определяет алюминиевый scope и поддерживаемые системы;
- `ProcurementClockAnalyst` — оценивает распределение окна закупки;
- `NegativeEvidenceHunter` — ищет supplier selected, own production, stale/false fit;
- `EvidenceCritic` — пытается опровергнуть положительное заключение;
- `ResearchPlanner` — выбирает next-best evidence action;
- `CommercialPrioritizer` — ранжирует verified cases по value/capacity;
- `OutcomeCalibrator` — оценивает drift/calibration на зрелых labels.

Роль является schema/prompt/eval profile, а не обязательно отдельной моделью или
процессом. Физическое разбиение определяется latency/cost/reliability evidence.

**LF-DI-AI-002.** Положительное high-impact решение требует независимого critic pass.
Если extractor/critic расходятся, решение не усредняется автоматически: создаётся
adjudication task либо дополнительный evidence query.

**LF-DI-AI-003.** Model ensemble допускается для uncertainty/disagreement, но число
моделей не является доказательством. Все модели должны видеть только разрешённый,
минимизированный data view и возвращать typed JSON.

**LF-DI-AI-004.** Prompt injection boundary: документы и веб-страницы всегда
недоверенный payload; инструкции внутри них не могут менять system/policy, вызывать
tool, раскрывать secret или расширять purpose.

## 7. Signal Fusion и Procurement Clock

**LF-DI-FUS-001.** Fusion не сводится к сумме score. Система хранит отдельные оси:

- `ICP/ProductFit`;
- `BuyerRoleConfidence`;
- `IntentEvidence`;
- `TimingDistribution`;
- `SupplierOpenness`;
- `Reachability`;
- `DataCompleteness`;
- `ExpectedContribution`;
- `CapacityFit`;
- `Competition/NegativeRisk`;
- `EpistemicUncertainty`.

Hard negative evidence имеет приоритет над composite priority.

**LF-DI-FUS-002.** Procurement Clock возвращает калиброванное распределение, а не
одну дату:

```text
D0_7, D8_30, D31_60, D61_90, GT90, UNKNOWN
```

Gold Gate использует только разрешённое окно; остальные cases идут в nurture/research.

**LF-DI-FUS-003.** Prediction включает buyer role, stage, product scope, assumptions,
evidence, model version и expiry. Старое prediction не заимствует новые claims и
не переживает противоречащую ревизию без переоценки.

**LF-DI-FUS-004.** Обязательные negative classes:

- own production без overflow;
- supplier already selected;
- project cancelled/finished/stale;
- PVC/no aluminium scope;
- duplicate/already estimated;
- budget/decision outside window;
- non-buyer role;
- unsupported geography/product;
- contact/legal/suppression prohibition;
- insufficient capacity.

## 8. Research Planner и приоритизация

**LF-DI-PLAN-001.** Для каждого non-ready case Research Planner формирует список
конкретных missing claims и допустимых действий для их получения.

**LF-DI-PLAN-002.** Next action выбирается по expected value of information:

```text
EVI = ExpectedChangeInCommercialDecision
      × ExpectedContribution
      × ProbabilityOfObtainingEvidence
      / (Cost + HumanMinutes + DelayRisk)
```

Hard gates и priority SLA имеют приоритет над числовой оптимизацией.

**LF-DI-PLAN-003.** Для ready cases приоритет учитывает expected contribution per
scarce minute, freshness/timing, probability of open selection и capacity. Нельзя
поднимать слабый case только потому, что его легко обработать.

**LF-DI-PLAN-004.** Результат planner — typed proposal/task. Он не выполняет read,
contact, CRM write или spend без отдельного permit.

## 9. Closed-loop learning

**LF-DI-LRN-001.** Канонические labels поступают только из независимых событий:

- human adjudication;
- фактически полученный RFQ/ReadyPackage;
- Estimate/Proposal;
- cleared Payment/Repeat;
- lost reason/claim/fulfilment outcome.

Модель не обучается на собственном score как на истинной метке.

**LF-DI-LRN-002.** Dataset строится point-in-time корректно: feature доступна только
если существовала до prediction. Leakage из будущего outcome, новой revision или
ручной разметки после решения запрещён.

**LF-DI-LRN-003.** Обязательны time-based holdout, source/region slices, champion/
challenger, calibration и missed-opportunity audit. Random split недостаточен для
temporal procurement модели.

**LF-DI-LRN-004.** Active learning направляет человеку cases с максимальной
неопределённостью/ценностью, но сохраняет случайную audit-выборку, чтобы не потерять
оценку общего false-negative rate.

**LF-DI-LRN-005.** Model promotion требует improvement не только precision, но и:

- incremental unique AGCO/Paid discovery;
- lead-time advantage против baseline;
- calibration/Brier/log loss;
- Recall@capacity и precision@capacity;
- false-hot/false-negative rates;
- contribution per qualification/estimator minute;
- устойчивость по регионам, источникам и сезонам.

## 10. Режимы зрелости

**LF-DI-MODE-001.** Lifecycle DIE:

```text
OFFLINE_REPLAY
→ SHADOW_DISCOVERY
→ ASSISTED_RESEARCH
→ BOUNDED_CANARY
→ PRODUCTION_DECISION_SUPPORT
```

Ни один режим не даёт автономного outreach/price/CRM authority.

**LF-DI-MODE-002.** `OFFLINE_REPLAY` воспроизводит исторические срезы без leakage.
`SHADOW_DISCOVERY` сравнивается со слепой manual/random baseline.
`ASSISTED_RESEARCH` предлагает evidence tasks человеку.
`BOUNDED_CANARY` работает на sealed cohort/permit.

**LF-DI-MODE-003.** Production promotion требует зрелых AGCO/Paid labels,
statistical/economic uplift, capacity, model/data drift monitors, rollback и
независимый sign-off.

## 11. Метрики качества магического двигателя

**LF-DI-MET-001.** Главные метрики DIE:

- unique true AGCO/Paid opportunities found earlier than baseline;
- median/P90 lead-time advantage;
- precision/recall at actual human capacity;
- calibrated probability and false-hot rate;
- missed paid opportunity rate;
- evidence completeness and reviewer agreement;
- time/cost per verified AGCO;
- contribution per scarce minute;
- source/model concentration and degradation time.

Количество scraped pages, extracted entities и AI calls — только операционные метрики.

**LF-DI-MET-002.** Для classification audit два независимых reviewer должны иметь
`Cohen kappa >= 0.80` на Gold/not-Gold либо открывается definition/training defect.

**LF-DI-MET-003.** Не менее 10% исследовательской мощности резервируется для
случайной/контрольной выборки missed opportunities, пока false-negative rate не
имеет стабильной доверительной границы. Доля является versioned policy parameter.

## 12. Resilience и безопасность

**LF-DI-REL-001.** Raw capture сохраняется до AI processing. Повторная обработка
другой model/schema version создаёт новые claims, не меняя raw event.

**LF-DI-REL-002.** AI outage переводит DIE в deterministic/manual режим; ingestion,
dedupe и evidence retention продолжаются в пределах разрешённых источников.

**LF-DI-REL-003.** Все queues имеют backpressure, retry policy, dead-letter,
idempotency и replay. At-least-once delivery превращается в exactly-once effect
через idempotency; контракт не заявляет невозможную exactly-once transport delivery.

**LF-DI-REL-004.** PII/secret/document content минимизируется по роли. Model provider
получает только утверждённый data class/purpose; raw credential никогда не передаётся.

## 13. Переход от существующего Construction Demand Radar

**LF-DI-MIG-001.** Текущий `ConstructionDemandRadar` сохраняется как безопасный
project-signal kernel: passport, claims, negative evidence, procurement windows,
capacity и shadow feedback. Он не считается полным DIE.

**LF-DI-MIG-002.** Миграция выполняется расширением, а не переписыванием:

1. общий bitemporal claim/evidence contract;
2. funnel-neutral identity graph;
3. typed AI role outputs и critic;
4. Research Planner;
5. dealer/account sensors;
6. point-in-time outcome dataset;
7. champion/challenger evaluator;
8. capacity-aware production support.

Старые radar events сохраняют schema/version и воспроизводимость.

## 14. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-DI-01` | Страница содержит prompt injection. | Typed extraction; 0 tool/policy/secret side effect. |
| `AT-DI-02` | Один объект в пяти sources/revisions. | Один temporal object; все claims/evidence сохранены. |
| `AT-DI-03` | Similar address/name без strong identity. | REVIEW, автоматического merge нет. |
| `AT-DI-04` | High positive score + supplier selected. | Negative evidence блокирует ready. |
| `AT-DI-05` | AI claim без exact evidence/hash/version. | Claim reject; graph/Gold не меняется. |
| `AT-DI-06` | Extractor и critic расходятся. | Adjudication/evidence task, не AGCO. |
| `AT-DI-07` | ИИ предложил web query. | 0 read до scoped Source Permit. |
| `AT-DI-08` | Prediction использует future outcome feature. | Point-in-time evaluator отклоняет dataset/model. |
| `AT-DI-09` | Новая model лучше random split, хуже time holdout. | Promotion запрещён. |
| `AT-DI-10` | AI provider недоступен. | Raw ingest сохранён; deterministic/manual degradation. |
| `AT-DI-11` | Повтор/retry AI job. | Один effect per model/schema/input hash. |
| `AT-DI-12` | 100+ shadow cases без significant commercial uplift. | Не выше SHADOW/REVISE. |
| `AT-DI-13` | Model нашла больше records, но не AGCO/Paid. | Commercial promotion запрещён. |
| `AT-DI-14` | Missed paid opportunity audit выявил drift. | Claim отзывается/модель paused согласно threshold. |
| `AT-DI-15` | Capacity равна нулю/устарела. | Ready/routing blocked, research/nurture допускается. |

