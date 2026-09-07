# APP-MDOS-SOURCE-PORTFOLIO — российская signal mesh

**Application ID:** `APP-MDOS-SOURCE-PORTFOLIO`  
**Версия:** `1.1.0`

## 1. Source semantics

**MDOS-SRC-001.** Source Capability Passport хранит owner/vendor, access mechanism,
contract/terms version, source roles (`DISCOVERY/TRIGGER/INTENT/RFQ/OUTCOME`), data
classes, purpose, may_read/store/derive/export/train/contact, retention/cache, quota,
cost, freshness, revision/stable key, evidence quality, geographic/product coverage,
writer capability, dependencies, security review и expiry.

**MDOS-SRC-002.** Один источник может иметь разные permissions для разных продуктов.
Например, Yandex organization search может допускать временный cache, а договорный
Data.2GIS — постоянную B2B-базу; UI-доступ не означает разрешённую bulk integration.

**MDOS-SRC-003.** Source role не переносится: карта/реестр даёт discovery, разрешение
даёт trigger, поисковый визит даёт intent, полученная спецификация даёт RFQ, а
reconciled bank/payment proof вместе с Order/Fulfilment ledgers даёт outcome.
Blended source KPI запрещён.

**MDOS-SRC-004.** Public page и robots.txt не заменяют licence/authorization.
Изменение terms/API/schema автоматически ставит adapter и derived decisions на
повторный review.

## 2. Приоритетный портфель

**MDOS-PORT-001.** `Tier A+ — First-party outcome and known demand`:

- bank API/payment provider/подписанные выписки: платёжная истина;
- локальные OrderRegistry/FulfilmentLedger: заказ, отгрузка, маржа, claim, repeat;
- ERP при появлении: опциональный reconciled adapter, не prerequisite;
- Bitrix24: компании, interactions, tasks, deals, lost reasons;
- email, calls/chats, quotes/specifications, service/claims;
- installed asset/history;
- site/forms/calculator, ClientID, Yandex Metrica/Webmaster/Direct feedback.

Это первая очередь, потому что она ближе всего к payment truth и не требует
массового холодного discovery.

**MDOS-PORT-002.** `Tier A — Explicit inbound/RFQ`:

- собственная RFQ-форма, телефон, чат, comparison upload;
- Yandex Search/Business/Maps/Direct, 2GIS inbound;
- Avito Business 360 RFQ после category/API/commercial confirmation;
- договорные RFQ-площадки Supl.biz/PulseCen и аналоги;
- referral introductions с consent/authority.

SLA измеряется от поступления usable request; marketplace availability и API не
предполагаются без письменного подтверждения.

**MDOS-PORT-003.** `Tier B — Account/dealer/partner discovery and triggers`:

- договорный Data.2GIS;
- Yandex organization search в пределах licence/cache;
- ФНС ЕГРЮЛ/ЕГРИП/БФО как identity/risk;
- сайты/новости компаний через разрешённый Search API/capture;
- Работа России/HH только в допустимом назначении;
- отраслевые реестры, системодержатели, MosBuild/мероприятия, referrals.

Вакансия/новый филиал/категория не являются intent; Account остаётся watchlist до
второго сигнала, inbound либо current need verification.

**MDOS-PORT-004.** `Tier B — Commercial openings/refit`:

- официальные отчёты и press centres сетей;
- реестры/карты филиалов, разрешения, отраслевые реестры объектов;
- property/fit-out partners, facility/service signals;
- мониторинг brand rollout/renovation claims в разрешённых публичных данных.

Каждая chain должна перейти от corporate event к exact site, scope, buyer и date.

**MDOS-PORT-005.** `Tier B/C — Project/specification intelligence`:

- ЕИСЖС/наш.дом.рф и Платформа данных ДОМ.РФ;
- Минстрой/open permits, региональные ГИСОГД, ЕГРЗ;
- developer/project/architect sites и технические материалы;
- НОСТРОЙ/НОПРИЗ и отраслевые реестры как universe/role evidence.

Проектные источники сначала создают Object/SpecificationInfluence; Lead/GDO только
после buyer/scope/window proof.

**MDOS-PORT-006.** `Tier C — Tender/formal procurement`:

- ЕИС, ЭТП, TenderPlan, Контур, SabyTrade и коммерческие procurement feeds.

Этот tier важен, но не управляет общей архитектурой и не смешивается с dealer,
inbound или spec-in denominators.

**MDOS-PORT-007.** `Tier C — Market planning`:

- Wordstat/search trends, Росстат, Минстрой/ДОМ.РФ aggregates;
- FNS financial/risk, macro/industry data.

Эти данные меняют coverage, experiment budget и региональный приоритет, но не
создают индивидуальный lead.

## 3. Apify, ScrapeGraphAI и buy/build decision

**MDOS-ADP-001.** `Apify` предпочтителен как managed capture runtime, когда нужны
scheduled actors, queues/datasets, proxy, webhook, monitoring и custom code. Actor
проходит code/security/licence/data-quality review; marketplace popularity не является
доказательством корректности или права.

**MDOS-ADP-002.** `ScrapeGraphAI` предпочтителен как extraction/crawl/monitor service,
когда структура страниц меняется и нужен schema-guided extraction. Его LLM result
остаётся claim с exact source/hash/eval; deprecated v1 endpoints не закладываются.

**MDOS-ADP-003.** Для официального API/feed используется API/feed, а не browser
scraping. Adapter purchase/development допускается после ручного sealed pilot,
который доказал predictive/incremental value signal family и разрешённый lifecycle.

**MDOS-ADP-004.** Build/buy gate сравнивает: licence certainty, coverage, freshness,
stable IDs/revisions, evidence fidelity, recall/precision at capacity, outage risk,
security/data residency, exit/export, cost per incremental GDO/Paid и concentration.

## 4. Outreach and advertising boundary

**MDOS-LGL-001.** До письменного legal workflow массовый холодный email, автоматическая
рассылка/дозвон и рекламный контакт без доказуемого предварительного согласия
технически выключены. Suppression действует независимо от source/contact смены.

**MDOS-LGL-002.** Advertising journey хранит advertiser, content/promise version,
audience basis, consent/purpose where applicable, marking/ORD identifiers, spend,
treatment assignment и downstream Paid/contribution.

**MDOS-LGL-003.** Первичный inbound, ответ на конкретный RFQ, договорное взаимодействие
и advertising являются разными legal/purpose profiles; их нельзя объединять одним
флагом `can_contact`.

## 5. Source SLAs and evidence

**MDOS-SLA-001.** Для каждого adapter измеряются freshness, capture completeness,
schema validity, stable-key collision, revision detection, extraction field accuracy,
cost, latency, outage, licence expiry и downstream incremental outcomes.

**MDOS-SLA-002.** Source без ground-truth outcome может оставаться discovery/research,
но не получает scale на основании объёма. Source с высокой Paid value и низким
coverage не штрафуется за малый объём.

**MDOS-SLA-003.** Dependency families учитываются в resilience: пять actors одного
сайта не являются пятью независимыми источниками.

## 6. Acceptance

| ID | Сценарий | Ожидаемый результат |
|---|---|---|
| `AT-SRC7-01` | Places API разрешает поиск, но не постоянное хранение. | Cache/TTL enforcement; CRM persistence blocked. |
| `AT-SRC7-02` | Data.2GIS договор разрешает XLSX client base. | Ingest только в contract scope с provenance/retention. |
| `AT-SRC7-03` | Avito RFQ category/API не подтверждены. | Pilot proposal; production adapter и volume promise blocked. |
| `AT-SRC7-04` | Apify Actor вернул 10000 contacts. | Raw candidates only; 0 lead/contact action до downstream gates. |
| `AT-SRC7-05` | ScrapeGraph извлёк неверную quantity. | Field eval/conflict; critical claim rejected. |
| `AT-SRC7-06` | Source terms изменились. | Permit expires; adapter/derived actions paused for review. |
| `AT-SRC7-07` | Public corporate phone найден в реестре. | Discovery evidence; advertising consent не создан. |
| `AT-SRC7-08` | Wordstat показывает рост запроса. | Market plan update; 0 individual lead. |
| `AT-SRC7-09` | Один provider питает пять adapters. | Один dependency family в concentration/failover metric. |
| `AT-SRC7-10` | Source дал много forms, но 0 incremental Paid. | Stop/revise; scale запрещён. |
