# APP-LF-SOURCE-CRM — bounded contexts, источники и Bitrix24

**Application ID:** `APP-LF-SOURCE-CRM`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Bounded contexts

**LF-ARC-001.** Реализация разделяется на контексты с явным владением данными:

1. `Source Lab` — разрешённое получение, raw event, freshness, quality и cost.
2. `Identity & Evidence Graph` — Company/Contact/Project identity, provenance и dedupe.
3. `Dealer Intelligence` — ICP, external buying, products, region и account lifecycle.
4. `Funnel Cases` — DealerAccountCase, RoutingRequest и ProjectPursuit.
5. `Qualification & Gold Gate` — versioned profiles и counting key.
6. `Method Lab` — proposals, experiments и promotion evidence.
7. `Capacity & Routing` — WIP, slots, assignment, protection и backpressure.
8. `Commercial Spine` — Estimate, Proposal, Order, Payment и Repeat.
9. `CRM Projection` — идемпотентная рабочая проекция для людей.
10. `Analytics & Economics` — cohorts, attribution, quality и margin.

**LF-ARC-002.** Контекст не может писать в чужое каноническое состояние напрямую.
Взаимодействие выполняется typed command/event с idempotency key и provenance.

**LF-ARC-003.** Bitrix — проекция и рабочее место человека, а не Event Store,
сырой рынок, Source Lab, Method Lab или авторитет оплаты.

## 2. Source Passport v2

**LF-SRC-001.** Паспорт описывает конкретную комбинацию:

```text
provider product + acquisition mode + data contract + permitted purpose
```

`Apify`, `ScrapeGraphAI`, `Яндекс`, `Авито`, `Контур` или `Saby` без product/mode
не являются достаточным `source_id`.

**LF-SRC-002.** Обязательные группы паспорта:

- Identity: source/provider/product/owner/version/lifecycle;
- Purpose: funnels, record kinds, product, geography, data classes;
- Legal: acquisition mode, licence/terms decision, URL/hash/version, validity,
  retention/deletion и personal-data restrictions;
- Contract: stable external ID, timestamps/revisions, schema/mapping ID+hash,
  evidence recipe, identity namespaces и dedupe policy;
- Runtime: auth reference без секрета, cursor/pagination, rate/quota/cost caps,
  freshness, read epoch и STOP authority;
- Reliability: replay/idempotency, reconciliation, failure modes, fallback и SLA;
- Quality/economics: ICP accuracy, unique signal share, overlap, AGCO/paid outcomes,
  stop/scale rules.

**LF-SRC-003.** Lifecycle вычисляется:

```text
DRAFT → OFFLINE_ELIGIBLE → CANARY_ELIGIBLE → ACTIVE
                                      ↘ PAUSED / REVOKED / EXPIRED
```

`ACTIVE` нельзя установить вручную. Одновременно действительны exact passport,
capability, licence, mapping, permit, runtime epoch и budget/capacity evidence.

**LF-SRC-004.** Никакой источник не создаёт Deal/AGCO напрямую. Он создаёт raw
SourceEvent и evidence; qualification выполняется независимо.

**LF-SRC-005.** Source, discovery channel, trigger, acquisition interaction,
RFQ channel, original attribution, latest attribution и order attribution
хранятся раздельно и не перезаписывают друг друга.

## 3. Роль конкретных классов источников

**LF-SRC-010.** Первая acquisition cohort формируется из существующего капитала:

1. warm conversations;
2. HOT dealer accounts;
3. deduplicated retail targets;
4. lapsed/previous buyers;
5. только затем новые discovery sources.

Смешанная legacy-очередь 40 680 не является eligible cohort без новой дедупликации
и dealer qualification.

**LF-SRC-011.** Яндекс Поиск/Карты, 2ГИС, Авито, сайты и отраслевые каталоги могут
быть discovery/trigger evidence для account-based работы. Карточка или объявление
не являются потребностью/AGCO.

**LF-SRC-012.** Supplier-intent search работает отдельным методом, ведёт на dealer
landing/RFQ, сохраняет UTM/yclid/correlation и получает feedback только по
DealerRFQ, TrialPayment, RepeatPayment и margin. Form submit — diagnostic event.

**LF-SRC-013.** Tender/EIS/project sources работают только в `PROJECT_TENDER`.
Победитель становится dealer candidate отдельной derived-командой после проверки
external buying и repeat potential.

**LF-SRC-014.** Apify является execution/monitoring infrastructure, а не источником
спроса. ScrapeGraph AI является extraction/classification layer, а не доказательством
факта. Их production purchase/use запрещены до ручного pilot evidence, что извлекаемые
признаки предсказывают DealerRFQ/Trial и источник разрешает выбранный mode.

**LF-SRC-015.** Новый сервис проходит capability test на собственных данных до
покупки production-тарифа: unique eligible accounts/signals, accuracy, freshness,
overlap, legal mode, cost per DealerRFQ/AGCO/Trial и operational burden.

## 4. CRM-проекция Bitrix24 Standard

**LF-CRM-001.** MVP не создаёт три физические Bitrix-воронки acquisition.
Логическая изоляция выполняется в TenderBot, а Bitrix получает только общую
коммерческую магистраль после Gold Gate.

**LF-CRM-002.** Проекция:

- `Company` — единый коммерческий аккаунт; dealer lifecycle хранится здесь;
- `Contact` — человек и роль;
- `Lead` — только truly unprocessed new inbound или первый живой неизвестный ответ;
- `Deal` — только distinct CommercialOpportunity/Project после Gold Gate;
- `Activity` — ближайшее человеческое действие;
- `Estimate/Proposal/Order/Payment` — коммерческие стадии/связанные записи.

Сырые Candidate/Signal/RoutingRequest/ProjectPursuit в Bitrix не пишутся.

**LF-CRM-003.** Ответ существующего дилера создаёт Interaction/Activity на Company
или Deal, а не новый Lead/Company.

**LF-CRM-004.** Одна Company с двумя distinct RFQ создаёт одну Company и две Deal.
Revision одного scope обновляет versioned RFQ/Deal, но не создаёт новый counting key.

## 5. Минимальные поля

**LF-CRM-005.** Общие поля Deal/Opportunity:

- `LF_FUNNEL_TYPE`;
- `LF_FUNNEL_CASE_ID`;
- `LF_DERIVED_FROM_CASE_ID`;
- `LF_QUALIFICATION_PROFILE_VERSION`;
- `LF_METHOD_VERSION`;
- `LF_COMMERCIAL_COUNTING_KEY`;
- `LF_SOURCE_EVENT_ID` и evidence reference;
- original/latest/RFQ/order attribution;
- `LF_NEXT_ACTION_AT`, owner и disposition;
- Project/product/region/decision window;
- ReadyPackage/Estimate/Proposal/Order/Payment IDs.

**LF-CRM-006.** Dealer Company fields:

- `LF_DEALER_ACCOUNT_ID` и subsegment;
- `LF_ICP_VERIFIED_AT`;
- `LF_EXTERNAL_BUYER_STATUS` и evidence;
- `LF_OWN_AL_PRODUCTION`;
- products, installation, delivery/service zone;
- decision-maker contact;
- dealer lifecycle/status reason/version;
- last DealerRFQ, last paid order, distinct order count;
- trial/repeat paid timestamps.

**LF-CRM-007.** RFQ/Deal fields:

- Dealer/Factory/Project RFQ ID и received time;
- project/scope fingerprint;
- completeness и missing items;
- decision/delivery date;
- quote SLA/version;
- payment trigger/paid time;
- distinct order ID;
- routing assignment/object protection IDs при применимости.

## 6. Каноническое владение

**LF-CRM-008.** TenderBot владеет funnel identity, evidence, source/method versions,
counting key и qualification decision. Bitrix владеет human owner, ручной
qualification feedback, next action и negotiation disposition. Учёт/подтверждённая
платёжная система владеет cleared payment и фактической маржой.

**LF-CRM-009.** Конфликт полей разрешается по карте ownership; latest timestamp
не является универсальным правилом. Несовпадение создаёт reconciliation task.

**LF-CRM-010.** CRM write идемпотентен по LF-ID/counting key, выполняется через
transactional outbox и подтверждается typed read-back. Timeout/retry не создаёт дубль.

## 7. Outcome feedback

**LF-CRM-011.** В рекламу/аналитику передаются раздельные события:

- diagnostic form submit;
- AGCO/DealerRFQ;
- Trial cleared payment;
- Repeat cleared payment;
- фактическая contribution/gross margin.

Обучать закупку трафика только на form submit запрещено после появления зрелого
CRM outcome.

**LF-CRM-012.** Не менее 95% Estimate, Proposal, Order и Payment должны быть связаны
с original case, counting key, method, source и Company. При measurement gap >5%
evaluation window не принимается.

## 8. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-SRC-01` | Истёк licence при valid passport. | Read отклонён. |
| `AT-SRC-02` | Secret записан в passport. | Schema/ingest reject. |
| `AT-SRC-03` | Mapping/passport hash mismatch. | 0 Source Lab rows/usage. |
| `AT-SRC-04` | Raw source record выглядит горячим. | 0 Deal/AGCO до Gold Gate. |
| `AT-CRM-01` | Один DealerAccount, два distinct RFQ. | 1 Company, 2 Deal. |
| `AT-CRM-02` | Повторный ответ existing dealer. | Activity, не новый Lead. |
| `AT-CRM-03` | Retry/timeout одного write. | Ровно одна remote entity. |
| `AT-CRM-04` | Form submit без outcome. | Diagnostic conversion, не AGCO. |
| `AT-CRM-05` | Payment без source/case linkage. | Measurement gap; proof блокируется. |
| `AT-CRM-06` | Routed demand без capacity/consent permit. | Assignment/write блокируется. |

