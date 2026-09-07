# Контракт АлюмКомплект Market & Demand OS v7.2 RC2

**Contract ID:** `AK-MDOS-V7`  
**Версия:** `7.2.0-rc.2`  
**Статус:** `RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION`  
**Дата фиксации:** 02.09.2026  
**Владелец результата:** АлюмКомплект  
**Исполнительный контур:** MDOS / TenderBot / сайт / Bitrix24 / банк или платёжный
провайдер / локальные реестры заказов и исполнения / люди

## 1. Предмет обязательства

**MDOS-MIS-001.** Система ОБЯЗАНА обнаруживать, проверять, развивать и измерять
коммерческий спрос АлюмКомплект во всех утверждённых `DemandMotion`, а не только в
тендерах, объектах, email-базах или одном рекламном канале.

**MDOS-MIS-002.** Главной единицей работы является `DemandUnit`: одна независимо
принимаемая потребность конкретного участника/группы участников в определённом
продуктовом scope, для объекта/места, с временным окном, supplier state,
доказательствами и экономически допустимым маршрутом.

**MDOS-MIS-003.** Контакт, компания, визит, разрешение, вакансия, публикация,
тендер, клик, форма и AI-score не являются DemandUnit или клиентом. Они являются
наблюдениями либо claims до выполнения соответствующих доказательных условий.

**MDOS-MIS-004.** Система ведёт разработку к `PROVEN_GDO10` — доказанной способности
создавать не менее десяти уникальных `AcceptedGoldenDemandOpportunity` в рабочий
день на зрелом окне наблюдения — и отдельно доказывает переходы в cleared payment,
положительную contribution margin и repeat.

**MDOS-MIS-005.** `GDO10` не означает «10 новых оплат/клиентов в день». Профиль
`PROVEN_PC10` разрешается активировать только отдельной ратификацией после
наблюдаемой обратной воронки, платёжной истины, unit economics и capacity proof.

**MDOS-MIS-006.** Ни контракт, ни ИИ не гарантируют поведение рынка. Контракт
гарантирует доказательный процесс: coverage, воспроизводимость, SLA, эксперименты,
правовой контроль, локализацию bottleneck и остановку методов без прироста.

## 2. Коммерческая система, а не воронка

**MDOS-SCP-001.** Нормативные motions:

1. `EXISTING_ACCOUNT_EXPANSION`;
2. `DEALER_AND_INSTALLER_ACTIVATION`;
3. `HIGH_INTENT_INBOUND`;
4. `PARTNER_AND_REFERRAL`;
5. `COMMERCIAL_OPENING_AND_REFIT`;
6. `PROJECT_SPECIFICATION_INFLUENCE`;
7. `PROJECT_BUYER_PURSUIT`;
8. `INSTALLED_BASE_SERVICE_AND_REPLACEMENT`;
9. `ROUTED_PREMIUM_CONSUMER`;
10. `TENDER_AND_FORMAL_PROCUREMENT`;
11. `MARKET_SHAPING_AND_EDUCATION`.

**MDOS-SCP-002.** Каждый motion имеет отдельные состояния, proof-of-intent,
тайминги, Gold Gate, KPI, offer, legal basis и denominator. Универсальная стадия
`HOT` и единый opaque score запрещены.

**MDOS-SCP-003.** `PROJECT_SPECIFICATION_INFLUENCE` и `MARKET_SHAPING_AND_EDUCATION`
могут создавать доказанный pipeline influence, но не GDO до появления покупателя,
открытого выбора, scope и decision window.

**MDOS-SCP-004.** Тендер является одним `EvidenceEvent` внутри отдельного motion.
Опубликованная закупка, победитель или разрешение сами по себе не создают GDO.

## 3. Разделение истин

**MDOS-TRU-001.** Авторитетные классы фактов разделены:

- платёж — только reconciled event банка, платёжного провайдера или подписанная
  банковская выписка с уникальным provider event, плательщиком, получателем, суммой,
  валютой, value date и content hash;
- заказ — утверждённая запись локального `OrderRegistry`, связанная с distinct
  DemandUnit, коммерческими условиями и версией;
- исполнение/отгрузка/рекламация — запись локального `FulfilmentLedger` с первичным
  документом, actor и evidence hash;
- consent/suppression — специализированный ledger;
- raw observation — неизменяемый source capture;
- identity/role/DemandUnit — versioned adjudicated decision с evidence;
- Bitrix24 — исполнительная проекция продаж, если иной ownership не закреплён;
- AI output — claim/proposal, никогда не canonical commercial fact.

**MDOS-TRU-002.** `latest timestamp wins` запрещён для конфликтующих фактов.
Конфликт сохраняет обе версии, блокирует зависимое critical action и проходит
независимый arbitration.

**MDOS-TRU-003.** Discovery source, trigger source, interaction source, influence,
action/treatment, RFQ origin, routing и order attribution хранятся раздельно и не
перезаписывают друг друга.

**MDOS-TRU-004.** Счёт, договор, акт менеджера, стадия Bitrix24, производство,
отгрузка и human adjudication не могут создать `CLEARED_PAYMENT`. Они могут создать
claim либо `QualityConflict`; коммерческий KPI увеличивается только после валидного
`PaymentProof` со статусом `RECONCILED`. При появлении ERP он подключается как
опциональный adapter и не отменяет банковскую платёжную истину.

## 4. Интеллектуальный актив

**MDOS-AST-001.** Главным активом является `Demand Intelligence & Orchestration
Engine` (`DIOE`), состоящий из:

- разрешённой sensor mesh;
- evidence/lineage substrate;
- bitemporal Market, Account, Object, Interaction и Installed-base Graph;
- role/buying-group и product-capability graph;
- DemandUnit resolver и motion engines;
- next-best-evidence и next-best-action planners;
- selective decision, capacity/economic optimizer;
- outcome, causal experiment и learning loop.

**MDOS-AST-002.** Apify и ScrapeGraphAI МОГУТ использоваться как заменяемые
capture/extraction adapters только после source capability/licence test. Они не
дают права доступа, не являются источником намерения и не получают полномочий
contact/CRM/spend.

**MDOS-AST-003.** TenderPlan, Контур, ЕИС, Авито, Яндекс, 2ГИС, ДОМ.РФ, ФНС,
ГИСОГД и будущие площадки подключаются через одинаковый Source Contract; бизнес-
логика не зависит от vendor-specific сущности `lead`.

## 5. Запрет подмены результата

**MDOS-OUT-001.** Не считаются результатом: scraped pages, contacts, messages,
opens, clicks, forms, companies, candidate objects, calculations без current need,
AI calls, CRM cards и quoted amount без независимого outcome.

**MDOS-OUT-002.** Считаются раздельно: `DemandUnit`, `GDO`, `RFQ`, `ReadyPackage`,
`Estimate`, `Proposal`, `PaidOrder`, `PositiveContributionOrder`, `RepeatOrder`,
`ActiveDealer`, `SpecifiedProject` и `RoutedConsumerOutcome`.

**MDOS-OUT-003.** Если GDO не превращаются в оплату и вклад, `PROVEN_GDO10` не даёт
права заявлять, что система приносит клиентов. Открывается diagnosis и меняются
offer, qualification, timing, channel, routing или fulfilment.

## 6. Полномочия и безопасность

**MDOS-AUT-001.** По умолчанию разрешены offline-анализ собственных законно
полученных данных, shadow scoring, schema/eval development и предложения методов.

**MDOS-AUT-002.** Внешнее чтение, сохранение, enrichment, передача провайдеру,
contact, реклама, публикация, покупка, цена/обещание, Bitrix-write и routing требуют
отдельного machine-verifiable permit с purpose, scope, TTL, role и budget/capacity.

**MDOS-AUT-003.** Публичность контакта, страница в интернете и robots.txt не являются
разрешением на сохранение, обучение либо рекламный контакт. Legal/source policy
проверяется при ingestion и повторно при каждом use/export/train/contact.

**MDOS-AUT-004.** ИИ не может разрешать собственное действие, создавать Payment,
Order, Consent, Suppression, Promise, Gold acceptance или необратимое identity merge.

**MDOS-AUT-005.** Каждое внешнее действие ссылается на exact immutable
`PermitDecision`, содержащий решение `ALLOW/DENY`, purpose, action/channel, subject
scope, legal/source basis, policy version, issuer, TTL, budget/capacity boundaries и
digest. Строка `permit_id`, просроченное разрешение или разрешение другого scope не
достаточны; действие блокируется до новой проверки непосредственно перед эффектом.

## 7. Definition of Success

**MDOS-SUC-001.** `PROVEN_GDO10` требует одновременно:

- sealed evaluation window 30 последовательных рабочих дней;
- не менее 300 уникальных accepted GDO и не менее 10 в 24 из 30 дней;
- immutable `GoldAcceptance` для каждого GDO: human reviewer, sealed cohort и
  denominator, cut-off, stable scope fingerprint, evidence bundle, lawful permit,
  capacity/economics snapshots и permitted next action;
- не менее трёх commercially independent motions либо approved concentration risk;
- 100% lawful-next-action decisions и ноль unauthorized external effects;
- estimator/sales/production capacity и p90 SLA без скрытого WIP;
- воспроизводимый source→claim→DemandUnit→decision→action→outcome lineage;
- зрелый post-window reconciliation оплат, потерь, fulfilment и repeat.

**MDOS-SUC-002.** `PROVEN_COMMERCIAL_MODEL` требует положительной incremental
contribution margin относительно preregistered baseline/holdout с учётом acquisition,
расчёта, переделок, доставки, рекламаций и человеческого времени.

**MDOS-SUC-003.** `PROVEN_PC10` требует отдельного профиля: минимум 300 новых
DealerAccount/CustomerAccount с первым distinct cleared paid order за 30 рабочих
дней, положительной expected contribution после fulfilment и capacity evidence.
Повтор, split payment и прежний клиент не считаются новым paying client.

**MDOS-SUC-004.** Любая цель может быть изменена только owner change record с
объяснением экономических последствий; срок, бюджет или исчерпание списка источников
не являются Definition of Done.

## 8. Нормативный состав и ратификация

**MDOS-GOV-001.** Нормативный состав фиксируется `contract-manifest.json`. Файл вне
manifest не изменяет обязательства. Markdown, schema, registry и policy digest
образуют одну immutable версию.

**MDOS-GOV-002.** `LF-OUTCOME-V6 6.1.0-rc.1` сохраняется как superseded design
source, не как параллельная коммерческая норма. Его safety-invariants перенесены в
`APP-MDOS-DELIVERY-ASSURANCE.md` и не могут быть ослаблены приложением.

**MDOS-GOV-003.** До ратификации все external read/write/contact/spend flags имеют
значение `false`; acceptance cases имеют статус `SPECIFIED_NOT_IMPLEMENTED`, если
не связаны с test/evidence в registry.

**MDOS-GOV-004.** Ратификация фиксирует exact package digest, target profile,
motions, один initial beachhead `product × region × fulfilment`, economics, owners,
capacity, payment truth, consent policy, source permits, promises и initial release
evidence. Самоподписание разработчиком или ИИ запрещено.

**MDOS-GOV-005.** После ратификации normative diff требует новой semver, change
record, impact analysis, обновлённых тестов/evidence и rollback. P0/legal/payment/
suppression/audit-integrity controls не waiverable.

**MDOS-GOV-006.** `APP-MDOS-MAIL-BITRIX-OBSERVER.md` является нормативным выбором
архитектуры inbound mail для successor RC2: нативная почта Bitrix — единственный
inbound CRM writer, а Lead Factory observer — read-only. Включение приложения в
manifest не ратифицирует и не активирует mailbox/Bitrix access, schedule, repair,
contact, MANGO, TenderPlan или outbound; для них обязательны отдельные решения.
