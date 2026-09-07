# APP-MDOS-COMMERCIAL-MODEL — рынок, роли и motions

**Application ID:** `APP-MDOS-COMMERCIAL-MODEL`  
**Версия:** `1.1.0`

## 1. Каноническая онтология

**MDOS-COM-001.** Система ОБЯЗАНА различать:

- `Account` — компания, группа компаний или домохозяйство;
- `Person` и `ContactPoint`;
- `Object/Site` — физический объект или площадка;
- `DemandUnit` — отдельная коммерческая потребность;
- `BuyingGroup` и `ActorRole`;
- `InstalledAsset` — поставленная/обслуживаемая конструкция;
- `ProductCapability` и `OfferVariant`;
- `Interaction`, `EvidenceEvent`, `Claim`;
- `CommercialCase`, `ProtectedOpportunity`, `SpecificationInfluence`;
- `RFQ`, `Estimate`, `Proposal`, `Order`, `Payment`, `Fulfilment`, `Repeat`.

**MDOS-COM-002.** Actor roles не взаимозаменяемы: `need_initiator`, `specifier`,
`technical_approver`, `economic_buyer`, `procurement`, `payer`, `installer`,
`referrer`, `channel_owner`, `end_user`. Одна роль не подразумевает другую.

**MDOS-COM-003.** DemandUnit identity задаётся `account/household + object/site +
independently_decidable_scope + purchase_decision`. Правка файлов или split invoice
не создают новую DemandUnit; новый объект/фаза/независимое решение — создают.

**MDOS-COM-004.** DemandUnit хранит: motion, need/JTBD, product/system/scope,
object/location, buying group, payer, decision horizons, supplier state, artifacts,
economics, fulfilment route, capacity fit, evidence graph, uncertainty, lawful next
action и outcome linkage.

## 2. Общий Gold minimum

**MDOS-GOLD-001.** `GoldenDemandOpportunity` существует только при выполнении общего
минимума и motion-specific profile:

1. текущая потребность подтверждена независимым evidence;
2. product/scope относится к реальным capability АлюмКомплект;
3. объект/место и ответственный покупатель/плательщик либо формально принятый
   посредник разрешены;
4. supplier selection открыта или существует доказанный switch/overflow path;
5. decision horizon входит в profile;
6. есть пригодный следующий коммерческий шаг и необходимые artifacts;
7. legal/contact/capacity/economics gates пройдены;
8. case уникален и принят человеком с next action/SLA.

**MDOS-GOLD-002.** `supplier selected`, `own production without overflow`, stale/
cancelled object, unsupported PVC-only scope, non-buyer, expired evidence, duplicate,
blocked contact, negative contribution либо отсутствующая capacity блокируют Gold.

**MDOS-GOLD-003.** Human acceptance подтверждает достаточность evidence и готовность
взять работу, но не может превратить отсутствие потребности, права или мощности в
Gold.

**MDOS-GOLD-004.** Принятие Gold создаёт immutable `GoldAcceptance`. Его identity
задаётся `demand_unit_id + scope_fingerprint + cohort_id + cut-off`. Reviewer,
evidence, permit, capacity/economics snapshots и permitted next action обязательны.
Изменение файлов, источника, CRM-стадии или повторная проверка того же scope не
создают ещё один GDO; новый независимый purchase decision требует нового fingerprint.

## 3. Motion profiles

**MDOS-MOT-001.** `EXISTING_ACCOUNT_EXPANSION`:

```text
KnownAccount → Reorder/Service/CrossSellTrigger → NeedConfirmed
→ GDO → RFQ/ReadyPackage → Paid → Retained/Expanded
```

Gold требует известного account, текущего need/объекта, причины реактивации и
ответственного лица. Календарная годовщина, recency или старая сделка — только trigger.

**MDOS-MOT-002.** `DEALER_AND_INSTALLER_ACTIVATION`:

```text
Candidate → ICPVerified → ExternalBuyer/OverflowVerified → DM
→ BenchmarkRFQ → GDO → TrialPaid → Active → Repeat
```

Gold требует реального distinct RFQ с файлом/эскизом/размерами, регионом, сроком и
явным запросом цены/срока. Обещание «пришлю позже» — `RFQ_COMMITTED`, не GDO.

**MDOS-MOT-003.** `HIGH_INTENT_INBOUND`:

```text
AnonymousInteraction → IdentifiedInquiry → NeedQualified
→ GDO → RFQ → Proposal → Paid
```

Повторный визит, запрос в поиске, скачивание каталога, звонок без разговора или форма
без достаточного scope — intent evidence, но не Gold. Paid status возвращается в
Метрику/рекламную систему только из независимой коммерческой истины.

**MDOS-MOT-004.** `PARTNER_AND_REFERRAL`:

```text
Partner → RegisteredIntroduction → Consent/AuthorityVerified
→ NeedQualified → GDO → Paid → AttributedReward
```

Вознаграждение по умолчанию возникает после cleared paid order и положительной
маржи; duplicate/collision и передача персональных данных проверяются до contact.

**MDOS-MOT-005.** `COMMERCIAL_OPENING_AND_REFIT`:

```text
Network/SiteWatch → Opening/Refit/FailureTrigger → BuyerResolved
→ ScopeAndDateConfirmed → GDO → PilotSitePaid → Rollout/Framework
```

Новое юрлицо, вакансия, аренда, новость или карточка филиала — weak trigger. Gold
требует конкретный site/CAPEX scope, decision role, срок и покупательский next step.

**MDOS-MOT-006.** `PROJECT_SPECIFICATION_INFLUENCE`:

```text
ProjectDetected → SpecifierResolved → TechnicalNeed → DesignAssist
→ Specified/RegisteredProject → BuyerTransition
```

Этот motion имеет собственный outcome `SpecificationInfluence`; до buyer transition
он не входит в GDO10. BIM/DWG, узлы, mock-up, budget envelope и technical desk —
часть предложения, а не маркетинговый декор.

**MDOS-MOT-007.** `PROJECT_BUYER_PURSUIT`:

```text
Project/Package → Buyer/PayerResolved → PackageOpen → Scope/Volume/Date
→ GDO → InvitedRFQ → Paid → Fulfilment
```

Разрешение, экспертиза, проектная декларация и назначение генподрядчика являются
evidence chain; Gold возникает только при открытом пакете и доступном buyer path.

**MDOS-MOT-008.** `INSTALLED_BASE_SERVICE_AND_REPLACEMENT`:

```text
InstalledAsset → Defect/Warranty/LeaseChange/PlanTrigger → Inspection
→ FundedNeed → GDO → Repair/ReplacementPaid → AssetHistory
```

Нужен реестр installed asset, совместимости систем, гарантии, владельца, service
region и партнёра. Complaint без технического scope/плательщика — service case,
не обязательно GDO.

**MDOS-MOT-009.** `ROUTED_PREMIUM_CONSUMER`:

```text
ConsumerInquiry → QualifiedProject → DealerCapacityMatch
→ ProtectedAssignment → DealerAccepted → FactoryRFQ → Paid/Attributed
```

До смены бизнес-модели частник является origin спроса, а не прямым фабричным
клиентом. Нет проверенного дилера, монтажа и гарантии — нет обещания и assignment.

**MDOS-MOT-010.** `TENDER_AND_FORMAL_PROCUREMENT`:

```text
ProcedureSignal → ScopeFit → Buyer/ParticipantResolved → SupplierWindowOpen
→ GDO → Bid/PrivateRFQ → Award → ClearedPayment
```

Процедура не смешивается с DealerRFQ или проектным spec-in. Участие без экономики,
capacity и payment risk запрещено.

**MDOS-MOT-011.** `MARKET_SHAPING_AND_EDUCATION`:

```text
DemandTheme → TechnicalAsset/Content/Event → Engagement → IdentifiedNeed
→ transition to another motion
```

Wordstat, SEO, BIM-библиотека, калькулятор, вебинар, выставка и showroom измеряются
по incremental transition в qualified motion, оплату и contribution, не по просмотрам.

## 4. Dealer Trust Protocol

**MDOS-DTP-001.** White-label/no-circumvention реализуется как протокол: один channel
owner, object registration, scope fingerprint, protection TTL/renewal, collision
rules, visibility audit, контактные границы, appeal и payment attribution.

**MDOS-DTP-002.** Protected Opportunity нельзя одновременно передавать нескольким
дилерам без прозрачного owner-approved режима. Dealer обязан принять/отклонить lead
в SLA; истечение защиты создаёт событие, а не молчаливую смену владельца.

**MDOS-DTP-003.** White-label не скрывает изготовителя там, где раскрытие требуется
договором, маркировкой, сертификатом, гарантией, УПД или правом. Public promise
проходит legal/capability review до использования.

## 5. География и предложение

**MDOS-GEO-001.** Единицей scale является `region × product × fulfilment model`, а
не «Россия». Допуск требует валовую маржу после доставки/боя/переделок, p90 срок,
замер/монтаж/сервис, гарантийный маршрут и повторяемость.

**MDOS-OFR-001.** `ProductCapabilityGraph` хранит системы, ограничения, инженерные
артефакты, минимальный заказ, нормативные документы, текущую capacity, lead-time,
delivery/service zones, unit economics и evidence freshness.

**MDOS-OFR-002.** `PromiseRegistry` обязателен для цены, скидки, 1-day calculation,
производственной мощности, гарантии, сроков, white-label, доставки и рекламаций.
Нет owner/evidence/TTL — promise блокируется.

## 6. Ратифицированный beachhead

**MDOS-BCH-001.** До первого live canary владелец ОБЯЗАН ратифицировать ровно одну
начальную ячейку `product scope × region × fulfilment model`. «Все продукты» или
«вся Россия» не являются допустимым beachhead.

**MDOS-BCH-002.** `BeachheadProfile` фиксирует ICP и exclusions, продукт/системы,
регионы, fulfilment route, offer и promise versions, минимальную contribution margin,
WIP/capacity limits, SLA, owners, разрешённые motions/channels и stop conditions.

**MDOS-BCH-003.** DemandUnit вне active beachhead может быть сохранена как observation
или routed в отдельный safe queue, но не входит в canary denominator, GDO10 proof и
не получает обещание, контакт либо Bitrix Deal без отдельного PermitDecision.

**MDOS-BCH-004.** Изменение продукта, региона или fulfilment создаёт новую versioned
ячейку и отдельный economics/capacity proof. Смешивание ячеек в одном denominator
запрещено.

**MDOS-BCH-005.** Покупка provider/API, массовый capture или автоматический outreach
для beachhead допускаются только после ручного sealed pilot, доказавшего, что signal
семейство улучшает GDO/Paid относительно baseline при допустимой экономике.

## 7. Acceptance

| ID | Сценарий | Ожидаемый результат |
|---|---|---|
| `AT-COM-01` | Один проект содержит инициатора, архитектора, дилера и плательщика. | Четыре роли; одна DemandUnit; роли не становятся четырьмя leads. |
| `AT-COM-02` | Дилер обещал прислать КП через неделю. | RFQ_COMMITTED; 0 GDO до получения пригодного artifact. |
| `AT-COM-03` | Архитектор принял узел, закупщик ещё неизвестен. | SpecificationInfluence; 0 GDO; создан buyer-transition task. |
| `AT-COM-04` | Вышло разрешение на строительство. | EvidenceEvent/Object watch; 0 lead и 0 GDO. |
| `AT-COM-05` | Частник прислал размеры, но в регионе нет дилера/монтажа. | Safe queue/reject; нет обещания и assignment. |
| `AT-COM-06` | Две части оплаты одного заказа. | Один PaidOrder; 0 RepeatOrder. |
| `AT-COM-07` | Дилер прислал новый объект после первого paid order. | Второй DemandUnit; при cleared payment — RepeatDealer. |
| `AT-COM-08` | Тендерный победитель повторно закупает алюминий на стороне. | Новый dealer motion с derivation; tender case не меняет тип. |
| `AT-COM-09` | Один routed object предложен второму дилеру при активной защите. | Block + collision case + audit. |
| `AT-COM-10` | Claim «20–30% дешевле» без свежего proof. | Offer/publication blocked. |
| `AT-COM-11` | Один ИНН имеет две площадки с независимыми refit решениями. | Один Account, две DemandUnit/Site. |
| `AT-COM-12` | Повторный визит к фасадной странице без идентификации. | Interaction/intent only; PII/Lead не создаются. |
| `AT-COM-13` | Canary запускается без RATIFIED BeachheadProfile. | Launch blocked; external flags остаются false. |
| `AT-COM-14` | Один пилот смешивает два региона и разные модели монтажа. | Две ячейки/denominator; blended proof запрещён. |
| `AT-COM-15` | Тот же объект повторно квалифицирован после правки файла. | Один scope fingerprint и один GDO; revision сохраняется. |
| `AT-COM-16` | Gold review не имеет permit/capacity/economics snapshot. | GoldAcceptance schema/gate rejects; GDO count не растёт. |
