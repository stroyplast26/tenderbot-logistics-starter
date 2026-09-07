# APP-LF-FUNNELS — dealer-first контуры и Gold Gates

**Application ID:** `APP-LF-FUNNELS`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Точный ICP

**LF-ICP-001.** Первичным ICP является юридическое лицо или ИП, которое:

1. продаёт окна, двери, входные группы, порталы, террасы, зимние сады, витражи,
   фасады, перегородки либо остекление балконов;
2. имеет продажи и монтаж либо управляет монтажом;
3. получает конечные заказы и сохраняет отношения со своим клиентом;
4. не имеет собственного алюминиевого производства либо имеет доказанную потребность
   во внешней мощности, технологии, системе, окраске или страхующем поставщике;
5. способно передать реальный объект на расчёт и размещать повторные заказы.

**LF-ICP-002.** Приоритет внутри ICP:

1. оконные/балконные ПВХ-компании с периодическими алюминиевыми заказами;
2. компании по террасам, верандам, панорамному и коттеджному остеклению;
3. монтажные, фасадные и остеклительные компании без алюминиевого цеха;
4. малые производители с дефицитом мощности или технологии;
5. комплектаторы коммерческих объектов с повторной закупкой.

**LF-ICP-003.** Производитель полного цикла без внешней потребности, чистая ПВХ-компания
без алюминиевых продаж, архитектор без закупочной роли, общий справочный контакт,
одноразовый тендерный участник и компания без доказанной продуктовой пригодности
не проходят dealer ICP.

## 2. Единица результата

**LF-GOLD-001.** `GoldenClientOpportunity` (`GCO`) — уникальная коммерческая
возможность, для которой одновременно:

- существует конкретный алюминиевый scope;
- идентифицирован покупатель либо закупающая роль;
- подтверждён ЛПР или человек, непосредственно организующий выбор поставщика;
- решение/выбор ожидается не позднее 30 календарных дней;
- получены файлы, спецификация, размеры, старое КП или иной достаточный для
  первичной коммерческой оценки пакет; обещание передать его позже сохраняется
  как `RFQ_COMMITTED`, но не проходит Gold Gate;
- выбор поставщика остаётся открытым;
- продукт, география, минимальная экономика и доступная мощность допустимы;
- сохранены evidence, источник, qualification profile и следующий шаг;
- возможность не является дублем и не находится в suppression.

**LF-GOLD-002.** `AcceptedGoldenClientOpportunity` (`AGCO`) — GCO, которая:

1. прошла funnel-specific Gold Gate;
2. принята ответственным человеком/расчётчиком в реальную коммерческую работу;
3. не признана невалидной в течение пяти рабочих дней;
4. прошла независимый quality audit, если попала в контрольную выборку.

В KPI `GCO10` учитываются только AGCO.

Мотивированный отказ сохраняется для аудита качества и capacity diagnosis, но не
увеличивает KPI, даже если входные данные были качественными.

**LF-GOLD-003.** Запрещено учитывать как AGCO:

- запись компании, email, телефон, посещение страницы, открытие или клик;
- ответ без конкретной потребности;
- просьбу прислать презентацию;
- разрешение на строительство, новость или тендер без подтверждённого scope и окна;
- расчёт исключительно ради формального участия без намерения заказать;
- дубль одного спроса из другого источника или funnel;
- потребность, превышающую утверждённую мощность без принятого capacity slot.

**LF-GOLD-004.** `NewPayingClient` (`NPC`) — уникальный по ИНН/контролируемой группе
контрагент, который впервые внёс согласованную предоплату. `AGCO`, `NPC`, заказ и
повторный заказ являются разными событиями и никогда не подменяют друг друга.

## 3. Архитектура контуров

```text
Source Adapters → Source Lab → Identity/Project Graph → Funnel Router
                                            ├─ DealerAccountCase
                                            ├─ RoutingRequest
                                            └─ ProjectPursuit
                                                       ↓
                                      funnel-specific Gold Gate
                                                       ↓
               CommercialOpportunity → Estimate → Proposal → Order
                                                       ↓
                                  Payment → Production → Repeat
                                                       ↓
                                             Bitrix projection
```

**LF-FNL-001.** `funnel_type` принимает только:

- `DEALER_ACQUISITION`;
- `END_CUSTOMER_ROUTING`;
- `PROJECT_TENDER`.

Тип неизменяем после создания case.

**LF-FNL-002.** Case не переносится между funnel. Один case может породить другой
только новой immutable-командой с новым ID и `derived_from_case_id`.

**LF-FNL-003.** Company, Contact и Project дедуплицируются глобально; funnel cases
и их знаменатели остаются отдельными. Suppression, контактная конкуренция,
защита объекта и capacity действуют сквозным образом.

**LF-FNL-004.** Каждый case связан с неизменяемыми `qualification_profile_version`,
`metric_version`, `method_version` и `commercial_counting_key`.

**LF-FNL-005.** Канонический counting key строится из нормализованных:

```text
buyer/company + project/object + buyer_role + product_scope + decision_window
```

Повторный источник, сообщение, funnel или импорт не увеличивает KPI.

## 4. Dealer Acquisition

Каноническая сущность — `DealerAccountCase`, ключ — Company.

```text
CANDIDATE
→ ICP_VERIFIED
→ EXTERNAL_BUYER_VERIFIED
→ DECISION_MAKER_VERIFIED
→ RFQ_INVITED
→ BENCHMARK_RFQ_RECEIVED
→ GOLD_GATE_PASSED / NURTURE / EXCLUDED
```

**LF-DLR-001.** В `ICP_VERIFIED` обязательны сайт/доказательство услуг, продукт,
география, монтажная роль и versioned ICP decision.

**LF-DLR-002.** В `EXTERNAL_BUYER_VERIFIED` доказано отсутствие собственного
алюминиевого производства либо конкретный overflow/technology need. Одного
предположения ИИ недостаточно.

**LF-DLR-003.** `BENCHMARK_RFQ_RECEIVED` требует текущий или недавний реальный
объект, спецификацию/размеры/эскиз/старое КП, срок решения и контакт ЛПР.

**LF-DLR-004.** Dealer Gold Gate создаёт CommercialOpportunity только при выполнении
`LF-GOLD-001`. Кандидат, разговор, обещание «когда-нибудь прислать» или общий интерес
не создают Deal в Bitrix и не входят в 10/день.

**LF-DLR-005.** Dealer lifecycle является состоянием Company, а не Opportunity:

```text
PROSPECT → VERIFIED_BUYER → TRIAL_ORDERED → ACTIVE_DEALER → REPEAT_DEALER
                                      ↘ DORMANT / SUSPENDED
```

- `TRIAL_ORDERED` — первый подтверждённый заказ;
- `ACTIVE_DEALER` — принятый DealerRFQ из `DEALER_ACQUISITION` либо paid order
  этого DealerAccount за последние 30 дней;
- `REPEAT_DEALER` — не менее двух оплаченных заказов в разные даты;
- одна Company может иметь множество RFQ/Opportunity/Order.

## 5. End-customer Routing

Каноническая сущность — `RoutingRequest`, ключ — inquiry/project.

```text
INQUIRY_RECEIVED
→ CONSENT_VERIFIED
→ PRODUCT_REGION_QUALIFIED
→ DEALER_ASSIGNED
→ DEALER_ACCEPTED
→ FACTORY_RFQ_RECEIVED
→ GOLD_GATE_PASSED / REROUTE / CLOSED
```

**LF-RTE-001.** Funnel работает только в режиме `B2C_ROUTING_ONLY`: АлюмКомплект
принимает разрешённую заявку, квалифицирует продукт/регион, защищает объект и
передаёт её дилеру; прямые розничная продажа, обещание цены и монтаж не разрешаются.

**LF-RTE-002.** До отдельного owner-approved permit режим остаётся `DISABLED`.
Permit фиксирует регионы, продукты, согласие, retention, дилеров, SLA, правила
назначения, защиту объекта и end-to-factory attribution.

**LF-RTE-003.** Consumer inquiry сама по себе не AGCO. Gold Gate проходит только
`FACTORY_RFQ_RECEIVED` после принятия дилером, привязки защищённого объекта и
выполнения `LF-GOLD-001`.

**LF-RTE-004.** Одновременная передача нескольким дилерам запрещена, кроме заранее
утверждённого reroute после SLA violation. Все назначения и отказы append-only.

## 6. Project/Tender

Каноническая сущность — `ProjectPursuit`, ключ — Project + target buyer role.

```text
PROJECT_SIGNAL
→ PARTICIPANT_RESOLVED
→ BUYER_IDENTIFIED
→ ALUMINIUM_SCOPE_VERIFIED
→ PROCUREMENT_WINDOW_VERIFIED
→ SUPPLIER_OPEN_VERIFIED
→ PROJECT_RFQ_RECEIVED
→ GOLD_GATE_PASSED / NURTURE / CLOSED
```

**LF-PRJ-001.** Публикация, разрешение, план, тендер, победитель или контракт являются
сигналом, но не AGCO.

**LF-PRJ-002.** Gold Gate требует конкретный покупательский субъект, алюминиевый scope,
окно до 30 дней, подтверждённо открытый выбор поставщика, финансирование/коммерческий
путь и следующий шаг либо RFQ.

**LF-PRJ-003.** Победитель/подрядчик может породить отдельный DealerAccountCase,
если он повторно закупает алюминий на стороне. ProjectPursuit при этом не меняет тип,
а оба case связываются `derived_from_case_id`.

## 7. Общая коммерческая магистраль

**LF-SPINE-001.** Только case, прошедший свой Gold Gate, может создать
`CommercialOpportunity` и Deal в Bitrix. Исключение — необработанный inbound Lead,
который не считается Deal/AGCO до квалификации.

**LF-SPINE-002.** После Gold Gate применяется единая цепочка:

```text
READY_PACKAGE → ESTIMATE_ACCEPTED → ESTIMATE_DONE → PROPOSAL_SENT
→ WON/LOST → ORDERED → PAID → PRODUCED → DELIVERED → REPEAT/CLAIM
```

**LF-SPINE-003.** Источник, funnel case, evidence, counting key, method и qualification
version сохраняются до оплаты, фактической маржи и повтора.

**LF-SPINE-004.** Превышение безопасной мощности не разрешает переименовать backlog
в AGCO. Новая возможность либо получает реальный slot, либо остаётся ожидать вне KPI.

## 8. Acceptance

| ID | Сценарий | Ожидаемый результат |
|---|---|---|
| `AT-FNL-01` | Dealer Candidate без RFQ. | 0 Deal, 0 AGCO. |
| `AT-FNL-02` | Consumer inquiry без consent/dealer acceptance/factory RFQ. | 0 AGCO. |
| `AT-FNL-03` | Project Signal без открытого выбора поставщика. | 0 AGCO. |
| `AT-FNL-04` | Попытка изменить `funnel_type`. | Атомарный reject. |
| `AT-FNL-05` | Один спрос пришёл из трёх источников/funnels. | Один counting key; все evidence сохранены. |
| `AT-FNL-06` | Project case породил Dealer case. | Новый ID и derivation; исходный case неизменён. |
| `AT-FNL-07` | Одна Company передала два разных объекта. | Одна Company, две Opportunity. |
| `AT-FNL-08` | Повторный заказ дилера. | Lifecycle Company обновлён; старые Opportunity неизменны. |
