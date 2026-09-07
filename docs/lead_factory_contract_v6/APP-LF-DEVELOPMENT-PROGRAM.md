# APP-LF-DEVELOPMENT-PROGRAM — программа разработки до GCO10

**Application ID:** `APP-LF-DEVELOPMENT-PROGRAM`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Принцип исполнения

**LF-PRG-001.** Программа outcome-driven: этап заканчивается доказательством gate,
а не количеством написанного кода или календарной датой.

**LF-PRG-002.** Технические lanes могут выполняться параллельно, но critical path
определяется ближайшим коммерческим bottleneck. Integration debt, attribution,
CRM outcome и capacity приоритетнее необязательного нового источника.

**LF-PRG-003.** Все live изменения отделены от разработки: offline fixtures → shadow
→ bounded canary → pilot → scale. Каждый переход имеет exact permit, rollback,
reconciliation и evidence.

## 2. Phase 0 — ратификация и baseline

Результаты:

- ratified v6 manifest;
- точные owner parameters;
- reproducible baseline существующей dealer-кампании, 88 warm, HOT и retail базы;
- определения payment trigger, quote SLA, products/regions/capacity;
- список людей и решений.

**GATE-V6-0:** manifest/hash валиден; target `GCO10`; внешние flags остаются 0;
baseline воспроизводится из raw state; открытые параметры либо заполнены, либо имеют
measurement owner/deadline.

## 3. Phase 1 — measurement и funnel core

Реализовать:

- `FunnelCase` с immutable type;
- global counting key и cross-source/funnel dedupe;
- versioned qualification profiles и Gold Gates;
- DealerAccount lifecycle отдельно от Opportunity;
- funnel-aware Event Store, analytics и CRM mapping fixtures;
- outcome linkage до Payment/Repeat;
- manifest-driven acceptance traceability.
- command/event/schema registry, Control Plane и architecture fitness functions;
- requirement → design → code → test → evidence registry.

**GATE-V6-1:** все `AT-FNL`, `AT-SRC`, `AT-CRM` offline зелёные; 100% fixture
outcomes имеют provenance; внешние readers/writers 0; backup/restore сохраняет v6 state.

## 4. Phase 2 — Dealer Core manual proof

Сначала:

1. разобрать судьбу 88 warm и старых technical lead;
2. сформировать deduplicated Dealer Core 300;
3. исключить own-production без overflow и mixed ExportBase/builders;
4. разделить PVC/balcony, terrace/cottage, facade/installer и overflow producers;
5. использовать CTA «один реальный объект на сравнение»;
6. обеспечить быстрый intake и estimate SLA;
7. записывать причины отказа и outcome до оплаты.

**GATE-V6-2:** sealed cohort 100–150; минимум 30 DM conversations, 10 DealerRFQ
с реальными данными и 3 distinct paid TrialOrder; denominator и payments
воспроизводятся из immutable events. Cold scale до gate запрещён.

## 5. Phase 3 — dealer acquisition engine

Реализовать доказанный manual method как управляемую систему:

- account research/score и reason-to-contact;
- отдельные subsegment offers/sequences;
- human task queue, SLO и follow-up;
- dealer landing/RFQ correlation;
- win/loss и quote/price/trust diagnosis;
- reactivation и referrals;
- daily/weekly dealer scorecard.

**GATE-V6-3:** минимум одна зрелая dealer method version имеет положительную
contribution economics, управляемый WIP, воспроизводимую RFQ→Trial конверсию и
не менее одного RepeatDealer. Scale permit остаётся bounded.

## 6. Phase 4 — supplier-intent inbound

Реализовать:

- Wordstat/intent research;
- dealer-only landing and RFQ;
- Search campaigns, product/system clusters и negatives;
- UTM/yclid/call/chat correlation;
- CRM feedback на AGCO/Trial/Repeat/margin;
- инкрементальный experiment и lifetime budget.

**GATE-V6-4:** источник даёт уникальный incremental AGCO/Paid outcome относительно
holdout/baseline, economics/capacity зелёные, measurement gap <=5%.

## 7. Phase 5 — Demand Intelligence и discovery automation

После manual proof подключать по passport:

- Яндекс/2ГИС/Авито/site monitoring;
- permitted exports/API;
- Apify scheduling/actors;
- ScrapeGraph AI extraction/classification;
- referrals/partner feeds;
- project/tender adapters в отдельном funnel.

Параллельно расширить существующий Construction Demand Radar до Demand Intelligence
Engine: bitemporal graph, typed multimodal claims, participant/buyer resolver,
procurement clock distribution, negative-evidence critic, Research Planner,
point-in-time datasets и champion/challenger evaluation.

**GATE-V6-5:** каждый source имеет unique signal/account uplift, lifecycle passport,
fallback, cost/outcome measurement; все `AT-DI` для достигнутого режима зелёные.
Demand Intelligence показывает incremental unique AGCO/Paid discovery и lead-time
advantage против manual/random baseline. Ни один scraper/AI не продвигается из-за
количества строк, страниц или model confidence.

## 8. Phase 6 — Project/Tender shadow и pilot

Реализовать ProjectPursuit, buyer/scope/window/open-supplier verification и derivation
повторно закупающего подрядчика в DealerAccountCase.

**GATE-V6-6:** shadow показывает положительный uplift против случайной/ОКВЭД baseline;
commercial canary создаёт AGCO/paid outcomes в отдельном denominator и не размывает
dealer metrics.

## 9. Phase 7 — End-customer Routing bounded canary

Предусловия:

- owner permit `B2C_ROUTING_ONLY`;
- максимум два утверждённых региона;
- проверенные dealer capacity и SLA;
- consent/data rules;
- single assignment, object protection и reroute;
- end-to-factory RFQ/order/payment attribution.

**GATE-V6-7:** тестовые и bounded live cases проходят `AT-FNL-02`, `AT-CRM-06`;
нет потерянных inquiries, double assignment или неатрибутированного заказа;
factory RFQ/paid outcome подтверждает коммерческий цикл.

## 10. Phase 8 — Method Lab production

Реализовать proposal registry, diagnostic engine, immutable protocols, permissions,
portfolio ranking, promotion decisions и automated evidence reports.

Добавить conservative forecasting, causal experiment registry, risk-adjusted
economics, Capacity Digital Twin/Monte Carlo, anti-gaming и outcome adjudication.

**GATE-V6-8:** `AT-MTH`, применимые `AT-DS`, `AT-NET` зелёные; система при искусственно созданных supply/data/
qualification/offer/fulfilment failures предлагает релевантные, а не случайные методы;
никакой Proposal не создаёт side effect без permit.

## 11. Phase 9 — controlled multi-method production

Масштабируются только proven/bounded methods. Общие зависимости, contact competition,
capacity и attribution управляются централизованно.

**GATE-V6-9:** минимум два работающих коммерческих метода, измеренная dependency graph,
fallback, conservative forecast, causal/incrementality status, contribution economics,
dealer network/object protection, stress simulation, WIP <=80% и отсутствие critical
backlog/measurement gap. Release/SoD/traceability gates зелёные.

## 12. Phase 10 — доказательство GCO10

Запускается evaluation window `APP-LF-G10-EVIDENCE`.

**GATE-V6-10:** вычислен `PROVEN_GCO10=true`; все `AT-G10` и унаследованные
safety/legal/reliability gates зелёные. Ручная установка статуса запрещена.

После gate программа не прекращает outcome feedback. Открывается постоянная задача
удержания GCO10, повышения Paid/Repeat и снижения концентрации/риска.

## 13. Диагностическое управление

**LF-PRG-010.** Каждый недельный review классифицирует главное ограничение:

- `SUPPLY`;
- `DATA_QUALITY`;
- `CONTACTABILITY`;
- `QUALIFICATION`;
- `ROUTING`;
- `RFQ_INTAKE`;
- `ESTIMATE_CAPACITY`;
- `OFFER_PRICE_TRUST`;
- `SALES_FOLLOWUP`;
- `PRODUCTION_FULFILMENT`;
- `MEASUREMENT`;
- `LEGAL_SECURITY`.

Следующий sprint обязан иметь primary deliverable, прямо меняющий выбранный bottleneck.

**LF-PRG-011.** Одновременно поддерживаются:

- critical-path work;
- одна независимая risk-reduction lane;
- bounded research lane, если она не мешает critical path.

## 14. Required scorecards

Ежедневно:

- eligible supply, conversations, committed/received RFQ, AGCO;
- SLA/WIP/backlog и capacity;
- missing disposition/evidence;
- live flags, errors, spend и safety state.

Еженедельно:

- funnel/method cohorts;
- RFQ→Estimate→Proposal→Paid→Repeat;
- contribution economics и причины потерь;
- Method Lab decisions и следующий bottleneck;
- gap forecast до GCO10 на LCB95.

Ежемесячно:

- Active/Repeat Dealer cohorts;
- revenue/margin per dealer/product/region;
- concentration/fallback;
- team/estimator/production capacity plan;
- target validity и proposals owner-level changes.

## 15. Acceptance программы

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-PRG-01` | Код готов, outcome gates не пройдены. | Program status не `DONE`. |
| `AT-PRG-02` | Достаточно accounts, мало RFQ. | Critical path — ICP/offer/contact, не новый scraper. |
| `AT-PRG-03` | RFQ есть, нет оплат. | Открыт offer/price/trust/estimate diagnosis. |
| `AT-PRG-04` | Производство перегружено. | Acquisition scale блокируется capacity gate. |
| `AT-PRG-05` | Один source отключён. | Fallback/degradation работает либо GCO claim отзывается. |
| `AT-PRG-06` | GCO10 пройден, repeat economics отрицательна. | GCO status сохранён как факт; commercial diagnosis остаётся open. |
