# APP-LF-DEALER-NETWORK-ECONOMICS — дилерская сеть, оффер и экономика

**Application ID:** `APP-LF-DEALER-NETWORK-ECONOMICS`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Назначение

**LF-NET-001.** Dealer Network является управляемой коммерческой сетью повторных
покупателей и, после отдельного разрешения, исполнителей конечного спроса. Это не
список email и не broadcast-группа.

**LF-NET-002.** Сеть должна создавать два взаимно усиливающих цикла:

```text
точный дилер → DealerRFQ → TrialOrder → RepeatDealer

конечный спрос → защищённое назначение дилеру → FactoryRFQ
→ заказ АлюмКомплект → качественный монтаж → новый конечный спрос
```

## 2. Dealer Capability Profile

**LF-NET-CAP-001.** Для routing/приоритизации дилер имеет versioned profile:

- verified legal/account identity;
- products/systems и подтверждённая компетенция;
- service/installation geography;
- собственное производство и external buying need;
- доступные sales/measurement/installation slots;
- response/acceptance SLA;
- trial/repeat/order/claim history;
- quality, warranty и customer feedback;
- payment/credit/commercial status;
- object-protection conflicts;
- evidence freshness и reviewer.

**LF-NET-CAP-002.** Profile разделяет hard facts, human decisions и model estimates.
Composite score не заменяет обязательную eligibility.

**LF-NET-CAP-003.** Dealer lifecycle:

```text
PROSPECT
→ ELIGIBLE
→ TRIAL
→ ACTIVE
→ REPEAT
→ PREFERRED
↘ DORMANT / PROBATION / SUSPENDED / EXITED
```

Status выводится из событий/правил, имеет reason/version/TTL и не ставится вручную
без signed override.

## 3. Onboarding и качество

**LF-NET-ONB-001.** До получения конечного routed demand дилер проходит:

1. identity/role verification;
2. product/geography/capacity verification;
3. договорённость о supply-only и factory attribution;
4. SLA принятия/первого контакта/disposition;
5. правила защиты объекта и данных;
6. bounded test cases либо подтверждённый order history;
7. quality/claim/feedback procedure.

**LF-NET-ONB-002.** Один paid order не автоматически доказывает способность
обслуживать routed consumer demand. Требуется отдельный routing eligibility profile.

**LF-NET-ONB-003.** Probation/suspension triggers включают SLA breach, потерянные
requests, ложный disposition, обход factory attribution, подтверждённую претензию,
data misuse, коммерческий конфликт или stale capacity.

## 4. Object Protection

**LF-NET-OBJ-001.** Защищённый объект имеет deterministic key:

```text
normalized customer/organization + address/project + product scope + time window
```

PII-minimized fingerprint не заменяет encrypted authorized details.

**LF-NET-OBJ-002.** Назначение фиксирует owner dealer, granted_at, expires_at,
accepted_at, SLA, source/method, permitted use, factory linkage и reason. Запись append-only.

**LF-NET-OBJ-003.** Один объект не передаётся нескольким дилерам одновременно.
Reroute возможен после decline/SLA breach/suspension отдельной command; история и
атрибуция сохраняются.

**LF-NET-OBJ-004.** Конфликт existing dealer/customer/project переводит assignment
в review. Нельзя обещать эксклюзивность до разрешения identity/object conflict.

## 5. Routing Optimizer

**LF-NET-RTE-001.** Сначала применяются hard eligibility:

- product/system;
- geography/logistics;
- verified capacity/freshness;
- legal/data/consent;
- active status и отсутствие suspension/conflict;
- SLA и object protection;
- factory/commercial compatibility.

**LF-NET-RTE-002.** Среди eligible кандидатов optimizer учитывает отдельные оси:

- probability of fast acceptance/contact;
- product/installation quality;
- conversion and customer outcome;
- factory RFQ/order attribution history;
- available capacity/load;
- contribution economics;
- distance/logistics;
- exploration value and concentration risk.

Нельзя выбирать только по максимальной выручке, минимальной цене или близости.

**LF-NET-RTE-003.** Routing decision объясняет hard filters, candidates, selected
dealer, policy/model versions, capacity reservation и fallback. Human override
имеет reason/evidence и не переписывает первоначальное решение.

**LF-NET-RTE-004.** Exploration допускается только bounded среди eligible dealers,
не снижает обещанный customer SLA и имеет отдельный budget/quality monitor.

## 6. Dealer Offer Engine

**LF-OFR-001.** Offer является versioned комбинацией:

```text
subsegment + trigger/problem + product scope + value proposition
+ proof + commercial promise + CTA + channel/sequence
```

**LF-OFR-002.** Dealer-first core promise:

- supply-only/no client poaching;
- white-label в утверждённых границах;
- dealer procurement price/margin mechanism без недоказанного процента;
- расчёт/комплектация по реальному объекту;
- готовый к монтажу комплект;
- утверждённые документы, гарантия, доставка и SLA.

**LF-OFR-003.** Primary CTA — передать один текущий/недавний объект для сравнения.
«Интересно сотрудничество?», download/open/click и общий запрос презентации являются
diagnostic, а не целевым коммерческим outcome.

**LF-OFR-004.** Любое утверждение о цене, проценте выгоды, сроке, производительности,
доставке, гарантии и бренде поступает только из active Promise Registry с owner,
evidence, applicability, TTL и approved render. ИИ не придумывает claim.

**LF-OFR-005.** Offer Engine может выбирать только утверждённые components и порядок.
Новая генерация сохраняется draft и проходит promise/legal/brand/human gate до отправки.

## 7. Экономическая модель

**LF-ECO-001.** Оптимизируется не число лидов и не минимальный CAC, а ожидаемая
contribution margin и repeat value на ограничивающий ресурс при сохранении качества:

```text
ExpectedContribution =
  P(Paid | AGCO, cohort)
  × (Revenue - materials - direct labour - logistics
     - warranty/claim reserve - financing/credit cost)
  - acquisition/data/channel cost
  - qualification/sales/estimate cost
```

**LF-ECO-002.** Для дилера считается cohort economics:

- Trial CAC и payback;
- distinct paid order count/frequency;
- contribution per order/m²/dealer;
- time-to-second-order;
- retention/reactivation;
- claim/return/credit risk;
- expected 90/180/365-day value с uncertainty.

Среднее по всем дилерам не заменяет subsegment/region/product cohorts.

**LF-ECO-003.** Cost attribution включает данные/API, рекламу, AI, инфраструктуру,
человеческое время, расчёт, rework, referral payout и incremental sales/fulfilment.

**LF-ECO-004.** Marginal budget allocation использует conservative incremental
contribution и capacity shadow price. Канал с положительным средним ROMI не
масштабируется, если marginal cohort перегружает дефицитный ресурс или имеет
отрицательную lower bound.

**LF-ECO-005.** Автоматическая price/discount/credit decision запрещена. Optimizer
может предложить scenario с margin/capacity impact; owner/authorized commercial
role принимает versioned решение.

## 8. Capacity-aware commercial portfolio

**LF-ECO-CAP-001.** Portfolio распределяется между:

- activation existing dealers;
- new dealer acquisition;
- supplier-intent inbound;
- referrals/partners;
- project/tender;
- bounded end-customer routing;
- research/exploration.

**LF-ECO-CAP-002.** Allocation решает многокритериальную задачу: GCO10 reliability,
paid/repeat contribution, source/method independence, learning value и capacity.
Никакой один score не обходит hard gate.

**LF-ECO-CAP-003.** При недостатке estimator/production capacity приоритет
назначается по expected contribution per scarce unit и customer commitment;
остальные cases получают честный defer/nurture, а не ложный SLA.

## 9. Anti-gaming и fraud

**LF-NET-FRD-001.** Выявляются и не увеличивают KPI:

- split одного объекта/RFQ/платежа;
- duplicate companies/groups/contacts;
- self-referral и referral collusion;
- фиктивное принятие без customer contact;
- fake/stale RFQ;
- изменение disposition для SLA/bonus;
- warranty remake/correction как repeat order;
- один end customer через несколько dealers/sources.

**LF-NET-FRD-002.** Bonus/commission не основывается на единственной метрике,
которую получатель может сам выставить. Payment/quality/attribution подтверждаются
независимыми источниками.

**LF-NET-FRD-003.** Suspicious pattern создаёт review, но не автоматическое
обвинение/блокировку без policy/evidence. Reviewer conflict проходит SoD.

## 10. Quality adjudication

**LF-NET-QA-001.** Dispute по AGCO, assignment, object protection, dealer quality
или attribution имеет immutable case, две стороны evidence и независимого reviewer.

**LF-NET-QA-002.** Решение `CONFIRM/REJECT/REROUTE/SUSPEND/REINSTATE` действует
prospectively, не переписывает исторические events и имеет appeal/review TTL.

**LF-NET-QA-003.** Ошибки routing/quality влияют на model/method/dealer score только
после зрелого adjudicated label; жалоба сама по себе не является истиной.

## 11. Метрики сети

**LF-NET-MET-001.** Обязательные:

- eligible/active/repeat/preferred dealers;
- capacity coverage по product/region;
- acceptance/first-contact/disposition SLA;
- routed request→FactoryRFQ→Paid attribution;
- dealer RFQ/Trial/Repeat cohorts;
- time-to-first/second order;
- contribution/m²/order/dealer;
- claim/quality/customer outcome;
- assignment concentration/reroute/lost request;
- object conflicts и fraud reviews.

## 12. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-NET-01` | Dealer paid once, capacity stale. | Routing eligibility=false. |
| `AT-NET-02` | Один объект двум dealers. | Второе active assignment blocked. |
| `AT-NET-03` | SLA breach и fallback available. | Atomic reroute, история сохранена. |
| `AT-NET-04` | Similar object identity conflict. | Review до exclusivity/assignment. |
| `AT-NET-05` | ИИ придумал скидку/срок. | Offer render/send blocked. |
| `AT-NET-06` | Split invoice одного заказа. | 1 Trial/Order, не Repeat. |
| `AT-NET-07` | Referral совпал с existing attribution. | Duplicate/fraud review, payout blocked. |
| `AT-NET-08` | Highest conversion dealer перегружен. | Capacity-aware eligible alternative/defer. |
| `AT-NET-09` | Override routing без evidence/role. | Reject. |
| `AT-NET-10` | Complaint later overturned. | Historical events unchanged; derived score corrected by new event. |
| `AT-ECO-01` | Средний ROMI positive, marginal cohort negative. | Scale denied/revised. |
| `AT-ECO-02` | Channel cheap, consumes scarce estimator capacity. | Shadow price/capacity included. |
| `AT-ECO-03` | Price scenario below approved margin floor. | Proposal only/reject; no automatic commercial action. |

