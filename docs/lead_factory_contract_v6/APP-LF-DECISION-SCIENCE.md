# APP-LF-DECISION-SCIENCE — прогноз, причинность, оптимизация и anti-gaming

**Application ID:** `APP-LF-DECISION-SCIENCE`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Иерархия результата

**LF-DS-001.** События не подменяют друг друга:

```text
Signal → Eligible → Contactable → Reached
→ GCO → AGCO → Estimate → Proposal
→ ClearedPayment → MaturePaidOutcome → Fulfilled → Repeat
```

**LF-DS-002.** `ClearedPayment` запускает Trial/paid event по утверждённому payment
trigger. `MaturePaidOutcome` дополнительно выдерживает versioned cancellation/refund/
claim window и имеет неотрицательную фактическую contribution margin либо объяснённый
accounting gap. Acquisition SLO и mature economics считаются раздельно.

**LF-DS-003.** Каждая стадия имеет immutable timestamp, actor/source, counting key,
evidence и metric version. Denominator cohort фиксируется до outcome maturity.

## 2. Intent classes

**LF-DS-INT-001.** Demand signal классифицируется:

- `I4` — прямой запрос цены/КП/срока/замера/расчёта с объектом;
- `I3` — подтверждённый нераспределённый scope с выбором до 30 дней;
- `I2` — активный объект/компания, но scope/покупатель/окно не подтверждены;
- `I1` — целевой аккаунт без текущего спроса;
- `I0` — информационный шум/out of scope.

Только `I3/I4` после Gold Gate могут создать AGCO. Class — model/human claim,
а не самостоятельный коммерческий факт.

## 3. Demand portfolio и независимость

**LF-DS-PORT-001.** Portfolio различает методы/lane:

- dealer activation/reactivation;
- supplier-intent inbound;
- account-based outbound/discovery;
- referrals/ecosystem;
- project/procurement;
- bounded end-customer routing;
- installed-base/repeat;
- research/exploration.

**LF-DS-PORT-002.** Два поставщика одних и тех же upstream данных, Яндекс Search/Maps
либо несколько тендерных агрегаторов одной ЕИС не считаются независимыми только по
разным source_id. Ведётся dependency graph и correlated-outage model.

**LF-DS-PORT-003.** Default production guardrails до отдельной калибровки:

- один source/dependency family — не более 35% AGCO;
- HHI долей dependency families — не более 0,25;
- минимум две families могут дать не менее 25% GCO10 каждая;
- outage крупнейшей family не снижает conservative forecast ниже 7 AGCO/день
  более чем на пять рабочих дней.

Изменение guardrail проходит risk/change control, а не скрытую настройку.

## 4. Conservative forecasting

**LF-DS-FC-001.** Для малых cohorts используется иерархическая модель либо
эквивалент с partial pooling:

```text
y_j ~ Binomial(n_j, p_j)
logit(p_j) ~ Normal(parent_mean, between_segment_variance)
```

Новая cohort не получает 0%/100% forecast из нескольких наблюдений.

**LF-DS-FC-002.** Arrival model учитывает overdispersion, день недели, сезон,
регион, source/method, budget, outage и promotion. Negative Binomial является
reference; альтернативная модель требует равной/лучшей out-of-time calibration.

**LF-DS-FC-003.** Decision/gates используют posterior lower bounds/probabilities
либо preregistered frequentist LCB. Нельзя выбирать framework после просмотра
результата для прохождения gate.

**LF-DS-FC-004.** Production forecast обязан выдавать distribution по дням,
не только среднее:

```text
LCB95(E[AGCO/day]) >= 10
P(AGCO/day >= 10) >= 0.80
P(AGCO/day >= 8) >= 0.95
LCB95(TrueAGCORate) >= 0.80
```

**LF-DS-FC-005.** Backtest использует rolling-origin/out-of-time windows. Минимум:

- 90% predictive interval покрывает не менее 85% недель;
- systematic bias не более 10%;
- ошибки показаны по source/product/region/season;
- model не продвигается только по aggregate average.

## 5. Drift и revalidation

**LF-DS-DRIFT-001.** Revalidation запускается при любом:

- posterior/LCB conversion deterioration выше versioned threshold;
- существенном изменении source/product/region mix;
- PSI/feature drift выше threshold;
- CUSUM/EWMA либо equivalent persistent shift;
- изменении цены, оффера, SLA, capacity, dealer network или Gold definition;
- росте missed-paid/false-hot/complaint rate;
- source/schema/model change.

**LF-DS-DRIFT-002.** Drift может отозвать forecast/tier/method promotion. Исторический
факт не удаляется; создаётся новый validity/revocation event.

## 6. Causal experimentation

**LF-DS-EXP-001.** Основной estimand коммерческого метода:

```text
ITT_Paid = E[Paid | assigned treatment] - E[Paid | assigned control]
IncrementalContribution = Contribution_treatment
                          - Contribution_control
                          - IncrementalCost
```

GCO — intermediate outcome; Paid/Contribution доказывают коммерческую причинность.

**LF-DS-EXP-002.** Randomization unit — CanonicalObjectID либо DealerAccountID,
не email/contact. Interference между дилерами/регионами/аукционами требует cluster
randomization или явно смоделированной interference.

**LF-DS-EXP-003.** До старта sealed:

- hypothesis/causal mechanism;
- treatment/control/eligible cohort;
- primary outcome и guardrails;
- MDE/sample/maturity;
- stopping rule;
- exclusions и subgroup plan;
- cost/capacity/ethical constraints.

**LF-DS-EXP-004.** Holdout по умолчанию 10–15% eligible cohort как versioned
parameter. Явный inbound `I4` нельзя игнорировать: тестируется SLA/offer/routing,
а не отсутствие обязательного ответа.

**LF-DS-EXP-005.** Досрочное решение возможно только preregistered sequential
procedure: alpha-spending/e-value/Bayesian stopping. Ежедневное подглядывание и
остановка на случайном пике запрещены.

**LF-DS-EXP-006.** Если randomized test невозможен, заранее утверждается
quasi-experimental design и sensitivity analysis. Такой lane маркируется
`HARVESTING/ASSOCIATIONAL`, пока incrementality не доказана.

**LF-DS-EXP-007.** Production offer/method требует posterior probability
положительного IncrementalContribution не менее 95% либо остаётся bounded
exploration. Safety/quality guardrail может остановить тест раньше экономики.

## 7. Risk-adjusted economics

**LF-DS-ECO-001.** Net Economic Value AGCO:

```text
NEV = P(Paid | AGCO)
      × (ExpectedContributionFirst
         + P(Repeat) × ExpectedContributionRepeat)
      - AcquisitionAndDataCost
      - QualificationAndSalesCost
      - EstimateAndDealerSupportCost
      - Congestion/DelayCost
      - ExpectedWarrantyAndCreditLoss
```

**LF-DS-ECO-002.** Contribution вычитает materials, direct production/labour,
logistics, dealer incentive, payment fees, variable sales, warranty reserve и
credit/return loss. Revenue/gross headline без полного variable cost не используется.

**LF-DS-ECO-003.** Break-even conversion:

```text
p_break_even = IncrementalCostPerAGCO
               / ExpectedContributionIfPaidIncludingRepeat
```

Scale требует `LCB95(p_AGCO→Paid) >= 1.2 × p_break_even` и
`P(cohort contribution > 0) >= 0.95` после maturity.

**LF-DS-ECO-004.** Budget allocator максимизирует expected incremental contribution
с CVaR/downside penalty при ограничениях GCO10, capacity, margin, concentration,
legal/source и exploration quota. Точный optimizer versioned и replayable.

**LF-DS-ECO-005.** 10–15% variable research capacity/budget сохраняется для
approved exploration. Bandit/Thompson Sampling допускается только внутри proven
eligibility, price/margin, safety и capacity guardrails и не заменяет causal holdout.

**LF-DS-ECO-006.** Lane ограничивается при `P(NEV<0)>0.80` и останавливается при
`P(NEV<0)>0.95` после minimum sample/maturity, если owner не утвердил отдельную
research value с lifetime cap.

## 8. Capacity simulation

**LF-DS-SIM-001.** Digital Twin моделирует очереди:

```text
capture → enrichment → qualification → contact/research
→ Gold review → estimate → proposal → production/logistics
```

и routing/installation, когда end-customer contour включён.

**LF-DS-SIM-002.** Arrival/service distributions зависят от времени, product,
region, complexity, method и season. Среднесуточное значение не используется для
P95 SLA/capacity planning.

**LF-DS-SIM-003.** Перед scale выполняется не менее 10 000 Monte Carlo/discrete-event
paths либо statistically equivalent convergence proof с posterior samples спроса,
конверсий, service times и outages.

**LF-DS-SIM-004.** Обязательные stress scenarios:

1. крупнейший source/dependency outage 10 дней;
2. ключевой dealer/sales capacity outage 5 дней;
3. inbound ×2 и региональный spike ×3;
4. estimator/production capacity −20%;
5. Paid conversion −30%;
6. quote/service time ×2;
7. одновременный source+capacity failure;
8. model/AI provider unavailable.

**LF-DS-SIM-005.** Scale gate:

- `P(GCO10) >=0.80`;
- `P(SLA breach <=5%) >=0.95`;
- `P(backlog age <=1 workday) >=0.95`;
- `P(commercial promise breach <=5%) >=0.95`;
- P90 utilization каждого critical resource <=0.85.

Фактические четыре недели должны отклоняться от simulated P50/P90 throughput/
latency не более чем на 15%, иначе Twin перекалибруется.

## 9. Outcome adjudication

**LF-DS-ADJ-001.** Evidence hierarchy:

1. cleared payment/contract/specification/accounting fact;
2. recorded conversation/written confirmation;
3. held meeting/survey and next action;
4. human disposition with evidence;
5. automatic/model conclusion.

Нижний уровень не отменяет противоречащий верхний без review.

**LF-DS-ADJ-002.** Спорный AGCO проверяется blinded reviewer, не видящим cost/source/
dealer score, когда это возможно. Outcome classes versioned: valid accepted,
valid capacity reject, customer lost, invalid data, duplicate, not current,
outside scope, SLA failure, unresolved.

**LF-DS-ADJ-003.** В GCO10 входит только independently valid accepted AGCO.
Appeal имеет срок, actor и immutable decision; historical KPI корректируется новым
event, но первоначальная запись не удаляется.

**LF-DS-ADJ-004.** Контрольная выборка `max(50, 20% AGCO)`, Wilson LCB95 true rate
>=80%, Cohen kappa >=0.80, unresolved <=2%.

## 10. Anti-gaming

**LF-DS-GAME-001.** Запрещено увеличивать KPI через:

- split object/contact/order/payment;
- duplicate import/source/funnel;
- фиктивный DM/RFQ/contact;
- future/stale потребность как current;
- формальный тендер без buying intent;
- связанные лица/сотрудника/конкурента;
- подмену dealer/SLA reject на customer loss;
- задержку/удаление статуса до конца окна;
- микрооплату для создания NPC;
- correction/warranty remake как Repeat.

**LF-DS-GAME-002.** Dealer/method performance считается intention-to-treat по
assigned eligible cohort с case-mix adjustment; добровольно принятые «лёгкие»
cases не являются знаменателем.

**LF-DS-GAME-003.** Bonus/optimization не опирается на self-reported metric без
independent evidence. Delayed label пересчитывает derived KPI и сохраняет defect.

## 11. Scale tiers

**LF-DS-TIER-001.** Коммерческие tiers:

- `C0_OBSERVE` — truth/dedupe/evidence;
- `C1_CONTROLLED_PILOT` — 1–2 methods, до 3 AGCO/day;
- `C2_GCO_PROOF` — GCO10 evaluation;
- `C3_PAID_PROOF` — mature positive incremental contribution;
- `C4_REGIONAL_SCALE` — network/fallback/stress proof;
- `C5_PORTFOLIO_SCALE` — risk-adjusted optimizer;
- `C6_REPEAT_OPTIMIZATION` — mature repeat/LTV proof.

**LF-DS-TIER-002.** Повышение tier не доказывает следующий. Automatic downgrade
triggered by quality, SLA, economics, attribution, capacity, legal/source incident
или drift thresholds.

## 12. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-DS-01` | Малый segment 1/1 success. | Forecast shrinkage, не 100%. |
| `AT-DS-02` | Random split хорош, time holdout плох. | Model promotion denied. |
| `AT-DS-03` | Search и Maps названы independent. | Dependency graph объединяет risk family. |
| `AT-DS-04` | Experiment остановлен на случайном пике. | Decision invalid без sequential rule. |
| `AT-DS-05` | Inbound I4 попал в no-response holdout. | Protocol reject. |
| `AT-DS-06` | GCO uplift есть, Paid contribution отрицательна. | Commercial scale denied. |
| `AT-DS-07` | Средний ROMI positive, marginal NEV negative. | Additional budget blocked. |
| `AT-DS-08` | Simulation не включает correlated outage. | Scale gate incomplete. |
| `AT-DS-09` | Split payment/order/duplicate source. | Один canonical outcome/KPI count. |
| `AT-DS-10` | Dealer принимает только easy cases. | ITT/case-mix score выявляет cherry-picking. |
| `AT-DS-11` | Drift threshold exceeded. | Forecast/tier revalidation or downgrade. |
| `AT-DS-12` | 10 000 stress paths проходят gates. | Simulation eligible; live load proof всё равно обязателен. |

