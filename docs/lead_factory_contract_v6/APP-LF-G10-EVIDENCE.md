# APP-LF-G10-EVIDENCE — доказательство 10 золотых возможностей в день

**Application ID:** `APP-LF-G10-EVIDENCE`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Целевой профиль

**LF-G10-001.** Цель `GCO10` равна 10 уникальным AGCO на каждый рабочий день
в утверждённом календаре и часах обслуживания.

**LF-G10-002.** Избыток одного дня не скрывает дефицит другого. Одновременно:

```text
AGCO_total >= 10 × D
mean(AGCO_day) >= 10
share(days with AGCO_day >= 10) >= 0.80
share(days with AGCO_day >= 8) >= 0.95
```

где `D` — число рабочих дней evaluation window.

**LF-G10-003.** Production claim требует одностороннюю нижнюю 95%-границу среднего
`LCB95(mean AGCO/day) >= 10`. Метод расчёта — заранее зафиксированный bootstrap
по рабочим дням либо t-bound при выполненных допущениях. Выбор метода после просмотра
результата запрещён.

**LF-G10-004.** Проектная мощность обязана иметь резерв. Перед production proof:

- load test доказывает 15 AGCO/день в течение 10 последовательных рабочих дней;
- utilization каждого критичного звена не превышает 0,80;
- `LCB95(SafeCapacity) >= 12.5 AGCO/day`;
- backlog старше одного рабочего дня не превышает 2%.

## 2. Сквозная математика

**LF-G10-MTH-001.** Для метода/источника `s` ожидаемый поток:

```text
AGCO_s = N_s
         × p_eligible
         × p_unique
         × p_contactable
         × p_reached
         × p_intent_confirmed
         × p_gold_gate
         × p_accepted
```

Общий результат считается после глобального cross-source/cross-funnel dedupe.

**LF-G10-MTH-002.** Для планирования используются односторонние нижние 95%-границы
наблюдаемых коэффициентов, а не точечные средние:

```text
N_required = ceil(
  10 /
  (LCB(p_eligible) × LCB(p_unique) × LCB(p_contactable)
   × LCB(p_reached) × LCB(p_intent_confirmed)
   × LCB(p_gold_gate) × LCB(p_accepted))
)
```

Для новой когорты до достаточного числа наблюдений коэффициент имеет статус `UNKNOWN`,
а расчёт является scenario, не forecast.

**LF-G10-MTH-003.** `SupplyCoverage`:

```text
SupplyCoverage = LCB95(ExpectedEligibleUniqueSupply) / RequiredEligibleUniqueSupply
```

Переход к production proof требует `SupplyCoverage >= 1.25`.

**LF-G10-MTH-004.** Общая мощность:

```text
Capacity_system = min(
  C_collect, C_enrich, C_qualify, C_contact,
  C_gold_review, C_estimate, C_sales, C_production
)
```

Все мощности приводятся к AGCO/рабочий день и имеют time-stamped evidence.

## 3. Leading и lagging metrics

**LF-G10-MET-001.** Leading metrics:

- уникальные eligible accounts/signals;
- ICP accuracy, freshness, duplicate rate, contactability;
- DM reached, разговоры, intent confirmed;
- `RFQ_COMMITTED`, DealerRFQ/FactoryRFQ/ProjectRFQ;
- полнота ReadyPackage;
- available estimator/sales/production slots;
- age и WIP очередей;
- source/method concentration.

**LF-G10-MET-002.** Lagging metrics:

- AGCO;
- Estimate/Proposal;
- TrialOrder/NewPayingClient;
- RepeatDealer и distinct paid orders;
- выручка, contribution/gross margin, маржа на м² и на дилера;
- `AGCO→Paid`, `Paid→Repeat`, sales cycle;
- CAC AGCO, CAC NPC, cost per Trial и contribution ROMI;
- претензии, переделки и дебиторская задолженность.

**LF-G10-MET-003.** Первичная коммерческая North Star dealer-first этапа:

```text
DealerRFQ → ReadyPackage → Paid TrialOrder → RepeatDealer
```

Высокий AGCO при отсутствии оплат или повторов является диагностическим успехом
acquisition, но коммерческим провалом фабрики в целом.

## 4. Confidence gates

**LF-G10-CONF-001.** Data quality:

- provenance — 100%;
- обязательные поля Gold Gate — 100%;
- скрытые дубли — не более 5%;
- невалидные контакты в принятой выборке — не более 5%;
- ошибочная продуктовая/географическая квалификация — не более 3%.

**LF-G10-CONF-002.** Конверсия используется в production forecast после минимум
100 наблюдений в неизменной method/ICP/qualification версии. `AGCO→NPC` требует
минимум 30 закрытых исходов и полного окна не короче `max(60 дней, P90 sales cycle)`.
Для долей применяется Wilson/Beta-binomial LCB95.

**LF-G10-CONF-003.** Ни один единственный источник не обеспечивает более 40%
планового AGCO без доказанного fallback, способного восстановить поток за пять
рабочих дней. Общая инфраструктурная зависимость также считается концентрацией.

**LF-G10-CONF-004.** Масштабирование разрешается только при:

```text
LCB95(ExpectedContributionMarginPerAGCO) > ExpectedCostPerAGCO
```

До созревания оплат допускается bounded research budget с заранее заданным lifetime cap.

## 5. Dealer-first pilot proof

**LF-G10-PILOT-001.** Первая cohort фиксируется до контакта:

- 100–150 уникальных DealerAccount;
- приоритет: 88 warm, 217 HOT, deduped retail и lapsed buyers;
- reason-to-contact и ICP evidence;
- одна версия подсегмента, оффера, CTA и qualification profile;
- минимум 30 завершённых разговоров с ЛПР;
- минимум 10 фактически полученных DealerRFQ с файлами/данными;
- минимум 3 distinct paid TrialOrder.

**LF-G10-PILOT-002.** Пилот доказывает manual method, но не GCO10. При провале
запрещено компенсировать качество объёмом. Открывается diagnostic branch:

- мало eligible supply → source/segment method;
- contactability/reach failure → data/channel method;
- разговоры есть, RFQ нет → ICP/offer/CTA/trust method;
- RFQ есть, ReadyPackage нет → intake/engineering method;
- КП есть, оплат нет → price/terms/speed/trust method;
- Trial есть, repeat нет → product/quality/service method.

## 6. Production proof

**LF-G10-PROOF-001.** Evaluation начинается только после готовности измерений,
Bitrix/outcome feedback, capacity schedule, qualification profiles, source/method
versions, телефонии/каналов, кодов исхода и независимого quality audit.

**LF-G10-PROOF-002.** Окно — 30 последовательных рабочих дней. Первые пять
дополнительных рабочих дней могут использоваться как calibration до начала окна,
но не для сокрытия известных дефектов.

**LF-G10-PROOF-003.** `PROVEN_GCO10` вычисляется, а не ставится вручную, когда:

1. `AGCO_total >= 300`;
2. выполнены все условия `LF-G10-002` и `LF-G10-003`;
3. минимум 80% первых ReadyPackage приняты без возврата из-за неполноты;
4. independent audit: `max(30, 20% AGCO)` и Wilson LCB95 истинных AGCO >=80%;
5. provenance и counting key сохранены у 100%;
6. все AGCO имеют disposition либо следующий шаг в SLO;
7. выполнены capacity/load/backlog gates;
8. минимум два коммерчески работающих метода не имеют общей single point of failure;
9. известны AGCO→Estimate→Proposal→Paid и причины потерь;
10. отсутствует critical measurement gap, legal/security breach или незакрытый P0/P1.

**LF-G10-PROOF-004.** Изменение Gold Gate, funnel mix, продукта, географии,
qualification profile, counting key или метода в evaluation window аннулирует только
затронутую когорту и запускает новое окно для неё.

## 7. Отдельное доказательство платящих клиентов

**LF-G10-NPC-001.** `NPC10` не выводится из GCO10. Требуемый AGCO-поток:

```text
AGCO_required_for_NPC10 = ceil(10 / LCB95(p_AGCO_to_NPC))
```

До зрелой когорты `p_AGCO_to_NPC=UNKNOWN`; публичное или внутреннее обещание
«10 новых платящих клиентов в день» запрещено.

**LF-G10-NPC-002.** `PROVEN_NPC10` требует отдельные 30 рабочих дней, 10 уникальных
первых cleared payments в среднем за день, lower confidence bound, capacity,
contribution margin и отсутствие дробления одного контрагента/платежа.

## 8. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-G10-01` | 30 дней и 300 AGCO, все quality/capacity/economics gates. | `PROVEN_GCO10=true`. |
| `AT-G10-02` | Один спрос повторён источником/funnel/revision. | KPI увеличивается ровно один раз. |
| `AT-G10-03` | 10 среднее достигнуто за счёт нескольких пиков. | Proof отклонён по daily distribution. |
| `AT-G10-04` | AGCO выше safe capacity. | Лишние записи не считаются processed capacity. |
| `AT-G10-05` | Form/reply без Gold Gate. | 0 AGCO. |
| `AT-G10-06` | 10 AGCO/day без оплат и зрелого outcome. | GCO proof возможен; claim «10 клиентов» запрещён, diagnosis открыт. |
| `AT-G10-07` | Изменена metric/profile version во время окна. | Затронутая когорта начинается заново. |
| `AT-G10-08` | 10 оплат состоят из частей одного заказа. | 1 NPC/Order, не 10. |

