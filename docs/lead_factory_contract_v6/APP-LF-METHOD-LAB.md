# APP-LF-METHOD-LAB — лаборатория методов достижения результата

**Application ID:** `APP-LF-METHOD-LAB`  
**Версия:** 1.0.0  
**Нормативный статус:** приложение `LF-OUTCOME-V6`

## 1. Разделение Source Lab и Method Lab

**LF-MTH-001.** Source Lab отвечает на вопрос: «Можно ли законно, надёжно и с
достаточным качеством получить эти данные?» Method Lab отвечает: «Даёт ли связка
сегмента, сигнала, оффера, канала и процесса RFQ, оплату и повтор?» Их статусы,
разрешения и метрики не смешиваются.

**LF-MTH-002.** Метод — immutable version связки:

```text
funnel + source cohort + selection rule + segment + trigger
+ offer + channel + CTA + human workflow + capacity model
```

Название источника само по себе не является методом.

## 2. Обязанность предлагать развитие

**LF-MTH-003.** Пока `PROVEN_GCO10=false`, Method Lab ОБЯЗАН поддерживать
ранжированный портфель не менее чем из:

- одного метода улучшения текущего bottleneck;
- одного независимого резервного метода;
- одного исследовательского метода с потенциально большим uplift.

Если подходящих методов нет, система формирует research task с точным пробелом данных,
а не повторяет старый эксперимент.

**LF-MTH-004.** Method Lab МОЖЕТ предлагать:

- новый ICP/subsegment, trigger или account score;
- новый разрешённый источник или способ enrichment;
- оффер, CTA, последовательность контакта и proof asset;
- supplier-intent landing/search campaign;
- реактивацию, referral или channel partnership;
- end-customer routing в bounded регионе;
- изменение intake, расчёта, SLA, КП или follow-up;
- staffing/capacity, продуктовую упаковку, географию и ценовую гипотезу;
- применение Apify/ScrapeGraph AI после доказательства нужных признаков.

Цена, публичное обещание, договор, новый продукт/регион и внешний канал требуют
владельца/Policy Engine permit; предложение такого изменения разрешено.

## 3. Сущности и состояния

**LF-MTH-005.** Обязательные сущности:

- `MethodProposal` — проблема, механизм, evidence, ожидаемый эффект, риски;
- `MethodVersion` — sealed protocol, cohort, factor, metrics, gates;
- `MethodReviewDecision` — решение и полномочия;
- `MethodExperiment` — фактический run, события, стоимость;
- `MethodPromotionDecision` — outcome и следующий статус.

**LF-MTH-006.** Lifecycle:

```text
PROPOSED
→ SCREENED
→ APPROVED_OFFLINE
→ SHADOW
→ CANARY
→ PILOT
→ SCALE_ELIGIBLE
→ PROVEN
↘ REVISE / STOPPED / RETIRED
```

Статус `SCALE_ELIGIBLE` не включает live authority автоматически.

## 4. Протокол предложения

**LF-MTH-007.** Каждый `MethodProposal` содержит:

1. `method_id`, parent/version и owner;
2. диагностируемую проблему и funnel;
3. target cohort и явные exclusions;
4. causal mechanism: почему действие должно повлиять на нужную стадию;
5. evidence и степень уверенности;
6. один основной изменяемый фактор;
7. control/holdout либо обоснование невозможности контроля;
8. primary metric, guardrails и знаменатель;
9. expected effect как range/scenario, не обещание;
10. sample/window/maturity;
11. budget, human WIP и production capacity;
12. legal/data/security/source requirements;
13. stop-loss и success/promotion criteria;
14. план отката и сохранения отрицательного результата.

Отсутствие любого обязательного поля блокирует canary.

## 5. Полномочия

**LF-MTH-008.** Method Lab не владеет credentials, Source Reader, Send Gate,
CRM writer, рекламным кабинетом или платёжным полномочием.

**LF-MTH-009.** ИИ может автономно создать/обновить Proposal, выполнить расчёты и
offline/shadow-анализ на уже разрешённых данных. Любой side effect проходит:

```text
MethodPermitRequest → Policy Engine → scoped permit → execution → reconciliation
```

**LF-MTH-010.** Permit фиксирует exact method/version, cohort, action, channel,
budget, WIP, время, legal status, content/promise version и stop authority.

## 6. Экспериментальная дисциплина

**LF-MTH-011.** Одновременное изменение ICP, источника, оффера и канала создаёт
новый комплексный метод, результат которого нельзя приписывать одному фактору.
Для оптимизации одного фактора остальные удерживаются фиксированными.

**LF-MTH-012.** Cohort, denominator, primary metric, maturity window и stop rule
sealed до первого внешнего действия. Post-hoc изменение запрещено.

**LF-MTH-013.** Открытия, клики, количество записей и ответы являются диагностикой.
Promotion dealer-first метода требует DealerRFQ и, для `PROVEN`, зрелых Trial/Repeat
outcomes либо заранее утверждённого промежуточного gate.

**LF-MTH-014.** Результат старой method/metric/qualification версии не продвигает
новую. Повтор stopped метода возможен только при новом evidence и новой версии.

**LF-MTH-015.** Unlimited-budget assumption не разрешает выбрасывать отрицательные
результаты, покупать все сервисы одновременно или масштабировать до attribution.
Оптимизируется коммерческий результат при сохранении качества, а не минимальная цена.

## 7. Приоритетизация

**LF-MTH-016.** Методы ранжируются по:

```text
Priority = ExpectedCommercialUplift
           × EvidenceConfidence
           × TimeToEvidenceFactor
           × CapacityFit
           × IndependenceValue
           / RiskAndComplexity
```

Формула является versioned policy; числовой score не обходит hard gates.

**LF-MTH-017.** Critical path всегда следует фактическому bottleneck:

- достаточно сырья, мало RFQ → не покупать ещё сырьё;
- RFQ есть, нет оплат → работать с КП/ценой/сроком/доверием;
- оплаты есть, нет repeat → работать с качеством/сервисом/ассортиментом;
- спрос превышает обработку → добавлять capacity до acquisition scale.

## 8. Promotion gates

**LF-MTH-018.** Решения:

- `STOP` — hard gate/экономика/качество провалены;
- `REVISE` — механизм возможен, но protocol/offer/cohort требует новой версии;
- `CONTINUE_SHADOW` — нужно больше offline evidence;
- `CONTINUE_PILOT` — bounded commercial evidence положительно;
- `SCALE_ELIGIBLE` — outcome, economics, capacity и risk gates выполнены;
- `PROVEN` — зрелая когорта подтверждает оплату/повтор в установленной экономике.

**LF-MTH-019.** Любое продвижение имеет immutable decision record с входными hashes,
метриками, окном, actor, временем и точной версией. Ручная правка статуса запрещена.

## 9. Acceptance

| ID | Сценарий | Критерий |
|---|---|---|
| `AT-MTH-01` | ИИ создал Proposal. | 0 external read/send/write/spend. |
| `AT-MTH-02` | Нет denominator/control/stop/capacity. | Canary permit отклонён. |
| `AT-MTH-03` | Изменены ICP+offer в том же version. | Требуется новая version/cohort. |
| `AT-MTH-04` | Старый положительный outcome, новый qualification profile. | Promotion отклонён. |
| `AT-MTH-05` | Метод дал клики, но 0 RFQ. | Не выше diagnostic/REVISE. |
| `AT-MTH-06` | Пилот дал RFQ/Trial, economics/capacity зелёные. | Может стать SCALE_ELIGIBLE, без автоматического live permit. |
| `AT-MTH-07` | Stopped метод запущен без нового evidence. | Атомарный reject. |
| `AT-MTH-08` | Bottleneck — quote→paid, предлагается новый scraper. | Priority policy отклоняет как не связанный с bottleneck. |

