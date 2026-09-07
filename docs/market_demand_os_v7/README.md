# АлюмКомплект Market & Demand OS v7

`MDOS v7` — новый архитектурный baseline коммерческой системы АлюмКомплект.
Он заменяет модель «поиск контакта/объекта/тендера → лид» моделью:

```text
наблюдение → проверяемое утверждение → DemandUnit → buying group
→ motion-specific решение → разрешённое действие → оплата/исполнение/повтор
```

## Вердикт по v6.1

`LF-OUTCOME-V6 6.1.0-rc.1` сохраняется как исторический дизайн-источник. Его сильные
идеи — evidence, bitemporal graph, negative evidence, point-in-time learning,
Policy Engine, capacity и causal experiments — перенесены без ослабления. Его
коммерческая рамка из трёх воронок и проектно-закупочный центр больше не являются
целевой архитектурой.

## Нормативный пакет

- `CONTRACT.md` — миссия, границы, единица результата и ратификация;
- `APP-MDOS-COMMERCIAL-MODEL.md` — сегменты, motions, роли и Gold-профили;
- `APP-MDOS-REFERENCE-ARCHITECTURE.md` — bounded contexts, данные и runtime;
- `APP-MDOS-DEMAND-INTELLIGENCE.md` — AI/ML, evidence, time-to-event и research;
- `APP-MDOS-SOURCE-PORTFOLIO.md` — source portfolio, capability/licence gates;
- `APP-MDOS-DECISION-OUTCOMES.md` — экономика, causal learning и GDO10/PC10;
- `APP-MDOS-DELIVERY-ASSURANCE.md` — программа реализации, safety и acceptance;
- `schemas/*.schema.json`, реестры и `contract-manifest.json` — machine layer.

## Статус

Версия `7.1.0-rc.1` — усиленный архитектурный release candidate, а не разрешение на live-
сбор, рекламу, контакт, Bitrix-write или расходование бюджета. Все внешние права
по умолчанию выключены. Ратификация требует exact package digest, владельцев,
параметров экономики и доказательств первого вертикального среза.

1С/ERP не является обязательной зависимостью. Каноническую оплату подтверждает банк,
платёжный провайдер или подписанная банковская выписка; заказ и исполнение ведутся в
локальных versioned реестрах, а Bitrix24 является рабочей проекцией.

## Главный принцип

Apify, ScrapeGraphAI, TenderPlan, Контур, ЕИС, Авито, Яндекс и любые будущие
сервисы являются сменными adapters/sensors. Ни один из них не является фабрикой
лидов. Интеллектуальным активом является связка `Market Graph + Demand Resolver +
Motion Engine + Outcome Learning`, которая доказывает, когда и почему наблюдение
следует превратить в коммерческую работу.
