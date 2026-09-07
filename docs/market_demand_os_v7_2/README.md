# АлюмКомплект Market & Demand OS v7.2 successor

Этот каталог — полный successor-пакет `7.2.0-rc.2`. Он сохраняет неизменяемый
baseline `7.1.0-rc.1`, добавляет нормативные операторский/телефонный контур и
read-only observer нативной почты Bitrix, машинные схемы и локальные test/evidence
bindings. Пакет остаётся
`RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION`: все внешние чтения, записи, контакты,
расходы, MANGO/Bitrix live и TenderPlan выключены.

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
- `APP-MDOS-OPERATOR-TELEPHONY.md` — роль оператора, MANGO/Bitrix ownership,
  доказательства звонка, подтверждение исхода и ограниченный пилот;
- `APP-MDOS-MAIL-BITRIX-OBSERVER.md` — нативная почта Bitrix как единственный
  inbound CRM writer, IMAP/CRM read-only observer, 5m/90m reconciliation и V4
  quarantine без Lead/Todo/Timeline/repair;
- `schemas/*.schema.json`, реестры и `contract-manifest.json` — machine layer.

`release-pin.json` отдельно фиксирует точные SHA manifest и package root. Это
устраняет возможность незаметно изменить поля manifest, не меняя digest списка
артефактов. Он не подключает successor к действующей authority 7.1 и не даёт live-
разрешения.

## Честный статус реализации

Реестры строятся детерминированно скриптом
`scripts/build_market_demand_os_v7_2_package.py`. Статус `IMPLEMENTED` означает только
наличие локальных code/test/evidence bindings. Он не означает независимую проверку,
ратификацию или production proof. Неполные требования сохраняются как `DESIGNED`, а
локально выполненные acceptance-сценарии — как `IMPLEMENTED_NOT_VERIFIED`.

`evidence/ratification-readiness.json` перечисляет незакрытые решения владельцев без
выдуманных имён, подписей и разрешений. Назначение оператора отложено на время
наблюдения, но обязательно до любого контакта. MANGO, TenderPlan, UniSender/SMTP и
outbound зафиксированы отдельной STOP-точкой.

## Статус

Версия `7.2.0-rc.2` — усиленный архитектурный release candidate, а не разрешение на live-
сбор, рекламу, контакт, Bitrix-write, mailbox-read или расходование бюджета. Все внешние права
по умолчанию выключены. Ратификация требует exact package digest, владельцев,
параметров экономики и доказательств первого вертикального среза.

Выбранный inbound design не даёт custom worker полномочий исправлять CRM. После
отдельного разрешения нативная почта Bitrix остаётся единственным inbound writer,
observer только читает IMAP/Activities и пишет локальный ledger. Он не создаёт Lead,
Todo, Timeline или repair; стабильный singleton проверяется пять минут, а отсутствие
projection переводится в локальный review через 90 минут.

1С/ERP не является обязательной зависимостью. Каноническую оплату подтверждает банк,
платёжный провайдер или подписанная банковская выписка; заказ и исполнение ведутся в
локальных versioned реестрах, а Bitrix24 является рабочей проекцией.

## Главный принцип

Apify, ScrapeGraphAI, TenderPlan, Контур, ЕИС, Авито, Яндекс и любые будущие
сервисы являются сменными adapters/sensors. Ни один из них не является фабрикой
лидов. Интеллектуальным активом является связка `Market Graph + Demand Resolver +
Motion Engine + Outcome Learning`, которая доказывает, когда и почему наблюдение
следует превратить в коммерческую работу.
