# Lead Factory — Connection Readiness Report

**Версия:** 0.1  
**Дата:** 22.08.2026  
**Контур:** Wave 1 / stage  
**Статус:** `NO_GO_FOR_GENERAL_CONNECTIONS`

## Решение

Техническая основа готова к **отдельно одобренным, ограниченным canary-подключениям**,
но статус `TECH_READY_FOR_CONNECTION` из §42.4 контракта пока не присваивается.
Ни токен, ни уже существующий legacy-клиент не являются разрешением на live-read,
live-write или массовую рассылку.

Этот отчёт фиксирует состояние на момент выпуска. Он не является
`OutboundAuthorization`, `MarketingSendPermit`, разрешением на покупку источника
или разрешением изменить данные во внешней системе.

## Обновление: подготовлен сайтный ingress (24.08.2026)

В исходниках сайта АлюмКомплект и в его подготовленном deploy-каталоге удалён
прямой вызов Bitrix `crm.lead.add`. Вместо него реализована подписанная
передача `POST /v1/site-deliveries` в локальный Lead Factory: HMAC, digest,
идемпотентность, лимит тела и fail-closed switch покрыты тестами. Приёмник
создаёт только local raw delivery, Source Lab/review и локальную
`SITE_QUALIFICATION` task; CRM, Unisender и OpenRouter не вызываются.

Сайтная связка пока **не опубликована**: для этого нужен постоянный HTTPS
адрес приёмника и одинаковый новый секрет в двух non-repository конфигурациях.
До размещения этих двух значений PHP-обработчик сохраняет заявку на РФ-хостинге
и отправляет fallback email, но `lead_factory=false`. Инструкция:
`LEAD_FACTORY_SITE_DELIVERY_RUNBOOK.md`.

## Обновление: проверка существующих учётных данных (24.08.2026)

По явному разрешению владельца выполнены read-only технические проверки уже
существующих ключей. Unisender подтвердил ключ и sender configuration; найдены
два подтверждённых домена. OpenRouter принял authentication request. Письма,
создание кампаний, обработка клиентских текстов моделью и любые CRM-операции не
выполнялись.

Добавлен `openrouter_gateway.py`: выключенный по умолчанию gateway принимает
только `PUBLIC`/`BUSINESS_INTERNAL`, локально редактирует распространённые
e-mail/телефон/секреты, ограничивает суточное/месячное число вызовов и хранит
только хеши prompt/output в immutable event log. Этот код не активирует модель
сам по себе.

Добавлен `unisender_go_transport.py`: выключенный по умолчанию adapter использует
существующие `UNISENDER_GO_*` variables, принимает только одну уже
авторизованную typed message и не имеет scheduler/campaign-discovery/retry
loop. Явный provider reject отделён от ambiguous timeout, поэтому последний не
может стать blind retry. Подключать его к `MultiMailSendGate` можно только после
отдельного Send Gate / dead-letter acceptance; текущая проверка ключа не
создаёт такого разрешения.

## Проверенные доказательства

- Bitrix graph canary `1 → 5` завершён: 20 операций имеют `SENT`, новые 16/16
  прошли независимый typed readback; runtime остановлен с выключенными внешними
  флагами. См. `LEAD_FACTORY_BITRIX_GRAPH_CAP5_LIVE_EVIDENCE.json` и журнал
  строительства от 22.08.2026.
- Targeted gates на релевантном live-срезе: 250/250 `OK`; полный Lead Factory:
  888/888 `OK`; TaskBot: 13/13 `OK`; `ruff` и `compileall` — `OK`.
- Каноническая база `state/lead_factory_stage.sqlite3` не мигрировалась:
  environment `stage`, schema 13, `external_writers_enabled=0`,
  `external_source_reads_enabled=0`, `manual_import_commits_enabled=0`.
- Контракты Tenderplan, Saby Trade, ДОМ.РФ и Контур.Поиск клиентов имеют статус
  `DRAFT_OFFLINE`; их fixtures не дают доступа к API и не доказывают лицензию,
  покрытие или коммерческую экономику.

## Матрица §42.4

| Критерий | Статус | Что доказано / чего не хватает |
|---|---|---|
| 1. Миграция v13 → v14 → v15, rollback и restore | `PASS` | 22.08.2026 canonical stage мигрирована в reversible Windows cutover и затем расширена до v16 для registered mailbox cursor. Writers и source reads остались выключены. |
| 2. Production import/evidence/review/provenance для Wave 1 | `PARTIAL` | Offline import, evidence, review и reconciliation зелёные. Нужны production evidence repository, identity/reassignment workflow и реальный источник. |
| 3. Полная CRM-цепочка и коммерческие исходы | `PARTIAL` | Bitrix graph canary доказал Company → Contact → Deal → Activity. Не закрыты постоянный outcome poller, причины потерь, заказ и фактическая маржа. |
| 4. Standard Source Adapter | `PARTIAL` | Контракт и offline runtime покрывают typed payload, cursor, quota и STOP. Нет одобренных auth reference, endpoint, licence binding и live reconciliation конкретного поставщика. |
| 5. Site, IMAP/Unisender, OpenRouter adapters | `OPEN` | Есть transport-neutral/offline модули и legacy-клиенты. Production-neutral adapters, budgets, dead-letter и offline acceptance для всего набора не оформлены. |
| 6. Среды, секреты, workers, monitoring, backup, runbooks | `PARTIAL` | Secret values изолированы, backup/restore и Bitrix canary runbook существуют. Не закрыты production worker inventory/RPO/RTO для всего Wave 1. |
| 7. Integrated regression, failure injection, red-team | `PARTIAL` | Релевантные регрессии зелёные, открытых воспроизводимых P0/P1 в Bitrix cap=5 нет. Нет общего закрывающего acceptance-пакета для всех live adapters. |
| 8. Fail-closed без credentials | `PASS` | Все три external/manual переключателя выключены; stage не выполняет source reads и writer actions. |
| 9. Versioned readiness evidence | `PARTIAL` | Создан этот отчёт; стать `PASS` он сможет только после закрытия критериев 1–8 и привязки к точным revision/schema/manifest/policy hashes. |

## Выполненный IMAP transport preflight

**Дата:** 22.08.2026  
**Scope:** существующая IMAP-учётка, использованная только по явному разрешению
владельца как исключение из требования отдельной canary-учётки.

- TLS/login и `SELECT "INBOX"` с `readonly=True` прошли; UIDVALIDITY присутствует.
- Получен ограниченный batch из 5 UID. Все пять raw MIME были проверены локально
  в памяти по SHA-256; адреса, темы, тела, IDs и хеши не выводились и не сохранялись.
- IMAP-сессия закрыта. Не выполнялись `STORE`, `COPY`, `MOVE`, `EXPUNGE`,
  `APPEND`, SMTP, Unisender, Bitrix, Telegram или OpenRouter.
- До и после прогона canonical stage остался schema 13 с
  `external_writers_enabled=0`, `external_source_reads_enabled=0`,
  `manual_import_commits_enabled=0`; event/inbox/CRM outbox и human-task counts
  не изменились.

Это доказывает только работоспособность read-only TLS transport. Полным inbound
canary он не является: для него нужны owner-approved migration/restore target,
registered mailbox, локальный evidence vault, UID cursor и reconciliation.

## Выполненный schema cutover v13 → v15

**Дата:** 22.08.2026  
**Pre-cutover backup:** `lead_factory_20260822T172123787083Z_409f67bb9c.sqlite3`  
**Post-cutover backup:** `lead_factory_20260822T172452349169Z_2dfcaecff5.sqlite3`

- Legacy writers были временно изолированы внутри reversible Windows bracket с
  DPAPI-protected recovery capsule; после миграции их исходное состояние
  семантически сверено и восстановлено, capsule удалена.
- 47 existing interactions сохранены; для них создана одна disabled
  `LEGACY_UNVERIFIED` mailbox-привязка. Ни один адрес, текст или иной PII не
  выводился и не переписывался.
- Canonical stage теперь имеет schema/meta/PRAGMA version `15`, две записи
  migration ledger, `external_writers_enabled=0` и
  `external_source_reads_enabled=0`.
- Post-cutover backup и restore-test прошли; restore не создал permits, outbox,
  CRM-команды или delivery events. Targeted schema/IMAP/recovery suite: 31/31
  `OK`; scoped `ruff` — `OK`.

Migration закрывает только criterion 1. Она не активирует IMAP worker и не
разрешает live source reads: для полноценного inbound canary остаются registration
конкретного mailbox, evidence/cursor binding и reconciliation.

## Переход с legacy-контура

По явному решению владельца legacy TenderBot/TaskBot writer entry points
приостановлены: проверка Windows readiness вернула `OK` без active legacy
components. Recovery capsules сохранены для контролируемого отката, но не
используются автоматически.

В canonical v16 зарегистрирована и активирована локальная цепочка только для
inbound canary: IMAP provider → mail domain → mailbox account. Все send caps
равны нулю; sender identity и campaign не созданы. Регистрация не включает
`external_source_reads_enabled` и не выполняет чтение IMAP.

## Разрешённый следующий технический шаг

Первым live-контуром рекомендуется **read-only IMAP intake** рабочего ящика:

1. не покупает новый источник и не отправляет писем;
2. создаёт доказуемый inbound event для ответа клиента и позволяет проверить SLO;
3. использует уже существующий рабочий ящик, но требует отдельного read-only
   credential, bounded batch, mailbox/UID cursor, evidence vault, dead-letter и
   reconciliation;
4. не создаёт Lead в Bitrix, задачу, Telegram-уведомление или auto-reply до
   отдельного разрешения и успешного canary.

Кодовые IMAP boundary и TLS client factory реализованы через injected client
factory и покрыты fixture-тестами; operational sequence описана в
`LEAD_FACTORY_IMAP_CANARY_RUNBOOK.md`. До canary допускаются только fixtures:
реальный IMAP login не выполнялся этим решением.

## Порядок подключения после закрытия этого шага

1. IMAP read-only canary: одна папка, ограниченный batch, zero-write verification.
2. Сайт/CRM-форма: tracking dry-run и один тестовый входящий без Bitrix write.
3. Один source capability test на разрешённой ручной/демо-выборке; Tenderplan,
   Saby и Контур оцениваются по отдельности, без автоматической покупки.
4. Bitrix reconciliation/canary только для заранее одобренной возможности.
5. Unisender и OpenRouter — после собственных adapter/limit/dead-letter gates;
   массовая отправка остаётся запрещённой до MarketingSendPermit.

## Явные запреты

- не включать `external_writers_enabled` или `external_source_reads_enabled` вручную;
- не использовать legacy SMTP/Unisender/Bitrix UI как обход Send Gate;
- не покупать платный API по наличию кода или токена;
- не переносить доказательства Bitrix canary на другой сервис;
- не запускать массовую рассылку или автоматические ответы.

## Обновление: выполненный owner-approved IMAP inbound canary

**Дата:** 22.08.2026  
**Статус:** `PASS_FOR_THIS_BOUNDED_INBOUND_STEP`; общий статус отчёта остаётся
`NO_GO_FOR_GENERAL_CONNECTIONS`.

После reversible cutover до schema v16 и остановки legacy-контура по явному
решению владельца выполнен один bounded intake рабочего IMAP mailbox:

- была создана отдельная локальная backup-точка до запуска;
- boundary подключился по TLS, выбрал только `INBOX` с `readonly=True` и
  прочитал не более пяти писем; IMAP-команды записи и любые отправки не
  выполнялись;
- все 5 raw MIME были сначала записаны в локальный immutable evidence vault,
  затем созданы 5 `inbound_received`/Interaction, а registered UID cursor и
  ordered manifest были зафиксированы после durable event;
- взаимодействия остались `UNROUTED`: не создавались task, auto-reply,
  sender identity, campaign, CRM command, Bitrix/SMTP/Unisender/Telegram или
  OpenRouter вызов;
- canonical stage после canary: schema `16`, events `112`, interactions `52`,
  `outbox=0`, `crm_outbox=0`, `external_writers_enabled=0`,
  `external_source_reads_enabled=0`;
- post-run backup `lead_factory_20260822T175112864625Z_a2d2917f28.sqlite3`
  и независимый restore-test прошли: в архиве ровно 5 raw-MIME и 5 metadata
  evidence files; restore также оставил оба external switch выключенными.

В ходе запуска обнаружена и устранена локальная несовместимость между worker и
IMAP boundary: marker папки теперь проверяется boundary до подключения и
отклоняет несовпадающий scope. Регрессии boundary/worker: 22/22 `OK`, scoped
`ruff` — `OK`. Это не включает постоянный scheduler и не является разрешением
на общее live source reading: следующий запуск требует отдельного решения и
reconciliation обработанных сообщений.

## Обновление: локальная conversation reconciliation канарейки

Пять принятых interactions прошли fail-closed сверку с каноническими outbound
conversation identities. Точного совпадения не найдено: 4 письма не содержат
thread reference, 1 не связан с известной исходящей conversation. Поэтому все
5 сохранены в `conversation_route_reviews` со state `OPEN`; human task, CRM
operation, ответ клиенту и изменение внешней системы не созданы.

Во время backup этого состояния найден и исправлен recovery-defect: производное
local routing event может ссылаться на уже сохранённый immutable raw-MIME
evidence, не дублируя транспортный envelope. Recovery принимает такую ссылку
только при наличии в том же backup исходного события с точными
SHA-256/size/mailbox/UID/UIDVALIDITY/parser metadata; частичный envelope или
ссылка без исходного envelope отклоняются. Recovery tests: 13/13 `OK`, scoped
`ruff` и compile — `OK`.

Финальный checkpoint: `lead_factory_20260822T175503083786Z_43478c059b.sqlite3`.
Его restore-test восстановил 5 raw-MIME и 5 metadata evidence, 5 review-records
и schema v16; оба external switch после восстановления остаются выключены.

## Обновление: owner-approved content review и routing

Владелец отдельно разрешил локальную содержательную проверку пяти сохранённых
MIME. Результат зафиксирован immutable route decisions без передачи письма во
внешний AI/service: одно письмо является содержательным ответом на коммерческий
расчёт, четыре — системные уведомления стороннего сервиса.

- один Interaction получил `HUMAN_REPLY`: создана одна локальная задача Диме и
  один cadence block; CRM handoff, CRM outbox и внешний writer не созданы;
- четыре Interaction получили `AUTO_REPLY`; они не создают задачу, suppression
  или любое внешнее действие;
- `UNSUBSCRIBE` не создан: совпадение слова в footer не было принято за волю
  адресата без явного запроса;
- финальный checkpoint
  `lead_factory_20260822T180721477278Z_49368a34d5.sqlite3` и restore-test
  прошли: schema v16, 122 events, 11 human tasks, 25 cadence blocks, `outbox=0`,
  `crm_outbox=0`, оба external switch `0`.

При backup была дополнительно уточнена recovery-проверка: `mailbox` в
производном routing event является контекстом, но transport envelope признаётся
только при полном наборе immutable UID/hash/size/parser fields исходного
inbound event. Релевантные routing/recovery tests: 20/20 `OK`.

## Operations checkpoint: локальная очередь и SLO

В offline CLI добавлена команда `work-queue`: она выдаёт только агрегаты
активных задач, inbound classifications, открытых conversation reviews, SLO и
external stop flags; адреса, темы, тексты и task IDs не выводятся. Для текущего
`HUMAN_REPLY_REVIEW` подготовлен обезличенный local brief: сверить объёмы и
спецификацию/ценовые строки до подготовки ответа. Поскольку due-time письма
уже истёк, один раз записана локальная SLO-эскалация; она не отправляла письмо,
Telegram или CRM-команду и не имитирует действие Димы.

Финальный полный Lead Factory regression: **899/899 `OK`**; `ruff` — `OK`.
Backup `lead_factory_20260822T192958116728Z_9cd678fd93.sqlite3` и restore-test
подтвердили schema v16, raw-MIME evidence, 124 events и forced-off external
writer/source-read flags. Это улучшает operations readiness, но не заменяет
отдельные contract/licence/canary approvals для постоянного IMAP, сайта,
источников, CRM и исходящих сообщений.

## Источники

- Контракт B2B Lead Factory, §9, §26, §32, §39, §40 и §42.
- `docs/LEAD_FACTORY_BUILD.md`, checkpoint 22.08.2026, Bitrix graph cap=5.
- `docs/LEAD_FACTORY_BITRIX_CANARY_RUNBOOK.md`, текущее состояние 22.08.2026.
