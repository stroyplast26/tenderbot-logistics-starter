# APP-MDOS-MAIL-BITRIX-OBSERVER — нативная почта Bitrix и read-only observer

**Application ID:** `APP-MDOS-MAIL-BITRIX-OBSERVER`  
**Версия:** `1.0.0`  
**Статус:** `INCLUDED_IN_7_2_RC_NOT_RATIFIED`  
**Кандидат версии:** `7.2.0-rc.2`  
**Нормативная сила:** exact digest включён в successor manifest; документ выбирает
архитектуру, но не включает mailbox/Bitrix access, расписание, контакт или внешний
writer и не является `PermitDecision`.

## 1. Единственный inbound writer

**MDOS-MBO-001.** Для одного exact mailbox и одного exact Bitrix24 portal scope
нативная интеграция `Bitrix24 Mail` является единственным writer-ом CRM-сущностей и
Activities, возникающих из входящей почты. Она может создать или привязать сущность
согласно своей утверждённой настройке; Lead Factory observer только проверяет факт
этой нативной проекции и никогда не приписывает её себе.

**MDOS-MBO-002.** Observer имеет только `IMAP READ-ONLY` и Bitrix read methods
`crm.activity.list` / `crm.activity.get`. Его единственный write scope — локальный
observer ledger и локальная review queue. IMAP flags/folders, Bitrix24 и внешние
провайдеры не изменяются.

**MDOS-MBO-003.** Observer не содержит и не получает пути `Lead`, `Todo`, `Timeline`,
Company/Contact/Deal create/update/delete, task assignment, stage/owner repair,
mail send, auto-reply или иного внешнего side effect. Отсутствующая, неоднозначная
или ошибочная нативная проекция создаёт только локальное наблюдение/review, не repair.

## 2. Correlation без автоматического repair

**MDOS-MBO-004.** Correlation использует hashed mail identity, immutable source
evidence, stable Bitrix Activity ID и полный candidate snapshot в bounded time window.
Совпадение только sender, subject, телефона, owner или близости времени не является
достаточным доказательством.

**MDOS-MBO-005.** Состояние `RECONCILED` допускается только если один и тот же
единственный кандидат наблюдался минимум в двух отдельных poll и оставался неизменным
не менее пяти минут. Смена или исчезновение provisional candidate сбрасывает stability
window; предыдущий singleton не используется как молчаливое подтверждение.

**MDOS-MBO-006.** Нулевой кандидат остаётся `WAITING_NATIVE_IMPORT` до 90 минут от
первого локального наблюдения, после чего создаётся `LOCAL_REVIEW_REQUIRED` без CRM-
repair. Несколько кандидатов, integrity conflict или исчезновение provisional
candidate могут создать локальный review раньше; ни один review не разрешает write.
После наступления 90-минутного deadline эта observation не может стать `RECONCILED`,
даже если позднее появился стабильный singleton: требуется новая human-reviewed связь.

## 3. Человек, singleton и миграция V4

**MDOS-MBO-007.** Назначенный оператор не требуется для разрешённого read-only
наблюдения. До любого звонка, ответа, исходящего сообщения, CRM task или иного контакта
обязательны exact active assignee, `OperatorWorkItem` и отдельный action permit;
observer не назначает человека и не создаёт задачу.

**MDOS-MBO-008.** Runtime имеет одного локального владельца расписания и один active
observer instance на mailbox/portal scope. Concurrent start блокируется до чтения;
exact replay идемпотентен и не создаёт второй local result, cursor или review.

**MDOS-MBO-009.** Перед запуском observer legacy authority `MAIL-TO-BITRIX-INBOUND-V4`
отзывается, её writer schedule остаётся disabled, а exact cutover cohort обязан
содержать ровно 10 недоставленных V4 operations: пять `OPERATOR_TODO` и пять
`TIMELINE_MAIL`. Все десять переводятся поддерживаемой процедурой в durable
`QUARANTINED` с evidence и никогда не dispatch-ятся; расхождение count/kind, ручное
редактирование SQLite или попытка re-enable создают STOP.

## 4. Наблюдаемость и STOP

**MDOS-MBO-010.** MANGO, TenderPlan, UniSender, SMTP/почтовая рассылка, auto-reply,
outbound contact и любой новый source/writer находятся за явной STOP-точкой. Каждый
контур требует отдельного successor change, source/action permit, preflight, rollback
и owner release; mail observer не является разрешением перейти эту границу.

**MDOS-MBO-011.** Каждый poll сохраняет локально release/runtime digests, authority
generation, cursor, candidate-set digest, stability age, outcome/reason, review state,
quarantine counts и invariant `external_write_methods_enabled=false`. Health обязан
показывать singleton/authority expiry и нулевой внешний write budget без PII payload.

**MDOS-MBO-012.** Включение приложения в `7.2.0-rc.2` фиксирует только нормативный
design. Все package live gates и defaults external read/write/contact/spend остаются
`false`; credentials, Windows task/schedule, live read и ратификация этим документом
не создаются.

## 5. Safety-review appendix

**MDOS-MBO-013.** `Subject` участвует в correlation как exact decoded value и exact
digest. Observer не делает trim, whitespace collapse/normalization, case folding или
truncation; любое отличие пробела, tab, переноса либо хвоста означает другой candidate
input и не может быть скрыто fuzzy matching.

**MDOS-MBO-014.** `OWNER_ID`/`OWNER_TYPE_ID` являются только metadata projection и не
участвуют в identity. Элемент `COMMUNICATIONS` участвует только если его тип и exact
value соответствуют наблюдаемому sender/mailbox identity; unrelated phone/email или
другая communication не подтверждает связь.

**MDOS-MBO-015.** Bitrix list pagination читается полностью по строго возрастающему
`next`, пока continuation отсутствует. Повторный, убывающий, malformed или missing
continuation при неполной странице переводит poll в `READ_UNKNOWN/LOCAL_REVIEW` и
запрещает принимать singleton из частичного набора.

**MDOS-MBO-016.** V4 quarantine сохраняет прежние `phase`, error/retry audit и payload
digest, добавляет immutable cutover receipt и не удаляет evidence. Legacy initialize,
restart или migration после cutover не могут оставить либо заново создать executable
`OPERATOR_TODO`/`TIMELINE_MAIL`; обнаружение такой строки блокирует observer startup.

**MDOS-MBO-017.** Exact authority generation, TTL, mailbox/portal scope, read flags и
zero write budget перепроверяются непосредственно до и после каждого remote IMAP или
Bitrix call. Изменение/expiry во время call делает response недоверенным: результат не
подтверждается, следующий remote call запрещён, локально фиксируется STOP/review.

## 6. Acceptance cases

| ID | Сценарий | Ожидаемый результат |
| --- | --- | --- |
| `AT-MBO-01` | Нативная почта Bitrix создала/привязала одну Activity. | Observer находит projection и сохраняет local evidence; 0 Lead/Todo/Timeline/CRM writes. |
| `AT-MBO-02` | Один и тот же singleton виден в двух poll с интервалом пять минут. | Только после второго poll local state становится RECONCILED; external writes = 0. |
| `AT-MBO-03` | Singleton изменился или исчез до истечения stability window. | Пятиминутное окно сброшено либо открыт local review; старый candidate не подтверждён. |
| `AT-MBO-04` | Нативная projection отсутствует 90 минут или кандидатов больше одного. | LOCAL_REVIEW_REQUIRED; Lead/Todo/Timeline/repair не создаются. |
| `AT-MBO-05` | Код пытается вызвать Bitrix write method или mutating IMAP operation. | Вызов блокируется до transport; локальный invariant/incident сохранён. |
| `AT-MBO-06` | Для mailbox scope ещё не назначен оператор. | Разрешённое наблюдение может продолжаться; task/call/reply/contact заблокированы до assignee, work item и permit. |
| `AT-MBO-07` | Cutover видит пять OPERATOR_TODO и пять TIMELINE_MAIL V4 operations. | Ровно 10 durable QUARANTINED, 0 dispatch; любой иной состав останавливает запуск. |
| `AT-MBO-08` | Exact poll replay или второй concurrent observer. | Один local effect; replay no-op, второй owner не получает lock. |
| `AT-MBO-09` | Предлагается включить MANGO, TenderPlan, UniSender, SMTP или outbound. | Явный STOP; 0 side effects до отдельного successor/permit/release. |
| `AT-MBO-10` | Собран `7.2.0-rc.2` без ratification record. | Manifest/release pin остаются DEFAULT_DENY, все live gates false, schedule не активирован. |
| `AT-MBO-11` | Два Subject отличаются только пробелом/tab, регистром или обрезанным хвостом. | Exact digest различается; normalization/truncation не создаёт match. |
| `AT-MBO-12` | OWNER совпал, но sender отсутствует либо COMMUNICATIONS содержит unrelated value. | Candidate не подтверждён; OWNER и unrelated COMMUNICATIONS не identity. |
| `AT-MBO-13` | Bitrix pagination вернула повторный/убывающий/malformed next или оборвалась до полного набора. | READ_UNKNOWN/LOCAL_REVIEW; singleton из partial page не принимается. |
| `AT-MBO-14` | Stable singleton впервые появился после 90-минутного deadline. | Исходная observation остаётся LOCAL_REVIEW_REQUIRED и не может стать RECONCILED автоматически. |
| `AT-MBO-15` | Cutover/legacy initialize обрабатывает V4 Todo/Timeline rows. | Phase/error audit и receipt сохранены; после initialize нет executable Todo/Timeline. |
| `AT-MBO-16` | Authority generation или TTL изменились во время remote call. | Response отброшен, следующий call не выполняется, local STOP/review сохранён. |

## 7. Условия отдельного live-read решения

До любой активации требуются exact mailbox/portal scope, read-only credentials,
независимое доказательство нативного writer ownership, подтверждённый V4 quarantine,
single-owner Windows schedule, 5m/90m offline evidence, retention/PII review, backup и
STOP/rollback rehearsal. Это решение не может одновременно включать MANGO,
TenderPlan, outbound или CRM repair.

Текущее состояние приложения:
`INCLUDED_IN_7_2_RC_NOT_RATIFIED / DEFAULT_OFF / DESIGN_ONLY`.
