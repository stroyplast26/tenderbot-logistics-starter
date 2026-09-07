# APP-MDOS-OPERATOR-TELEPHONY — оператор и телефония

**Версия приложения:** `1.1.0`  
**Статус:** `INCLUDED_IN_7_2_RC_NOT_RATIFIED`  
**Кандидат версии:** `7.2.0-rc.2`  
**Нормативная сила:** exact digest включён в successor manifest; полномочия и live-
разрешение отсутствуют до ратификации владельцами.

Этот проект приложения фиксирует предлагаемую роль человека, Bitrix24 и телефонии в
Lead Factory. Он не включает MANGO, Bitrix-write, запись разговоров, внешний AI или
контакт с клиентом и не является `PermitDecision`.

## 1. Роль человека

**MDOS-OPT-001.** Оператор является обязательным участником коммерческого контура, а
не временным ручным обходом. Система готовит приоритет, контекст, сценарий и следующий
шаг; оператор ведёт разговор и подтверждает наблюдаемый результат.

**MDOS-OPT-002.** AI, телефония, транскрипция и правила МОГУТ создать только draft,
claim, reminder или review. Они НЕ МОГУТ подтвердить намерение клиента, обещание,
`GoldAcceptance`, suppression, стадию, заказ, оплату или итог звонка вместо назначенного
человека.

**MDOS-OPT-003.** До любого контакта существует `OperatorWorkItem` с назначенным
actor, opportunity/demand scope, целью, разрешённым каналом, due time, evidence,
policy/permit reference и stop conditions. Открытая задача не считается совершённым
действием или коммерческим результатом.

**MDOS-OPT-004.** Рабочее место оператора — Bitrix24. Каноническая append-only история,
версии решений, idempotency и reconciliation остаются в локальном ledger Lead Factory.

**MDOS-OPT-005.** Read-only наблюдение нативной почты Bitrix не требует заранее
назначенного оператора и не создаёт `OperatorWorkItem`. Назначение exact active actor
может быть отложено только на фазе observation; до звонка, ответа, исходящего сообщения,
CRM task или любого контакта требования `MDOS-OPT-003` обязательны и fail-closed.

## 2. Разделение владения

**MDOS-TEL-001.** При нативной интеграции MANGO ↔ Bitrix ownership разделяется:

- MANGO/Bitrix native connector владеет call, нативной Activity, recording и vendor
  transcript;
- Lead Factory Integration Worker владеет только `LF_*` correlation/status,
  подтверждённым человеком структурированным summary/next action и reconciliation;
- оператор подтверждает или исправляет коммерческую интерпретацию;
- два writer-а не изменяют одно поле и не создают одну сущность.

**MDOS-TEL-002.** На один стабильный provider call/conversation создаётся не более
одной канонической call session и одной нативной CRM Activity. Повтор доставки создаёт
новый receipt, но не второй business effect.

**MDOS-TEL-003.** Связь звонка с contact/opportunity/task не определяется только
совпадением телефона или близостью времени. Неоднозначность создаёт review; выбор
фиксирует оператор с immutable candidate snapshot.

**MDOS-TEL-004.** Transfer и несколько recording segments принадлежат одной session
только при явном provider conversation/entry ID либо подтверждённой transfer-связи.
Позднее событие не возвращает terminal call в состояние `IN_PROGRESS`.

## 3. Evidence и данные разговора

**MDOS-TEL-005.** Локальный event ledger хранит только стабильные provider/CRM IDs,
timestamps, schema/revision, content digest, opaque evidence reference и
структурированные коды. Сырой звук, сырой transcript и временный/signed recording URL
в event payload, логах и ошибках запрещены.

**MDOS-TEL-006.** Recording и transcript имеют отдельные retention, access,
purpose/legal basis, consent/notice status и audit. Наличие записи в MANGO или Bitrix
не даёт Lead Factory автоматического права скачать, хранить или передать её дальше.

**MDOS-TEL-007.** Текущий внешний AI gateway не допускается для сырого transcript,
содержащего персональные или конфиденциальные данные. До отдельного data-flow permit и
проверенного processor contract разрешены deterministic/manual обработка, синтетические
fixtures либо отдельно утверждённая локальная модель.

**MDOS-TEL-008.** Если уведомление о записи или иное требуемое основание невозможно
доказать, результат создаёт `RECORDING_NOTICE_REVIEW`; автоматическая обработка записи
останавливается.

## 4. Подтверждение результата

**MDOS-OPR-001.** `OperatorAdjudication` содержит как минимум:

- stable call session и Bitrix Activity IDs;
- task/opportunity и назначенного operator actor;
- монотонную `confirmation_version`;
- technical и commercial disposition;
- next action, owner и due time либо terminal reason;
- recording notice status;
- ссылки на использованный draft/evidence и review requests.

**MDOS-OPR-002.** Подтвердить результат может только actor, которому принадлежит
связанная задача. Exact replay является no-op; другая полезная нагрузка с тем же
idempotency/version key создаёт conflict.

**MDOS-OPR-003.** Если указан следующий шаг или требуется Gold/suppression/complaint/
recording review, рабочая задача остаётся активной до отдельного подтверждения review
или выполнения next action. Terminal задача не открывается повторно скрытым retry.

**MDOS-OPR-004.** `QUALIFIED_FOR_GOLD_REVIEW` создаёт только review request.
`DO_NOT_CONTACT` создаёт только suppression review. Канонические Gold и suppression
пишут их специализированные владельцы после самостоятельной проверки.

**MDOS-OPR-005.** Unknown внешний write outcome переводится в `UNCERTAIN/REVIEW` и
проходит read/reconciliation. Слепой повтор `create` запрещён.

## 5. Минимальные логические записи

До machine schemas этот раздел является проектом семантики, а не разрешением на
произвольные JSON payload.

| Запись | Назначение | Канонические ограничения |
| --- | --- | --- |
| `OperatorWorkItem` | Работа человека до коммерческого исхода | actor, scope, SLA, permit, next action, version |
| `CallInteraction` | Стабильная session и legs | provider identity, direction, times, state, dedupe |
| `CallEvidence` | Recording/transcript metadata | digest/ref/revision/retention; no raw/temporary URL |
| `AnalysisDraft` | Машинное предложение | model/prompt/input digests/confidence; non-authoritative |
| `OperatorAdjudication` | Подтверждённый итог | assigned actor, version, dispositions, next action/reviews |
| `TelephonyPilot` | Ограниченный canary | allowlist, cap, WIP, TTL, owner, STOP evidence |

## 6. Технический пилот

**MDOS-PIL-001.** Первый live-шаг допускается только как отдельно ратифицированный
`TECHNICAL_TELEPHONY_PILOT_V1`: 24 часа, сначала один и не более пяти whitelisted
внутренних/тестовых звонков, `WIP=1`, один портал/CRM scope, один оператор и один
контролёр.

**MDOS-PIL-002.** В пилоте запрещены реальные клиентские звонки, auto-dial, внешний
AI, raw download в Lead Factory, Unisender/почтовые побочные эффекты, TenderPlan и
автоматические Gold/stage/payment/suppression/promise writes.

**MDOS-PIL-003.** После первого звонка требуется ручной checkpoint. Любой дубль,
неверная CRM-привязка, ambiguous/unknown outcome, raw/secret leak, превышение cap/WIP
или недоступность STOP завершает пилот и отзывает permit.

## 7. Acceptance cases

| ID | Сценарий | Ожидаемый результат |
| --- | --- | --- |
| `AT-OPT-01` | Один provider event доставлен повторно. | Один call effect; replay no-op. |
| `AT-OPT-02` | Recording пришёл раньше call metadata. | Evidence сохраняется unbound и позже однозначно связывается. |
| `AT-OPT-03` | Transfer создал две legs и две recordings. | Одна session, все segments сохранены отдельно, без дубля Activity. |
| `AT-OPT-04` | Один Bitrix call/activity ID предложен двум sessions. | Вторая связь отклонена conflict-ом. |
| `AT-OPT-05` | Телефон соответствует нескольким CRM-кандидатам. | REVIEW; автоматической привязки нет. |
| `AT-OPT-06` | AI недоступен или не разрешён. | Оператор подтверждает вручную; звонок не теряется. |
| `AT-OPT-07` | Draft не соответствует persisted transcript digest. | Подтверждение draft блокируется как stale/conflict. |
| `AT-OPT-08` | Оператор выбрал callback. | Work item остаётся активным с owner/due time. |
| `AT-OPT-09` | Оператор запросил Gold. | Только Gold review; canonical Gold не меняется. |
| `AT-OPT-10` | Клиент потребовал не связываться. | Только suppression review; повторный контакт не планируется. |
| `AT-OPT-11` | Crash после event, до обновления задачи. | Restart/reconciliation достраивает проекцию без второго effect. |
| `AT-OPT-12` | Binding повторён после terminal task. | Safe no-op; terminal задача не открывается. |
| `AT-OPT-13` | Signed recording URL попал во входной payload. | URL отклонён до canonical event/log. |
| `AT-OPT-14` | Не назначенный actor подтверждает звонок. | Отказ; состояние не меняется. |
| `AT-OPT-15` | Mail observer видит inbound, но оператор ещё не назначен. | Только local observation; task/call/reply/contact запрещены до assignee, work item и permit. |

## 8. Условия ратификации

Приложение может стать нормативным только после одновременного выполнения условий:

1. создана новая semver-версия полного contract package и пересчитан exact manifest
   digest;
2. утверждены схемы перечисленных записей и traceability requirements;
3. назначены владелец операционного контура, оператор, контролёр и владельцы данных;
4. утверждены notice/consent/retention и processor правила для конкретной телефонии;
5. offline acceptance имеет ссылки на test/evidence, а все live gates остаются false;
6. отдельно ратифицирован pilot scope и выдан machine-verifiable permit;
7. после пилота permit закрыт, evidence сохранён, а расширение scope рассматривается
   отдельным решением.

До ратификации состояние приложения:
`INCLUDED_IN_7_2_RC_NOT_RATIFIED / DEFAULT_OFF / LOCAL_SHADOW_ONLY`.
