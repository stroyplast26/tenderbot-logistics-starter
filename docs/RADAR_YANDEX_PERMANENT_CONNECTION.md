# Постоянное подключение Yandex Search API

Сервисный аккаунт и API-ключ создаются один раз. Ключ со scope
`yc.search-api.execute` и ролью аккаунта `search-api.webSearch.user` может иметь
неограниченный срок действия. Подключение не прекращается при завершении
отдельного поискового задания.

`radar_yandex_connection` выполняет вручную разрешённое задание через это
подключение. Первое задание — один контрольный запрос с резервом 49 копеек.
Это отдельный путь, не активация прежнего пакета из двадцати запросов.

## Постоянные данные

Доверенный каталог текущего пользователя ОС:
`.codex/local_state/TenderBot/yandex-search`. Он находится вне репозитория.
Профиль определяется средствами ОС; переменные `HOME` и `USERPROFILE` не меняют
точку доверия. Перенаправления каталогов не допускаются.

- `credential.json` хранит идентификаторы каталога, сервисного аккаунта и ключа,
  scope, отсутствие срока и секрет, зашифрованный Windows DPAPI CurrentUser.
- `connection.json` закрепляет идентичность подключения и отпечаток ключа.
  Он не содержит секрет и сам по себе не разрешает платный запрос.
- Отдельное задание закрепляет точный запрос, проверенную версию кода, локальный
  журнал, указание владельца, независимую приёмку и готовность биллинга.

Постоянные metadata подключения не имеют срока exact job. Текущий
`source yandex-prepare` создаёт неактивный draft на шесть часов, а
`retention_hours` raw response обязан быть равен ровно 24 часам. Существующий
`source yandex-activate` после code freeze и реальных evidence публикует exact
`request.json` и activation, не продлевая исходные шесть часов. Старые
job/activation не переносятся на новый release candidate. Исторический внешний
installer не поддерживается и не используется.

Секрет не помещают в Git, описание PR, чат, аргументы команд или текст задания.
Права каталога ограничивают текущим пользователем Windows и SYSTEM. DPAPI
привязан к пользователю Windows; это не переносимая резервная копия ключа.

## Поведение запуска

Сначала проверяются exact checkout, допуск задания и постоянные привязки. Затем
возвращается сохранённый результат, если он уже есть. Только для новой отправки
фиксированный DPAPI broker расшифровывает ключ, проверяется его отпечаток,
отдельно сохраняются резерв и намерение отправки, а общий HTTPS-транспорт
получает одноразовый допуск. Broker не принимает произвольный child command,
путь к другому checkout или альтернативный credential-файл.

Повторный запуск завершённого задания читает локальный результат без нового
HTTP и без нового расхода. Ошибка с неизвестным исходом сохраняет резерв;
автоматической повторной отправки нет. CLI требует действующий допуск и для
отправки, и для возврата кэша; срок хранения дополнительно ограничивает чтение
ответа. STOP запрещает только новый intent: точный сохранённый ответ остаётся
доступен без расшифровки ключа, пока действуют допуск и срок хранения. Эти сроки
не являются сроком ключа или подключения.

Cache hit не расшифровывает DPAPI и даёт `external_requests_this_run=0`. Cache
miss допускает не более одной HTTP-попытки и даёт
`external_requests_this_run=1`, в том числе при timeout, ошибке статуса или
разбора после начала HTTPS. Нативный journal обязан подтверждать то же значение.
Недоступное или противоречивое accounting переводит запуск в `UNCERTAIN` до
ручной сверки; автоматический и проверочный retry запрещены.

Текущий путь допускает одну попытку на задание и резерв 49 копеек. Новый запрос
требует отдельного задания с фактическим указанием владельца; оно использует
тот же аккаунт и ключ. Постоянного расписания или безлимитных расходов нет.
Fixed RC1 и прежние общие точки внешнего доступа сохраняют отказ.

Перед cache lookup, расшифровкой ключа и HTTP source controller добавляет
неизменяемый binding receipt: exact job, policy, connection, canonical journal
path и identity journal. После исхода отдельный accounting receipt ссылается на
hash binding receipt и фиксирует outcome, journal counters и
`external_requests_this_run`. Несогласованность этих записей fail-closed даёт
`UNCERTAIN`; удаление или перепривязка для повтора не поддерживаются.

## Команды оператора

Подготовить локальный неактивный draft через общий launcher:

```powershell
.\scripts\run_safe_lead_flow.ps1 source yandex-prepare --query "ТОЧНЫЙ НЕПЕРСОНАЛЬНЫЙ ЗАПРОС" --region "Краснодарский край" --idempotency-key "YANDEX-PREPARE-FIRST-V1" --confirm-inactive-only
```

Результат имеет состояние `PREPARED_NOT_ACTIVATED` и не является разрешением
на Yandex read. Команда создаёт только `request.draft.json`, пустой
`request.sqlite` и пустой `dispatch-claims` с шестичасовым сроком draft. Она не
читает credential и не делает HTTP, не создаёт `request.json`,
owner/reviewer/readiness evidence, retention activation или active pin.
Успешный и ошибочный JSON не раскрывают query, region, folder ID или локальные
пути. Точный replay с тем же idempotency key и теми же входами не создаёт второй
draft; изменённый replay отклоняется без перезаписи. Временные артефакты
неуспешной попытки очищаются, а опубликованный `PREPARED_NOT_ACTIVATED` draft не
продлевается, не заменяется и не активируется автоматически. Результат выдаёт
санитизированные `job_id`, `draft_sha256`, `policy_sha256`, `scope_sha256`,
`expires_at_utc`, `created`, `replayed`, явные `authority_verified=false` и
`launch_allowed=false`, а также список ещё не закрытых gates.

После подготовки всё ещё требуются code freeze, exact owner instruction,
независимый reviewer `ACCEPT` и свежая проверка billing/API/credential. Полная
схема всех top-level и nested keys, неизменяемые константы, правила времени и
ролей, проверенная canonical UTF-8/no-replace публикация и ACL admission описаны
в [точной инструкции evidence](RADAR_YANDEX_ACTIVATION_EVIDENCE.md). Файл версии
`radar-yandex-manual-activation-evidence-v1` публикуется по единственному пути,
где OS profile получен через `[Environment]::GetFolderPath('UserProfile')`, а не
через ambient `%USERPROFILE%`:

```text
[OS profile]\.codex\local_state\TenderBot\yandex-search\activation-evidence\<job_id>\<evidence_sha256>.json
```

Evidence содержит ровно семь top-level ключей: `version`, `job_id`,
`draft_sha256`, `scope_sha256`, `owner_receipt`, `independent_acceptance`,
`readiness`; exact `code_sha256` переносится целиком из draft. Он связывает
job, scope, code, connection и folder; reviewer не может быть владельцем или
автором реализации. Owner/readiness фиксируются не раньше draft, review
допускается не более чем за 24 часа до него, и все времена должны быть не позже
активации. Activator этот файл не создаёт и не исправляет. V1 не поддерживает
rotation, revocation, перезапись или автоматическую замену корневого pin, даже
после expiry.

Активировать точный draft локально, без чтения ключа и без HTTP:

```powershell
$JobId = "JOB_ID_FROM_PREPARE"
$DraftSha256 = "DRAFT_SHA256_FROM_PREPARE"
$ScopeSha256 = "SCOPE_SHA256_FROM_PREPARE"
$EvidenceSha256 = "SHA256_OF_CANONICAL_EVIDENCE"
.\scripts\run_safe_lead_flow.ps1 source yandex-activate --job-id $JobId --expected-draft-sha256 $DraftSha256 --expected-scope-sha256 $ScopeSha256 --evidence-sha256 $EvidenceSha256 --confirm-final-activation
```

Команда принимает ровно показанный порядок и строчный UUID/SHA, повторно
проверяет весь exact scope, ACL, времена и пустой journal, затем публикует
`request.json`, `retention-activation.json` и корневой pin последним. Успех
возвращает `ACTIVATED_AWAITING_EXPLICIT_RUN_ONE`, `authority_verified=true` и
`launch_allowed=false`. Это всё ещё не provider read: credential, HTTP, spend,
CRM, contact, outbox, campaign и schedule не затрагиваются. Шестичасовой срок
draft не продлевается; после его истечения нужны новый draft и новый evidence.

Проверить подготовленное задание без чтения секрета и HTTP можно только из
точного принятого checkout через общий launcher:

```powershell
$ProfileRoot = [Environment]::GetFolderPath('UserProfile')
$YandexJob = Join-Path $ProfileRoot ".codex\local_state\TenderBot\yandex-search\requests\$JobId\request.json"
.\scripts\run_safe_lead_flow.ps1 source check --source YANDEX --yandex-job "$YandexJob" --folder-id "FOLDER_ID"
```

Успешная проверка возвращает `authority_verified=true` и
`READY_FOR_EXPLICIT_CONFIRMATION`. Она открывает уже существующий journal и
обновляет только его монотонное наблюдаемое время; при этом не читает credential,
не создаёт reservation/intent и не вызывает HTTP. `authority_verified=false`
или любой fail-closed ответ не является допуском к запуску.

Только после отдельного `check` один отдельно разрешённый read выполняет тот же
launcher:

```powershell
.\scripts\run_safe_lead_flow.ps1 source run-one --source YANDEX --yandex-job "$YandexJob" --folder-id "FOLDER_ID" --confirm-one-authorized-read
```

Не запускайте `radar_yandex_connection` напрямую и не используйте внешний или
скопированный wrapper. Launcher текущего checkout проходит всю принятую цепочку
controller → Source Lab bridge → native authority/accounting → фиксированный
DPAPI broker → transport. Exact code hash задания связывает каждый элемент этой
цепочки; изменение любого из них требует нового job, activation и независимого
`ACCEPT`.

Перед bootstrap launcher удаляет ambient `YANDEX_SEARCH_API_KEY`, а несекретный
маркер для `yandex-prepare`, `yandex-activate` и `run-one` выставляет только после
успешного `-CheckOnly` и удаляет в `finally`. Проверка маркера блокирует случайный
прямой запуск, но маркер известен и не является защитой от злонамеренного
процесса того же пользователя ОС. Граница доверия такого процесса остаётся
операционной, как и для локального state и DPAPI CurrentUser.

На настроенном Windows-хосте broker при cache miss получает ключ из
фиксированного DPAPI helper через приватно захваченный `stdout` pipe, держит его
только в памяти текущего Python-процесса и передаёт непосредственно transport.
Ключ не помещается в argv, environment, журнал, JSON или Source Lab. Ссылки на
него удаляются best effort после вызова, но для неизменяемой Python-строки нельзя
обещать физическое зануление памяти. Ветка чтения сохранённого результата не
запускает helper и не расшифровывает ключ.
Успешный JSON содержит `external_requests_this_run`: `1` для HTTP-отправки и
`0` для локального replay; отдельный `journal` показывает накопленный резерв,
число попыток и их состояния без ключа или его отпечатка.
После начавшегося HTTPS безопасный error JSON также сообщает `1` и durable
`UNCERTAIN`; preflight, STOP без кэша и отказ ключа сообщают `0`.
Поддерживаемый `status` дополнительно показывает санитизированные hash binding и
accounting receipts, job ID, policy digest, journal-path digest, outcome и число
внешних попыток; query, raw response, ключ и его fingerprint туда не входят.

Draft находится в `requests/<UUID>/request.draft.json`; activator рядом
публикует `request.json`, затем обязательный per-job
`retention-activation.json`, а `request-activation.json` в корне подключения —
только последним шагом. `request.sqlite` и `dispatch-claims` остаются теми же
exact объектами. `run-one` эти файлы не создаёт, не продлевает допуск и не
подставляет автоматическое согласие.

Для задач нового activator per-job retention pin обязателен. Если он существует,
но повреждён или не совпадает с job, maintenance завершается fail-closed и не
переходит к root/archive. Корневая `request-activation.json` или её архив
`request-activation.<archive>.json` могут служить fallback только для старых
задач при физическом отсутствии per-job файла. Эта привязка позволяет проверить
и очистить старый journal после замены активного job, не перепривязывая его к
новой activation и не продлевая просроченный допуск. Архивные журналы и claims
сохраняются при установке следующего задания.

Проверить журнал и удалить только просроченный raw response через тот же launcher:

```powershell
.\scripts\run_safe_lead_flow.ps1 source yandex-status --job-id "01234567-89ab-4cde-8fab-0123456789ab"
.\scripts\run_safe_lead_flow.ps1 source yandex-purge --job-id "01234567-89ab-4cde-8fab-0123456789ab" --confirm-expired-raw-purge
```

Оператор передаёт только `job_id` в каноническом строчном UUID-формате.
Путь `yandex-search\requests\<UUID>\request.json` вычисляется самой командой из
доверенного OS state текущего пользователя. Произвольные job paths и SQLite-файлы не
принимаются. Exact job, journal identity и сохранённая per-job
retention-activation должны совпасть; иначе команда завершается fail-closed.

`yandex-status` сообщает `retained_responses`, `purge_due_count`,
`next_purge_at_utc` и одно из состояний `RAW_RETENTION_PENDING`, `RAW_PURGE_DUE` или
`NO_RAW_RESPONSE_RETAINED`. `yandex-purge` требует явное
`--confirm-expired-raw-purge`, до `retain_until_utc` ничего не удаляет, а с момента
наступления срока удаляет только raw payload и correlation headers. Повторный
запуск идемпотентен; hashes, accounting и terminal state сохраняются.
Обе команды не читают credential, не обращаются к provider, не продлевают
job/activation и не выводят query, response, correlation headers или путь. Для
защиты от отката часов они могут только продвинуть монотонное `last_at_utc`
journal.

## Результат поиска

Ответ Яндекса — материал для исследования. Поисковая ссылка и snippet ещё не
подтверждают объект, стадию строительства или его участников. Ответ не создаёт
запись CRM и не запускает рассылку. Для карточки объекта проверяют первичный
источник и используют существующий ручной импорт Radar.

Состояние счётчика и резерва в локальном журнале не заменяет детализацию
биллинга. [Тариф Yandex Search API](https://aistudio.yandex.ru/ru/docs/search-api/pricing)
на 9 сентября 2026 года: 488 ₽ за 1 000 дневных синхронных запросов и 366 ₽ за
1 000 ночных. Резерв 49 копеек округляет дневной тариф вверх; при изменении
тарифа лимит требует пересмотра.

Journal хранится только по заранее принятому каноническому пути с ACL для
текущего оператора ОС и SYSTEM. Raw payload и correlation headers очищаются
штатным `purge` сразу после 24-часового `retain_until_utc`; резервные копии и
копии уровня ОС подчиняются тому же сроку. Это отдельный контроль от постоянных
metadata подключения.

Локальная привязка и журнал не защищают от злонамеренной подмены всего состояния
процессом с правами того же пользователя ОС. Удаление журнала/claims и возврат
старой копии не являются допустимым способом повторить запрос.
