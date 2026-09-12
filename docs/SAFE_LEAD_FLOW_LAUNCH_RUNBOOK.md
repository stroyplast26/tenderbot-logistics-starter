# Безопасный запуск первого Lead Flow

Этот runbook относится только к ручному первому срезу source discovery и
локальному Gold quarantine. Он не включает рассылку, контакт, CRM/outbox,
рекламную кампанию, расписание или автоматический повтор.

Операционный предел первого месяца — **не более 30 000 ₽ суммарно**. Источники
подключаются строго по одному: сначала контрольный срез, ручная проверка качества
в Source Lab и подтверждение добавочной ценности, затем отдельное решение о
следующем источнике. Наличие общего бюджета не разрешает пакетную закупку,
параллельные live-запуски или автоматическое увеличение лимита.

Текущий код жёстко ограничивает первый Yandex job одной попыткой с резервом
49 копеек, но ещё не ведёт единый машинный месячный лимит по всем платным
источникам. До второго платного источника нужен общий spend-ledger; пока предел
30 000 ₽ контролируется владельцем по журналам источников и детализации биллинга.

`plan`, `status`, `check`, `yandex-prepare`, `yandex-activate`, `yandex-status`,
`yandex-purge`, `review-list`, `review-decide` и `review-close` всегда локальны.
`yandex-prepare` создаёт только неактивный draft, `yandex-activate` локально
публикует exact request и его pins, а `yandex-purge` удаляет только просроченный
raw response после отдельного явного подтверждения. Ни одна из этих команд не
читает credential и не делает HTTP. В рамках поддерживаемого safe flow обращение к провайдеру
разрешено только через `source run-one` с отдельным явным подтверждением; после
него всё равно повторно срабатывает нативная authority-проверка Yandex или
TenderPlan. Без неё запрос не отправляется. В репозитории остаётся отдельный
исторический owner-pilot transport, но он не является частью этого flow и сейчас
не имеет действующего activation; его нельзя использовать вместо launcher.

## 1. Канонический Windows runtime

Нужен ровно CPython 3.11.9 64-bit. Bootstrap закрепляет `pip==26.2.1`,
`setuptools==65.5.0` и полный набор версий из
`requirements-dev-win-py311.lock.txt`.

Первичное создание `.venv` выполняется из корня репозитория:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap_python_runtime.ps1
```

Эта первичная команда обращается к публичному PyPI. Версии закреплены, но
artifact hash-lock пока отсутствует. Это явный supply-chain GAP: до появления
проверенного hash-lock и wheel provenance этот bootstrap нельзя называть
криптографически воспроизводимым.

Перед каждым запуском Lead Flow выполняйте только локальную проверку:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap_python_runtime.ps1 -CheckOnly
```

Дальше используйте только `scripts/run_safe_lead_flow.ps1`. Он сам повторяет
`-CheckOnly`, запускает исключительно `.venv\Scripts\python.exe` текущего
репозитория и не использует fallback Python, shell eval или строковую сборку
команд.

Launcher удаляет ambient `YANDEX_SEARCH_API_KEY` до bootstrap и child process.
После успешного bootstrap он кратковременно выставляет известный несекретный
маркер только для `source run-one` и локальных mutating
`source yandex-prepare` и `source yandex-activate`; Python entry проверяет его до изменения state, а
accounted runner — до broker и provider. Это защита от случайного прямого
вызова и ошибки bootstrap-пути, а не криптографическая capability и не защита
от злонамеренного процесса с правами того же пользователя ОС.

Запуск разрешён только из **точного текущего checkout**, который прошёл
независимую приёмку как единый release candidate. Не используйте копию launcher,
старый worktree, внешний wrapper с зафиксированным чужим путём или прямой вызов
внутреннего Python-модуля. После любого изменения исполняемой цепочки требуется
новая exact-приёмка до provider read.

## 2. Полностью локальные source-команды

План и состояние:

```powershell
.\scripts\run_safe_lead_flow.ps1 source plan
.\scripts\run_safe_lead_flow.ps1 source status
```

Создать неактивный Yandex draft для дальнейшего независимого согласования:

```powershell
.\scripts\run_safe_lead_flow.ps1 source yandex-prepare --query "ТОЧНЫЙ НЕПЕРСОНАЛЬНЫЙ ЗАПРОС" --region "Краснодарский край" --idempotency-key "YANDEX-PREPARE-FIRST-V1" --confirm-inactive-only
```

Это локальная подготовка со статусом `PREPARED_NOT_ACTIVATED`, а не job с
live-authority. Она создаёт только `request.draft.json`, пустой
`request.sqlite` и пустой `dispatch-claims` с шестичасовым сроком draft.
Команда не читает credential, не обращается к Yandex, не создаёт
`request.json`, owner/reviewer/readiness evidence или activation и не даёт права
выполнить `check` либо `run-one`. Один idempotency key навсегда связывается с
одинаковыми query и region: точный повтор возвращает тот же draft без второго
создания, а изменённый повтор завершается fail-closed. Незавершённые временные
артефакты собственной неудачной попытки удаляются; опубликованный
`PREPARED_NOT_ACTIVATED` draft автоматически не заменяется и не становится
активным.

Успешный JSON не повторяет query, region, folder ID или локальные пути и явно
содержит отключённые external read, CRM, contact, outbox, campaign и schedule.
Даже exit code `0` означает только успешную локальную подготовку. Для сверки
точного draft результат содержит только безопасные `job_id`, `draft_sha256`,
`policy_sha256`, `scope_sha256`, `expires_at_utc`, `created`, `replayed`, явные
`authority_verified=false` и `launch_allowed=false`, а также список незакрытых
gates.

После code freeze нужны три реальные привязки: указание владельца на exact
scope, независимый `ACCEPT` exact кода и свежая проверка billing/API/credential.
Полная схема без необъявленных ключей, правила времени и ролей, проверенная
канонизация UTF-8, no-replace публикация и read-only ACL admission находятся в
[точной инструкции evidence](RADAR_YANDEX_ACTIVATION_EVIDENCE.md). Файл версии
`radar-yandex-manual-activation-evidence-v1` находится только по
content-addressed пути, вычисленному от Windows OS profile через
`[Environment]::GetFolderPath('UserProfile')`, а не через ambient
`%USERPROFILE%`:

```text
[OS profile]\.codex\local_state\TenderBot\yandex-search\activation-evidence\<job_id>\<evidence_sha256>.json
```

Верхний уровень содержит ровно `version`, `job_id`, `draft_sha256`,
`scope_sha256`, `owner_receipt`, `independent_acceptance` и `readiness`.
Вложенные exact-ключи и неизменяемые константы перечислены в инструкции;
`code_sha256` целиком копируется из exact draft. Reviewer должен отличаться от
владельца и авторов реализации. Owner/readiness не могут быть старше draft,
review может предшествовать draft не более чем на 24 часа; все три времени не
могут быть позже активации. Activator evidence не создаёт и не исправляет.
V1 не поддерживает rotation, revocation, перезапись или автоматическую замену
корневого pin, даже после expiry.

Сначала разместите реальные receipts в fixed
`activation-candidates\<job_id>\candidate.json` и выполните штатную публикацию
по [инструкции evidence](RADAR_YANDEX_ACTIVATION_EVIDENCE.md):

```powershell
.\scripts\run_safe_lead_flow.ps1 source yandex-publish-evidence --job-id $JobId --expected-draft-sha256 $DraftSha256 --expected-scope-sha256 $ScopeSha256 --expected-candidate-sha256 $CandidateSha256 --confirm-local-publication
```

`EVIDENCE_PUBLISHED_AWAITING_ACTIVATION` означает только локальную проверку и
публикацию (`authority_verified=false`, `launch_allowed=false`). Возьмите
`evidence_sha256` из результата; публикатор не создаёт подтверждения за
owner/reviewer, не проверяет billing через сеть и не запускает активацию.

Только после проверки реального evidence выполните локальную активацию одной
точной задачи:

```powershell
$JobId = "JOB_ID_FROM_PREPARE"
$DraftSha256 = "DRAFT_SHA256_FROM_PREPARE"
$ScopeSha256 = "SCOPE_SHA256_FROM_PREPARE"
$EvidenceSha256 = "SHA256_OF_CANONICAL_EVIDENCE"
.\scripts\run_safe_lead_flow.ps1 source yandex-activate --job-id $JobId --expected-draft-sha256 $DraftSha256 --expected-scope-sha256 $ScopeSha256 --evidence-sha256 $EvidenceSha256 --confirm-final-activation
```

Launcher принимает после `yandex-activate` ровно девять токенов в показанном
порядке; UUID и SHA должны быть строчными. Команда повторно проверяет draft,
scope, code, connection, evidence, времена, ACL и пустой journal, затем публикует
`request.json`, per-job `retention-activation.json` и только последним шагом
корневой `request-activation.json`. Она не читает credential, не делает provider
read, не тратит деньги и не включает CRM/contact/outbox/campaign/schedule.
Успех — `ACTIVATED_AWAITING_EXPLICIT_RUN_ONE` с `authority_verified=true`, но
`launch_allowed=false`: платный read всё ещё требует отдельную команду раздела 3.
Исходный шестичасовой срок draft не продлевается; после истечения нужно создать
новый draft и новый exact evidence. Точный повтор активации идемпотентен, иной
job, hash или evidence завершается fail-closed без замены опубликованных файлов.

Локальная проверка конкретного источника:

```powershell
$ProfileRoot = [Environment]::GetFolderPath('UserProfile')
$YandexJob = Join-Path $ProfileRoot ".codex\local_state\TenderBot\yandex-search\requests\$JobId\request.json"
.\scripts\run_safe_lead_flow.ps1 source check --source YANDEX --yandex-job "$YandexJob" --folder-id "FOLDER_ID"
.\scripts\run_safe_lead_flow.ps1 source check --source TENDERPLAN --query "алюминиевые конструкции"
.\scripts\run_safe_lead_flow.ps1 source check --source SABY
.\scripts\run_safe_lead_flow.ps1 source check --source DOMRF
.\scripts\run_safe_lead_flow.ps1 source check --source KONTUR
```

Для Yandex эта команда проходит нативную проверку exact connection, job,
activation, code hashes, owner/reviewer/readiness receipts и journal. Она не
читает ключ и не делает HTTP. Успех содержит `authority_verified=true` и
`READY_FOR_EXPLICIT_CONFIRMATION`; любой отсутствующий, просроченный или
несогласованный элемент даёт санитизированный fail-closed ответ и exit code `2`.

Для Saby, DOM.RF и Kontur ожидаемое состояние сейчас —
`BLOCKED_OFFLINE_CONTRACT`, а exit code — `2`. TenderPlan/Yandex `check`
не вызывает provider read.

Для TenderPlan `check` проверяет существующую регистрацию и нативную очередь
без чтения credential, создания SQLite-файла или записи в журнал. Можно передать
`--tenderplan-registration` и `--tenderplan-store`; путь очереди должен совпадать
с каноническим путём текущего native intake и сохранённой привязкой хранилища.
Отсутствующая или повреждённая регистрация даёт `BLOCKED_TENDERPLAN_REGISTRATION`,
чужой путь — `BLOCKED_TENDERPLAN_STORE_LOCATION`, отсутствующая или некорректная
очередь — `BLOCKED_TENDERPLAN_STORE_RECONCILIATION`. Незавершённые native-попытки
дают `BLOCKED_TENDERPLAN_UNCERTAIN` либо `BLOCKED_TENDERPLAN_IN_FLIGHT`;
истечение срока INTENT само по себе не снимает блокировку. Общий STOP/WIP
проверяется первым и может скрывать эти более узкие причины.

Успех TenderPlan означает только `READY_FOR_SEPARATE_AUTHORITY_CHECK` при
`authority_verified=false`: доступность credential/API и разрешение внешнего
вызова ещё не доказаны. `run-one` выполняет ту же проверку до общего reserve и
затем требует уже существующую native queue. Если очередь исчезла или стала
некорректной между проверкой и native run, новая история не создаётся; сбой
после общего reserve сохраняет `UNCERTAIN` и требует сверки. Не использовать
`run-one` как диагностическую команду и не восстанавливать очередь во время
работы команды. Прежний standalone native runner сохраняет отдельную процедуру
первичной подготовки; она не является способом обойти этот запрет.

Портфель первого этапа разделён следующим образом:

- Мегион — только локальный импорт двух exact-публикаций из allowlist, без сети;
- Yandex — не более одного отдельно разрешённого read по exact job;
- TenderPlan — отдельный read-only контур со своей регистрацией, authority,
  журналом и очередью проверки; Yandex authority его не разрешает;
- Saby, DOM.RF и Kontur — STOP до договоров, подтверждённых условий использования,
  цены и отдельной приёмки коннектора.

Переход к следующему источнику разрешается только после ручной оценки текущего:
доля пригодных карточек, отсутствие ложных фактов, стоимость одного проверенного
объекта и фактическая польза для менеджера. DOM.RF не является обязательным для
первого потока и не покупается только ради расширения охвата.

`status` и `check` не создают controller state database. Yandex `check` открывает
только уже существующий exact native journal и обновляет его монотонное
наблюдаемое время для защиты от отката часов; job, activation, credential и
provider response он не создаёт. Все source-команды намеренно
используют только фиксированный canonical state
`state\lead_factory\source_discovery_control.sqlite3`; произвольный
`--state-path` через launcher не допускается.

Локальный Yandex review также работает только с каноническими базами Source
Lab и source controller; произвольные пути через launcher не принимаются.
Контроллер `source-discovery-control-v4` связывает batch с хешем точного
канонического пути Source Lab. Копия или перенос controller/Source Lab в другой
каталог не может закрыть исходный batch.

Состояние и обязательная очистка raw response для одного канонического job:

```powershell
.\scripts\run_safe_lead_flow.ps1 source yandex-status --job-id "01234567-89ab-4cde-8fab-0123456789ab"
.\scripts\run_safe_lead_flow.ps1 source yandex-purge --job-id "01234567-89ab-4cde-8fab-0123456789ab" --confirm-expired-raw-purge
```

Вместо пути оператор передаёт только `job_id` в каноническом строчном
UUID-формате. Команда сама вычисляет путь
`yandex-search\requests\<UUID>\request.json` из доверенного OS state текущего
пользователя; произвольный job path или SQLite-файл передать нельзя.
Затем она проверяет exact job, journal и его физическую identity, а также
сохранённую retention-привязку именно этого job. Основное место для неё —
`requests/<UUID>/retention-activation.json`. Для задач нового activator эта
копия обязательна и имеет приоритет: если файл существует, но повреждён или не
совпадает, fallback запрещён. Корневая `request-activation.json` или её архив
`request-activation.<archive>.json` допустимы только для старых задач при
физическом отсутствии per-job копии. Во всех случаях exact hashes и срок должны
совпасть с job; просроченная привязка не продлевается и используется только для
обязательной privacy-очистки.

`yandex-status` показывает `retained_responses`, `purge_due_count`,
`next_purge_at_utc` и состояние `RAW_RETENTION_PENDING`, `RAW_PURGE_DUE` или
`NO_RAW_RESPONSE_RETAINED`. `yandex-purge` требует точный confirmation,
удаляет только raw payload и correlation headers с наступившим
`retain_until_utc` и идемпотентен: до срока ничего не удаляет, после повтора
не повреждает accounting. Hashes, расход и terminal state сохраняются.
Обе команды не читают credential, не обращаются к provider и не
выводят query, job path, raw response или correlation headers. Для защиты от
отката часов обе могут только продвинуть монотонное `last_at_utc` journal; это
не продлевает job или activation.
Просмотр exact batch требует `batch_receipt_sha256` из результата
соответствующего `source run-one`:

```powershell
.\scripts\run_safe_lead_flow.ps1 source review-list --attempt-id "ATTEMPT_ID" --expected-receipt-sha256 "64_HEX_FROM_RUN_ONE"
```

Решение по каждому найденному source-link добавляется отдельно и
идемпотентно. Передавайте неизменённые receipt hash и `state_digest` самого
элемента из `review-list`; это защита от решения по устаревшему состоянию:

```powershell
.\scripts\run_safe_lead_flow.ps1 source review-decide --attempt-id "ATTEMPT_ID" --expected-receipt-sha256 "64_HEX_FROM_RUN_ONE" --review-id "REVIEW_ID" --expected-state-digest "64_HEX_FROM_REVIEW_LIST" --reviewer "OPAQUE_REVIEWER_ID" --decision REJECT --reason "NOT_RELEVANT" --evidence-ref "evidence://local-review/REVIEW_ID" --idempotency-key "YANDEX-DECISION-REVIEW_ID-V1"
```

Один `idempotency-key` навсегда связывается с неизменяемым намерением решения:
decision, reviewer, reason, evidence, receipt, review и lease. Повтор после
сбоя с тем же намерением безопасно завершается без второго решения; попытка
использовать тот же key для другого решения или evidence завершается
конфликтом, даже если item уже был reclaimed и получил новый state digest.
Если сбой произошёл после claim и его lease успела истечь, сначала снова
выполните `review-list`, затем повторите то же намерение и тот же key с новым
`state_digest`: старый CAS digest намеренно завершается fail-closed.

Допустимые решения: `APPROVE`, `REJECT`, `NEEDS_RESEARCH`.
`APPROVE` означает только то, что человек признал локально сохранённую ссылку
релевантной для дальнейшего исследования. Это **не** квалифицированный лид,
не promotion permit, не разрешение на CRM/outbox и не разрешение на контакт
или рассылку. `NEEDS_RESEARCH` оставляет batch незавершённым. `HOLD` намеренно
не принимается: базовая queue считает его необратимо resolved, тогда как
контроллер не имеет права закрыть по нему Yandex batch.

Эти команды не читают провайдера и не пишут CRM, outbox или контакт. Для
локальных review-команд launcher принимает только обязательные именованные
аргументы и безопасную ASCII-грамматику без пробелов, кавычек, backtick и `$`:
ID, reviewer/actor и idempotency key — ASCII tokens; reason — верхнерегистровый
код; digest — 64 lowercase hex; evidence ref — URI. Idempotency key ограничен
128 символами. Небезопасные символы можно
percent-encode только внутри evidence URI; свободный текст причины храните в
связанном evidence artifact, а в `--reason` передавайте его короткий код. Не
используйте в аргументах секреты или персональные данные. Это token-only
контракт, а не обещание byte-preservation произвольного текста в Windows
PowerShell 5.1. Вывод
`review-list` содержит только публичную ссылку, её evidence semantics,
служебные ID/digests и состояние review; query, title, snippet, token и raw
provider response в него не включаются. В Source Lab/controller projection
сохраняется только HTTPS URL без userinfo, query string и fragment; ссылка с
любым из этих компонентов туда не записывается и не отражается в review-list
или сообщении об ошибке. На controller boundary такой hit безопасно исключается
из review batch; ответ содержит только `discarded_hit_count`. Если пригодных
ссылок не осталось, attempt завершается без backpressure как
`COMPLETE_NO_RESULTS` с более точной классификацией
`NO_SAFE_REVIEWABLE_RESULTS`, а не превращается в постоянный `UNCERTAIN`.
Все публичные операции Yandex Source Lab bridge при обычной программной ошибке
`Exception`, а также controller boundary `run_source_discovery_once` при любом
перехваченном отказе возвращают только код из закрытого allowlist: исходное
исключение, его `context/cause`, входные пути, query/title/snippet и поля решения
не остаются достижимыми через production traceback. Самостоятельный bridge-вызов
намеренно не преобразует управляющие `KeyboardInterrupt`, `SystemExit` и
`GeneratorExit`; поддерживаемый `run-one` закрывает и этот внешний boundary.
Нельзя заменять boundaries прямым вызовом внутренних `_..._core` функций или
логированием внутренних исключений. Для остальных локальных controller-команд
действует более узкий контракт: не передавайте им секреты или персональные
данные и не сериализуйте traceback.

Это не означает отсутствие raw storage во всём нативном Yandex-контуре: до
bridge `radar_yandex_journal` сохраняет raw provider response в своём локальном
attempt journal до `retain_until_utc`. Хранение raw response задаётся
`retention_hours=24` — меньшее или большее значение не принимается. Окно
действия exact job может быть короче, но не превышает 24 часа. До live-read
отдельно утвердите канонический journal path, ограничьте
ACL текущим оператором ОС и SYSTEM и назначьте штатный `purge` сразу после
`retain_until_utc`. Purge удаляет payload и correlation headers; резервные копии
и копии уровня ОС должны подчиняться тому же сроку. Source Lab minimization не
заменяет эту privacy-проверку.

## 3. Один отдельно разрешённый provider read

Следующие команды уже не являются offline-проверкой. Они допускаются только
после проверки точного job/registration, учётной записи, условий использования
и лимита стоимости.

Постоянные metadata подключения Yandex — идентичность каталога, сервисного
аккаунта, ключа и его fingerprint без секрета — живут отдельно от разового
exact job. Они не имеют 24-часового срока задания и сами по себе ничего не
разрешают. Exact job и его activation создаются заново **после последнего
изменения кода**, действуют не более 24 часов и закрепляют указание владельца,
лимит, текущий checkout и независимый `ACCEPT`. Исторический внешний installer
создавал шестичасовое окно, но сейчас он не поддерживается и не используется;
это не меняет обязательное 24-часовое raw-retention.

Code hash задания охватывает всю цепочку до сети: launcher, preparer, activator,
activation ACL helper, controller, Source Lab bridge, нативные Yandex
authority/accounting/transport и фиксированный DPAPI broker. Нельзя принять
только transport, а затем заменить broker, launcher, activator или controller.
Любое изменение одного из этих файлов отзывает старые job, activation и
acceptance; требуется новый exact-комплект.

Yandex:

```powershell
.\scripts\run_safe_lead_flow.ps1 source run-one --source YANDEX --yandex-job "$YandexJob" --folder-id "FOLDER_ID" --confirm-one-authorized-read
```

TenderPlan:

```powershell
.\scripts\run_safe_lead_flow.ps1 source run-one --source TENDERPLAN --query "алюминиевые конструкции" --tenderplan-registration "C:\ABSOLUTE\verified-registration.json" --confirm-one-authorized-read
```

Provider read может быть тарифицируемым. `campaign_spend_enabled=false`
означает только отсутствие рекламной кампании; это не обещание нулевой цены
API или подписки. Перед Yandex-run нужно отдельно проверить native accounting
и разрешённый cost cap. Новый внешний вызов нельзя делать ради такой проверки.

Секрет получает только фиксированный DPAPI broker и только после того, как
нативная authority-проверка завершена и подтверждён cache miss. Cache hit
возвращается локально: broker не расшифровывает ключ,
`external_requests_this_run=0`. Cache miss допускает не более одной попытки
HTTP, после которой `external_requests_this_run=1`, даже если получены timeout,
ошибка статуса или ошибка разбора. Секрет не выводится в пользовательский
stdout/stderr, не сериализуется в controller/Source Lab и не передаётся через
argv или environment: фиксированный
DPAPI helper возвращает его в приватно захваченный `stdout` pipe, после чего ключ
существует только в памяти текущего Python-процесса до передачи transport.
Ссылки удаляются best effort, но физическое зануление неизменяемой Python-строки
не гарантируется.

Controller принимает результат только вместе с нативным accounting и состоянием
durable journal. Поле `external_requests_this_run` и journal должны согласованно
доказывать ровно `0` или `1` внешний запрос. Отсутствие accounting, невозможное
значение, расхождение с journal или сбой после начала HTTPS переводят попытку в
`UNCERTAIN`. Это постоянный STOP: требуется ручная сверка controller, Source Lab,
нативного journal и биллинга; автоматического или «проверочного» повтора нет.

До cache lookup, расшифровки ключа и HTTP controller неизменяемо записывает
binding receipt с точными digest job, policy, connection, canonical journal path
и identity самого journal. После результата он добавляет accounting receipt,
который включает hash binding receipt, outcome, journal counters и значение
`external_requests_this_run`. Поддерживаемый `status` показывает только
санитизированные идентификаторы и digest этих записей, чтобы оператор мог сверить
точную попытку без ключа, query или raw response.

Перед provider read команда локально создаёт либо проверяет schema 17 Source
Lab и обе integrity-цепочки; corrupt, future-schema или недоступная база
останавливает команду до обращения к Яндексу. Проверка повторяется после
durable reservation непосредственно перед provider boundary. На всём интервале
`source run-one` запрещены backup restore, копирование, замена и ручное изменение
controller/Source Lab SQLite-файлов; штатное восстановление выполняется только
после завершения команды. Это обязательный operational invariant: внешняя
утилита копирования не обязана соблюдать блокировки SQLite. Обнаруженная между
проверками замена даёт fail-closed reconciliation/`UNCERTAIN` и ноль provider
reads; вмешательство после последней проверки считается нарушением процедуры и
требует отдельной сверки до следующего запуска.

Controller и Source Lab сверяются двусторонне по каждому Yandex batch receipt:
link только в controller и receipt только в Source Lab одинаково считаются
ошибкой reconciliation. Поэтому нельзя восстанавливать или заменять только один
из двух файлов; после любого штатного restore сначала нужна согласованная
проверка пары, а не новый provider read.

После ненулевого результата controller оставляет один
`READY_FOR_REVIEW` batch. Pilot cap и WIP limit равны `1`; все следующие source
reads блокируются `BLOCKED_BACKPRESSURE`. После решения всех Yandex-кандидатов
batch закрывается только явной локальной сверкой:

```powershell
.\scripts\run_safe_lead_flow.ps1 source review-close --attempt-id "ATTEMPT_ID" --actor "OPAQUE_OPERATOR_ID" --evidence-ref "evidence://local-review/ATTEMPT_ID/close" --idempotency-key "YANDEX-CLOSE-ATTEMPT_ID-V1" --confirm-local-close
```

Закрытие допускается только для доказуемо полного Yandex batch. Незакрытые
`NEEDS_RESEARCH`, пропущенные или конфликтующие решения, неверный
attempt и отсутствие явного `--confirm-local-close` дают fail-closed результат
и не снимают backpressure. Нельзя удалять или редактировать SQLite state,
чтобы обойти его. Любой `UNCERTAIN` также является постоянным **STOP** до
отдельного расследования.

Перед append-only записью закрытия controller повторно сверяет всю пару
controller/Source Lab и отклоняет даже чужой ранее появившийся orphan receipt.
Во время `review-close` запрещён любой параллельный прямой writer в Source Lab:
это две отдельные SQLite-базы без общей распределённой транзакции. Нарушение
этой сериализации требует ручной reconciliation и не даёт права продолжать
provider reads.

Для TenderPlan штатное закрытие controller batch пока отложено: используйте
его нативную локальную review queue, но не пытайтесь закрыть такой attempt
командой Yandex и не обходите WIP вручную.

## 4. Мегион v4: бесплатный локальный первый слой

Мегион не использует DOM.RF и не требует provider API. Импорт разрешён только
для exact-публикаций 3 августа и 2 сентября 2026 года, закреплённых в v4 allowlist
по точным URL, дате публикации, размеру и SHA-256. Будущая публикация, другой URL,
другой размер или другие байты отклоняются до парсинга и записи. Полный контракт
приведён в [RADAR_MEGION_PUBLIC_PERMITS.md](RADAR_MEGION_PUBLIC_PERMITS.md).
Разрешены ровно эти манифесты:

- `https://opendata.admmegion.ru/opendata/csv/31875/data/data-20260803T095353-structure-20240702T122402.csv`,
  публикация `2026-08-03`, 93 946 байт,
  SHA-256 `fd5138a8562e2810dca4a8651a536dd103d86dacf103e70e71b932f4158779a9`;
- `https://opendata.admmegion.ru/opendata/csv/31875/data/data-20260902T145832-structure-20240702T122402.csv`,
  публикация `2026-09-02`, 93 856 байт,
  SHA-256 `64da610e83005420bd8e48ffbbeaf6e64b5490144822de3c2440efb2decd95d4`.

В Source Lab/Radar допускаются только контролируемые структурные факты:

- номер разрешения начинается с `86-`, а год в его суффиксе совпадает с датой
  выдачи;
- кадастровый номер публикуется только для точной грамматики и префикса
  `86:19:`; структурно корректный номер другого района скрывается и не участвует
  в identity;
- исходные `title`, `address`, `developer_name`, описание и произвольный текст
  органа всегда скрыты;
- координаты в v4 всегда скрыты: ни числовая форма, ни `0,0`, ни точка другого
  города не считаются проверенным location-фактом.

Результат — очередь исследования, а не лид и не разрешение на контакт. Каждый
объект проходит ручную проверку в Source Lab: первичный источник, актуальная
стадия, участники, закупщик, предмет потребности и срок. До решения человека
никакой кандидат не повышается и не передаётся наружу.

## 5. Gold quarantine: локальные действия и STOP

Gold quarantine читает уже существующий Source Lab и пишет только digest-only
sidecar. Он не пишет CRM/outbox и не является promotion permit.

Локальный агрегированный отчёт:

```powershell
.\scripts\run_safe_lead_flow.ps1 gold report --source-database "C:\ABSOLUTE\source-lab.sqlite3" --quarantine-database "C:\ABSOLUTE\gold-quarantine.sqlite3"
```

Подготовка exact approval request требует реальные непротиворечивые ID и
digests из Source Lab:

```powershell
.\scripts\run_safe_lead_flow.ps1 gold prepare --source-database "C:\ABSOLUTE\source-lab.sqlite3" --quarantine-database "C:\ABSOLUTE\gold-quarantine.sqlite3" --source-record-id "SOURCE_RECORD_ID" --observation-id "OBSERVATION_ID" --review-id "REVIEW_ID" --latest-resolution-id "RESOLUTION_ID" --reviewer-id "HUMAN_REVIEWER_ID" --demand-id "DEMAND_ID" --product-key "PRODUCT_KEY" --buyer-id "OPAQUE_BUYER_ID" --stage "RFQ_EXPECTED" --purchase-deadline-utc "2026-09-30T12:00:00Z" --capacity-snapshot-sha256 "64_HEX" --economics-snapshot-sha256 "64_HEX" --evidence-sha256 "64_HEX" --idempotency-key "GOLD_IDEMPOTENCY_KEY"
```

`Gold signer` сейчас **STOP**: production-поставка намеренно не содержит HMAC
sealer, decoder или verifier, независимо управляемого signer,
custody/rotation-процедуры и promotion adapter. Команды `gold admit` и
`gold revalidate` всегда завершаются кодом 2 до чтения environment, approval
receipt, Source Lab или quarantine state. Launcher удаляет любой ambient
`TENDERBOT_GOLD_APPROVAL_SECRET_B64` до bootstrap и дочернего процесса, а также
в `finally`. Формы ниже документируют только будущий интерфейс и сейчас не могут
выполнить admission или revalidation:

```powershell
.\scripts\run_safe_lead_flow.ps1 gold admit --source-database "C:\ABSOLUTE\source-lab.sqlite3" --quarantine-database "C:\ABSOLUTE\gold-quarantine.sqlite3" --source-record-id "SOURCE_RECORD_ID" --observation-id "OBSERVATION_ID" --review-id "REVIEW_ID" --latest-resolution-id "RESOLUTION_ID" --reviewer-id "HUMAN_REVIEWER_ID" --demand-id "DEMAND_ID" --product-key "PRODUCT_KEY" --buyer-id "OPAQUE_BUYER_ID" --stage "RFQ_EXPECTED" --purchase-deadline-utc "2026-09-30T12:00:00Z" --capacity-snapshot-sha256 "64_HEX" --economics-snapshot-sha256 "64_HEX" --evidence-sha256 "64_HEX" --idempotency-key "GOLD_IDEMPOTENCY_KEY" --authority-id "APPROVAL_AUTHORITY_ID" --approval-receipt "C:\ABSOLUTE\sealed-receipt.json"
.\scripts\run_safe_lead_flow.ps1 gold revalidate --source-database "C:\ABSOLUTE\source-lab.sqlite3" --quarantine-database "C:\ABSOLUTE\gold-quarantine.sqlite3" --acceptance-id "ACCEPTANCE_ID" --source-record-id "SOURCE_RECORD_ID" --observation-id "OBSERVATION_ID" --review-id "REVIEW_ID" --latest-resolution-id "RESOLUTION_ID" --reviewer-id "HUMAN_REVIEWER_ID" --demand-id "DEMAND_ID" --product-key "PRODUCT_KEY" --buyer-id "OPAQUE_BUYER_ID" --stage "RFQ_EXPECTED" --purchase-deadline-utc "2026-09-30T12:00:00Z" --capacity-snapshot-sha256 "64_HEX" --economics-snapshot-sha256 "64_HEX" --evidence-sha256 "64_HEX" --idempotency-key "GOLD_IDEMPOTENCY_KEY" --authority-id "APPROVAL_AUTHORITY_ID" --approval-receipt "C:\ABSOLUTE\sealed-receipt.json"
```

Не помещайте HMAC secret, PAT, персональные данные или raw provider payload в
командную строку, state database, логи или чат. Для `--query` используйте только
заранее одобренную неперсональную поисковую формулировку. Переменная
`TENDERBOT_GOLD_APPROVAL_SECRET_B64` не является поддерживаемым production
интерфейсом и принудительно очищается launcher-ом.

Gold signing, promotion, CRM write, outbox, email/телефонный outreach и scheduler
остаются **отключены**. Даже human `APPROVE` в Source Lab разрешает только
дальнейшее исследование и не включает ни одну из этих возможностей.

## 6. Оставшиеся обязательные gates

До расширения пилота нужны:

1. hash-lock и проверенная provenance всех Python wheels, включая pip/setuptools;
2. независимый Gold signer с custody, rotation, audit receipt и verifier-only
   runtime boundary;
3. отдельный audited bridge и доказуемое закрытие cap-one batch для TenderPlan;
4. новый exact Yandex job/activation после финального кода, независимый `ACCEPT`,
   согласованный native accounting и утверждённый cost cap в пределах общего
   месячного бюджета 30 000 ₽;
5. проверенные ACL и автоматизируемый операционный контроль exact 24-hour purge
   нативного raw journal;
6. formal release/permit для каждого live source;
7. независимый review и полный offline regression точного release candidate;
8. отдельный promotion adapter и повторная revalidation перед любым CRM task.

Пока эти пункты не закрыты, корректный статус — безопасный ручной первый срез,
а не production lead flow.

Репозиторий намеренно не создаёт реальные owner/reviewer/billing evidence.
`source yandex-prepare` закрывает только неактивную фазу, а существующий
`source yandex-activate` принимает уже подготовленный реальный evidence и
локально выпускает `request.json` и exact pins. Он не подменяет owner, reviewer
или проверку кабинета и не выполняет provider read. Нельзя использовать для
evidence synthetic test helper или старый внешний installer; до настоящего
evidence и отдельного `source run-one` задача остаётся безопасно не запущенной.
