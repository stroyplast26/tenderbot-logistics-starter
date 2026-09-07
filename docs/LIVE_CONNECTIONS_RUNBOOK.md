# Mail.ru → Bitrix V4 и проверка UniSender

> **SUPERSEDED / DO NOT ACTIVATE.** Этот документ описывает исторический V4
> writer-контур, который мог создавать Lead, Todo и Timeline. После проверки
> живого Bitrix штатная Bitrix24 Mail назначена единственным writer для входящей
> почты, а V4 authority отозвана. Актуальный безопасный порядок находится в
> `LIVE_CONNECTIONS_OBSERVER_RUNBOOK.md`. Команды bootstrap, canary, run-once и
> включения задачи из этого документа выполнять нельзя.

Этот runbook описывает единственный разрешённый live-контур текущего этапа:
read-only приём писем из Mail.ru, создание и сверку рабочего комплекта в
Bitrix и read-only preflight UniSender. Исходящие письма, рассылки, MANGO и
TenderPlan этим разрешением не включаются.

## Что именно делает V4

Для каждого разрешённого входящего письма создаётся связанный комплект:

1. `Lead` в Bitrix с детерминированным `ORIGIN_ID`;
2. `Todo` ответственному оператору;
3. комментарий в Timeline с нормализованным содержанием письма.

Lead является родителем, а Todo и Timeline — независимыми дочерними
проекциями. Ошибка Todo не подавляет сохранение Timeline и наоборот, но письмо
получает локальный state `CRM_READY` только после проверенного readback обеих
проекций. Неоднозначный внешний `create` никогда не повторяется вслепую.

Вложения сохраняются только в локальном evidence vault. Автоматическая
передача файлов в Bitrix отключена: `FILES` не отправляется, payload содержит
`LOCAL_QUARANTINE`. Это исключает случайную загрузку вредоносного или лишнего
вложения в CRM.

## Разрешения и запреты

Разрешено:

- IMAP `INBOX`: login, `SELECT readonly`, UID search/fetch без изменения писем;
- SMTP SSL: login и `NOOP` только для проверки подключения;
- Bitrix: поиск, создание и readback Lead, Todo и Timeline comment;
- UniSender Go: read-only списки шаблонов, доменов и webhook;
- локальный SQLite ledger, evidence vault и защищённая задача Windows.

Запрещено:

- удалять, перемещать, помечать или отвечать на письма;
- отправлять через SMTP или UniSender;
- загружать вложения в Bitrix автоматически;
- менять стадии, сделки, обещания клиенту или коммерческий результат;
- обращаться к TenderPlan;
- подключать MANGO или обрабатывать записи звонков этим worker.

Секреты читаются только из Windows Credential Manager, target
`TenderBot/LeadFactory/LiveConnections/v1`. `.env` используется лишь как
одноразовый источник для команды импорта и не является runtime fallback.

## Маршруты писем

| Маршрут | Bitrix | Задача человеку |
| --- | --- | --- |
| `FACADE_AUTO` | Lead, source `FASAD_RU`, Timeline | `Позвонить по входящему запросу` |
| `CAMPAIGN_HUMAN_AUTO` | Lead, Timeline | Позвонить |
| `DIRECT_INQUIRY_AUTO` | Lead, Timeline | Позвонить |
| `FACADE_AUTH_REVIEW` | Review Lead, Timeline | Проверить письмо, не звонить автоматически |
| `CAMPAIGN_IDENTITY_REVIEW` | Review Lead, Timeline | Проверить личность/цепочку |
| `CAMPAIGN_AUTH_REVIEW` | Review Lead, Timeline | Проверить аутентификацию |
| `INQUIRY_REVIEW` с payload | Review Lead, Timeline | Проверить входящий запрос |
| `UNMAPPED_THREAD_REVIEW` | Только локальный review | Сверить исходящую кампанию |
| bounce, unsubscribe, system, historical, unknown, Message-ID conflict | Только локальный review | CRM-записи нет |

Важно: V4 намеренно создаёт Review Lead для коммерчески похожего, но
неаутентифицированного запроса. У такого Lead действие `REVIEW`, а не `CALL`;
это сохраняет потенциальный лид для человека, не выдавая спам или подмену за
доказанный запрос.

Facade попадает в автоматический маршрут только при точном адресе
`info@facade.ru` и согласованном верхнем trace-блоке Mail.ru: SPF и DKIM pass,
совпадают `header.d`, `smtp.mailfrom`, `Return-Path`, `From` и DKIM `d=`.
Дубликат или перестановка служебных заголовков, lookalike и простое совпадение
отображаемого имени переводят письмо в review.

`CAMPAIGN_HUMAN_AUTO` требует точного `In-Reply-To`/`References`, ожидаемого
адреса и SPF/DKIM. `DIRECT_INQUIRY_AUTO` требует аутентифицированного домена,
явного коммерческого маркера и не допускает собственные адреса ящика.

Один клиент может прислать несколько разных заявок: e-mail — контактный
атрибут, а не idempotency key. Повтор тех же MIME-байтов не создаёт дубль;
другая заявка того же клиента получает другой `ORIGIN_ID`.

Ответ на исходящее письмо считается кампанийным только после того, как точный
`Message-ID` отправленного письма импортирован в защищённую карту V4. Любая
неизвестная цепочка с `In-Reply-To`/`References` получает
`UNMAPPED_THREAD_REVIEW` и не создаёт CRM-запись. После будущей разрешённой
отправки snapshot синхронизируется отдельной append-only командой:

```powershell
& $Runtime @LiveArgs sync-campaign-snapshot `
  --campaign-snapshot-path $CampaignSnapshot `
  --confirm-sync SYNC-CAMPAIGN-SNAPSHOT-V1
```

Команда требует действующую authority и тот же абсолютный путь, который был
закреплён при bootstrap. Изменять уже импортированную identity нельзя. На
текущем этапе исходящая отправка запрещена, поэтому команда приведена только
как контракт следующего этапа и сейчас не запускается.

## Ответственный оператор

`--assigned-by-id` задаётся при bootstrap; текущий согласованный default —
Bitrix user ID `13`. ID должен принадлежать активному пользователю, который
будет работать с очередью.

- новые и безопасно ожидающие Lead/Todo привязываются к текущему ID;
- смена ответственного запрещена при неоднозначном Lead create, уже
  зафиксированном remote Lead ID или незавершённом Todo; безопасные
  `PENDING/RETRYABLE` без remote ID можно перепривязать;
- незавершённая Todo старой canary не блокирует нового ответственного: при
  reauthorization она переводится в `CANARY_INVALIDATED_REVIEW`, сохраняется
  как evidence и никогда не повторяется;
- при backfill завершённого V3 Lead исторический Todo сохраняет владельца,
  уже записанного в проверенном Lead payload, а не переписывает историю новым
  глобальным ID;
- смена поколения authority или ответственного требует нового canary.

## Authority, бюджет и canary

Scoped authority V4 выдаётся точной фразой
`MAIL-TO-BITRIX-INBOUND-V4`, действует максимум 168 часов и содержит конечный
бюджет попыток записи от 6 до 500. Рекомендуемый рабочий бюджет — 200.

Бюджет и переход операции в `CREATE_DISPATCH` фиксируются одной SQLite
транзакцией. Падение до её commit не расходует попытку; падение после commit
считается неоднозначным и допускает только read-only reconciliation.
Постоянная неопределённость после восьми сверок переводится в ручной review.
Подтверждённый провайдером отказ до создания (`429` и аналогичный retryable
ответ) фиксируется как `DEFINITE_NO_CREATE`: после перезапуска сначала снова
выполняется read-only lookup, затем допускается ровно одна новая попытка.
Любой уже сохранённый remote ID исключает повторный `add`, даже если marker
временно не виден или удалённый объект исчез.

Canary с фразой `LF-CANARY-CAP-1-V4` создаёт максимум один помеченный
no-contact Lead и проверяет Todo и Timeline. Новый canary требует три записи и
разрешён только при остатке не менее шести попыток: после него всегда
резервируется полный production-комплект Lead + Todo + Timeline.

Рабочий gate проверяет не только флаг canary, но и полный локальный seal:
неизменённый payload Lead, его remote ID и ровно две подтверждённые дочерние
записи Todo/Timeline текущего поколения. Потеря или изменение любой части
немедленно делает `operational_ready=false` и запрещает production write.
Remote ID Lead сохраняется сразу после однозначного ответа `add` или уникального
marker lookup, ещё до readback. При смене поколения незавершённая canary
переносится в durable tombstone с origin, payload и известным Lead ID; новая
canary может быть выполнена, но `needs_attention` остаётся истинным до ручной
сверки tombstone.

Истечение срока authority или наблюдённый откат системного времени являются
терминальными для текущего поколения: authority фиксируется как `REVOKED`,
budget обнуляется, canary инвалидируется. Возврат часов вперёд или перезапуск
процесса ничего не восстанавливает — нужны новый явный bootstrap и новый
canary.

Canary проверяет endpoint, ответственного, тексты, deadline, idempotency и
readback. Он не доказывает две production-особенности:

- наличие пользовательского source `FASAD_RU`;
- фактическое отображение `pingOffsets=[0,15]` в интерфейсе Todo.

Поэтому первый реальный Facade Lead и напоминания обязательно проверяются в
Bitrix UI до признания запуска полностью принятым.

## Совместимость и хранилище

- Текущая schema — V4.
- Принимаются только точные опубликованные варианты V3; миграция переводит
  старую authority в `REVOKED`, создаёт V4 delivery outbox и требует повторный
  bootstrap/canary.
- Для текущего production state разрешена миграция только после совпадения с
  уже проверенным профилем: `5` завершённых Facade Lead, `0` старых delivery,
  безопасные body и `5/5` локальных MIME evidence. Любое расхождение в числе,
  digest, payload или evidence означает STOP. Общая миграция произвольной V3
  базы этим решением не одобрена.
- V2, изменённый DDL, лишние schema objects, broken foreign keys и
  противоречивые terminal states отклоняются fail-closed.
- Для terminal Lead/Todo/Timeline обязательны положительный remote ID и
  `phase=READBACK_VERIFIED`; origin Lead должен точно соответствовать
  канонической паре `ORIGINATOR_ID/ORIGIN_ID` сообщения.
- Старые завершённые Lead получают Todo и Timeline после настройки
  ответственного. Их удалённый `SOURCE_ID` автоматически не переписывается:
  V4 не расширяет allowlist методом `crm.lead.update`.
- State directory, DB, WAL/SHM/journal, lock и evidence проверяются на
  reparse point, symlink, hardlink и смену identity. Отзыв authority при ещё
  отсутствующей DB материализует пустое V4-состояние с durable revocation
  fence, поэтому параллельный bootstrap не может воскресить старое разрешение.
- Evidence учитывается по физическим mailbox delivery, включая одинаковые MIME
  под разными UID. Жёсткий предел — 5 GiB, резерв свободного места — 2 GiB.
  Достижение любой границы останавливает cursor до записи следующего письма.
- Перед каждым новым Bitrix write сверяются plain-file identity, размер и
  SHA-256 исходного MIME. При потере evidence новый write запрещён; если внешний
  create уже мог выполниться, сначала разрешена только read-only сверка и
  фиксация найденного remote ID, после чего операция остаётся в review.
- Перед новым Todo/Timeline `add` повторно читается родительский Lead и точно
  сверяются его ID и immutable origin. Временно пустой readback повторяется
  ограниченно; явная подмена origin переводит дочерние операции в review.
- Текстовые части с `filename`/`name`, attachment-контейнеры и инкапсулированные
  `message/*` (кроме классификатора `message/delivery-status`) не попадают в
  Lead COMMENTS или Timeline. Они остаются только в локальном MIME evidence;
  вложенный DSN не может изменить маршрут письма.
- MIME, который нельзя безопасно разобрать либо который превышает границы
  `64` уровней / `10 000` частей, сохраняется как raw evidence с маршрутом
  `LOCAL_PARSE_REVIEW`. Для него CRM outbox не создаётся, а UID фиксируется
  атомарно, поэтому такое письмо не блокирует следующие входящие.
- Собственные незавершённые temp-файлы evidence после падения удаляются под
  runtime lock. Готовый orphan `.eml` переигрывается; если тот же UID ещё есть
  в IMAP, его digest обязан совпасть. Гонка `SEARCH` → `FETCH`, где письмо уже
  expunged, считается повторяемой, а неверный IMAP contract остаётся fail-closed.
- Смена Bitrix webhook на другой portal scope в той же DB запрещена. Нужен
  новый state store после явной сверки старого outbox.

Worker имеет строго одного владельца state. Нельзя одновременно запускать V3
и V4, копировать авторизованную DB на второй компьютер или активировать две
задачи с одним mailbox scope. Перед переносом старый task должен быть disabled,
все его процессы остановлены, а authority в единственном state — доказанно
`REVOKED`. Только затем допустимы установка V4, bootstrap и canary.

Остаточная граница доверия: пользователь с теми же правами к локальной
файловой системе способен на сложную same-identity ABA-подмену. Production
защита опирается также на ACL каталога `%ProgramFiles%`, SID задачи и
ограниченный Windows account.

Гарантия crash/restart относится к падению процесса и обычному перезапуску.
Полная сохранность при внезапной потере питания до того, как Windows/файловая
система закрепила метаданные впервые созданного UIDVALIDITY-каталога, не
заявляется; для production нужны локальный стабильный диск, резервное
копирование state/evidence и желательно UPS.

## Импорт и проверка ключей

Выполнять от Windows-пользователя, под которым будет работать задача:

```powershell
.\.venv\Scripts\python.exe .\scripts\import_live_connection_credentials.py --env-file .\.env
.\.venv\Scripts\python.exe .\scripts\import_live_connection_credentials.py --verify-only
```

После успешного импорта plaintext `.env` не удаляется автоматически. Сначала
нужно убедиться, что Credential Manager readback проходит, затем отдельно
ротировать/архивировать старые ключи. В UniSender допускается только sender с
подтверждённым доменом и активным DKIM.

## Установка защищённого V4

Production-команды выполняются из чистого detached checkout конкретного Git
commit вне OneDrive/Dropbox и любых каталогов с reparse points. Рабочая копия
может оставаться в OneDrive для разработки, но не является источником
привилегированной установки. Wrapper запускается в обычном, **не
администраторском** Windows PowerShell 5.1. Он до UAC строит content-addressed
`.pyz` и private CPython только из чистого committed Git HEAD, фиксирует SHA-256
релиза и privileged installer, затем последовательно запрашивает **два UAC**.
После начала cutover workspace/`.venv` больше не исполняются elevated:
замороженный bootstrap копирует
privileged installer в защищённый `Program Files`, проверяет его SHA-256, а уже
он копирует релиз как данные, перепроверяет manifest/runtime/ACL и оставляет
задачу отключённой:

```powershell
$Install = & .\scripts\install_live_inbound_task.ps1 | ConvertFrom-Json
$WinPS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$TaskStatus = & $WinPS -NoLogo -NoProfile -NonInteractive `
  -ExecutionPolicy Bypass -File $Install.status_path | ConvertFrom-Json
if ($Install.status -ne 'installed_not_authorized' -or
    $TaskStatus.status -ne 'installed_revoked' -or
    $TaskStatus.task_marker_version -ne 4) {
  throw 'Protected V4 task verification failed'
}
```

Только защищённый `read-status.ps1` из content-addressed release является
активационным gate. Workspace-файл
`scripts\live_inbound_task_status.ps1` — исходник сборки и не может подтвердить
`configuration_verified=true`.

Не запускать `scripts\install_live_inbound_task_admin.ps1` вручную. Он обязан
исполняться только из `Program Files\TenderBot\LiveInbound\installers\<sha>`
после проверки self-hash, DACL и high-integrity label. Dirty/staged/untracked
runtime, builder, wrapper или admin installer блокируют production-сборку до
UAC.

Trust anchor wrapper содержит независимые SHA-256 исходных компонентов,
application archive и полного 974-файлового runtime-tree. `python.exe`,
`python3.dll` и `python311.dll` дополнительно обязаны иметь валидную
Authenticode-подпись Python Software Foundation с закреплённым thumbprint.
Git HEAD в receipt остаётся provenance claim; разрешение на cutover дают именно
встроенные pins и повторная проверка фактических байтов.

Если старая задача существует, первая UAC-фаза сначала полностью защищает и
проверяет новый release, затем только quiesce: отключает V3, останавливает её
экземпляры и оставляет регистрацию на месте. Medium-integrity launcher после
этого выполняет durable revoke. Вторая UAC-фаза заменяет регистрацию на V4 в
состоянии disabled, после чего medium launcher повторно делает revoke/readback,
закрывая возможную reauthorization-гонку. Ошибка до quiesce не меняет V3; ошибка
после quiesce оставляет контур остановленным и fail-closed. Пользователь должен
подтвердить оба UAC-диалога. Пока весь cutover не завершён, V4 live не запускать.
При upgrade с точной известной V3-схемы read-only status может показать
`authority_state=REVOKED_LEGACY_STORE`: это допустимый промежуточный revoked
store, привязанный к новому release/runtime через committed meta-receipt; V3
`ACTIVE`, неизвестная схема или неполный receipt всегда дают `authority_unknown`.

Status переходно распознаёт точный старый marker V3, но только V3 с
его старым описанием. Cross-pair V3/V4, версия 5, суффиксы и interval вне
`30..3600` отклоняются. Новый installer всегда пишет marker V4.

Получить закреплённые пути:

```powershell
$Sha = $TaskStatus.release_sha256
$ProgramFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$ReleaseDir = Join-Path $ProgramFiles "TenderBot\LiveInbound\releases\$Sha"
$Artifact = Join-Path $ReleaseDir 'live-inbound.pyz'
$Runtime = Join-Path $ReleaseDir 'runtime\python.exe'
$Profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$StateDir = Join-Path $Profile '.tenderbot\live_inbound'
$ProjectRoot = (Resolve-Path '.').Path
$CampaignSnapshot = Join-Path $ProjectRoot 'pool\outreach_queue.json'
$LegacyProcessed = Join-Path $ProjectRoot 'pool\facade_processed.json'
$LegacyRegistry = Join-Path $ProjectRoot 'pool\leads_registry.json'
$LiveArgs = @(
  '-I', '-S', '-B', $Artifact,
  '--release-sha256', $Sha,
  '--runtime-sha256', $TaskStatus.runtime_sha256,
  '--manifest-sha256', $TaskStatus.manifest_sha256,
  '--artifact-sha256', $TaskStatus.artifact_sha256,
  '--state-dir', $StateDir
)
```

## Последовательность включения

0. Выполнить административный single-writer cutover установщиком и доказать,
   что новая V4-задача имеет status `integrity_verified_disabled`, marker `4`,
   `task_enabled=false` и `running=false`. Не создавать копию live state.

1. Оставить задачу disabled и выполнить только read-only проверки:

   ```powershell
   & $Runtime @LiveArgs status
   & $Runtime @LiveArgs preflight
   & $Runtime @LiveArgs unisender-preflight
   ```

2. Сверить `UIDVALIDITY` и последний безопасный UID со старой DB. Нельзя
   выбирать текущий хвост на глаз:

   ```powershell
   & $Runtime @LiveArgs bootstrap `
     --uidvalidity <ПРОВЕРЕННОЕ_UIDVALIDITY> `
     --last-uid <ПРОВЕРЕННЫЙ_ПОСЛЕДНИЙ_UID> `
     --confirm-owner-authority MAIL-TO-BITRIX-INBOUND-V4 `
     --authority-hours 168 `
     --write-attempt-budget 200 `
     --assigned-by-id 13 `
     --campaign-snapshot-path $CampaignSnapshot `
     --legacy-processed-path $LegacyProcessed `
     --legacy-registry-path $LegacyRegistry
   ```

   Все три пути должны быть абсолютными существующими plain files. Bootstrap
   атомарно импортирует и закрепляет их содержимое; удаление внешнего файла не
   стирает уже защищённую карту, но смена path scope или конфликт identity
   запрещены. Перед командой сохранить SHA-256 этих трёх файлов в evidence
   запуска.

   Для текущего live V3 ожидаемая двухфазная миграция такова: до bootstrap
   сохраняются `5` подтверждённых Lead и `0` delivery-операций, authority имеет
   состояние `REVOKED`; после bootstrap и следующего `status`/`initialize`
   появляются ровно `10 PENDING` операций — по Todo и Timeline для каждого из
   пяти исторических Lead. Повторный status не должен увеличивать это число.
   Эти пять Todo сохраняют владельца `13` из проверенного V3 payload и будут
   уже просрочены относительно исторической даты. До canary и `run-once`
   владелец обязан явно признать эти пять Lead рабочей очередью. Если старые
   Lead не нужно возвращать оператору, остановить запуск и оформить отдельное
   проверяемое cutoff-решение; вручную менять live SQLite запрещено.

3. Выполнить полный canary и проверить health:

   ```powershell
   & $Runtime @LiveArgs bitrix-canary --confirm-create LF-CANARY-CAP-1-V4
   $Health = & $Runtime @LiveArgs status | ConvertFrom-Json
   if (-not $Health.operational_ready -or
       -not $Health.bitrix_canary_generation_matches -or
       -not $Health.bitrix_canary_assignee_matches -or
       -not $Health.bitrix_canary_projection_sealed -or
       -not $Health.evidence_storage_ready -or
       $Health.write_attempts_remaining -lt 3) {
     throw 'Authority/canary verification failed'
   }
   ```

4. До первого production цикла в Bitrix UI:

   - подтвердить, что user ID `13` активен и видит Todo;
   - отключить штатное автоматическое создание Lead из того же почтового
     ящика, иначе Bitrix и V4 могут создать два разных Lead;
   - убедиться, что source code `FASAD_RU` существует;
   - после первого Facade Lead проверить source, ответственного, Timeline,
     deadline и два напоминания Todo.

5. Выполнить один ограниченный цикл, затем включить задачу только при чистом
   status:

   ```powershell
   & $Runtime @LiveArgs run-once --limit 50
   $Health = & $Runtime @LiveArgs status | ConvertFrom-Json
   if (-not $Health.operational_ready -or $Health.needs_attention) {
     throw 'Live inbound is not ready'
   }
   # Эти две команды выполнять в отдельном elevated x64 Windows PowerShell 5.1:
   Enable-ScheduledTask -TaskPath '\' -TaskName 'TenderBot Live Inbound'
   Start-ScheduledTask -TaskPath '\' -TaskName 'TenderBot Live Inbound'
   & $WinPS -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
     -File $Install.status_path
   ```

## Наблюдение и остановка

`status` не выводит секреты. Проверять:

- `operational_ready=true`;
- `authority_state=ACTIVE`, срок и остаток budget;
- `bitrix_canary_*_matches=true`;
- `bitrix_canary_projection_sealed=true`;
- `bitrix_canary_tombstone_count=0`; ненулевое значение требует сверки
  незавершённой canary предыдущего поколения;
- `local_parse_review_count=0`; ненулевое значение означает, что raw MIME
  сохранён, но письмо намеренно не передано в CRM и требует локальной сверки;
- `local_review_count=0` и пустой `local_review_routes`; сюда входят terminal,
  конфликтные и не сопоставленные с кампанией письма без CRM-проекции;
- `missing_evidence_count=0`; проверяются path, размер и SHA-256 каждого
  tracked delivery, в том числе уже подтверждённого локального review;
- `evidence_storage_ready=true`, а `evidence_bytes`, quota, free и reserve
  оставляют достаточный запас;
- `outbox_states` и `delivery_outbox_states`;
- `needs_attention=false` и отсутствие failed runs.

`CRM_CREATED` означает: Lead подтверждён, но одна или обе дочерние проекции
ещё не завершены. `CRM_READY` означает: Lead, Todo и Timeline прочитаны обратно
и совпадают. `MANUAL_RECONCILIATION_REVIEW`, `PERMANENT_REVIEW` и
`RETRY_EXHAUSTED_REVIEW` требуют человека.

Локальные review просматриваются и подтверждаются только точечно. Эти команды
никогда не создают Lead:

```powershell
& $Runtime @LiveArgs list-local-reviews
& $Runtime @LiveArgs ack-local-review `
  --message-key <mail_64_HEX> `
  --confirm-ack ACK-LOCAL-REVIEW-NO-CRM-V1
& $Runtime @LiveArgs ack-local-parse-reviews `
  --confirm-ack ACK-LOCAL-PARSE-REVIEW-V1
```

Canary tombstone снимается только отдельной read-only сверкой. Пустой поиск в
Bitrix не считается доказательством отсутствия и не закрывает tombstone:

```powershell
& $Runtime @LiveArgs reconcile-canary-tombstones `
  --confirm-reconcile RECONCILE-CANARY-TOMBSTONES-V1
```

Durable stop без секретов:

```powershell
& $Runtime @LiveArgs revoke `
  --confirm-revoke MAIL-TO-BITRIX-INBOUND-REVOKE-V1 `
  --reason operator
```

Автоматическое удаление задачи в первом V4-релизе намеренно не выпущено.
Workspace-скрипт fail-closed и ничего не меняет:

```powershell
& .\scripts\uninstall_live_inbound_task.ps1
```

Ожидаемый результат — `status=blocked`, `changed=false` и exit code `78`.
Безопасная аварийная остановка сейчас — medium-integrity `revoke` выше; задачу
оставить зарегистрированной и отключённой, release/state/credentials/receipts
сохранить. Удалять регистрацию вручную до отдельного protected uninstall-flow
нельзя: отсутствие задачи не доказывает revoke.

## STOP перед следующими интеграциями

После подтверждения Mail.ru → Bitrix V4 и UniSender preflight работа
останавливается:

- UniSender sending не включать;
- MANGO и прослушивание звонков не подключать этим этапом;
- TenderPlan не вызывать и старый TenderPlan run не повторять;
- другие источники не публиковать.

MANGO планируется отдельным этапом с нативной связкой MANGO ↔ Bitrix.
TenderPlan остаётся отдельной контрольной точкой и требует нового явного
решения владельца после показа evidence входящего контура.
