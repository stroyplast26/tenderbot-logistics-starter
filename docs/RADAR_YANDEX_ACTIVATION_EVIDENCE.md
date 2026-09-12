# Exact evidence для локальной активации Yandex

Эта процедура только публикует заранее полученные реальные подтверждения и
готовит локальную активацию. Она не создаёт согласие владельца, независимую
приёмку или readiness, не читает credential, не вызывает Yandex и не разрешает
`run-one`. Выдуманные значения, самооценка вместо независимого `ACCEPT` и
непроверенный billing/API/credential запрещены.

## 1. Единственная схема v1

Подготовьте файл `candidate.json` с реальными подтверждениями ровно следующей
структуры. Лишние и отсутствующие ключи запрещены. Все SHA-256 — 64 строчных
шестнадцатеричных символа, все времена — UTC вида `YYYY-MM-DDTHH:MM:SSZ`.

```json
{
  "version": "radar-yandex-manual-activation-evidence-v1",
  "job_id": "<lowercase UUID from yandex-prepare>",
  "draft_sha256": "<draft_sha256 from yandex-prepare>",
  "scope_sha256": "<scope_sha256 from yandex-prepare>",
  "owner_receipt": {
    "kind": "CAPTURED_OWNER_INSTRUCTION",
    "owner_id": "<opaque owner id>",
    "source_thread_id": "<opaque source thread id>",
    "instruction_sha256": "<sha256 of the retained exact owner instruction>",
    "captured_at_utc": "<UTC timestamp>",
    "scope_sha256": "<same scope_sha256>"
  },
  "independent_acceptance": {
    "kind": "INDEPENDENT_CODE_ACCEPTANCE",
    "reviewer_id": "<opaque independent reviewer id>",
    "reviewed_at_utc": "<UTC timestamp>",
    "verdict": "ACCEPT",
    "code_sha256": {
      "<every exact relative key from request.draft.json code_sha256>": "<same sha256 value>"
    },
    "evidence_sha256": "<sha256 of the retained review receipt>",
    "implementation_author_ids": [
      "<opaque implementation author id>"
    ]
  },
  "readiness": {
    "kind": "BILLING_API_READINESS",
    "observed_at_utc": "<UTC timestamp>",
    "billing_status": "ACTIVE",
    "search_api_status": "CONFIGURATION_VERIFIED",
    "credential_status": "AVAILABLE",
    "folder_id_sha256": "<sha256 of the exact folder id UTF-8 bytes>",
    "connection_sha256": "<exact connection_sha256 from request.draft.json>",
    "evidence_sha256": "<sha256 of the retained readiness receipt>"
  }
}
```

В `code_sha256` нужно целиком и без изменений перенести объект `code_sha256`
из exact `request.draft.json`: placeholder из примера оставлять нельзя. Не
копируйте query, region, folder ID или credential в evidence. `owner_id`,
`source_thread_id`, `reviewer_id` и каждый author ID допускают только
`A-Z`, `a-z`, `0-9`, `_`, `.`, `:`, `-`, начинаются с буквы или цифры и имеют
длину 1–128. Авторов должно быть от 1 до 8, без повторов; reviewer не может быть
владельцем или одним из авторов.

`billing_status` допускает только `ACTIVE` или `TRIAL_ACTIVE`; остальные
константы из шаблона неизменяемы. Owner и readiness фиксируются не раньше
создания draft. Review может предшествовать draft не более чем на 24 часа. Ни
одно из трёх времён не может быть позже активации. Все receipt hashes должны
ссылаться на реально сохранённые неизменяемые доказательства, а не на текстовые
заглушки.

## 2. Проверка и публикация штатной командой

Только после code freeze и подготовки exact draft оператор собирает реальные
подтверждения по схеме выше. Сохраните готовый JSON как обычный UTF-8 файл
`candidate.json` в фиксированном inbox:

```text
[OS profile]\.codex\local_state\TenderBot\yandex-search\activation-candidates\<job_id>\candidate.json
```

Inbox содержит только `candidate.json`; его каталоги и файл наследуют защищённые
ACL корневого state. Символические ссылки, junction, hardlink, лишние файлы и
неверные права запрещены. Candidate может быть форматированным JSON, но не
содержать BOM, повторяющиеся ключи, NaN/Infinity или более 131072 байт. Не
помещайте туда credential, query, region или folder ID. Хеши receipts относятся
к реально сохранённым доказательствам; заполненный шаблон сам по себе их не
заменяет. Если реальных подтверждений нет, остановитесь до публикации.

Задайте значения из `yandex-prepare` и вычислите SHA-256 точных байтов готового
candidate. Произвольный input path команда не принимает:

```powershell
$JobId = "JOB_ID_FROM_PREPARE"
$DraftSha256 = "DRAFT_SHA256_FROM_PREPARE"
$ScopeSha256 = "SCOPE_SHA256_FROM_PREPARE"
$ProfileRoot = [Environment]::GetFolderPath('UserProfile')
$StateRoot = Join-Path $ProfileRoot ".codex\local_state\TenderBot\yandex-search"
$Candidate = Join-Path $StateRoot "activation-candidates\$JobId\candidate.json"
$CandidateSha256 = (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash.ToLowerInvariant()
.\scripts\run_safe_lead_flow.ps1 source yandex-publish-evidence --job-id $JobId --expected-draft-sha256 $DraftSha256 --expected-scope-sha256 $ScopeSha256 --expected-candidate-sha256 $CandidateSha256 --confirm-local-publication
```

Launcher принимает ровно девять токенов после `yandex-publish-evidence` в
указанном порядке. Команда сначала проверяет ACL fixed inbox, затем exact raw
hash, размер/тип/identity файла, строгий JSON, роли, времена, полный code map,
connection, scope и свежесть draft. Только после успешной проверки она создаёт
фиксированные каталоги назначения и публикует канонические UTF-8 байты:

```text
[OS profile]\.codex\local_state\TenderBot\yandex-search\activation-evidence\<job_id>\<evidence_sha256>.json
```

Публикация использует exclusive stage, fsync, Windows no-replace rename и
повторную проверку. Совпадающие байты дают exact replay; существующие отличные
байты никогда не перезаписываются. Candidate не меняется. После публикации
helper обязан вернуть `YANDEX_ACTIVATION_ACL_READY` для прежней фазы `Draft`.
Новая фаза `Evidence` допускает отсутствие назначения только до публикации и
требует готовый защищённый inbox; требования четырёх фаз активации сохранены.

Успех — `EVIDENCE_PUBLISHED_AWAITING_ACTIVATION`, `authority_verified=false`,
`launch_allowed=false`, `evidence_sha256` и нулевые внешние эффекты. Это проверка
согласованности предоставленных данных. Команда не создаёт согласие владельца,
независимый ACCEPT или readiness, не выдаёт grant, не устанавливает request/pin,
не читает credential и не вызывает provider, CRM, почту или расписание. Проверка
пустого journal может брать SQLite locks, но не резервирует запрос и не
изменяет accounting.

Сохраните `evidence_sha256` из успешного JSON в `$EvidenceSha256`. Если получен
`YANDEX_EVIDENCE_PUBLICATION_RECONCILIATION_REQUIRED`, стабильный файл может
уже существовать: сохраните его и разберите причину. Команда не удаляет
опубликованный evidence. При временном конфликте параллельных команд допустим
только повтор с теми же exact inputs после устранения причины; автоматической
активации или продолжения после ошибки нет.

## 3. Активация и фактический job path

```powershell
.\scripts\run_safe_lead_flow.ps1 source yandex-activate --job-id $JobId --expected-draft-sha256 $DraftSha256 --expected-scope-sha256 $ScopeSha256 --evidence-sha256 $EvidenceSha256 --confirm-final-activation
$StateRoot = Join-Path $ProfileRoot ".codex\local_state\TenderBot\yandex-search"
$YandexJob = Join-Path $StateRoot "requests\$JobId\request.json"
```

Успех активации — только `ACTIVATED_AWAITING_EXPLICIT_RUN_ONE`. Для последующих
`source check` и `source run-one` параметр `--yandex-job` обязан быть именно
абсолютным `$YandexJob`, опубликованным activator, а не candidate, draft или
скопированным файлом.

V1 не поддерживает rotation, revocation, перезапись или автоматическую замену
корневого `request-activation.json`, даже после expiry. Если корневой pin уже
есть или публикация стала неопределённой, ничего не удаляйте и не заменяйте:
остановитесь для отдельной reconciliation. Новый job или будущая rotation
требуют отдельной реализации, доказательств и явного разрешения.
