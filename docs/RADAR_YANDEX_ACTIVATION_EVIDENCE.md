# Exact evidence для локальной активации Yandex

Эта процедура только публикует заранее полученные реальные подтверждения и
готовит локальную активацию. Она не создаёт согласие владельца, независимую
приёмку или readiness, не читает credential, не вызывает Yandex и не разрешает
`run-one`. Выдуманные значения, самооценка вместо независимого `ACCEPT` и
непроверенный billing/API/credential запрещены.

## 1. Единственная схема v1

Подготовьте вне trusted state файл `evidence.candidate.json` ровно следующей
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

## 2. Канонизация и no-replace публикация

Сначала задайте четыре значения из результата `yandex-prepare` и абсолютный
путь к заполненному candidate. Trusted profile получают только через Windows
OS API, а не через `%USERPROFILE%` или другой ambient environment.

```powershell
$JobId = "JOB_ID_FROM_PREPARE"
$DraftSha256 = "DRAFT_SHA256_FROM_PREPARE"
$ScopeSha256 = "SCOPE_SHA256_FROM_PREPARE"
$Candidate = "C:\ABSOLUTE\evidence.candidate.json"
$ProfileRoot = [Environment]::GetFolderPath('UserProfile')
```

Следующий блок проверяет exact ключи верхнего и вложенных объектов,
канонизирует JSON как UTF-8 без BOM с сортировкой ключей и без пробелов,
вычисляет content hash и публикует файл через собственный stage и Windows
no-replace rename. При любой ошибке digest не возвращается и продолжать нельзя.

```powershell
$Publisher = @'
import hashlib, json, os, pathlib, secrets, stat, sys, uuid

TOP = {"version", "job_id", "draft_sha256", "scope_sha256", "owner_receipt", "independent_acceptance", "readiness"}
OWNER = {"kind", "owner_id", "source_thread_id", "instruction_sha256", "captured_at_utc", "scope_sha256"}
REVIEW = {"kind", "reviewer_id", "reviewed_at_utc", "verdict", "code_sha256", "evidence_sha256", "implementation_author_ids"}
READY = {"kind", "observed_at_utc", "billing_status", "search_api_status", "credential_status", "folder_id_sha256", "connection_sha256", "evidence_sha256"}

def exact_object(value, keys):
    if type(value) is not dict or set(value) != keys:
        raise ValueError()

def main():
    source = pathlib.Path(sys.argv[1]).resolve(strict=True)
    profile = pathlib.Path(sys.argv[2]).resolve(strict=True)
    job_id, draft_sha256, scope_sha256 = sys.argv[3:6]
    if str(uuid.UUID(job_id)) != job_id:
        raise ValueError()
    for digest in (draft_sha256, scope_sha256):
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError()
    value = json.loads(source.read_bytes())
    exact_object(value, TOP)
    exact_object(value["owner_receipt"], OWNER)
    exact_object(value["independent_acceptance"], REVIEW)
    exact_object(value["readiness"], READY)
    if (value["version"] != "radar-yandex-manual-activation-evidence-v1"
            or value["job_id"] != job_id
            or value["draft_sha256"] != draft_sha256
            or value["scope_sha256"] != scope_sha256):
        raise ValueError()
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    directory = profile / ".codex" / "local_state" / "TenderBot" / "yandex-search" / "activation-evidence" / job_id
    directory.mkdir(parents=True, exist_ok=True)
    if directory.resolve(strict=True) != directory.absolute():
        raise ValueError()
    target = directory / (digest + ".json")
    if target.exists():
        raise FileExistsError()
    stage = directory / ("." + digest + ".json.stage-" + str(os.getpid()) + "-" + secrets.token_hex(8))
    descriptor = -1
    identity = None
    try:
        descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino, opened.st_mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError()
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if stage.read_bytes() != payload:
            raise OSError()
        os.rename(stage, target)
        if target.read_bytes() != payload:
            raise OSError()
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            current = os.lstat(stage)
            current_identity = (current.st_dev, current.st_ino, current.st_mode)
            if current_identity == identity and stat.S_ISREG(current.st_mode) and not stat.S_ISLNK(current.st_mode):
                os.unlink(stage)
        except OSError:
            pass
        raise
    print(digest)

try:
    main()
except BaseException:
    raise SystemExit(2)
'@
$EvidenceOutput = & .\.venv\Scripts\python.exe -I -c $Publisher $Candidate $ProfileRoot $JobId $DraftSha256 $ScopeSha256
$PublishExitCode = $LASTEXITCODE
$EvidenceSha256 = (@($EvidenceOutput) -join '').Trim()
if ($PublishExitCode -ne 0 -or $EvidenceSha256 -notmatch '\A[0-9a-f]{64}\z') {
    throw "YANDEX_EVIDENCE_PUBLICATION_FAILED"
}
```

Нельзя использовать `Set-Content`, копирование поверх существующего файла или
повторную публикацию по тому же имени. После публикации выполните реальный
read-only ACL admission. Единственный допустимый stdout — marker READY:

```powershell
$AclHelper = ".\scripts\check_yandex_activation_acl.ps1"
$AclOutput = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $AclHelper -JobId $JobId -EvidenceSha256 $EvidenceSha256 -Phase Draft
$AclExitCode = $LASTEXITCODE
$AclResult = (@($AclOutput) -join '').Trim()
if ($AclExitCode -ne 0 -or $AclResult -ne "YANDEX_ACTIVATION_ACL_READY") {
    throw "YANDEX_ACTIVATION_ACL_REJECTED"
}
```

ACL-проверка подтверждает protected root ACL, наследование только от текущего
Windows SID и `SYSTEM`, обычные файлы/каталоги, отсутствие reparse points,
stage residue, посторонних job-файлов и непустых claims. Сам `yandex-activate`
повторяет эту проверку перед каждым переходом фазы.

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
