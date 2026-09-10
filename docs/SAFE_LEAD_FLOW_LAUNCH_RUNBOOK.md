# Безопасный запуск первого Lead Flow

Этот runbook относится только к ручному первому срезу source discovery и
локальному Gold quarantine. Он не включает рассылку, контакт, CRM/outbox,
рекламную кампанию, расписание или автоматический повтор.

`plan`, `status` и `check` всегда локальны. Единственная команда, способная
обратиться к провайдеру, — `source run-one` с отдельным явным подтверждением;
после него всё равно повторно срабатывает нативная authority-проверка Yandex
или TenderPlan. Без неё запрос не отправляется.

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

## 2. Полностью локальные source-команды

План и состояние:

```powershell
.\scripts\run_safe_lead_flow.ps1 source plan
.\scripts\run_safe_lead_flow.ps1 source status
```

Локальная проверка конкретного источника:

```powershell
.\scripts\run_safe_lead_flow.ps1 source check --source YANDEX --yandex-job "C:\ABSOLUTE\approved-yandex-job.json" --folder-id "FOLDER_ID"
.\scripts\run_safe_lead_flow.ps1 source check --source TENDERPLAN --query "алюминиевые конструкции"
.\scripts\run_safe_lead_flow.ps1 source check --source SABY
.\scripts\run_safe_lead_flow.ps1 source check --source DOMRF
.\scripts\run_safe_lead_flow.ps1 source check --source KONTUR
```

Для Saby, DOM.RF и Kontur ожидаемое состояние сейчас —
`BLOCKED_OFFLINE_CONTRACT`, а exit code — `2`. TenderPlan/Yandex `check`
показывает только готовность перейти к отдельной нативной authority-проверке;
он не подтверждает live-authority сам и не вызывает provider read.

`status` и `check` не создают state database. Все source-команды намеренно
используют только фиксированный canonical state
`state\lead_factory\source_discovery_control.sqlite3`; произвольный
`--state-path` через launcher не допускается.

## 3. Один отдельно разрешённый provider read

Следующие команды уже не являются offline-проверкой. Они допускаются только
после проверки точного job/registration, учётной записи, условий использования
и лимита стоимости.

Yandex:

```powershell
.\scripts\run_safe_lead_flow.ps1 source run-one --source YANDEX --yandex-job "C:\ABSOLUTE\approved-yandex-job.json" --folder-id "FOLDER_ID" --confirm-one-authorized-read
```

TenderPlan:

```powershell
.\scripts\run_safe_lead_flow.ps1 source run-one --source TENDERPLAN --query "алюминиевые конструкции" --tenderplan-registration "C:\ABSOLUTE\verified-registration.json" --confirm-one-authorized-read
```

Provider read может быть тарифицируемым. `campaign_spend_enabled=false`
означает только отсутствие рекламной кампании; это не обещание нулевой цены
API или подписки. Перед Yandex-run нужно отдельно проверить native accounting
и разрешённый cost cap. Новый внешний вызов нельзя делать ради такой проверки.

После ненулевого результата controller оставляет один
`READY_FOR_REVIEW` batch. Pilot cap и WIP limit равны `1`; все следующие source
reads блокируются `BLOCKED_BACKPRESSURE`. Штатной команды закрытия batch в этом
срезе нет. Нужна ручная сверка с нативной review queue и будущий доказуемый
reconciliation receipt. Нельзя удалять или редактировать SQLite state, чтобы
обойти backpressure. Любой `UNCERTAIN` также является постоянным STOP до
отдельного расследования.

## 4. Gold quarantine: локальные действия и STOP

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

`Gold signer` сейчас **STOP**: в поставке нет независимо управляемого signer,
утверждённой custody/rotation-процедуры и promotion adapter. Поэтому
`gold admit` и `gold revalidate` ниже показывают только форму будущей команды,
но не являются разрешением на её выполнение:

```powershell
.\scripts\run_safe_lead_flow.ps1 gold admit --source-database "C:\ABSOLUTE\source-lab.sqlite3" --quarantine-database "C:\ABSOLUTE\gold-quarantine.sqlite3" --source-record-id "SOURCE_RECORD_ID" --observation-id "OBSERVATION_ID" --review-id "REVIEW_ID" --latest-resolution-id "RESOLUTION_ID" --reviewer-id "HUMAN_REVIEWER_ID" --demand-id "DEMAND_ID" --product-key "PRODUCT_KEY" --buyer-id "OPAQUE_BUYER_ID" --stage "RFQ_EXPECTED" --purchase-deadline-utc "2026-09-30T12:00:00Z" --capacity-snapshot-sha256 "64_HEX" --economics-snapshot-sha256 "64_HEX" --evidence-sha256 "64_HEX" --idempotency-key "GOLD_IDEMPOTENCY_KEY" --authority-id "APPROVAL_AUTHORITY_ID" --approval-receipt "C:\ABSOLUTE\sealed-receipt.json"
.\scripts\run_safe_lead_flow.ps1 gold revalidate --source-database "C:\ABSOLUTE\source-lab.sqlite3" --quarantine-database "C:\ABSOLUTE\gold-quarantine.sqlite3" --acceptance-id "ACCEPTANCE_ID" --source-record-id "SOURCE_RECORD_ID" --observation-id "OBSERVATION_ID" --review-id "REVIEW_ID" --latest-resolution-id "RESOLUTION_ID" --reviewer-id "HUMAN_REVIEWER_ID" --demand-id "DEMAND_ID" --product-key "PRODUCT_KEY" --buyer-id "OPAQUE_BUYER_ID" --stage "RFQ_EXPECTED" --purchase-deadline-utc "2026-09-30T12:00:00Z" --capacity-snapshot-sha256 "64_HEX" --economics-snapshot-sha256 "64_HEX" --evidence-sha256 "64_HEX" --idempotency-key "GOLD_IDEMPOTENCY_KEY" --authority-id "APPROVAL_AUTHORITY_ID" --approval-receipt "C:\ABSOLUTE\sealed-receipt.json"
```

Не помещайте HMAC secret, PAT, персональные данные или raw provider payload в
командную строку, state database, логи или чат. Для `--query` используйте только
заранее одобренную неперсональную поисковую формулировку. До отдельного
signer/release решения не задавайте `TENDERBOT_GOLD_APPROVAL_SECRET_B64` для
операционного запуска.

## 5. Оставшиеся обязательные gates

До расширения пилота нужны:

1. hash-lock и проверенная provenance всех Python wheels, включая pip/setuptools;
2. независимый Gold signer с custody, rotation, audit receipt и verifier-only
   runtime boundary;
3. audited bridge из native Yandex/TenderPlan review queue в Source Lab и
   доказуемое закрытие cap-one batch;
4. видимый provider-read accounting и отдельно утверждённый cost cap;
5. formal release/permit для каждого live source;
6. независимый review и полный offline regression точного release candidate;
7. отдельный promotion adapter и повторная revalidation перед любым CRM task.

Пока эти пункты не закрыты, корректный статус — безопасный ручной первый срез,
а не production lead flow.
