# Безопасный запуск первого Lead Flow

Этот runbook относится только к ручному первому срезу source discovery и
локальному Gold quarantine. Он не включает рассылку, контакт, CRM/outbox,
рекламную кампанию, расписание или автоматический повтор.

`plan`, `status`, `check`, `review-list`, `review-decide` и `review-close`
всегда локальны. Единственная команда, способная
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

Локальный Yandex review также работает только с каноническими базами Source
Lab и source controller; произвольные пути через launcher не принимаются.
Контроллер `source-discovery-control-v2` связывает batch с хешем точного
канонического пути Source Lab. Копия или перенос controller/Source Lab в другой
каталог не может закрыть исходный batch.
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

Это не означает отсутствие raw storage во всём нативном Yandex-контуре: до
bridge `radar_yandex_journal` сохраняет raw provider response в своём локальном
attempt journal до `retain_until_utc`; policy допускает retention от 1 до 24
часов. До live-read отдельно утвердите точный journal path, доступ, retention и
штатный purge. Source Lab minimization не заменяет эту privacy-проверку.

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

Для TenderPlan штатное закрытие controller batch пока отложено: используйте
его нативную локальную review queue, но не пытайтесь закрыть такой attempt
командой Yandex и не обходите WIP вручную.

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
3. отдельный audited bridge и доказуемое закрытие cap-one batch для TenderPlan;
4. видимый provider-read accounting и отдельно утверждённый cost cap;
5. formal release/permit для каждого live source;
6. независимый review и полный offline regression точного release candidate;
7. отдельный promotion adapter и повторная revalidation перед любым CRM task.

Пока эти пункты не закрыты, корректный статус — безопасный ручной первый срез,
а не production lead flow.
