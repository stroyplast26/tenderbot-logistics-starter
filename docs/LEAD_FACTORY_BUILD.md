# Lead Factory — журнал строительства

Дата начала: 18.08.2026.

## Обновление 22.08.2026 — Connection Readiness Report v0.1

Выпущен versioned status-report для следующего этапа: 
`docs/LEAD_FACTORY_CONNECTION_READINESS_REPORT.md`.
Он консолидирует текущие evidence и честно фиксирует
`NO_GO_FOR_GENERAL_CONNECTIONS`: после Bitrix graph canary возможны только
отдельно одобренные bounded canary, но `TECH_READY_FOR_CONNECTION` ещё не
присвоен. Следующим техническим кандидатом определён read-only IMAP intake;
реальный login, внешние reads/writes и transport этим обновлением не выполнялись.

Добавлены `lead_factory/imap_readonly_boundary.py` и
`lead_factory/imap_canary_runtime.py`: узкая injected IMAP boundary и явная TLS
client factory без `.env`, CLI, worker registration или write-команд. Runtime
принимает только отдельные `LEAD_FACTORY_IMAP_CANARY_*` variables и игнорирует
legacy credentials. Boundary всегда открывает mailbox только с `readonly=True`,
читает ограниченную UID-последовательность и возвращает только raw MIME + hash
для `UnifiedInboundWorker`; malformed UIDVALIDITY и gaps не дают продвинуть
локальный cursor. Fixture-тесты не используют сеть.

По отдельному явному разрешению владельца выполнен read-only IMAP transport
preflight на существующей legacy-учётке как временное исключение из требования
отдельного canary credential. TLS/login, `SELECT "INBOX" readonly=True` и
UIDVALIDITY прошли; boundary получила ровно 5 raw MIME сообщений, не выводя и
не сохраняя их содержимое. Session закрыта; SMTP/Unisender/Bitrix/Telegram/
OpenRouter не вызывались. До/после canonical stage остался schema 13 с тремя
external/manual flags `0`, а Event/interaction/cursor/outbox/task counts не
изменились. Это transport proof, не полный inbound canary: migration,
mailbox registry, evidence vault, durable UID cursor и reconciliation остаются
следующим gate.

## Проверено 22.08.2026 — canonical stage v13 → v15 migration gate

После явного разрешения владельца выполнен production-stage cutover через
`lead_factory/migrate_v15_cutover.py`. До миграции создан свежий v13 backup и
успешный restore-test. Windows provider сохранил DPAPI recovery capsule,
временно изолировал nine known legacy writer components, подтвердил safe
readiness, затем семантически восстановил их исходное состояние; capsule удалена
только после restore verification.

- canonical DB последовательно мигрирована `13 → 14 → 15`; schema meta и PRAGMA
  равны `15`, migration ledger содержит ровно две записи;
- сохранены 98 Event, 47 Interaction и 10 human tasks; миграция создала одну
  disabled `LEGACY_UNVERIFIED` mailbox mapping и 47 scoped legacy claims, не
  изменив коммерческие очереди;
- final safety: `external_writers_enabled=0`,
  `external_source_reads_enabled=0`, outbox/CRM outbox/inbox cursors равны `0`;
- новый v15 backup и restore-test зелёные. Backup:
  `state/lead_factory/backups/lead_factory_20260822T172452349169Z_2dfcaecff5.sqlite3`;
- targeted schema/recovery/IMAP regression: **31/31 `OK`**; scoped `ruff` и
  `compileall` — `OK`. SMTP/Unisender/Bitrix/Telegram/OpenRouter не вызывались.

Это закрывает §42.4(1) для canonical stage, но не включает source reads и не
завершает `TECH_READY_FOR_CONNECTION`. Следующий gate — зарегистрировать один
read-only mailbox в v15, связать его с LocalEvidenceVault и durable UID cursor,
после чего выполнить отдельный bounded inbound canary.

## Проверено 22.08.2026 — §42.3(5) live Bitrix graph cap=1→5

Production-critical lane доведён до genuinely green live cap=5 checkpoint по
явному разрешению владельца. Использован новый отдельный webhook пользователя
`15` с exact scope `crm`; secret не включён в evidence, события или документацию.
Fresh read-only preflight и все live writes выполнялись только внутри bounded
Windows quiesce с crash-recovery capsule и обязательным exact restore.

- fresh graph preflight выполнил `56` allowlisted reads и подтвердил все пять
  checks; report hash
  `cfed5d671ffe2bb73fbdf97dc5cb7ecd8c09caf49b07abaf14852715e11e9cc6`.
  Отдельные `12` exact correlation probes для четырёх кандидатов дали только нули;
  evidence hash
  `cf344a981b10d81c5252e4c61375cac20d0cab2f17b295637bf3104914a8e37c`;
- перед HTTP воспроизведён и закрыт P1 controller ordering: durable members ранее
  сравнивались с incidental SQL order при одинаковой секундной timestamp. Cutover
  теперь проверяет durable member set, а dispatch order выводит только из
  immutable sealed `expansion_candidates`. Adversarial test с перемешанными ID
  подтверждает ordinal `2..5`; неуспешная первая попытка не изменила control DB и
  не выполнила create;
- sealed cutover hash
  `216872f2e21c1fb55c3862c515226d06da8788847413f9f741136ac1a0095a3c`
  допустил ровно `16` новых операций. Все `16/16` имеют `SENT`, положительный
  remote ID и `attempt_count=1`: Company `1123/1125/1127/1129`, Contact
  `529/531/533/535`, Deal `537/539/541/543`, Activity `2941/2943/2945/2947`.
  Исходный cap=1 graph `1121/527/535/2939` сохранён;
- независимый typed readback `16/16` зелёный, без внешних записей; report hash
  `2803472db1d8e6a421a46f85649ce8c9e062257045fd1bc1071b337ed0f39423`.
  Финальный run `STOPPED`, reason `cap_five_complete`; outbox `20 SENT`, ACTIVE
  mappings: Company `5`, Contact `5`, Deal `5`; все три external flags `0`;
- disposable schema-17 control DB: размер `1769472`, `quick_check=ok`, FK `0`,
  WAL/SHM отсутствуют, SHA-256
  `6f49f371666866f5b006c64d485b00de2b9ae793350fd55672770dc91d6a674e`.
  Legacy Windows state восстановлен exact, recovery capsule удалена только после
  semantic recapture.

Финальные gates на live relevant state: Bitrix/Windows/Site/Source/CRM targeted
**250/250 `OK`**; полный Lead Factory **888/888 `OK`**; TaskBot **13/13 `OK`**;
полный `ruff check lead_factory tests taskbot` и compileall `OK`. Canonical
`state/lead_factory_stage.sqlite3` повторно проверена только через
`mode=ro&immutable=1`: размер `598016`, schema `13`, `quick_check=ok`, FK `0`,
WAL/SHM отсутствуют, SHA-256
`01c477519b05402c7adea7d930f2a96b3d4e97fb9cb44b6b66325b7e8cb7908f`.
Live source reads, SMTP, IMAP и OpenRouter не выполнялись.

Canonical live cap=5 evidence:
`LEAD_FACTORY_BITRIX_GRAPH_CAP5_LIVE_EVIDENCE.json`, declared hash
`f26fb7d3592d720bf9c391a05781329d9aef23d9f24b88735da10e2657a052ce`.
Открытых воспроизводимых P0/P1 в §42.3(5) live cap=5 lane нет. Writers и source
reads финально выключены; дальнейшее массовое расширение этим checkpoint не
разрешено и требует нового отдельного owner approval.

## Исторический checkpoint 22.08.2026 — §42.3(5) offline Bitrix graph cap=1→5

Этот раздел фиксирует состояние до live cutover и заменён новым checkpoint выше;
его `DRAFT/NO-GO` не описывает текущий финальный state.

Кодовый production-critical P1 расширения закрыт до offline green checkpoint без
live REST и без writer activation. Продолжение выполнено на восстановленном exact
cap=1 schema-17 snapshot, а не в новом независимом run: исходный SHA-256
`3cecfa36046f6402a6856e5e31022f3d2983abb0bb7aaf868b3d4e97fb9cb44b6b66325b7e8cb7908f8`
совпал до первой записи. Owner approval на `1→5` закреплён sealed cohort input.

- тот же cap=1 run получил immutable completion checkpoint и approval sequence
  `2`, cumulative cap `5`; run находится в `DRAFT`, не `ACTIVE`;
- deterministic cohort hash
  `576caf0eb28f5269ad6942f5ca08c2bf9c748ce8e4c4f017ec1afad9a52de445`
  связывает ровно четыре новых distinct candidate slots `2..5`, deployment hash
  `c77b349a8322d3682b535e8fe2cac31b65e80601928817ff3f048117c31fba36`,
  mapping manifest
  `490ccc858c26b96908d17f4a0210606c8784f4818d5f1d6c139b0f7562fe7512`,
  cap=1 evidence и исходный control snapshot;
- controller требует для каждого member неизменный cap=1 input baseline плюс общий
  `expansion_cohort` и свой ordinal `expansion_candidate_2..5`; swapped, duplicate,
  missing, shadow и extra bindings fail closed;
- expansion credential не может повторять cap=1 evidence: допускается только новый
  exact `crm`-only credential с `owner_accepted_existing_credential=false` и
  отдельным isolation evidence. Старое cap=1 исключение не переносится;
- crash-recoverable preparation идемпотентно создала четыре новых graph member и
  16 ordered PENDING operations. Финально: approvals `2` (`cap=1`, затем `cap=5`),
  scope members `5`, immutable operation bindings `20`, outbox `4 SENT + 16 PENDING`;
  Company/Contact/Deal/Activity live create для новых slots не выполнялись;
- disposable control DB после preparation: размер `1613824`, schema `17`,
  `quick_check=ok`, FK violations `0`, WAL/SHM отсутствуют, SHA-256
  `33e79783808aa05c6e8429c96991e03ae0776fb61da13e2be5c443ffa79673bf`.
  `external_writers_enabled=0`, `external_source_reads_enabled=0`,
  `manual_import_commits_enabled=0`. Canonical offline evidence declared hash:
  `2ba7daa9f820a508000575c4023178583988b053d4d72eb6088846d6f3dd8724`;

Финальные gates на новом relevant state: Bitrix/Windows/Site/Source/CRM targeted
**249/249 `OK`**; полный Lead Factory на runtime с test-only attestation dependency
**887/887 `OK`**; manual evidence/parser targeted **26/26 `OK`**; TaskBot
**13/13 `OK`**; полный `ruff check lead_factory tests taskbot` и compileall `OK`.
Первый полный запуск через project `.venv` корректно fail closed только в 23
test-only attestation cases из-за отсутствующей там `cryptography`; на штатном
Python с `cryptography 46.0.5` эти 26 tests и весь regression зелёные. Защита не
ослаблялась.

Canonical `state/lead_factory_stage.sqlite3` повторно проверена только через
`mode=ro&immutable=1`: размер `598016`, schema `13`, `quick_check=ok`, FK `0`,
WAL/SHM отсутствуют, SHA-256
`01c477519b05402c7adea7d930f2a96b3d4e97fb9cb44b6b66325b7e8cb7908f`.
Live source reads, SMTP, IMAP, OpenRouter и новые Bitrix writes не выполнялись.

Открытых воспроизводимых code P0/P1 в §42.3(5) offline lane нет. Live activation
`1→5` намеренно остаётся `NO-GO`: нужен отдельный Bitrix user/role и новый minimal
`crm` webhook, изолированный от read-only/legacy процессов, затем fresh read-only
preflight, bounded Windows quiesce и отдельный sealed cutover. Создание ещё одного
webhook для того же пользователя не считается credential isolation.

## Проверено 22.08.2026 — §42.3(5) live Bitrix graph cap=1

Production-critical lane закрыт до genuinely green cap=1 checkpoint. На отдельной
disposable schema-17 БД реализованы immutable approval/scope/four-operation bindings,
atomic cutover, fenced connector/rate leases, transaction-local dispatch permit,
pre-create correlation lookup, durable `SENT/UNCERTAIN/REVIEW`, exact read-only
reconciliation, recovery-resume того же cap=1 и повторяемый STOP. Canonical schema13
в этом runtime не использовалась.

- owner-approved synthetic graph создал ровно по одной сущности: Company `1121`,
  Contact `527`, Deal `535`, Activity `2939`. Все четыре operation имеют `SENT`,
  положительный remote ID и финальный exact readback; create reservation ровно `4`,
  attempt count каждой операции ровно `1`. Candidate hash
  `af606a1e578aa373b6874db13b54d86c6283251db22375f38d64a188a4288379`,
  cutover seal
  `47a1a4d77ee7b1e14942b6fff2c0e5486a727e03a1f4adab7c02a0a232248102`,
  final readback report
  `723171ff1f15f555e9a5918f21c3a6b87c6b5c614d22d32f8cee2e02a40814a4`;
- live failure injection обнаружил реальные provider-shape gaps до повтора:
  `crm.activity.todo.add` возвращает object ID, Activity readback использует `SUBJECT`
  и может нормализовать timezone deadline, а Contact multifield добавляет provider-owned
  `ID/TYPE_ID`. Contact был найден exact correlation lookup и переведён в `SENT`
  read-only; второго Contact create не было. После recovery Deal/Activity прошли один раз;
- повторный STOP после recovery-resume теперь имеет отдельный immutable fence/event.
  Финальный run `STOPPED`; `external_writers_enabled=0`,
  `external_source_reads_enabled=0`, `manual_import_commits_enabled=0`;
- Windows lane восстановлен: шесть существующих tasks enabled, один active poll,
  один `tb_bot`, HKCU autorun present, unknown components `0`. Opaque receipt получил
  DPAPI-encrypted/authenticated crash capsule: fresh provider может импортировать его
  только для restore, tamper/path escape/oversize/overwrite fail closed, удаление —
  только после exact semantic recapture;
- gates окончательного state: Bitrix/CRM/Windows targeted adjacent **132/132 `OK`**,
  Windows provider **37/37 `OK`**, полный Lead Factory **862/862 `OK`**, TaskBot
  **13/13 `OK`**, полный Ruff и compileall `OK`.

Canonical `state/lead_factory_stage.sqlite3` финально проверена только через
`immutable=1`: размер `598016`, schema `13`, `quick_check=ok`, FK violations `0`,
WAL/SHM отсутствуют, SHA-256
`01c477519b05402c7adea7d930f2a96b3d4e97fb9cb44b6b66325b7e8cb7908f`.
Live source reads, SMTP, IMAP и OpenRouter не выполнялись. Canonical evidence v2 hash:
`96541d2a5589607890fe7e31ae2a2fc151cce02c62d37d9cc5b71b0f31133bde`.

Открытых воспроизводимых P0/P1 в §42.3(5) cap=1 lane нет. Честное ограничение:
использован существующий явно принятый владельцем `crm` credential, поэтому
`credential_isolation_limited=true`. Расширение `1 → 5` не активировано и требует
нового отдельного owner approval/checkpoint.

## Исторический checkpoint 22.08.2026 — live read-only Bitrix graph preflight

Этот раздел фиксирует pre-cap1 snapshot и заменён более новым checkpoint выше;
его `NO-GO/canary_ready=false` не описывает текущий финальный state.

Закрыт production-critical P1 для graph mapping/preflight без активации CRM
canary. Site, Source и reviewed-opportunity commercial bridges передают один
sealed mapping manifest, exact source lineage и заранее закреплённый immutable
Activity deadline во все реальные Company → Contact → Deal → Activity пути.

- canonical deployment input sealed hash:
  `c77b349a8322d3682b535e8fe2cac31b65e80601928817ff3f048117c31fba36`;
  mapping manifest hash:
  `490ccc858c26b96908d17f4a0210606c8784f4818d5f1d6c139b0f7562fe7512`;
- по явному разрешению владельца создано ровно 38 недостающих Bitrix UF:
  Company `3`, Contact `2`, Deal `33`. Повторная полная reconciliation создала
  `0` и подтвердила existing `38`; UF plan hash
  `4c9061bd760d8101a9aa4accf05d86dd81576e7745b73e78c4c4eeb27dafa7e6`;
- live read-only preflight выполнил 56 allowlisted чтений, сверил 57 обязательных
  полей, route/source/owner, readback-capabilities и пустые exact correlation
  probes Company/Contact/Deal. Все пять checks зелёные; report hash
  `cfed5d671ffe2bb73fbdf97dc5cb7ecd8c09caf49b07abaf14852715e11e9cc6`;
- default-off graph runtime имеет action-bound create/get/reconcile boundary и
  запрещает повторный create при ambiguous outcome. Он не активировался:
  Company/Contact/Deal/Activity создано `0`, canary activation `false`;
- concrete Windows quiesce provider прошёл реальный bounded smoke:
  capture `OK`, quiesced readiness `OK`, restore `OK` с первой попытки.
  После bracket подтверждены active legacy poll, `tb_bot` и HKCU autorun;
  запланированные задачи не отключались постоянно. Команды, PID, пути и receipt
  не попадают в ошибки или аргументы PowerShell;
- live evidence canonical hash:
  `43a876829663ebea59423a7892d57fe8083d67e3d6c6968acc3ff2cd47e62e01`.

Финальные gates на текущем состоянии:

- Bitrix/Site/Source/CRM/Windows adjacent: **373/373 — `OK`**;
- targeted regression после финальных lint-fixes: **117/117 — `OK`**;
- полный Lead Factory discover: **839/839 — `OK`**;
- TaskBot: **13/13 — `OK`**; полный `ruff check lead_factory tests` и
  `compileall lead_factory taskbot` — `OK`;
- test-only Ed25519 attestation dependency закреплена как
  `cryptography>=46.0`; targeted manual evidence/parser: **26/26 — `OK`**.

Каноническая `state/lead_factory_stage.sqlite3` снова проверена только через
`mode=ro&immutable=1`: размер `598016`, schema `13`, `quick_check=ok`,
foreign-key violations `0`, WAL/SHM отсутствуют, SHA-256
`01c477519b05402c7adea7d930f2a96b3d4e97fb9cb44b6b66325b7e8cb7908f`.
`external_writers_enabled=0`; canonical DB не мигрировалась и не записывалась.
SMTP/IMAP/OpenRouter и live source reads не выполнялись.

Открытых воспроизводимых P0/P1 в §42.3(5) code/preflight checkpoint нет.
Отдельный live-activation lane имеет перечисленные ниже P1 gates. Ограничение
остаётся явным: текущий owner-approved webhook имеет более широкие права, поэтому
`credential_isolation_limited=true`, `canary_ready=false`. Создание реальных
Company/Contact/Deal/Activity и canary `1 → 5` требуют отдельного явного owner
approval именно на CRM-сущности; до него production writer остаётся default-off.

### Owner approval для cap=1 — activation gate 22.08.2026

Владелец дал отдельное разрешение на первый live CRM canary. Разрешение записано
как полученное, но само по себе не обходит технические fail-closed gates.
Read-only `scope` probe двух имеющихся credential выполнен в reversible Windows
bracket и восстановлен: credential различаются, основной имеет только `crm`
scope, второй имеет `crm` и ещё 66 scopes. Dedicated minimal write credential
не доказан; внешних CRM write и activation не было.

Offline activation rehearsal — **56/56 `OK`**. Live gate остаётся `NO-GO` по
четырём точным причинам: отсутствуют разрешённый canonical schema17 cutover,
durable four-operation graph canary controller, dedicated minimal write
credential и exact cap=1 candidate/scope. Evidence hash после фиксации approval
и scope probe:
`01315d7d5d7faedb22a8715e3dc41d85ddcd306fd2c13e53048f9b972ef53ad0`.

## Проверено 21.08.2026 — §42.3(5) offline Bitrix graph bridge binding

Закрыт следующий offline integration gap §42.3(5) на disposable schema-17
fixtures. Никакой live Bitrix preflight, canary activation, HTTP/API-вызов или
writer authority этим checkpoint не создаются.

- `BitrixGraphBridgeBinding` держит sealed manifest, exact LF source и
  authority-bound immutable Activity `DEADLINE`. Site и Source commercial
  bridges включают эти три факта в typed approval receipt, immutable evidence
  anchor и все четыре staged CRM-operation metadata; retry воспроизводит срок,
  а не вычисляет его от wall-clock;
- Site использует union manifest для полного commercial context, а Source
  добавляет exact opportunity/source-event/source-id payload binding. При
  cross-source reuse исходные Deal/Activity source и deadline берутся только
  из receipt-bound creator anchor: второй источник не переписывает provenance;
- offline graph preflight теперь может породить только fixed evidence plan
  `1 → 2 → 3 → 4 → 5`. Он сохраняет `live_calls_performed=0`,
  `external_writes_performed=0`, `live_preflight_ok=false`,
  `activation_permitted=false`; попытка `activate()` всегда отклоняется.

Проверки этого checkpoint:

- Bitrix mapping/preflight/canary + Site/Source bridge targeted: **86 tests,
  75 subtests — OK**;
- composed cross-source, first-queue reconciliation и commercial E2E:
  **OK** (пустой `lastfailed` после финального запуска); first-queue отдельно
  **14 tests, 18 subtests — OK**;
- финальный полный `tests` regression после всех исправлений — **OK** (пустой
  `lastfailed`); повторный expensive gate на неизменённом состоянии не нужен;
- `compileall` для `lead_factory`, `taskbot`, `tests` и scoped `ruff` всех
  изменённых файлов — **OK**.

Полный `ruff` по всему workspace всё ещё сообщает 7 несвязанных старых
замечаний в TaskBot/legacy модулях; они не относятся к этому checkpoint.
Live Bitrix read-only preflight и canary `1 → 5` требуют явного owner approval,
отдельного sealed live controller и credential boundary. До этого
`FAST_COMMERCIAL_SLICE_READY` и внешняя writer authority не присваиваются.

## Проверено 21.08.2026 — composed first-queue reconciliation, phase 2

Закрыт offline composed acceptance gate §42.3(6) на одной временной schema-17
БД. Это доказательство не создаёт production authority, transport или FAST.

- phase-1 prefix остаётся ровно 104 immutable Event; один reviewed Site graph
  проходит `APPROVE` → отдельный commercial graph → четыре offline `SENT` CRM
  operations с четырьмя точными transport attestations → `SCREENED`; три
  enriched Wave source дают один creator и два reuse, четыре `PENDING` CRM
  operations. Финальное состояние: 167 Event, 19 открытых review, flags `0`;
- reconciliation вычисляет Radar evidence, Source Lab и пустой manual-import
  ledger hashes в одной `mode=ro&immutable=1`, `query_only=1`, `BEGIN` snapshot
  transaction и включает их в signed report. Hashes не захардкожены;
- backup/restore проверяет exact backup table counts без `schema_meta`, schema
  marker `17`, stage environment, пустой evidence summary/archive/restored
  directory, source-lab/Radar/manual ledger bindings и artifact stamps до/после.
  Restore report теперь также несёт exact Source Lab ledger;
- normalized graph проверяет source event и created-at lineage всех
  Company/Contact/Project/Opportunity rows. Site event hash заново выводится из
  exact `ReviewedOpportunityIntake`, а cross-source creator — из верифицированного
  SourceCommercialBridge source envelope. Resealed подмены lineage или payload
  hash отклоняются;
- Source Lab review request использует injected UTC clock и для immutable review
  event, поэтому queue не получает искусственно future review при deterministic
  replay/fixture execution.

Проверки финального снимка:

- targeted phase-2 reconciliation: **14/14 — `OK`**;
- adjacent phase-1/cross/source/site/queue/CRM/recovery: **142/142 — `OK`**;
- полный offline Lead Factory discover: **802/802 — `OK`**;
- TaskBot: **13/13 — `OK`**; scoped `ruff` и `compileall` с временным pycache —
  `OK`.

Каноническая `state/lead_factory_stage.sqlite3` проверена только через
`mode=ro&immutable=1`: `schema_meta=13`, `PRAGMA user_version=0`,
`quick_check=ok`, foreign-key violations `0`. До/после audit совпали размер
`598016`, mtime и SHA-256
`01c477519b05402c7adea7d930f2a96b3d4e97fb9cb44b6b66325b7e8cb7908f`;
WAL/SHM/journal отсутствуют. Live HTTP/API/Bitrix/SMTP/IMAP/OpenRouter не
вызывались, canonical DB не мигрировалась и не записывалась, legacy scheduled
tasks не изменялись.

`criterion_42_3_6_passed=true`, но `fast_commercial_slice_ready=false`.
Открыты Bitrix graph mapping/live preflight и отдельный canary `1 → 5`; поэтому
никакая live коммерческая готовность или внешняя writer authority не заявляется.

## Проверено 21.08.2026 — immutable first-queue reconciliation, phase 1

Добавлено строгое offline-доказательство сохранности входной части первой
коммерческой очереди. Это phase-1 evidence для §42.3(6), но не закрытие всего
критерия:

- один временный snapshot schema 17 содержит четыре закреплённых Wave 1 pack:
  Tenderplan, Saby Trade, публичные проекты ДОМ.РФ и Контур.Поиск клиентов — по
  2 страницы, 2 записи и 2 открытых review; AT-SITE-01 содержит 20 raw/processed
  deliveries с матрицей `12 ACCEPTED / 4 DUPLICATE / 2 FORM_REJECTED / 2 SPAM`;
- в одном snapshot подтверждены ровно 20 Source Lab records и 20 открытых, ещё
  не назначенных `QUALIFICATION` review. Commercial graph, CRM/outbox и outcome
  projection в phase 1 намеренно пусты;
- exact manifest закрепляет полный schema inventory, глобальный Event ledger
  вместе с rowid/head, Site policy/delivery/evidence/canonical-output bindings,
  Wave 1 contract/fixture/mapping/auth/receipt/import-manifest hashes, raw page
  hashes и cursor chain;
- инспектор использует одну SQLite connection и одну транзакцию через
  `mode=ro&immutable=1` с `query_only=1`. Все три внешних переключателя равны
  нулю, manual-import ledgers пусты, WAL/SHM/journal отсутствуют, а
  size/mtime/SHA исходного файла не меняются;
- deterministic replay возвращает тот же отчёт. Backup/restore schema 17
  сохраняет semantic hash и выбранную lineage; меняются только допустимые
  physical/report hashes и fenced epochs, все внешние переключатели после
  restore остаются выключены;
- проверки корректности отклоняют изменённый manifest/policy/delivery/source,
  незавершённую Site delivery, повреждённый payload, дополнительный Source Lab
  source/review, посторонний Event, скрытый schema object, включение любого
  внешнего switch и полностью переподписанную подмену Wave 1 record благодаря
  внешнему import-manifest binding.

Проверки финального снимка:

- полный offline Lead Factory regression: **788/788 — `OK`**;
- targeted first-queue acceptance: **9/9 — `OK`**;
- независимая смежная проверка: **54/54 — `OK`**; открытых воспроизводимых P0/P1
  в срезе не осталось;
- TaskBot: **13/13 — `OK`**; scoped `ruff` — `OK`; `compileall` для 137 Python-
  файлов `lead_factory`/`taskbot`/`tests` — `OK`.

Публичный отчёт намеренно возвращает `status=PARTIAL_EVIDENCE`,
`intake_reconciliation_status=PASSED`, `criterion_42_3_6_passed=false` и
`fast_commercial_slice_ready=false`. До полного §42.3(6) отсутствуют exact
`BACKUP_RESTORE_COMPOSER`, `COMMERCIAL_GRAPH`, `CROSS_SOURCE_RECONCILIATION` и
`OUTCOME_RECONCILIATION` в одном composed acceptance snapshot. §42.3(5) также
остаётся частично открыт: нужны bindings реальных Site/Source bridges, sealed
read-only Bitrix preflight, production graph transport и canary `1 → 5`.
Реальный сайт не получает статус `SITE_INSTRUMENTED`; durable default-off
`READ_ONLY_API` относится к §42.4. Поэтому `FAST_COMMERCIAL_SLICE_READY` не
присваивается и production/live authority не возникает.

Каноническая `state/lead_factory_stage.sqlite3` повторно проверена исключительно
через `mode=ro&immutable=1` и `query_only=1`: `schema_meta=13`,
`PRAGMA user_version=0`, `external_writers_enabled=0`, writer leases `0`,
`quick_check=ok`, foreign-key violations `0`. Source-read/manual-commit keys в
schema 13 отсутствуют и остаются default-off. До/после audit совпали размер
`593920`, mtime и SHA-256
`65ccbb8c7fba434f3513315db5f7863afee5be8d202dea096235680a2a734b78`;
WAL/SHM/journal отсутствуют.

Live API/HTTP/Bitrix/SMTP/IMAP/OpenRouter не вызывались; canonical schema 13 не
мигрировалась, Scheduled Tasks не останавливались и не изменялись.

## Проверено 21.08.2026 — offline Bitrix graph mapping/preflight `DRAFT_OFFLINE`

Закрыт bounded offline-разрыв первой половины §42.3(5): добавлены точный
versioned mapping-контракт и offline schema preflight для локального графа
Company → Contact → Deal → Activity. Срез не содержит HTTP, credentials,
production transport или live controller, не меняет schema и не заявляет
готовность canary/Bitrix.

- `BitrixGraphMappingManifest` имеет exact lifecycle `DRAFT_OFFLINE`, evidence
  mode `OFFLINE_FIXTURE`, portal identity, mapping/route/source bindings и
  canonical declared hash. Изменение порядка, поля, маршрута, source или hash
  отклоняется до построения provider-команды;
- `CrmGraphOutbox` теперь может неизменно привязать mapping-manifest hash ко всем
  четырём операциям и source ID только к Deal/Activity. Company/Contact остаются
  source-neutral, поэтому их можно безопасно переиспользовать для другой
  возможности. Additive request повторно доказывает local identity, source event,
  idempotency, полный command seal и exact graph identities;
- mapper принимает реальные requests из `CrmGraphOutbox`, а не отдельный
  упрощённый fixture. Он сам добавляет Company/Contact/Deal parents, route,
  assignee и `SOURCE_ID`, переводит email/phone в Bitrix multifield и формирует
  opaque Activity marker. Activity требует заранее сохранённый UTC-seconds
  `DEADLINE`; retry не вычисляет срок от текущего времени;
- Company/Contact/Deal correlation lookup связан с exact operation и LF identity,
  возвращает только один bounded candidate, после чего обязателен GET/readback.
  Activity lookup намеренно остаётся `SafeReconciliationUnsupported`: без
  доказанного provider search повторный create запрещён;
- readback перепроверяет exact remote type, ASCII positive remote IDs, все parent
  slots и каждое mapping-owned поле, включая Deal route/source и Activity
  responsible/ping/color/marker. Receipt и mapping objects имеют redacted repr;
- отдельный hashed `BitrixGraphSchemaSnapshot` сверяет полный field inventory,
  route/category/stage, активных ответственных, source IDs, mapped-field и
  relation-readback capabilities, а также три unused correlation probe,
  выведенные из exact Company/Contact/Deal LF identities. Успешный offline report
  всегда сохраняет `live_calls_performed=0`, `external_writes_performed=0`,
  `live_preflight_ok=false`, `canary_ready=false`;
- adversarial-проверки отклоняют post-seal payload mutation, ложный Project ID,
  unknown Activity source, Unicode/leading-zero remote ID, подменённые
  create/lookup plan, unsafe GET method, неверный source-plan hash, изменённый
  Activity route и provider readback с правильной identity, но неверными
  business/route полями. Фактическая зависимость Activity
  Company+Contact+Deal закреплена end-to-end fixture через настоящий outbox и
  offline mapper-backed transport.

Проверки финального снимка:

- полный offline Lead Factory regression: **779 тестов — `OK`**;
- mapper/preflight + CRM graph targeted: **53/53 — `OK`**; смежные
  source/site commercial bridges, cross-source, old Bitrix preflight/canary/REST:
  **141/141 — `OK`**;
- независимая повторная проверка исходных probes: **52 теста с 61 subtests —
  `OK`**; открытых воспроизводимых P0/P1 в срезе не осталось;
- TaskBot: **13/13 — `OK`**; scoped `ruff` и `compileall` для `lead_factory`,
  `taskbot`, `tests` — `OK`.

Каноническая `state/lead_factory_stage.sqlite3` после среза повторно проверена
только через `mode=ro&immutable=1`: `schema_meta=13`,
`PRAGMA user_version=0`, `external_writers_enabled=0`, source-read/manual-commit
keys в schema 13 отсутствуют и остаются default-off, `query_only=1`,
`quick_check=ok`. До/после audit совпали размер `593920`, mtime и SHA-256
`65ccbb8c7fba434f3513315db5f7863afee5be8d202dea096235680a2a734b78`;
WAL/SHM/journal отсутствуют. Последний факт по-прежнему `inbound_received` от
активного `legacy_dealer_poll` (`occurred_at_utc=2026-08-21T08:14:35Z`,
`recorded_at_utc=2026-08-21T08:19:36Z`). Scheduled Tasks не останавливались и не
изменялись.

Ограничитель среза: текущие реальные Site/Source commercial bridges ещё не
передают manifest/source binding и immutable Activity deadline; текущий fixture
manifest покрывает только базовые поля и один offline source. SLA следующего
действия в контракте остаётся `TBD`, поэтому срок не был придуман автоматически.
Нужны отдельные union manifest, authority-bound deadline, sealed read-only REST
preflight, production graph transport и новый graph canary `1 → 5`. Старый
Lead→Activity canary это не доказывает. Поэтому §42.3(5) остаётся частично открыт,
а `FAST_COMMERCIAL_SLICE_READY` не присваивается. Live
API/HTTP/Bitrix/SMTP/IMAP/OpenRouter не вызывались.

## Проверено 21.08.2026 — offline `AT-SRC-PAR-01`

Закрыт offline integration-разрыв §42.3(3): на временной schema 17 БД три
независимых source-evidence цепочки сходятся в один нормализованный коммерческий
граф без потери provenance и без смешивания source metrics. Новый
`cross_source_reconciliation` принимает exact manifest из трёх отсортированных
source ID, сильного project identity и трёх typed policy/approval-receipt bindings,
после чего только через `mode=ro&immutable=1` и `query_only` сверяет schema,
Source Lab integrity, граф и выключенные safety switches.

- enriched `OFFLINE_FIXTURE` для `wave1:domrf_public_projects`,
  `wave1:saby_trade` и `wave1:tenderplan` проходит Radar
  passport/permit/evidence → import → review queue claim/`APPROVE` → commercial
  bridge. Это специально обогащённые contact-bearing fixtures, а не текущие
  pinned public двухстраничные Wave 1 packs;
- три раздельные record/observation/review/resolution/evidence/anchor цепочки
  сходятся ровно в одну Company/Contact/Project/Opportunity: один source создаёт
  graph, два его переиспользуют. `source_slices` остаются отдельными; одинаковый
  ИНН без сильного project identity не сливает разные проекты;
- формируются ровно четыре untouched `PENDING` CRM graph operations
  Company → Contact → Deal → Activity с точными dependencies и creator
  causation. Attempts/reconcile/mappings равны 0; remote/error/lease/suspect
  поля пусты. Public payload заново выводится из normalized graph, поэтому
  согласованная подмена outbox вместе с пересчитанным stage-anchor и изменение
  любого operational поля отклоняются fail-closed;
- latest review/resolution, exact policy/source/request/receipt, commercial
  anchor и creator/reuse lineage перепроверяются. Shadow/rehashed anchors,
  поздний `REJECT`, переставленные creator flags и подменённые hashes/receipts
  отклоняются;
- exact replay не создаёт новых фактов и сохраняет report hash; backup/restore
  v17 возвращает тот же report при switches-off. Reconciliation не меняет
  размер, mtime или SHA БД и не создаёт WAL/SHM/journal;
  `live_calls_performed=0`;
- Site commercial bridge теперь принимает для exact company match только ИНН из
  10/12 цифр с допустимым форматированием пробелами/дефисами. Текстовая обёртка
  вокруг цифр уходит в `REVIEW / EXACT_COMPANY_IDENTITY_REQUIRED` без graph
  writes.

Проверки финального снимка:

- полный offline Lead Factory regression: **757 тестов — `OK`**;
- текущий targeted: **25/25 — `OK`**; смежные Source Lab/review queue/commercial
  bridge/recovery: **108/108 — `OK`**;
- независимая проверка: **13 тестов с 18 adversarial subtests — `OK`**;
  отдельный adjacent набор: **62/62 — `OK`**; открытых воспроизводимых P0/P1 в
  срезе не осталось;
- TaskBot: **13/13 — `OK`**; scoped `ruff` и `compileall` для `lead_factory`,
  `taskbot`, `tests` — `OK`.

Каноническая `state/lead_factory_stage.sqlite3` повторно проверена только через
`mode=ro&immutable=1`: `schema_meta=13`, `PRAGMA user_version=0`,
`external_writers_enabled=0`, source-read/manual-commit keys в schema 13 физически
отсутствуют и остаются default-off, `query_only=1`, `quick_check=ok`. До/после
финального audit совпали размер `593920`, mtime и SHA-256
`65ccbb8c7fba434f3513315db5f7863afee5be8d202dea096235680a2a734b78`;
WAL/SHM/journal отсутствуют. Этот снимок отличается от предыдущего BUILD
checkpoint: последний новый факт — `inbound_received` от активного
`legacy_dealer_poll` (`occurred_at_utc=2026-08-21T08:14:35Z`,
`recorded_at_utc=2026-08-21T08:19:36Z`). Код текущего среза миграцию и запись в
canonical DB не выполнял; Scheduled Tasks не останавливались и не изменялись.

Срез закрывает generic offline-критерий §42.3(3), но не доказывает реальное
пересечение текущих pinned public Wave 1 packs между собой или с Site и не
присваивает `FAST_COMMERCIAL_SLICE_READY`. Остаются graph Bitrix
mapping/preflight/canary `1 → 5` §42.3(5), общий first-queue reconciliation gate
§42.3(6), реальный `SITE_INSTRUMENTED`, production authority/controller/RBAC и
durable default-off `READ_ONLY_API` §42.4. Legacy tasks остаются cutover blocker.
Live API/HTTP/Bitrix/SMTP/IMAP/OpenRouter не вызывались.

## Проверено 21.08.2026 — offline Source Lab review-очередь

Закрыт следующий integration-разрыв §42.3(4): Wave 1 и Site review теперь попадают в
единую durable локальную очередь, где решение можно принять только владельцем актуального
claim. Срез работает на существующей schema 17, не содержит UI/HTTP/live adapters и
проверяется только на временных БД:

- добавлен `source_review_queue` поверх существующего append-only Event Store. Один
  snapshot-list показывает ровно 20 открытых `QUALIFICATION` review из текущих FAST
  fixtures: 8 Wave 1 и 12 AT-SITE-01. Есть source/kind filters, bounded keyset pagination,
  точный upper event anchor и epoch-bound cursor; raw Source Lab payload и lease token в
  item/repr не выдаются;
- `claim`, `assign`, `reclaim` и `resolve_claimed` выполняются под `BEGIN IMMEDIATE`.
  Command/state hashes, idempotency, bounded lease, monotonic fence, exact assignee,
  requester/reviewer separation и source-read epoch перепроверяются внутри write-
  транзакции. Два одновременных claimant дают одного владельца; expired, restored,
  stale, clock-rollback и permit с нестрогими JSON/Python types отклоняются до решения;
- schema 17 больше не разрешает создать новый Source Lab resolution прямым публичным
  вызовом ни до, ни после первого claim. Решение записывается только queue-owned командой,
  которая атомарно добавляет immutable Source Lab resolution и точный queue binding.
  `NEEDS_RESEARCH` допускает новый fenced claim и следующую superseding decision;
  terminal correction оформляется новым review. Исторический schema 16 append-only
  resolution contract и exact replay старого факта сохранены;
- Site review связан с уже созданной `SITE_QUALIFICATION` задачей Диме. Первый self-claim
  атомарно переводит task в `ACKNOWLEDGED`, любое решение фиксирует first human action,
  `NEEDS_RESEARCH` оставляет task `IN_PROGRESS`, а `APPROVE`/`REJECT`/`HOLD` завершает её
  с exact review/resolution pointer. Параллельный публичный `HumanTaskController` не может
  создать вторую версию lifecycle до или после queue claim;
- queue-owned resolution timestamp канонизируется до UTC seconds и принимается reviewed
  Site commercial bridge. Site fixture после queue `APPROVE` по-прежнему проходит
  Company → Contact → Project → Opportunity → CRM graph fixture и offline outcome до
  `SCREENED`; внешнего CRM-вызова нет. Public-only Wave 1 после `NEEDS_RESEARCH` сохраняет
  0 Company/Contact/Project/Opportunity/CRM writes;
- Source Lab semantic recovery ledger включает точную queue-chain и full-row hashes её
  queue/task companion events. Проверяются chronological row order, event envelope,
  evidence, reason policy, SoD, task owner/state и resolution binding. Queue fact внутри
  authoritative schema 16, изменённый task envelope, repaired outer hash и queue event до
  review request отклоняются до backup/restore publication;
- restore ротирует `source_read_epoch`: старые cursor/permit становятся недействительны,
  незавершённый claim явно `RECLAIMABLE`, terminal review не возвращается в open list.
  External writers, source reads и manual commits остаются выключенными; schema не менялась.

Проверки финального снимка:

- полный offline Lead Factory regression: **743 теста — `OK`**;
- queue unit/integration: **22 теста — `OK`** в составе финального regression;
- независимая финальная проверка queue/site/source/recovery: **75 тестов — `OK`**;
  отдельно queue → Site commercial → offline outcome E2E: **1 тест — `OK`**;
- ранее выполненный смежный срез Wave 1/AT-SITE/Source Lab/commercial/recovery:
  **182 теста — `OK`**; после двух финальных boundary-исправлений весь набор повторно
  покрыт полным regression;
- TaskBot: **13 тестов — `OK`**; `compileall` для `lead_factory`, `taskbot` и `tests` — `OK`;
- scoped `ruff` для queue/site/Wave 1 модулей и изменённых тестов — `OK`.

Каноническая `state/lead_factory_stage.sqlite3` проверена только через
`mode=ro&immutable=1`: `schema_meta=13`, `PRAGMA user_version=0`,
`external_writers_enabled=0`, source-read key в schema 13 физически отсутствует и поэтому
остаётся default-off, `quick_check=ok`. До/после совпали размер `589824`, mtime и SHA-256
`ad6826c13dd928e4f956cf769ce2e649bff701caac45c43bb0a6fddda342af50`; WAL/SHM не
появились. Миграция и запись в canonical DB не выполнялись. Legacy Scheduled Tasks не
останавливались и не изменялись.

Этот срез закрывает offline-критерий §42.3(4) на уровне кода и fixtures, но не присваивает
`FAST_COMMERCIAL_SLICE_READY`. Queue principals пока являются строго проверяемыми строками,
а не authenticated production identity: RBAC/SSO, production authority/controller/UI и
отдельный durable enrollment registry отсутствуют. Event-only очередь опирается на
существующие immutable Event Store triggers и поэтому не является production cutover
authority. До FAST остаются integrated cross-source acceptance §42.3(3), общий first-queue
reconciliation gate §42.3(6) и graph Bitrix mapping/preflight/canary `1 → 5` §42.3(5);
реальный сайт всё ещё не имеет `SITE_INSTRUMENTED`. Durable default-off `READ_ONLY_API`
control plane относится к §42.4. Live API/HTTP/Bitrix/SMTP/IMAP/OpenRouter не вызывались.

## Проверено 21.08.2026 — offline AT-SITE-01 и SLA-задача

Закрыт следующий ранний integration-разрыв §42.3(2): transport-neutral site delivery
теперь фиксируется до проверки формы, а уникальная валидная заявка доходит до Source Lab,
ручной review и локальной SLA-задачи Диме. Срез не содержит HTTP/browser/analytics/Bitrix
адаптеров и проверяется только на временных schema 17 БД:

- добавлен `site_delivery_intake`. Он принимает exact canonical JSON bytes не более 128 KiB
  и до разбора формы пишет отдельный append-only `site_raw_delivery_captured` fact с
  delivery/source ID, hash, размером, временем и immutable evidence reference. Сами
  непроверенные bytes и PII в Event Store не копируются; exact replay обязан предъявить те
  же bytes и проходит сверку с сохранённым hash;
- raw capture коммитится отдельно и раньше downstream-обработки. Если процесс падает после
  capture либо перед вторым commit, audit показывает ровно одну pending delivery; повтор с
  теми же bytes достраивает цепочку без второго raw fact, Source Lab record, review или task;
- `SourceLabSink.ingest_record_with_review()` в одной существующей schema 16+ транзакции
  пишет site record и одну immutable `QUALIFICATION` review. В той же downstream-транзакции
  создаются один synthetic `SITE/INBOUND` Interaction без Company/Contact/Opportunity и одна
  `human_tasks(kind=SITE_QUALIFICATION, assigned_to=dima)`; внешний CRM writer не нужен;
- AT-SITE-01 fixture содержит ровно 20 разных delivery ID: 12 уникальных валидных форм,
  4 повтора тех же submission ID, 2 honeypot spam и 2 отказа consent. Итог: 20 raw facts,
  20 terminal processed facts, 12 canonical records, 12 reviews, 12 interactions и 12 tasks.
  Original/latest UTM, `yclid`, click ID, landing/form/offer versions и оба consent artefact
  совпадают; повторы, spam и отказ не создают canonical/task дубли;
- exact replay повторно проверяет raw/processed Event Store envelope, полный Source Lab
  integrity, persisted record/observation/review/interaction/task lineage, trusted assignee
  и SLA scope. Подмена task ID, assignee, SLA, policy/canonical projection либо reused
  delivery ID отклоняется fail-closed;
- непроверенный submission ID из spam/invalid body не попадает ни в result, ни в events;
  delivery evidence reference применяет тот же запрет secret-like значений, `?` и `@`, что
  и site ingress. Audit корректно разделяет несколько site source и игнорирует старые
  legacy SiteIngress records того же source, не теряя coordinator-owned lineage;
- backup/restore schema 17 сохраняет raw→processed→Source Lab→review→Interaction→task цепочку,
  оставляет writers/source reads выключенными и после restore даёт тот же audit без ошибок.

Проверки финального снимка:

- полный offline Lead Factory regression: **721 тест — `OK`**;
- targeted AT-SITE-01: **8 тестов — `OK`**;
- adjacent site ingress/Source Lab/commercial path: **69 тестов — `OK`**;
- независимая проверка корректности: **84 теста — `OK`**; отдельно подтверждены rejection
  подменённого lineage, чистый multi-source/legacy audit и отсутствие PII в raw facts;
- TaskBot: **13 тестов — `OK`**; `compileall` для `lead_factory` и `taskbot` — `OK`;
- scoped `ruff` для изменённых модулей и acceptance-тестов — `OK`.

Каноническая `state/lead_factory_stage.sqlite3` повторно открывалась только через
`mode=ro&immutable=1`: `schema_meta=13`, `PRAGMA user_version=0`,
`external_writers_enabled=0`, `quick_check=ok`; размер и mtime не изменились, WAL/SHM
отсутствуют. Schema/migration и запись в неё не выполнялись. Legacy Scheduled Tasks не
останавливались и не изменялись.

Этот срез доказывает offline AT-SITE-01 и закрывает §42.3(2) на уровне кода/fixtures, но не
присваивает реальному сайту статус `SITE_INSTRUMENTED`: deployed mobile form, phone/chat,
пользовательское сообщение об ошибке и реальная доставка ещё не проверялись. Текущий task
due использует 240 elapsed minutes; рабочий календарь/timezone и метрики человеческого SLO
из §15.4 остаются отдельным operational gap. До `FAST_COMMERCIAL_SLICE_READY` также остаются
operational review queue, integrated cross-source acceptance и graph Bitrix
mapping/preflight/canary `1 → 5`. Durable default-off `READ_ONLY_API` относится уже к §42.4.
Live API/HTTP/Bitrix/SMTP/IMAP/OpenRouter не вызывались.

## Проверено 21.08.2026 — offline Wave 1 → Source Lab → review

Закрыт более ранний integration-разрыв FAST-среза: четыре уже закреплённых Wave 1
fixture-контракта теперь доходят от точного двухстраничного collector до durable Source
Lab batch и открытых заявок на ручную квалификацию. Срез остаётся строго offline-only и
проверяется только на временных schema 17 БД:

- добавлен двухфазный `source_wave1_ingest`: collector сначала проверяет registered
  contract, exact manifest/page hashes, authorization/receipt, cursor, quota и terminal
  page, затем формирует канонические bytes. Отдельная persistent Radar-цепочка
  `passport → OFFLINE_FIXTURE permit → evidence receipt` должна связать именно эти bytes
  до commit;
- prepared batch хранит точный parsed manifest, исходные pinned page bytes, redacted
  offline authorization/receipt и оба `SourcePageReceipt`. Перед записью граница повторно
  материализует страницы из исходных bytes через тот же `Wave1OfflineFixtureBoundary` и
  `SourceAdapterRuntime` на историческом fixture-clock и требует полного совпадения
  receipts. Подмена normalized payload с пересчитанными content/seal hashes поэтому
  отклоняется до Source Lab;
- каждый persisted `source-import-record-v2` сохраняет provider/product, raw page hash,
  contract/mapping hashes, adapter authorization/receipt/page hashes, cursor chain,
  page sequence и exact company INN identity. Person/email/phone/raw URL не добавлялись;
- `SourceLabSink.ingest_batch_with_reviews()` одной существующей schema 16+
  транзакцией записывает весь persistently-authorised batch и по одной immutable
  `QUALIFICATION` review на запись. Сбой на второй review откатывает run, batch, records,
  observations, reviews и Event Store facts; точный повтор создаёт всё один раз;
- acceptance на четырёх реальных fixture packs подтверждает 4 batch, 8 records,
  8 observations и 8 reviews, exact replay без дублей, 0 Company/Contact/Project/
  Opportunity/CRM/outbox writes и выключенные external switches. Backup/restore v17
  сохраняет batch/review связи и после restore оставляет writers/source reads/manual
  commits выключенными;
- schema не менялась: кодовый кандидат остаётся additive schema 17. Старый v15 permit
  по-прежнему физически допускает только `OFFLINE_FIXTURE`; `DRAFT_OFFLINE`, exact fixture
  hashes и отсутствие HTTP/endpoint/credentials/`READ_ONLY_API` не ослаблены.

Проверки финального снимка:

- полный offline Lead Factory regression: **713 тестов — `OK`**;
- targeted/adjacent Wave 1 + Source Import + Source Lab: **62 теста — `OK`**;
- независимая повторная проверка подменённого и заново запечатанного receipt:
  **7 тестов — `OK`**, 0 Source Lab rows/events на отказе;
- TaskBot: **13 тестов — `OK`**; `compileall` для `lead_factory` и `taskbot` — `OK`;
- scoped `ruff` для изменённых модулей и нового acceptance-теста — `OK`.

Каноническая `state/lead_factory_stage.sqlite3` открывалась только через
`mode=ro&immutable=1`: `schema_meta=13`, `PRAGMA user_version=0`,
`external_writers_enabled=0`, `quick_check=ok`; WAL/SHM отсутствуют. Миграция и запись в
неё не выполнялись. Legacy Scheduled Tasks не останавливались и не изменялись.

Этот срез продвигает §42.3(1), (3), (4) и (6), но сам по себе ещё не означает
`FAST_COMMERCIAL_SLICE_READY`: public-only Wave 1 records намеренно не содержат contact
email и пока не могут пройти существующий commercial bridge; также остаются отдельные
gaps AT-SITE-01, graph Bitrix canary/preflight и durable default-off `READ_ONLY_API`
control plane. Live API/HTTP/Bitrix/SMTP/IMAP/OpenRouter не вызывались.

## Проверено 20.08.2026

Собран следующий offline-срез технического ядра. Он проверяется только на временных
SQLite-БД и fixtures и пока не является разрешением на подключение живых источников или
CRM:

- текущий кандидат кода — additive schema 17. Он сохраняет schema 16 Source Lab
  неизменной и добавляет отдельный, пока физически выключенный контур ручного импорта.
  Source Lab принимает уже полученные разрешённым способом записи в одной локальной
  транзакции и сохраняет неизменяемые run/batch/record/observation, точную provenance,
  идемпотентность и exact identity-связи между источниками. Email и телефон в
  identity-ключах хэшируются; fuzzy merge не выполняется;
- review, его последовательные resolution-факты и связь source evidence с Opportunity
  append-only. `v15 → v16` и `v16 → v17` выполняются только явными миграциями; обычный
  `init()` не обновляет существующие v13/v14/v15/v16;
- backup/restore поддерживает v13–v17 и проверяет точный набор таблиц, индексов,
  триггеров и views, DDL каждой управляемой таблицы, точный versioned manifest,
  семантические ledgers и Event Store anchors. Публикация backup/restore выполняется
  без перезаписи уже существующих целей: изменение staging, появление чужого файла или
  сбой любого шага оставляют 0 собственных частичных итогов. Restore сохраняет внешние
  switches выключенными и ротирует source/manual epochs ровно на `+1`;
- AlumKomplekt site ingress принимает уже захваченную B2B-форму без HTTP-клиента и
  требует отдельный versioned `TrustedSitePolicy`: exact source/origin/path, версии
  form/landing/offer и точный hash текста consent. Сохраняются original/latest UTM и
  явные `PAID`/`ORGANIC`/`DIRECT`/`REFERRAL`; replay идемпотентен, а изменённые факты под
  тем же submission ID отклоняются;
- URL с незарегистрированными host/path/query, secret-like параметрами, неподтверждённой
  версией deployment или consent отклоняется до Source Lab. Технические ошибки и `repr`
  не выводят контактные данные или токены;
- добавлен reviewed Site → Commercial bridge. Точная `site-form-submission-v1` после
  latest `APPROVE` и отдельного typed authority может одной schema17-транзакцией создать
  Company, Contact, Project, Opportunity, evidence anchor и четыре зависимые CRM-команды.
  ИНН и email должны быть точными данными подтверждённой человеческой проекции: phone-only
  или отсутствующая Company identity остаются в `REVIEW` с 0 commercial writes. HOLD,
  superseded review, изменение payload/policy/identity, event envelope или bound timestamp
  отклоняются до CRM. Fixture-only путь доходит до CRM outcome `SCREENED`; живой Bitrix
  при этом не вызывается;
- новый transport-neutral CRM graph outbox атомарно ставит цепочку
  `Company → Contact → Deal → Activity` с точными parent dependencies. Writer/STOP/canary
  gates перепроверяются перед adapter call; потерянный или неоднозначный create не
  повторяется вслепую и требует exact correlation readback;
- добавлен transport-neutral Source Adapter SDK без HTTP/credentials: каждая страница
  привязана к versioned authorization receipt, cursor и лимитам. Runtime-owned bounded
  collector не принимает лишние records/bytes, параллельный запрос той же позиции
  блокируется, а STOP фиксируется даже во время зависшего boundary-call. Полученный после
  STOP результат остаётся `UNCERTAIN` и не двигает cursor/quota ledger;
- добавлен Wave 1 contract/fixture pack для четырёх разных продуктов: Tenderplan,
  Saby Trade, публичные проекты ДОМ.РФ и Контур.Поиск клиентов. Для каждого закреплены
  synthetic two-page manifest/page hashes, contract/mapping version, cursor и строгий
  public-only normalized envelope без person/email/phone/raw URL. Boundary требует точные
  `AdapterAuthorization` и receipt, `BUSINESS_PUBLIC`, OFFLINE_FIXTURE и mapping evidence
  hash до чтения первой страницы. Все четыре контракта имеют статус `DRAFT_OFFLINE`;
  `READ_ONLY_API`, endpoint, credentials и HTTP намеренно отсутствуют до утверждения
  официальных схем, лицензий и отдельного persistent live-control plane;
- добавлен bytes-only импорт `CSV`/`XLSX`/`JSON`/`JSONL` с точным mapping contract,
  manifest/content/row hashes и жёсткими лимитами. `JSON`/`JSONL` принимаются только как
  strict UTF-8; XLSX с macro/dialog/ActiveX/external content отклоняется. Весь batch
  предварительно проверяется и записывается одной транзакцией: ошибка последней строки
  оставляет 0 строк;
- Source Import v2 допускается только через атомарный batch API и persistent цепочку
  `passport → permit → evidence receipt → immutable event`. Один receipt разрешает один
  exact manifest; epoch/latest/revocation/expiry перепроверяются внутри write-транзакции.
  Существующий v16-контур разрешает только `OFFLINE_FIXTURE`; он не был ослаблен ради
  `MANUAL_IMPORT`, а live API по-прежнему fail-closed;
- schema 17 добавляет 7 append-only manual-import ledgers и 42 точных schema objects,
  но `manual_import_commits_enabled` физически допускает только `0`. Разрешён только
  класс `BUSINESS_PUBLIC`; пути, URL, credentials, ключи и исходные байты в ledgers не
  сохраняются. Ручная загрузка может дойти только до `PREPARED` и останавливается с
  `PERSISTENCE_BLOCKED_SCHEMA_17_NO_DURABLE_CONTROLLER`;
- bytes-only vault и parser реализованы только как явно `TEST_ONLY` in-memory fixtures.
  Parser сам вычисляет фактическое число и порядок строк, row/batch/manifest hashes,
  принимает только явные `MAP`/`DISCARD` правила и не выпускает PII в plaintext
  projection. Production vault, durable verifier, authenticated operator/approver
  provider, retention service и commit controller отсутствуют, поэтому manual
  persistence намеренно не включена;
- собран offline-only schema cutover rehearsal с exact raw DDL/PRAGMA/inode/content
  fingerprint, one-to-one mailbox mapping, quiescence gates и контролем main/WAL/SHM.
  Источник открывается immutable; новый backup, rollback-restore и миграции выполняются
  только в новых каталогах. Успешный отчёт всегда содержит
  `ready_for_live_cutover=false` и `live_calls_performed=0`;
- выполнена реальная репетиция канонической stage-базы на копиях: отдельный restore
  подтверждён как exact v13, вторая копия последовательно прошла `13 → 14 → 15 → 16`.
  На v16 `external_writers_enabled=0`, `external_source_reads_enabled=0`, active-work
  gates=0, все 9 таблиц Source Lab пусты. Исходная stage-база сохранила SHA-256
  `706b42426f46d4a2b454ac6fe6769ee03a03ef1417a563ae2b2d6762e1c0461e`, размер,
  mtime и inode; WAL/SHM не появились. Доказательство:
  `state/lead_factory/cutover_rehearsals/schema-cutover-rehearsal-1787208542-27741bfbafab/report.json`;
- отдельно выполнена temp-only репетиция `v16 → v17`: один явный migration call,
  точное сохранение всех v16 rows/meta/ledger кроме разрешённого v17 delta, 7 новых
  ledgers пусты, commits/readers/writers выключены, rollback остаётся v16. Отчёт всегда
  имеет `live_calls_performed=0` и `ready_for_live_cutover=false`. Эта репетиция не
  мигрировала каноническую stage-базу;
- approved Source Lab record переводится в commercial graph только через обязательный
  typed approval authority. Строки `resolved_by`/`APPROVE` сами по себе не являются
  полномочием. Bridge создаёт независимый append-only anchor, связывающий observation,
  resolution, authority receipt, strong project identity и Opportunity; обычная или
  поддельная evidence-link не участвует в cross-source dedupe;
- финальная проверка актуального `APPROVE`, writers-off и постановка четырёх CRM-команд
  выполняются под одной `BEGIN IMMEDIATE`. Если между graph commit и CRM staging появляется
  `HOLD`, CRM получает 0 операций. Полный ранее поставленный CRM graph принимается только
  с точным creator resolution event; чужая causation и подмена anchor metadata отклоняются;
- по итогам независимых проверок корректности добавлены strict finite JSON, future-time
  fences, контроль полной immutable Source Lab цепочки, обязательный доверенный site
  registry, запрет provider-owned relationship fields и независимый Event Store anchor
  CRM-команды. Подмена payload/hash/correlation/dependency переводит операцию в ручной
  `REVIEW` до транспорта;
- полный offline Lead Factory regression на финальном снимке: **706 тестов — `OK`**;
  отдельно recovery-набор: **38 тестов и 48 подтестов — `OK`**; отдельно
  **13 тестов TaskBot — `OK`**; `compileall` для `lead_factory` и `taskbot` — `OK`.
  `ruff` для всех новых Wave1/Site bridge модулей и тестов — `OK`.
  Полный `ruff check` сохраняет 8 известных hygiene-замечаний (неиспользуемые
  imports/локальные переменные и один lambda-style), без runtime-дефектов.

Canonical stage намеренно не мигрирована: `schema_meta=13`,
`PRAGMA user_version=0`, `external_writers_enabled=0`, Source Lab и manual-import tables
отсутствуют. Финальная immutable-проверка 20.08.2026 15:51 MSK: `quick_check=ok`, FK violations=0,
WAL/SHM отсутствуют, active-work gates=0, schema SHA-256 `5e97d45a…8300c7a`, file SHA-256
`183122c0…9a48ae`, 92 Event, 41 Interaction и 10 HumanTask. Это текущий снимок, а SHA
`706b…` выше остаётся историческим доказательством прежней репетиции. Legacy scheduled
tasks `ALT_DealerPoll`, `ALT_DealerSend` и `TenderBotWatchdog` всё ещё включены и могут
добавлять старые inbound-факты независимо от switches новой фабрики; перед cutover их
нужно отдельно остановить и доказать quiescence.
External source reads, CRM/Bitrix writers, HTTP/API, SMTP/IMAP, OpenRouter и другие live
services в этом срезе не запускались. Это ещё не `TECH_READY_FOR_CONNECTION`, не
`FAST_COMMERCIAL_SLICE_READY` и не production/canary approval.

## Обновление 19.08.2026 — контракт v5.2 и первая коммерческая очередь

По решению владельца контракт обновлён до v5.2 без расширения на другие бизнесы:

- сайт АлюмКомплект зафиксирован как `SITE_UNPROVEN` с owner-reported нулевым
  доказанным потоком;
- capability tests источников Wave 1 разрешено вести параллельно через единый Source Lab;
- определены отдельные статусы `FAST_COMMERCIAL_SLICE_READY` и
  `TECH_READY_FOR_CONNECTION`, которые не заменяют production/canary и Definition of Done;
- плановый ориентир раннего технического среза — 14–18.09.2026, полного технического
  ядра Wave 1 — 28.09–07.10.2026 при неизменном scope и своевременных решениях.

Это только нормативная и плановая фиксация. Она не утверждает реализацию нового ingress,
сайта, production evidence repository или live adapters. Фактическое защитное состояние
не изменилось: canonical stage остаётся schema 13, external writers и source reads выключены,
Windows readiness — `NO-GO`, реальные API/Bitrix/SMTP/IMAP/OpenRouter не вызывались.

## Обновление 19.08.2026 — offline commercial spine, multimail и Demand Radar v15

Каноническая stage-БД намеренно не мигрирована: она остаётся schema 13 с
`external_writers_enabled=0`. Schema 14 зафиксирована в текущем коде отдельным pinned
checksum/fingerprint; это не утверждение об исторической byte-for-byte неизменности без VCS.
Текущий кандидат кода — additive schema 15, проверяемая только на временных БД и копиях. Любой v14/v15-файл
с неизвестным fingerprint отклоняется. `init()` не обновляет существующую v13/v14 БД:
переходы `v13 → v14 → v15` выполняются только явной миграцией после отдельного cutover gate.

Фактически реализовано offline:

- явная миграция `v13 → v14` под `BEGIN IMMEDIATE`, authoritative `PRAGMA user_version`,
  migration ledger, schema fingerprint, downgrade/future-version fence и crash/race tests;
- реестр ProviderAccount/SendingDomain/MailboxAccount/SenderIdentity/Campaign/Conversation
  без credentials; identity и conversation pinning append-only;
- независимые mailbox cursors/claims, все `In-Reply-To/References`, scoped Message-ID dedupe,
  exact/ambiguous/unmatched routing и registered-mailbox fixture worker;
- атомарные account/domain/mailbox/sender/campaign daily+lifetime reservations, строгий
  envelope, suppression, first-touch/follow-up fences, SENT/RFC Message-ID ledger и
  delivery metrics по domain/identity/campaign;
- нормализованный Company/Contact/Project/Opportunity spine с cross-company invariants,
  typed lifecycle, local Dima task и CRM Lead/Activity outbox только после persisted
  `HUMAN_REPLY` и verified actor binding;
- recovery v14/v15 проверяет schema/ledger/table counts, exact quota semantics и всегда
  восстанавливает writers выключенными; v15 дополнительно проверяет Radar provenance,
  выключает source reads и необратимо продвигает read epoch;
- Construction Demand Radar для `IZHS_SUPPLY_CHAIN`, `COMMERCIAL_OPENING` и
  `CAPITAL_PROJECT`: temporal Object Graph, composite permit/expertise identity,
  time-bound participants, current-revision claims, procurement clocks D14/D30/D60,
  aluminium demand, negative evidence, capacity priority, feedback и consent-first sensor
  ledger;
- Radar source passport отдельно фиксирует capability, licence, validity, data classes,
  data-contract version и Event Store provenance. Adapter boundary содержит только
  `normalize_fixture`; fetch/scrape отсутствуют;
- `SHADOW_READY` не создаёт Opportunity, задачу, CRM operation или Send Permit. Shadow MVP
  требует минимум 100 ручных reviews, сопоставимую baseline и evidence значимого uplift;
  даже успешная локальная оценка сохраняет `commercial_claim_allowed=false`.
- additive v15 добавляет ограниченный offline BLOB-vault Radar (до 256 KiB, content hash,
  allowlist media type, Event/passport/source/time binding), append-only evidenced решение
  review и offline `SourceAccessPermit` с точным passport/data-class scope и атомарными
  лимитами operations/records/bytes/cost;
- только `CONFIRM_CURRENT_OBJECT` может снять exact identity blocker. `KEEP_SEPARATE` остаётся
  `OBJECT_REASSIGNMENT_REQUIRED`, `REJECT_SIGNAL` не разрешает fallback к старой ревизии,
  `NEEDS_RESEARCH` сохраняет review; ни одно решение не создаёт коммерческих side effects;
- `external_source_reads_enabled=0`, а `source_read_epoch` монотонен и ротируется при restore.
  Старые permits после restore непригодны. В срезе разрешён только `OFFLINE_FIXTURE`:
  transport/fetch и API включения живого чтения отсутствуют;
- pinned v14 checksum/current schema spec проверяются отдельным regression; migration/bootstrap/
  read snapshot, recovery и v15 ledgers покрыты duplicate/restart/crash/race/tamper тестами,
  включая два конкурентных fresh `init()`.

Граница v15 намеренно узкая: bounded vault защищает evidence новых review/access ledgers,
но не заменяет все существующие Radar `evidence_ref` и не является encrypted/ACL/retention
document store либо хранилищем с общим quota. Offline `SourceAccessPermit` не является
универсальным gate для `ConstructionDemandRadar.ingest()`; безопасность текущего среза
обеспечена отсутствием fetch/HTTP/credential/live adapter. Этот разрыв блокирует live source.

Независимая проверка корректности закрыла false merge, stale/future revision, historical claim borrowing,
неподходящую buyer role, неверное окно, missing evidence, forged passport/consent/permit,
cross-source review, stale negative, ложное снятие `KEEP_SEPARATE`, epoch rewind,
cross-passport/time-scope evidence и ledger tampering. Полноценный assignment-based
merge/split/reassignment, production evidence repository, live source authorization/transport,
reviewer/cohort/CRM-order binding и статистический пилот остаются обязательными до shadow/live.

Живые SMTP/IMAP/Unisender/Bitrix/source API не вызывались. Домены, ящики, тарифы, поля,
Scheduled Tasks, процессы и массовые кампании не менялись.

### Проверено 19.08.2026

- полный offline Lead Factory regression: 421 тест — `OK`;
- TaskBot: 13 тестов — `OK`;
- Construction Radar: 48/48; v15 review/access: 35/35; schema + recovery + оба
  Radar-набора: 119/119 — `OK`;
- AST-разбор 87 Python-файлов — `OK`;
- независимые architecture и adversarial reviews не нашли открытых P0/P1 в текущем
  offline Radar-срезе;
- stage открыт только через immutable/read-only URI: `schema_meta=13`, fingerprint 13,
  `PRAGMA user_version=0`, environment `stage`, writers `0`;
- stage содержит 91 Event, 40 исторических Interaction и 10 задач, все задачи закрыты как
  `CLOSED_LEGACY_HANDLED`; Company/Contact/Project/Opportunity остаются `0`;
- canary, authorization/permit/outbox, CRM outbox/mapping, inbox cursor/manifest,
  Bitrix gate/reservations — `0`; v14/v15/multimail и Radar-таблицы в stage отсутствуют;
- защитное состояние stage: 23 cadence blocks, 20 active suppression и 8 superseded;
- Windows readiness: `NO-GO`, 12 blockers из фиксированных 15 компонентов, unknown `0`.
  Этот inventory не доказывает отсутствие неизвестного writer, поэтому до GO нужен
  отдельный completeness/manual gate всех send/pause/resume entry points.

Следующие обязательные blockers: assignment-based merge/split/reassignment, production
evidence repository, reviewer и CRM/order binding, predeclared cohort/statistics, а перед
любым live source-read — отдельная owner-approved source authorization с credential/endpoint/
licence scope, typed adapter, runtime STOP и transport reconciliation. Текущий offline permit
этого разрешения не даёт.

## Текущий безопасный срез

Реализовано изолированное stage-ядро, которое не вызывает Unisender, SMTP, Bitrix или OpenRouter:

- append-only Event Store с идемпотентностью;
- отдельные Company, Contact, Project, Opportunity и Interaction;
- durable intake первого входящего;
- одна локальная задача Диме и блокировка каданса на один живой ответ;
- адресная suppression для отписки и hard bounce;
- default-deny Policy Engine;
- `OutboundAuthorization`, одноразовый Send Permit и staged outbox без транспорта;
- PII-safe baseline старых состояний;
- теневое подключение входящих дилерской и строительной линий;
- отдельный CRM outbox: timeout/обрыв после создания переводится в `UNCERTAIN`,
  повторный `lead.add` запрещён до сверки по неизменному event ID;
- атомарный local handoff: только уже routed `HUMAN_REPLY` с существующей
  Opportunity и ровно одной открытой задачей Диме создаёт в одной SQLite-транзакции
  задачу, Lead operation и зависимую Activity operation; иначе — только `REVIEW`;
- Activity eligible лишь после `SENT` точной Lead operation и её ACTIVE mapping.
  Перед будущим REST-вызовом эта зависимость, remote Lead ID, writer gate и lease
  сверяются повторно. API Bitrix не документирует immutable Activity idempotency key,
  поэтому ответ Activity принимается только как typed receipt с readback-подтверждением
  owner Lead; строковый ID, неверный owner и любой неоднозначный исход уходят в
  terminal `REVIEW` без автоматического повтора;
- независимый IMAP UID-cursor: курсор нельзя продвинуть до durable event, смена
  UIDVALIDITY переводит его в `RESET_REQUIRED`;
- stage-only unified inbox: точный resume UID-manifest, raw MIME evidence до
  event/cursor и безопасный `UNROUTED` без ложной задачи;
- immutable evidence vault с SHA-256, размером, mailbox/UID/UIDVALIDITY и parser version;
- ссылка evidence проверяется до Event Store: blob и metadata обязаны реально существовать,
  а sender, Message-ID и thread выводятся из сохранённого MIME, не из параллельных полей;
- stage-reader принимает только встроенный `LocalEvidenceVault`; произвольный/no-op
  storage adapter отклоняется до Event и движения cursor;
- явный lifecycle человеческой задачи: acknowledge, first action, complete и SLO escalation;
- ответ контакта блокирует все следующие холодные серии на адрес в новом Send Gate;
- Pause Controller: ни ручная, ни TTL-пауза не снимается без audit event и evidence;
- полный backup-set SQLite + raw evidence + manifest и fail-closed restore;
- офлайн Bitrix canary adapter: whitelist полей, exact correlation, read-after-write,
  duplicate detection, rate gate и read-only preflight;
- hard kill-switch для будущих внешних workers (`external_writers_enabled=0`);
- durable canary-control: одновременно допускается только один активный запуск
  Bitrix canary; точный scope хранит mailbox, campaign, email, outbound thread и
  Opportunity, а неизменяемый лимит сначала равен 1 и может стать суммарно 5
  только после ручного checkpoint по первому случаю;
- локальный `CanaryDispatchPermit` привязан к одной CRM-операции, её payload hash,
  correlation token, approval и двум fenced lease. Старые несвязанные записи CRM
  outbox такой permit получить не могут;
- restart-safe guard в dealer/builder poll читает scope из SQLite на каждом запуске.
  Для canary-контакта он останавливает legacy SMTP, прямой Bitrix и дальнейший
  cadence; неверный thread и недоступная stage-БД обрабатываются fail-closed;
- на время явно активированного canary старые очереди SMTP и Bitrix, а также
  прямой `tb_bitrix.create_lead`, переходят в HOLD без удаления записей;
- изолированная HTTP-граница Bitrix принимает webhook и HTTP session только явной
  инъекцией, разрешает узкий список методов, не читает `.env` и не раскрывает URL,
  PII или provider error description. Методы записи требуют одноразовую capability;
- общий SQLite rate gate сериализует фактические HTTP-вызовы: crash-safe hold
  коммитится заранее, а финальная проверка, запрос и отметка завершения проходят
  под одним межпроцессным барьером; следующий вызов ждёт completion + 1 секунду;
- отдельный `CanaryExecutor` исполняет только точную связанную операцию с action-bound
  permit. `CREATE`, correlation-only `RECONCILE` и локальный `ACTIVITY_REVIEW`
  технически разделены, поэтому потерянный ответ не превращается в повторный create;
- sealed Bitrix runtime принимает только каноническую stage-БД, rate gate того же
  portal fingerprint и узкую HTTP-границу. После ожидания лимитера он ещё раз
  проверяет permit, затем выдаёт capability ровно на один метод записи;
- generic CRM workers исключают связанные canary-операции на уровне SQL. Старые
  низкоуровневые Bitrix write-вызовы TaskBot/TenderBot во время canary уходят в HOLD
  до HTTP, а чтения сохраняются;
- legacy Bitrix retry повторно проверяет durable HOLD непосредственно перед каждой
  HTTP-попыткой; активация canary между попытками не допускает следующий запрос;
- STOP сохраняет restart-safe quarantine старых writers, пока у связанной canary
  операции остаётся неоднозначный outcome. Снятие возможно только отдельной
  state-bound terminal-resolution записью с actor/evidence в audit log;
- шесть старых диагностических Bitrix helpers используют общий строгий read-only
  allowlist: `add`, `batch` и неизвестные методы отклоняются до HTTP. AST-regression
  фиксирует полный инвентарь прямых Bitrix transport sinks;
- generic Lead/Activity workers полностью удерживаются во время ACTIVE approved
  canary, даже если общий writer flag включён;
- sealed read-only preflight допускает только `userfield.list`, `lead.fields` и
  `lead.list`, проверяет exact token/БД/портал и проводит каждый запрос через общий
  rate barrier без write-capability;
- read-only Windows readiness checker fail-closed проверяет известные Scheduled
  Tasks, процессы TenderBot/TaskBot и HKCU autorun, не выводя PID, пути, команды
  или сырые ошибки;
- расширение canary `1 → 5` возможно только после точных `SENT` Lead и Activity,
  положительных remote ID и действующего ACTIVE Lead mapping;
- автоматические P0-тесты.

Stage база: `state/lead_factory_stage.sqlite3`.

Внешние writers по умолчанию выключены (`external_writers_enabled=0`). Этот флаг нельзя
включать до прохождения P0, restore-test и отдельного cutover.

## Команды без внешних действий

```powershell
python -m lead_factory.cli init
python -m lead_factory.cli baseline
python -m lead_factory.cli status
python -m lead_factory.cli reconcile-shadow
python -m lead_factory.cli backup --output-dir state\lead_factory\backups
python -m lead_factory.cli restore-test --backup <backup.sqlite3> --restore-path <new.sqlite3>
python -m unittest discover -s tests -p "test_lead_factory*.py" -v
```

## Что пока намеренно не включено

- изменение текущих писем и сегментов;
- новая или возобновлённая массовая отправка;
- автоматические ответы клиентам;
- запись в Bitrix и изменение его полей/воронок;
- OpenRouter и внешние источники;
- production Send Worker;
- запуск unified inbox против живого IMAP: stage-worker требует явно внедрённый
  read-only fetcher и сам по себе не может прочитать почту;
- подключение sealed Bitrix runtime к живому worker и настоящий webhook.

Текущие `--poll` дилерской и строительной линий зеркалируют совпавшие входящие в stage.
Даже если зеркало недоступно, оно не ломает обычный poll; адреса и тексты не выводятся в
его технические ошибки. Для будущего точного canary добавлен durable guard, но сейчас он
не активен: в stage нет run/approval/scope, а writer flag равен `0`.

Следующий безопасный offline-срез: assignment-based merge/split/object reassignment поверх
неизменяемого Radar graph, формальная reviewer/cohort/CRM-order provenance и typed source-
adapter fixtures с credential/endpoint/licence/data-contract binding — по-прежнему без fetch.
Параллельно нужны typed live-fetch envelope для multipmail и per-contact cadence/stop rules;
writers и source reads остаются выключенными.

Read-only preflight реального Bitrix возможен только отдельным предложением владельцу.
Обычный `CrmOutbox` для live-canary запрещён кодом для связанных операций. Preflight и
live writer должны иметь разные OS-процессы и разные Bitrix credential: у preflight
только read-only.

## Проверено 18.08.2026

- 241 офлайн-тест Lead Factory — `OK`, включая 10 синтетических ответов,
  fail-closed evidence/recovery, pagination, readback/suspect-ID и повторную
  проверку kill-switch перед create, restart legacy guard, cap `1 → 5`,
  fenced permit, quarantine после STOP, sealed preflight, Windows readiness и
  HOLD старых writers;
- 13 тестов TaskBot — `OK`;
- компиляция новых модулей, campaign runners и legacy outbox helpers — `OK`;
- stage: `external_writers_enabled=0`, очереди внешних операций пусты;
- schema version 13; активных canary runs, approvals, scopes, bindings и leases — `0`;
- rate gates/reservations — `0`; generic и legacy writers остаются default-off/HOLD-ready;
- свежий реальный stage backup/restore прошёл: 90 events, 39 interactions, 10 tasks,
  writer flag после восстановления `0`, restore 24 ms;
- локальный Windows readiness snapshot сейчас `NO-GO`: включены старые poll/send/
  watchdog-задачи, работают `tb_bot`, builder poll и TaskBot, присутствует TaskBot
  autorun. Проверка ничего не останавливала и не меняла;
- реальные REST/SMTP/Unisender вызовы при проверках не выполнялись.

Проверенный backup manifest:
`state/lead_factory/backups/lead_factory_20260818T184947651466Z_d0be4eb192.sqlite3.manifest.json`.

В живой stage-базе raw MIME пока 0: новый unified reader намеренно не подключён к IMAP.
Полная цепочка raw MIME → Event → route → task → backup/restore проверена на изолированных
fixtures; это не выдаётся за доказательство live-cutover.

Теневой dealer poll уже зафиксировал 39 исторических входящих: 27 отписок,
10 писем, похожих на человеческий ответ, и 2 автоответа. Это не новые лиды.
Дубликатов Interaction и task нет. 10 задач по уже обработанной истории закрыты
как `CLOSED_LEGACY_HANDLED`; открытых stage-задач после сверки нет. Из 27 записей
suppression 19 уникальных активных, 8 повторов сохранены как `SUPERSEDED`.
В Event Store есть 78 `inbound_received` capture-events для этих 39 Interaction:
вторая фиксация появилась при переходе shadow intake с Message-ID на строгий UID-key.
Это не 78 писем и не 78 лидов; коммерческая метрика берётся по canonical Interaction.
Для legacy без UIDVALIDITY сохранён Message-ID dedupe, поэтому повтор больше не растёт.

После независимой проверки корректности исправлено:

- падение CRM worker между claim и dispatch больше не оставляет вечный `LEASED`;
- permit нельзя применить к другому адресу, sender, content или cohort;
- пустой email получает deny;
- один Opportunity не может создать два CRM Lead;
- конфликт удалённого CRM mapping уходит в `CONFLICT_REVIEW`, не в `SENT`;
- повторное reconcile имеет backoff и конечный переход в ручной review;
- lease имеет fencing token: медленный старый worker не может перезаписать
  результат нового worker/reconciliation;
- делегированная отписка останавливает каданс, но не создаёт автоматический
  suppression чужого адреса без проверки;
- HUMAN_REPLY нельзя связать с чужим адресом, а sender берётся из raw MIME;
- domain suppression выводится из фактического email, неизвестный scope паузы
  обрабатывается fail-closed;
- UIDVALIDITY mismatch в свежей и возобновляемой партии переводит cursor в
  `RESET_REQUIRED` и инвалидирует manifest;
- evidence ref связан с точными mailbox/UID/UIDVALIDITY и проверяется до Event;
- restore сверяет envelope Event Store с metadata архива, а не только SHA файла;
- неверный Bitrix readback сохраняет suspect Lead ID для ручного разбора;
- отсутствующий `total` и неполная pagination Bitrix lookup считаются конфликтом;
- после уже полученного Bitrix ID любой readback-сбой остаётся `UNCERTAIN`,
  сохраняет suspect ID и не превращается в новый `lead.add`;
- истёкшая пауза продолжает блокировать отправку до зафиксированного release/expiry;
- восстановление проверяет DB, raw MIME, metadata и manifest hashes и всегда
  выключает external writers.

UID-cursor сверяет producer, mailbox, UID и UIDVALIDITY с конкретным immutable
event. Фактически найденные IMAP UID сначала сохраняются ordered manifest:
нормальная последовательность `5 → 7 → 9` разрешена, но найденный UID `7`
перепрыгнуть нельзя. Незавершённый manifest восстанавливается после рестарта.
Отдельный crash-test подтверждает продолжение партии `[5, 7]` новым процессом
после сохранения только UID `5`.
После `RESET_REQUIRED` обычный advance не может снова включить cursor: нужен
явный rescan с evidence. Unified inbox и raw evidence готовы в stage, но не включены
в scheduler и не заменяют legacy poll.

## Checkpoint 22.08.2026 — переход на Lead Factory и bounded IMAP intake

По прямому решению владельца legacy TenderBot/TaskBot entry points остановлены
через reversible retirement procedure; rollback capsule сохранена, но старый
контур больше не запускается автоматически. Canonical Lead Factory мигрирована
до schema v16, а зарегистрированная inbound mailbox-binding активна только для
read-only canary; sender identities, campaigns и все send caps отсутствуют/равны
нулю.

Выполнен один owner-approved IMAP intake: TLS + `SELECT INBOX readonly`, лимит
5, immutable local raw-MIME evidence перед event, registered UID cursor и
ordered manifest. В фабрике добавлены ровно 5 interactions, без task, route,
CRM command, Bitrix, SMTP, Unisender, Telegram или OpenRouter. Writer/source
switches остались `false`, scheduler не включён. Post-run backup и restore-test
проверили 5 raw MIME + 5 metadata files, schema v16 и forced-off external
switches. Реальный новый входящий поток пока не считается коммерческим лидом:
он остаётся `UNROUTED` до отдельного routing/reconciliation gate.

После owner-approved local conversation reconciliation все 5 канареечных
interactions получили fail-closed state `REVIEW`: четыре без thread reference и
одно без точной outbound conversation identity. Ни CRM, ни task, ни reply не
созданы. Backup/restore recovery обновлён так, чтобы производное routing event
могло законно использовать тот же immutable MIME pointer, но только если
исходный inbound event в этом backup доказывает полный transport envelope;
13/13 recovery tests — `OK`. Финальный backup/restore checkpoint содержит
117 events, 52 interactions, 5 open conversation reviews и по-прежнему нулевые
outbox/CRM outbox при выключенных external switches.

## Operations checkpoint 22.08.2026

Добавлена PII-free команда `python -m lead_factory.cli work-queue`: SLO,
активные задачи, inbound classifications, open conversation reviews, outbox и
external stop flags доступны одной локальной командой. Просроченная задача
`HUMAN_REPLY_REVIEW` получила только локальную SLO-эскалацию и обезличенный
brief для Димы (проверить объёмы и расхождения спецификации/цены); отправка,
CRM и фиктивное human acknowledgement не выполнялись.

Полный Lead Factory suite: **899/899 `OK`**, `ruff` — `OK`. Backup и restore
`lead_factory_20260822T192958116728Z_9cd678fd93.sqlite3` подтверждают schema
v16, raw-MIME evidence и выключенные external writer/source-read switches.
Дальнейшие реальные подключения не запускаются автоматически: они требуют
конкретных auth/licence/policy данных и отдельных contract-gate approvals.

Владелец разрешил локальную содержательную проверку канареечной пятёрки. Одно
письмо классифицировано как `HUMAN_REPLY` и получило локальную задачу Диме с
cadence block; четыре системных уведомления классифицированы `AUTO_REPLY`.
Ни одна отписка не создана: слово из footer не признано запросом адресата без
явной воли. Уточнён recovery envelope gate: routing-context `mailbox` не
является частичным raw-MIME envelope, однако такой event допускается только при
полном immutable inbound envelope в том же backup. Routing/recovery tests
20/20 и финальный backup/restore checkpoint `...180721477278Z_49368a34d5`
прошли; внешние writer/source-read flags, outbox и CRM outbox остаются нулевыми.
