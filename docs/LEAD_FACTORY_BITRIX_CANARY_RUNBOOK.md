# Bitrix canary — операционный runbook

Статус: **CAP=5 LIVE GREEN / RUN STOPPED / WRITERS OFF**.

Этот документ описывает только единичный canary Lead Factory. Он не разрешает
массовую запись, не включает writer и не заменяет отдельное согласие владельца.

## Обязательная изоляция

Нормативный production режим использует разные изолированные процессы и разные
credential:

- preflight запускается отдельным OS-процессом/пользователем только с удалённым
  read-only доступом к Bitrix; live write credential в этом процессе отсутствует;
- live canary получает отдельный webhook/пользователя с минимальными правами на
  требуемые Lead/Activity и доступен только одному выделенному OS worker-процессу.

Live credential:

- хранится только в локальной исключённой из публикации secret-конфигурации и не
  передаётся TaskBot или legacy-скриптам;
- доступен только одному выделенному worker-процессу;
- не выводится в CLI, события, исключения и отчёты;
- отзывается отдельно, не затрагивая read-only диагностику.

Для первого cap=1 владелец явно принял существующий credential с exact `crm` scope.
Для cap=5 использован новый отдельный webhook пользователя `15` с exact scope
`crm`, `owner_accepted_existing_credential=false` и отдельным sealed isolation
evidence. Ни URL, ни token не сохраняются в runbook или immutable events.

Старые Bitrix writers на время canary должны быть остановлены либо лишены write-доступа.
Кодовый HOLD, allowlist и одноразовые capability — дополнительная защита от ошибок,
но не security boundary: Python-private API и ссылки на injected HTTP objects доступны
коду того же процесса. Реальную границу дают read-only права preflight, отдельный
OS-процесс live worker и отсутствие write credential у остальных процессов.

## Preflight без записи

До включения writer должны быть подтверждены:

1. Каноническая `state/lead_factory_stage.sqlite3` открывается только через
   `mode=ro&immutable=1`; audit/rate state размещается в отдельном schema-17 control store.
2. `external_writers_enabled=0`; активных run, bindings и leases нет.
3. Exact sealed graph manifest выводит 38 строковых немножественных Company/Contact/Deal
   UF. Read-only проверка подтверждает полный shape и не находит заранее сгенерированные
   Company/Contact/Deal correlation tokens.
4. Gate identity совпадает с fingerprint фактического HTTPS-host Bitrix.
5. Legacy pending queues пусты либо поставлены в HOLD; TaskBot и другие write-процессы
   остановлены.
6. Concrete Windows provider захватывает exact scheduled-task/process-tree/autorun
   receipt, временно quiesce только эти identities, требует readiness `ok=true` и
   восстанавливает исходное состояние с последующей semantic recapture. `unknown`
   считается запретом, а не успешной проверкой.
7. Сделан свежий backup/restore; восстановленная база имеет writer flag `0`.
8. Назначен человек, который разберёт `UNCERTAIN`, `REVIEW` и `CONFLICT_REVIEW`.

После успешного preflight всё ещё требуется отдельное согласие владельца на exact
tagged scope. Для завершённого cap=5 такое согласие, isolated credential evidence
и отдельный live cutover seal были получены. Этот факт не разрешает дальнейшее
массовое расширение: для нового cap нужен новый approval и новый sealed scope.

## Нормальная последовательность

1. Точный canary scope и cap=1 фиксируются в stage.
2. Exact Company, Contact, Deal и Activity operations сохраняются локально с одним
   manifest/source/deadline binding.
3. Единственный worker получает action-bound permit и connector lease.
4. Sealed runtime подготавливает crash-safe rate hold.
5. Под `BEGIN IMMEDIATE` повторно проверяются run, writer flag, permit, operation lease
   и mapping. Тот же барьер удерживается до завершения HTTP.
6. Write получает одноразовую capability; затем выполняется обязательный readback.
7. Неоднозначный Company/Contact/Deal допускает только exact correlation lookup без
   второго create. Activity с неоднозначным outcome остаётся `UNCERTAIN/REVIEW` без
   автоматического повтора.

## STOP

STOP считается линейным относительно уже начатого HTTP:

- если stop зафиксирован до dispatch barrier — внешнего write нет;
- если HTTP уже вошёл в barrier — stop ждёт его завершения и применяется сразу после;
- ожидание может длиться до настроенного HTTP timeout. Нельзя аварийно удалять SQLite
  или сбрасывать state: это уничтожит доказательство неоднозначного результата.

Если команда stop получила `database busy`, оператор повторяет её после освобождения
barrier. При внешней аварии сначала отзывается отдельный canary credential, затем
сохраняются DB/логи и выполняется reconciliation. Никакого повторного `create`.
Windows receipt до quiesce сохраняется как DPAPI-encrypted/authenticated crash capsule;
fresh provider импортирует её только для restore, а удаляет только после exact recapture.

STOP не снимает HOLD старых Bitrix writers, если у canary осталась связанная операция
в `UNCERTAIN`, `REVIEW`, `CONFLICT_REVIEW` или другом неоднозначном состоянии. HOLD
сохраняется после перезапуска. Его можно снять только явной state-bound резолюцией
`resolve_canary_operation_quarantine(...)` с actor, evidence и одним из разрешённых
terminal outcomes; резолюция записывается неизменяемым audit event. Обычный STOP без
таких операций освобождает старые writers как раньше.

Сигналы немедленного STOP:

- второй outbound после человеческого ответа;
- запись вне точного canary scope;
- дубль Lead/Activity/task;
- неверный correlation readback или mapping;
- потеря raw evidence;
- обход sealed runtime, rate barrier или legacy HOLD.

## После canary

Расширение cap `1 → 5` возможно только если exact Company, Contact, Deal и Activity
имеют `SENT`, положительные remote ID, а первые три сохраняют точные ACTIVE mappings. Затем требуется
ручной checkpoint с evidence и новое неизменяемое одобрение. Любой `REVIEW`, `DEAD`,
`UNCERTAIN` или конфликт означает разбор и остановку расширения.

## Текущее состояние 22.08.2026

- По явному owner approval provisioned ровно 38 graph UF; повторная reconciliation:
  `created=0`, `existing=38`.
- Fresh live read-only preflight зелёный: `56` allowlisted reads, все пять checks;
  report hash
  `cfed5d671ffe2bb73fbdf97dc5cb7ecd8c09caf49b07abaf14852715e11e9cc6`.
  Все `12` candidate correlation probes пусты; evidence hash
  `cf344a981b10d81c5252e4c61375cac20d0cab2f17b295637bf3104914a8e37c`.
- Тот же cap=1 run расширен до cumulative cap=5. Исходный graph: Company `1121`,
  Contact `527`, Deal `535`, Activity `2939`. Четыре новых graph: Company
  `1123/1125/1127/1129`, Contact `529/531/533/535`, Deal `537/539/541/543`,
  Activity `2941/2943/2945/2947`.
- Все `20` operations имеют `SENT`; новые `16/16` выполнены с
  `attempt_count=1`. Независимый typed readback `16/16` зелёный, report hash
  `2803472db1d8e6a421a46f85649ce8c9e062257045fd1bc1071b337ed0f39423`.
- Run финально `STOPPED`, reason `cap_five_complete`; ACTIVE mappings
  Company/Contact/Deal = `5/5/5`; external writers, source reads и manual commits
  равны `0`.
- Reversible Windows provider восстановил exact legacy state; DPAPI capsule удалена
  только после semantic recapture. Неоднозначных live outcomes нет.
- Live evidence: `LEAD_FACTORY_BITRIX_GRAPH_CAP5_LIVE_EVIDENCE.json`, declared hash
  `f26fb7d3592d720bf9c391a05781329d9aef23d9f24b88735da10e2657a052ce`.

Открытых воспроизводимых P0/P1 в live cap=5 lane нет. Любой следующий cutover
требует нового owner approval, нового exact scope и повторения всех preflight,
quiesce, sealed cutover, readback и STOP gates.
