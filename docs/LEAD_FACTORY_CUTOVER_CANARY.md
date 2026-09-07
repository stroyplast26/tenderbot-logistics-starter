# Lead Factory — предложение canary cutover

Статус: **DRAFT / LIVE НЕ РАЗРЕШЁН**.

Операционная изоляция credential и порядок STOP описаны в
`docs/LEAD_FACTORY_BITRIX_CANARY_RUNBOOK.md`.

Цель canary — доказать на малом потоке, что первый живой ответ сохраняется, останавливает
все холодные продолжения, создаёт одну задачу Диме и одну CRM-карточку без дублей. Canary
не меняет текст писем, сегменты, дневную квоту или рекламный бюджет.

## Что уже готово в stage

1. Raw MIME сохраняется до Event/Interaction и движения IMAP UID-cursor.
2. После сбоя незавершённый manifest продолжается без нового SEARCH.
3. `UNROUTED` не создаёт ложную задачу; отдельный route decision идемпотентен.
4. `HUMAN_REPLY` создаёт одну задачу и блокирует дальнейший cold cadence адреса.
5. Task lifecycle фиксирует acknowledge, first action, completion и SLO escalation.
6. CRM outbox не повторяет `lead.add` после неоднозначного результата.
7. Bitrix adapter проверяет concrete UF через add → get/readback → exact list.
8. Backup восстанавливает SQLite + raw evidence; external writers после restore равны `0`.
9. Dealer/builder poll после рестарта читает точный canary scope из SQLite и не
   допускает legacy автоответ, прямую запись в Bitrix или следующее касание.
10. Canary cap принуждается кодом: сначала 1 случай, затем суммарно максимум 5
    только после точных `SENT` Lead+Activity, положительных remote ID и ACTIVE mapping.
11. Lead, Activity и задача создаются локально одной транзакцией; Activity ждёт
    точный `SENT` Lead и подтверждённый ACTIVE mapping.
12. Старые SMTP/Bitrix retry и прямой `tb_bitrix.create_lead` умеют переходить в
    недеструктивный HOLD на время активного canary.
13. Audited executor разделяет `CREATE`, correlation-only `RECONCILE` и локальный
    `ACTIVITY_REVIEW`; действие неизменно связано с operation lease.
14. Sealed runtime допускает Bitrix write только внутри общего dispatch barrier:
    permit проверяется в той же транзакции, которая удерживается до завершения HTTP.
15. HTTP-граница отклоняет `lead.add` и `activity.todo.add` без одноразовой capability;
    portal rate bucket связан с fingerprint фактического HTTPS-host.
16. Generic CRM workers не выбирают canary bindings, а raw legacy writes TaskBot и
    TenderBot блокируются до HTTP.
17. Sealed read-only preflight допускает только три Bitrix read-метода и повторно
    проверяет canonical DB/portal/writer/outbox внутри rate barrier.
18. Windows readiness checker даёт только безопасные component statuses и fail-closed
    блокирует cutover при работающем или неизвестном legacy writer.

## Обязательные условия перед live

- пользователь отдельно согласовал дату, одну линию и canary scope;
- восстановлен REST-доступ Bitrix без раскрытия webhook;
- администратор вручную создал одно строковое немножественное поле correlation ID;
- read-only Bitrix preflight прошёл, canary token отсутствует;
- выбран владелец ручного `REVIEW` и подтверждён рабочий график Димы;
- durable guard остаётся доступен после рестарта и доказал, что legacy не может
  автоответить, продолжить каданс или напрямую записать canary-контакт в CRM;
- локальная задача, Lead и CRM Activity образуют одну атомарную handoff-цепочку;
- canary scope зажат в коде: один активный run, cumulative cap `1 → 5`, один
  connector lease и permit только на точную связанную операцию;
- sealed audited runtime принимает `CanaryDispatchPermit`, повторно сверяет
  writer/connector/operation leases внутри dispatch barrier и только затем вызывает adapter;
- legacy pending queue повторно проверена; старые write-пути остановлены/HOLD, а
  общий Bitrix rate gate использует fingerprint того же портала;
- Windows readiness report равен `ok=true`; preflight использует отдельный OS-процесс
  и read-only Bitrix credential, которого нет у live writer;
- evidence vault имеет утверждённые ACL, срок хранения, лимит диска и проверенную
  устойчивость записи каталога;
- сделан свежий backup/restore и сохранён manifest;
- внешний writer flag остаётся `0` до последнего отдельного решения.

## Последовательность canary

1. Внутренний fixture: одно тестовое письмо в отдельном thread.
2. Новый inbox сохраняет raw evidence и создаёт `UNROUTED`.
3. Router классифицирует fixture как `HUMAN_REPLY` и создаёт одну задачу.
4. Проверяется, что legacy не отправил автоуточнение и не создал второй Lead.
5. После отдельного разрешения audited executor создаёт одну tagged Bitrix Lead
   только по точному `CanaryDispatchPermit`.
6. Выполняются get/readback и exact lookup по correlation UF.
7. Сначала допускается один реальный ответ выбранной линии. После ручного разбора владелец
   отдельно разрешает продолжить максимум до 5 ответов без массового изменения отправок.
   После каждого случая обязателен ручной checkpoint; число 5 не является автоматическим GO.

## Go / Stop

**Основание предложить владельцу расширение после fixture и максимум 5 ответов:**

- 100% raw evidence и inbound events сохранены;
- 100% задач созданы не позднее 5 минут после intake;
- 0 автоуточнений до решения Димы;
- 0 повторных холодных писем после человеческого ответа;
- 0 дублей Interaction, task и Bitrix Lead;
- correlation/readback совпадает у каждой CRM-записи;
- backup/restore и reconciliation не оставили необработанный хвост.

**Немедленный STOP:** потеря/неполное evidence, неверный адрес suppression, второй outbound,
дубль CRM, UID reset, обход единого writer или любая запись вне canary scope. При
`UNCERTAIN` после Bitrix-мутации останавливаются новые CRM-записи и выполняется только
сверка по correlation ID; повторный create запрещён.

## Rollback

1. Отозвать canary authorization и оставить external writers=`0`.
2. Остановить новый live reader/CRM worker; не удалять события и очереди.
3. Вернуть legacy-линию из observe-only только для canary scope.
4. Выполнить reconciliation и сохранить причину rollback.
5. Никакой автоматический повтор внешнего действия при rollback не выполняется.

## Что требует отдельного согласия владельца

- включение чтения живого IMAP новым worker;
- перевод выбранной legacy-линии в observe-only;
- создание/изменение поля Bitrix;
- единственная canary-запись в Bitrix;
- включение любого внешнего writer;
- расширение canary более чем на первые 5 реальных ответов.

## Текущие блокеры live

- sealed runtime пока не подключён к worker/планировщику и намеренно не читает `.env`;
- реальный read-only preflight ещё не запускался;
- REST-доступ Bitrix и конкретное строковое UF correlation ID фактически не проверены;
- текущий Windows readiness report имеет `ok=false`: legacy tasks/processes и TaskBot
  autorun ещё активны; они не были остановлены без отдельного согласия пользователя;
- отдельные read-only credential preflight и write credential live worker ещё не созданы;
- перед canary надо подтвердить остановку/координацию остальных Bitrix-процессов и
  повторно проверить пустые legacy pending queues;
- правила доступа, квота и срок хранения raw MIME ещё не утверждены;
- нет отдельного согласия владельца на включение writer и одну tagged CRM-запись.

Пока эти пункты не закрыты, документ остаётся DRAFT независимо от числа зелёных
офлайн-тестов.
