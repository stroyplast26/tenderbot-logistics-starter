# IMAP read-only canary — операционный runbook

## Назначение

Canary читает ограниченную UID-последовательность из одной папки рабочего ящика
и записывает только локальные immutable evidence и inbound events. Он не отправляет
писем, не создаёт Lead/сделки/задачи в Bitrix, не посылает Telegram и не меняет
сообщения на IMAP.

## До запуска

1. Владелец отдельно подтверждает: mailbox, folder, время окна, batch limit и
   zero-write scope.
2. Создана отдельная IMAP-учётка с доступом только на чтение нужной папки.
   `MANAGER_IMAP_*` и другие legacy credentials для canary не применяются.
3. В окружении launcher, но не в коде, заданы:

   - `LEAD_FACTORY_IMAP_CANARY_HOST`
   - `LEAD_FACTORY_IMAP_CANARY_USER`
   - `LEAD_FACTORY_IMAP_CANARY_PASSWORD`
   - необязательно: `LEAD_FACTORY_IMAP_CANARY_PORT=993`, `LEAD_FACTORY_IMAP_CANARY_TIMEOUT=25`

4. Создан новый backup и подтверждён restore-test target schema. У stage
   `external_writers_enabled=0` и `external_source_reads_enabled=0`.
5. Утверждены mailbox account, evidence retention, consumer ID и предел первого
   запуска (рекомендуется не более 5 UID).

## Canary

1. Выполнить отдельный read-only preflight: TLS, `LOGIN`, `SELECT ... readonly=True`,
   проверка UIDVALIDITY. Не выполнять `STORE`, `COPY`, `MOVE`, `EXPUNGE`, `APPEND`.
2. Взять не более пяти UID; сохранять raw MIME и SHA-256 до создания локального
   inbound event.
3. Убедиться, что cursor продвинулся только для сохранённых UID, все события
   имеют evidence pointer, а human tasks, CRM outbox, delivery events и outbound
   permits остались без изменений.
4. Закрыть IMAP session, сформировать readback/reconciliation report и вернуть
   runtime в stopped state.

## Немедленный STOP

- отсутствие/смена UIDVALIDITY;
- login/select/fetch error, неполный batch либо raw MIME без hash;
- обнаружен любой write-capability или попытка использовать legacy credential;
- изменился scope, mailbox, folder, schema, policy или evidence retention;
- появился внешний writer, CRM task, send permit или неясный результат.

STOP не повторяет пропущенный UID вслепую, не удаляет evidence и не включает
следующий сервис. Причина и recovery decision фиксируются отдельно.
