# Lead Factory — канонический canary gate

Дата проверки: 19.08.2026. Текущий вердикт: **NO-GO**.

Этот файл является входной точкой оператора. Подробные процедуры находятся в:

- `LEAD_FACTORY_BITRIX_CANARY_RUNBOOK.md` — один tagged Bitrix Lead + Activity;
- `LEAD_FACTORY_CUTOVER_CANARY.md` — изоляция старых writers, STOP и rollback.

Ни один шаг ниже не является разрешением на live-вызов. Для read-only preflight,
единственной записи или изменения внешней системы требуется отдельное явное согласие владельца.

## Почему сейчас NO-GO

- каноническая stage-БД остаётся schema 13, `external_writers_enabled=0`;
- допустимая legacy-пара до явной миграции: `PRAGMA user_version=0` и
  `schema_meta.schema_version=13`; любая другая несогласованная пара означает STOP;
- schema 14 зафиксирована отдельным checksum/fingerprint, schema 15 является текущим additive
  offline candidate; ни одна из них в stage не мигрирована, а обычный `init/status` не
  выполняет скрытый upgrade;
- нет живого canary run/approval/scope/binding/lease;
- активны legacy Scheduled Tasks/processes и autorun; среди задач возможны снятие общей паузы
  и последующий legacy send;
- Bitrix read-only capability и точные LF user fields не подтверждены свежим preflight;
- production Send Worker, multi-account live inbox и transport reconciliation не готовы;
- Construction Demand Radar использует только fixtures; v15 по умолчанию держит source reads
  выключенными, но stage v13 ещё не имеет этого meta-key. Transport отсутствует, поэтому live
  read запрещён текущим NO-GO и отсутствием adapter/executor; ручной shadow MVP не проводился.

Ничего из перечисленного нельзя автоматически останавливать, включать или мигрировать.

## Gate до любого внешнего canary

1. Владелец явно разрешает конкретное действие и maintenance window.
2. Readiness inventory включает не только poll/send/watchdog, но и все legacy pause/resume
   mutators. Все конфликты устранены владельцем или подтверждены как безопасные.
3. Создан новый backup-set; restore-test подтвердил schema, Event Store, evidence,
   reservations и `external_writers_enabled=0`. Для v15 он также подтверждает
   `external_source_reads_enabled=0`, целостность Radar ledger и продвижение read epoch.
4. Старая запись в shared DB остановлена; только затем выполняется явная миграция schema.
   Обычный `init/status` не используется как скрытый migrator.
5. Read-only Bitrix preflight запущен отдельным процессом и read-only credential. Разрешены
   только allowlisted list/fields методы; запись технически недоступна.
6. Проверены exact LF fields, portal fingerprint, owner mapping Димы, pagination, rate gate
   и отсутствие конфликтующей записи по LF opportunity/event ID.
7. Созданы ровно один run, approval, scope, binding и fenced permit для заранее выбранной
   тестовой Opportunity. Любое расхождение означает STOP.
8. До запуска пользователю показаны точное действие, ожидаемый remote result, риски,
   stop-критерий, rollback и требуемое от него подтверждение.

## Допустимое первое предложение владельцу

После выполнения gate можно предложить, но не выполнить без согласия:

- **действие:** read-only preflight конкретного Bitrix portal без `add/update/delete`;
- **ожидаемый результат:** подтверждены поля, owner mapping, тарифная доступность и exact
  duplicate lookup; внешние данные не изменены;
- **риски:** ограничение тарифа/прав, неполная pagination, неверный portal или credential scope;
- **STOP:** любой write-capability, неизвестный метод, portal mismatch, неполный список,
  `429/5xx`, отсутствие обязательного поля или утечка секретов;
- **нужно от владельца:** явное разрешение на preflight и отдельный read-only credential.

Предложение на одну tagged запись формируется отдельно только после успешного preflight.

## Немедленный STOP

- writer flag не равен строго `0` до финальной авторизации;
- readiness не `OK` или обнаружен неизвестный resume/send process;
- schema/meta/fingerprint/manifest не совпадают;
- потеря lease/fencing, изменившийся payload, scope или owner;
- duplicate/conflict/ambiguous remote outcome;
- timeout после передачи: состояние `AMBIGUOUS`, blind retry запрещён;
- suppression, legal, reputation, quota или capacity gate изменился;
- секрет, webhook, персональные данные или raw provider error попали в технический вывод.

STOP отзывает permit/authorization и сохраняет quarantine/evidence. Он не удаляет события и
не запускает повторную запись.

## Construction Demand Radar

Radar не входит в Bitrix canary. v15 содержит только bounded offline evidence vault для новых
review/access ledgers, append-only review decisions и quota-bound permit для `OFFLINE_FIXTURE`.
Vault не покрывает автоматически все старые observation evidence и не является общим encrypted
document store. Permit не является universal ingest gate. Source reads в v15 остаются `0`;
методов fetch/scrape и API их включения нет. Этот permit не является live-разрешением.

До живого source adapter обязательны отдельный source passport, capability/licence/ToS test,
data-contract fixture и evidence policy, а также owner-approved authorization с точным
credential/endpoint/source/data-class scope, бюджетом, runtime STOP и reconciliation. До shadow
нужны assignment-based merge/split/reassignment, production evidence repository, reviewer
identity и связь feedback с CRM/order, predeclared comparison protocol, не менее 100 вручную
проверенных объектов, сопоставимая baseline-когорта и значимый uplift. `SHADOW_READY` не создаёт
CRM-задачу и не разрешает outreach. `KEEP_SEPARATE` без object reassignment остаётся REVIEW;
даже локальный `CONTINUE_SHADOW` не доказывает «10 лидов в день» и всегда сохраняет
`commercial_claim_allowed=false`.
