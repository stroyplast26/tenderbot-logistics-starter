"use strict";

const $ = id => document.getElementById(id);
const RESULTS = {
  NO_ANSWER: "Не удалось связаться", CALLBACK: "Договорились перезвонить",
  NEEDS_RESEARCH: "Нужны дополнительные сведения", RFQ_REPORTED: "Получен запрос расчёта · со слов менеджера",
  QUOTE_REPORTED: "Подготовлено КП · со слов менеджера", RESEARCH_COMPLETE: "Исследование завершено",
  NOT_RELEVANT: "Объект не подходит", DO_NOT_CONTACT: "Больше не связываться"
};
const ACTIONS = {NONE: "Работа завершена", CALLBACK: "Перезвонить", RESEARCH: "Собрать сведения", VERIFY_NEED: "Уточнить потребность", PREPARE_QUOTE: "Подготовить расчёт и КП", FOLLOW_UP: "Обсудить предложение"};
const ALLOWED = {NO_ANSWER: ["CALLBACK"], CALLBACK: ["CALLBACK"], NEEDS_RESEARCH: ["RESEARCH", "VERIFY_NEED"], RFQ_REPORTED: ["PREPARE_QUOTE"], QUOTE_REPORTED: ["FOLLOW_UP"], RESEARCH_COMPLETE: ["NONE"], NOT_RELEVANT: ["NONE"], DO_NOT_CONTACT: ["NONE"]};
const STATES = {OPEN: "Назначено", ACKNOWLEDGED: "Принято", IN_PROGRESS: "В работе", COMPLETED: "Завершено", CLOSED: "Закрыто"};
const LABELS = {TITLE: "Название", OFFICE: "Офисное здание", SCHOOL: "Школа", HOTEL: "Гостиница", ENTRANCE_GROUPS: "Входные группы", FACADE: "Фасад", WINDOWS: "Окна", STAGE: "Стадия строительства", DEMAND: "Предполагаемая потребность", ALUMINIUM_DEMAND: "Предполагаемая потребность", ADDRESS: "Адрес", ENCLOSING_STRUCTURES_APPROACHING: "Приближаются ограждающие конструкции", CONSTRUCTION: "Строительство", DESIGN: "Проектирование", GENERAL_CONTRACTOR: "Генеральный подрядчик", DEVELOPER: "Застройщик", DESIGNER: "Проектировщик", WINDOW_AND_FACADE: "Окна и фасады", MEDIUM: "Средний объём", UNKNOWN: "Неизвестно", D14: "В пределах 14 дней", D30: "В пределах 30 дней", D90: "В пределах 90 дней"};
let session, items = [], total = 0, offset = 0, selected = null, dossier = null, selectionRequest = 0, queueRequest = 0, saving = false;
const PAGE_SIZE = 100;
const el = (tag, text, className) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = String(text); if (className) node.className = className; return node; };
const date = value => value ? new Date(value).toLocaleString("ru-RU", {dateStyle: "short", timeStyle: "short"}) : "не указан";
const label = value => LABELS[value] || String(value ?? "—");
const active = task => task && !["COMPLETED", "CLOSED", "CANCELLED"].includes(task.state);
const overdue = task => active(task) && task.due_at_utc && Date.parse(task.due_at_utc) < Date.now();
function message(text, kind = "") { $("message").textContent = text; $("message").className = kind; }
function badge(text, kind = "") { return el("span", text, `badge ${kind}`); }
function defaultDue() { const value = new Date(); value.setDate(value.getDate() + 1); value.setHours(9, 0, 0, 0); return new Date(value.getTime() - value.getTimezoneOffset() * 60000).toISOString().slice(0, 16); }
function utcInput(id) { const value = $(id).value; if (!value || !Number.isFinite(Date.parse(value))) throw new Error("Укажите дату и время следующего шага."); return new Date(value).toISOString().replace(".000Z", "Z"); }
async function api(path, body) {
  const response = await fetch(path, {method: body ? "POST" : "GET", credentials: "same-origin", headers: body ? {"Content-Type": "application/json", "X-Workspace-Token": session.token} : {}, body: body ? JSON.stringify(body) : undefined});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Не удалось выполнить действие.");
  return result;
}
function renderQueue() {
  const query = $("search").value.trim().toLocaleLowerCase("ru");
  const filter = $("filter").value;
  const shown = items.filter(item => (!query || `${item.title} ${item.address}`.toLocaleLowerCase("ru").includes(query)) && ({all: true, mine: item.work_item?.assignee === session.actor && active(item.work_item), unassigned: !item.work_item, overdue: overdue(item.work_item), stale: item.freshness === "STALE", review: item.review_count > 0})[filter]);
  $("object-list").replaceChildren();
  for (const item of shown) {
    const button = el("button", undefined, `object-row${selected === item.object_id ? " selected" : ""}`);
    button.type = "button"; button.setAttribute("aria-pressed", String(selected === item.object_id));
    button.append(el("strong", item.title || item.address || "Объект без названия"), el("small", item.work_item ? `${item.work_item.assignee} · ${date(item.work_item.due_at_utc)}` : "Без исполнителя"));
    if (item.freshness === "STALE") button.append(badge("Обновить сведения", "warn"));
    if (overdue(item.work_item)) button.append(badge("Просрочено", "bad"));
    if (item.review_count) button.append(badge(`Вопросы: ${item.review_count}`, "warn"));
    if (item.work_item?.do_not_contact) button.append(badge("Не связываться", "bad"));
    button.addEventListener("click", () => { if (!saving) selectObject(item.object_id).catch(error => message(error.message, "error")); });
    $("object-list").append(button);
  }
  if (!shown.length) $("object-list").append(el("p", total ? "По этому фильтру на странице ничего нет." : "Объектов пока нет. Добавьте разрешённую выгрузку по инструкции импорта.", "muted"));
  $("count").textContent = total;
  $("page").textContent = total ? `${offset + 1}–${Math.min(offset + items.length, total)} из ${total}` : "0";
  $("prev").disabled = saving || offset === 0; $("next").disabled = saving || offset + PAGE_SIZE >= total;
}
async function loadQueue() {
  const request = ++queueRequest;
  const result = await api(`/api/objects?limit=${PAGE_SIZE}&offset=${offset}`);
  if (request !== queueRequest) return;
  items = result.items; total = result.total; renderQueue();
}
async function selectObject(id) {
  const request = ++selectionRequest;
  selected = id; dossier = null; $("dossier").hidden = true; $("empty").hidden = false; renderQueue();
  const result = await api(`/api/objects/${encodeURIComponent(id)}`);
  if (request !== selectionRequest || selected !== id) return;
  dossier = result; renderDossier();
}
function sourceCaption(row) {
  const reasons = {SOURCE_PASSPORT_SUPERSEDED: "разрешение источника заменено", SOURCE_PASSPORT_INACTIVE: "источник не разрешён", SOURCE_APPROVAL_EXPIRED: "срок разрешения источника истёк", SOURCE_DATA_STALE: "сведения устарели"};
  const status = (row.freshness_reasons || []).map(reason => reasons[reason] || "источник требует проверки").join("; ");
  return `${row.source_key || "Источник"} · ${date(row.source_date_utc || row.observed_at_utc || row.predicted_at_utc)}${row.is_current_revision === false ? " · предыдущая версия" : ""}${status ? ` · ${status}` : row.source_freshness === "STALE" || row.freshness === "STALE" ? " · устарело" : ""}`;
}
function details(parent, row) {
  const block = el("details"); block.append(el("summary", "Происхождение записи"));
  block.append(el("pre", JSON.stringify(row, null, 2))); parent.append(block);
}
function dataRow(title, text, row) {
  const node = el("div", undefined, "data-row"); node.append(el("strong", title), el("p", text), el("p", sourceCaption(row), "muted")); details(node, row); return node;
}
function claimValue(row) {
  let value; try { value = JSON.parse(row.value_json); } catch { value = row.value_json; }
  if (value && typeof value === "object") return Object.entries(value).map(([key, item]) => `${({aluminium_system: "Система", quantity_band: "Объём", building_type: "Тип здания"})[key] || key}: ${label(item)}`).join(" · ");
  return label(value);
}
function renderDossier() {
  const data = dossier, obj = data.object, task = data.work_item;
  $("dossier").hidden = false; $("empty").hidden = true;
  $("object-title").textContent = obj.title || obj.address || "Объект без названия"; $("address").textContent = obj.address;
  $("object-badges").replaceChildren(badge(`Источников: ${obj.source_count}`), badge(obj.freshness === "CURRENT" ? "По сроку актуально" : obj.freshness === "STALE" ? "Нужна актуализация" : "Свежесть неизвестна", obj.freshness === "CURRENT" ? "good" : "warn"));
  if (obj.review_count) $("object-badges").append(badge(`Нерешённых вопросов: ${obj.review_count}`, "warn"));
  $("coordinates").textContent = obj.latitude && obj.longitude ? `Координаты по сведениям источника: ${obj.latitude}, ${obj.longitude}` : "Координаты пока не указаны.";
  $("task-state").textContent = task ? STATES[task.state] || task.state : "Без задачи";
  $("current-task").replaceChildren();
  if (task) {
    const summary = el("div", undefined, "task-summary"); summary.append(el("p", `Исполнитель: ${task.assignee}`), el("p", `Следующий шаг: ${ACTIONS[task.next_action] || task.next_action}`));
    if (task.due_at_utc) summary.append(el("p", `Срок: ${date(task.due_at_utc)}${overdue(task) ? " · просрочено" : ""}`));
    if (task.result) summary.append(el("p", RESULTS[task.result] || task.result));
    $("current-task").append(summary);
  } else $("current-task").append(el("p", "Назначьте исполнителя и срок проверки объекта.", "muted"));
  $("assignee").value = task?.assignee || session.actor; $("assign-due").value = defaultDue();
  $("assign-form").hidden = !!task && !active(task);
  $("assign-button").textContent = task ? "Переназначить задачу" : "Назначить задачу";
  $("result-form").hidden = !active(task) || task.assignee !== session.actor;
  $("assignment-note").textContent = task?.do_not_contact ? "Зафиксирован отказ от контакта. Работа по этому объекту заблокирована. Общая блокировка адресата в каналах связи ещё не синхронизирована." : active(task) && task.assignee !== session.actor ? `Результат может сохранить исполнитель ${task.assignee}.` : task && !active(task) ? "Задача завершена, история сохранена." : "";
  $("reason").value = ""; $("result").value = "NO_ANSWER"; $("next-due").value = defaultDue(); updateActions();
  $("claims").replaceChildren();
  for (const row of data.project_claims) $("claims").append(dataRow(label(row.claim_type), claimValue(row), row));
  for (const row of data.predictions) $("claims").append(dataRow("Предполагаемое окно закупки", `${date(row.window_start_utc)} — ${date(row.window_end_utc)} · предполагаемый покупатель: ${row.likely_buyer_inn || "не указан"}`, row));
  for (const row of data.negative_evidence || []) $("claims").append(dataRow("Ограничение из источника", row.kind || row.negative_kind || "Требует проверки", row));
  if (!$("claims").children.length) $("claims").append(el("p", "Стадия и потребность пока не указаны.", "muted"));
  $("participants").replaceChildren();
  for (const row of data.participants) $("participants").append(dataRow(label(row.role), `ИНН: ${row.company_inn} · роль указана на период ${date(row.valid_from_utc)} — ${date(row.valid_until_utc)}`, row));
  if (!data.participants.length) $("participants").append(el("p", "Участников предстоит установить. Контакт закупщика ещё не подтверждён.", "muted"));
  $("sources").replaceChildren();
  for (const row of data.signals) {
    const node = dataRow(row.source_key, `Получено: ${date(row.collected_at_utc)} · версия ${row.source_revision}`, row);
    if (row.source_url) { try { const url = new URL(row.source_url); if (url.protocol === "https:" && !url.username && !url.password) { const link = el("a", "Открыть страницу источника ↗"); link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer"; node.append(link); } } catch { /* invalid links remain plain data */ } }
    $("sources").append(node);
  }
  $("reviews").replaceChildren();
  for (const row of data.reviews) { const node = el("p", `${row.effective_state === "OPEN" ? "Требует проверки" : "Рассмотрено"}: ${row.reason || row.review_kind || row.review_id}`, "warning"); details(node, row); $("reviews").append(node); }
  $("history").replaceChildren();
  for (const row of [...data.history].reverse()) {
    const item = row.work_item, node = el("li");
    node.append(el("strong", row.operation === "ASSIGN" ? "Задача назначена" : row.operation === "REASSIGN" ? "Задача переназначена" : RESULTS[item.result] || item.result), el("p", `${date(row.time)} · ${row.actor}`, "muted"));
    if (row.operation === "RESULT") node.append(el("p", item.reason));
    node.append(el("p", `${item.assignee} · ${ACTIONS[item.next_action] || item.next_action}${item.due_at_utc ? ` · ${date(item.due_at_utc)}` : ""}`));
    $("history").append(node);
  }
  if (!data.history.length) $("history").append(el("li", "Действий менеджера ещё нет.", "muted"));
}
function updateActions() {
  const result = $("result").value, actions = ALLOWED[result];
  $("next-action").replaceChildren(...actions.map(value => { const option = el("option", ACTIONS[value]); option.value = value; return option; }));
  const terminal = actions[0] === "NONE"; $("next-date-label").hidden = terminal; $("next-due").required = !terminal;
  $("terminal-warning").hidden = !terminal;
  $("terminal-warning").textContent = result === "DO_NOT_CONTACT" ? "Этот результат заблокирует дальнейшие действия по объекту. Сохраните, только если зафиксирован отказ от контакта." : "Этот результат завершит задачу. Сохранённую историю нельзя удалить через это рабочее место.";
}
async function save(action, values) {
  if (saving || !dossier) return;
  saving = true; const id = selected, version = dossier.work_item?.version || 0;
  document.querySelectorAll("form button").forEach(button => button.disabled = true); $("refresh").disabled = true; renderQueue();
  try {
    const key = crypto.randomUUID();
    await api(`/api/objects/${encodeURIComponent(id)}/${action}`, {...values, expected_version: version, idempotency_key: key, ...(action === "result" ? {evidence_ref: `evidence://radar-workbench/manager-note/${key}`} : {})});
    await loadQueue(); await selectObject(id); message("Сохранено. Следующий шаг и история обновлены.", "success");
  } catch (error) { message(`${error.message} При потере соединения обновите досье перед повторным сохранением.`, "error"); }
  finally { saving = false; document.querySelectorAll("form button").forEach(button => button.disabled = false); $("refresh").disabled = false; renderQueue(); }
}
$("assign-form").addEventListener("submit", event => { event.preventDefault(); try { save(dossier.work_item ? "reassign" : "assign", {assignee: $("assignee").value.trim(), due_at_utc: utcInput("assign-due")}); } catch (error) { message(error.message, "error"); } });
$("result-form").addEventListener("submit", event => { event.preventDefault(); try { const next = $("next-action").value; save("result", {result: $("result").value, reason: $("reason").value.trim(), next_action: next, next_action_at_utc: next === "NONE" ? "" : utcInput("next-due")}); } catch (error) { message(error.message, "error"); } });
$("result").addEventListener("change", updateActions);
$("search").addEventListener("input", renderQueue); $("filter").addEventListener("change", renderQueue);
$("refresh").addEventListener("click", async () => { try { await loadQueue(); if (selected) await selectObject(selected); message("Данные обновлены."); } catch (error) { message(error.message, "error"); } });
for (const [id, delta] of [["prev", -PAGE_SIZE], ["next", PAGE_SIZE]]) $(id).addEventListener("click", () => { offset = Math.max(0, offset + delta); loadQueue().catch(error => message(error.message, "error")); });
async function start() { try { session = await api("/api/session"); $("actor").textContent = `Исполнитель: ${session.actor}`; $("demo").hidden = !session.demo; await loadQueue(); } catch (error) { message(`Рабочее место недоступно. ${error.message}`, "error"); } }
start();
