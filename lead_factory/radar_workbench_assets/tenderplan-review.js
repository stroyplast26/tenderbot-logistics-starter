"use strict";

function initializeTenderplanReviewPanel() {
  const node = id => document.getElementById(id);
  const panel = node("tenderplan-panel");
  if (!panel) return;
  const VERSION = "tenderplan-workbench-review-v1";
  const SEMANTICS = "UNVERIFIED_PROVIDER_SEMANTICS";
  const PAGE_SIZE = 50;
  const stateLabels = {READY_FOR_REVIEW: "На проверку", KEEP: "Оставлено", DISMISS: "Отклонено", HOLD: "Отложено"};
  let enabled = false, token = "", open = false, offset = 0;
  let queueGeneration = 0, detailGeneration = 0, selectedReference = null;
  let queueAbort = null, detailAbort = null, expiryTimer = null;
  let deadline = 0, wallDeadline = 0;
  const textNode = (tag, value, className) => {
    const element = document.createElement(tag);
    element.textContent = String(value ?? "");
    if (className) element.className = className;
    return element;
  };
  const metadataDate = value => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString("ru-RU") : "не указан";
  const message = (text, error = false) => {
    node("tenderplan-message").textContent = text;
    node("tenderplan-message").className = error ? "error" : "";
  };
  function selectionBadges() {
    for (const button of node("tenderplan-list").querySelectorAll("button")) {
      const active = button.dataset.referenceId === selectedReference;
      button.classList.toggle("selected", active);
      button.setAttribute("aria-pressed", String(active));
    }
  }
  function clearDetail(text = "Выберите карточку для просмотра.") {
    ++detailGeneration;
    detailAbort?.abort(); detailAbort = null;
    clearTimeout(expiryTimer); expiryTimer = null;
    deadline = 0; wallDeadline = 0; selectedReference = null;
    node("tenderplan-detail").replaceChildren(textNode("p", text, "muted"));
    selectionBadges();
  }
  function closePanel() {
    open = false; ++queueGeneration;
    queueAbort?.abort(); queueAbort = null;
    clearDetail();
    node("tenderplan-list").replaceChildren();
    node("tenderplan-content").hidden = true;
    node("tenderplan-toggle").textContent = "Открыть очередь";
    node("tenderplan-toggle").setAttribute("aria-expanded", "false");
    message("");
  }
  async function readJSON(path, signal) {
    const response = await fetch(path, {
      method: "GET", credentials: "same-origin", cache: "no-store", signal,
      headers: token ? {"X-Workspace-Token": token} : {}
    });
    if (!response.ok) throw Object.assign(new Error("Source unavailable"), {status: response.status});
    return response.json();
  }
  function unavailable(error) {
    if (error.status === 410) return "Срок хранения карточки истёк. Содержимое недоступно.";
    if (error.status === 404) return "Карточка больше недоступна. Обновите очередь.";
    return "Не удалось открыть сохранённую запись. Нужна проверка доступности очереди.";
  }
  function expireView(generation) {
    if (generation !== detailGeneration) return;
    if (!open || document.hidden || performance.now() >= deadline || Date.now() >= wallDeadline) {
      clearDetail("Просмотр завершён. Откройте карточку снова, чтобы проверить её доступность.");
      return;
    }
    expiryTimer = setTimeout(() => expireView(generation), Math.min(deadline - performance.now(), 1000));
  }
  function renderCard(card, reference) {
    const detail = node("tenderplan-detail");
    detail.replaceChildren(
      textNode("span", "Сведения источника · требуют проверки", "badge warn"),
      textNode("h3", card.title || "Карточка без названия"),
      textNode("p", "Даты, регион, цена и статус приведены как в источнике. Их смысл и актуальность нужно уточнить по документации.", "muted")
    );
    const fields = [
      ["Номер закупки", card.number], ["Идентификатор в источнике", card.tender_id],
      ["Редакция", card.revision], ["Дата публикации в источнике", card.publication_datetime],
      ["Срок подачи в источнике", card.submission_close_datetime],
      ["Цена в источнике", card.max_price], ["Валюта в источнике", card.currency],
      ["Регион в источнике", card.region], ["Статус в источнике", card.status]
    ];
    for (const [label, value] of fields) {
      const row = textNode("div", "", "data-row");
      row.append(textNode("strong", label), textNode("p", typeof value === "string" && value ? value : "Не указано"));
      detail.append(row);
    }
    const customers = textNode("div", "", "data-row");
    customers.append(textNode("strong", "Заказчики по сведениям источника"));
    for (const name of card.customer_legal_names) customers.append(textNode("p", name));
    if (!card.customer_legal_names.length) customers.append(textNode("p", "Не указаны"));
    detail.append(customers,
      textNode("p", `Содержимое доступно до ${metadataDate(reference.expires_at_utc)}.`, "muted"),
      textNode("p", "Для назначения задачи нужны подтверждённый объект и профильный пакет работ. Проверка этой связи — следующий шаг.", "notice")
    );
  }
  async function selectReference(reference) {
    clearDetail("Открываем выбранную карточку…");
    if (!open || document.hidden || reference.content_state !== "AVAILABLE") return;
    const generation = detailGeneration;
    selectedReference = reference.reference_id; selectionBadges();
    detailAbort = new AbortController();
    const started = performance.now();
    let result;
    try {
      result = await readJSON(`/api/tenderplan/reviews/${encodeURIComponent(reference.item_id)}?reference_id=${encodeURIComponent(reference.reference_id)}`, detailAbort.signal);
      if (generation !== detailGeneration || !open || document.hidden) return;
      if (result.version !== VERSION || result.reference?.reference_id !== reference.reference_id ||
          result.reference?.item_id !== reference.item_id || result.reference?.content_state !== "AVAILABLE" ||
          result.reference?.semantic_status !== SEMANTICS || result.card?.semantic_status !== SEMANTICS ||
          !Array.isArray(result.card.customer_legal_names) || result.card.customer_legal_names.some(value => typeof value !== "string")) {
        throw new Error("Invalid source response");
      }
      const remaining = Date.parse(result.reference.expires_at_utc) - Date.parse(result.server_now_utc) - (performance.now() - started);
      if (!Number.isFinite(remaining) || remaining <= 0) throw Object.assign(new Error("Expired"), {status: 410});
      deadline = performance.now() + remaining;
      wallDeadline = Date.now() + remaining;
      renderCard(result.card, result.reference);
      message("Открыта одна сохранённая карточка.");
      expireView(generation);
    } catch (error) {
      if (generation === detailGeneration && error.name !== "AbortError") {
        clearDetail(unavailable(error)); message("Карточка не открыта.", true);
      }
    } finally {
      // No provider DTO is retained in panel state or event/timer closures.
      if (result && typeof result === "object") result.card = null;
      if (generation === detailGeneration) detailAbort = null;
    }
  }
  async function loadReferences() {
    clearDetail();
    const generation = ++queueGeneration;
    queueAbort?.abort(); queueAbort = new AbortController();
    node("tenderplan-list").replaceChildren();
    node("tenderplan-prev").disabled = true; node("tenderplan-next").disabled = true;
    message("Загружаем список сохранённых записей…");
    try {
      const result = await readJSON(`/api/tenderplan/reviews?limit=${PAGE_SIZE}&offset=${offset}`, queueAbort.signal);
      if (generation !== queueGeneration || !open) return;
      if (result.version !== VERSION || !Array.isArray(result.items) || !Number.isInteger(result.total) || result.total < 0) throw new Error("Invalid source list");
      for (const [index, reference] of result.items.entries()) {
        const button = textNode("button", "", "object-row");
        button.type = "button"; button.dataset.referenceId = reference.reference_id;
        button.setAttribute("aria-pressed", "false");
        button.append(textNode("strong", `Карточка ${offset + index + 1}`),
          textNode("small", `Сохранена ${metadataDate(reference.created_at_utc)}`),
          textNode("small", `Доступна до ${metadataDate(reference.expires_at_utc)}`),
          textNode("span", stateLabels[reference.state] || "Требует проверки", "badge"));
        button.disabled = reference.content_state !== "AVAILABLE";
        if (button.disabled) button.append(textNode("span", "Срок хранения истёк", "badge warn"));
        button.addEventListener("click", () => selectReference(reference));
        node("tenderplan-list").append(button);
      }
      if (!result.items.length) node("tenderplan-list").append(textNode("p", "Сохранённых карточек на этой странице нет.", "muted"));
      node("tenderplan-page").textContent = result.total ? `${offset + 1}–${Math.min(offset + result.items.length, result.total)} из ${result.total}` : "0";
      node("tenderplan-prev").disabled = offset === 0;
      node("tenderplan-next").disabled = offset + PAGE_SIZE >= result.total;
      message("Список содержит сведения о записях. Содержимое открывается по нажатию.");
    } catch (error) {
      if (generation === queueGeneration && error.name !== "AbortError") message(unavailable(error), true);
    } finally {
      if (generation === queueGeneration) queueAbort = null;
    }
  }
  node("tenderplan-toggle").addEventListener("click", () => {
    if (!enabled) return;
    if (open) { closePanel(); return; }
    open = true; offset = 0;
    node("tenderplan-content").hidden = false;
    node("tenderplan-toggle").textContent = "Скрыть очередь";
    node("tenderplan-toggle").setAttribute("aria-expanded", "true");
    loadReferences();
  });
  for (const [id, delta] of [["tenderplan-prev", -PAGE_SIZE], ["tenderplan-next", PAGE_SIZE]]) {
    node(id).addEventListener("click", () => { offset = Math.max(0, offset + delta); loadReferences(); });
  }
  document.addEventListener("radar:object-selected", closePanel);
  document.addEventListener("visibilitychange", () => { if (document.hidden) closePanel(); });
  window.addEventListener("pagehide", closePanel);
  readJSON("/api/session").then(session => {
    enabled = session.tenderplan_review_enabled === true;
    token = typeof session.token === "string" ? session.token : "";
    panel.hidden = !enabled;
  }).catch(() => { panel.hidden = true; });
}

initializeTenderplanReviewPanel();
