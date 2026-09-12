'use strict';

// Run the real shipped asset. The harness implements only the DOM/event/clock
// contracts it uses; it neither reproduces panel logic nor parses provider HTML.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const assetPath = path.join(__dirname, '..', 'lead_factory', 'radar_workbench_assets', 'tenderplan-review.js');
const assetSource = fs.readFileSync(assetPath, 'utf8');
const VERSION = 'tenderplan-workbench-review-v1';
const SEMANTICS = 'UNVERIFIED_PROVIDER_SEMANTICS';
const SERVER_NOW = '2026-09-12T12:00:00.000Z';

function createTenderplanPanelHarness() {
  function events(target) {
    const listeners = new Map();
    target.addEventListener = (type, listener) => {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(listener);
    };
    target.dispatchEvent = event => {
      for (const listener of listeners.get(event.type) || []) listener.call(target, event);
      return true;
    };
    return target;
  }

  function element(tagName) {
    let ownText = '';
    const classes = new Set();
    const attributes = new Map();
    const node = events({
      tagName: tagName.toUpperCase(), children: [], dataset: {},
      hidden: false, disabled: false,
      classList: {
        toggle(name, active) {
          if (active) classes.add(name); else classes.delete(name);
        },
        contains(name) { return classes.has(name); }
      },
      setAttribute(name, value) { attributes.set(name, String(value)); },
      getAttribute(name) { return attributes.get(name); },
      append(...children) { this.children.push(...children); },
      replaceChildren(...children) { ownText = ''; this.children = [...children]; },
      querySelectorAll(selector) {
        assert.equal(selector, 'button', 'minimal harness supports only the actual button query');
        const found = [];
        function visit(current) {
          for (const child of current.children) {
            if (child.tagName === 'BUTTON') found.push(child);
            visit(child);
          }
        }
        visit(this);
        return found;
      },
      click() { if (!this.disabled) this.dispatchEvent({type: 'click'}); }
    });
    Object.defineProperty(node, 'textContent', {
      get() { return ownText + this.children.map(child => child.textContent).join(''); },
      set(value) { ownText = String(value); this.children = []; }
    });
    Object.defineProperty(node, 'innerHTML', {
      set() { throw new Error('Provider content must be written as text, never HTML'); }
    });
    return node;
  }

  const ids = [
    'tenderplan-panel', 'tenderplan-message', 'tenderplan-list',
    'tenderplan-detail', 'tenderplan-content', 'tenderplan-toggle',
    'tenderplan-prev', 'tenderplan-next', 'tenderplan-page'
  ];
  const nodes = new Map(ids.map(id => [id, element(
    ['tenderplan-toggle', 'tenderplan-prev', 'tenderplan-next'].includes(id) ? 'button' : 'div'
  )]));
  nodes.get('tenderplan-panel').hidden = true;
  nodes.get('tenderplan-content').hidden = true;
  nodes.get('tenderplan-prev').disabled = true;
  nodes.get('tenderplan-next').disabled = true;
  const document = events({
    hidden: false,
    getElementById(id) {
      assert.ok(nodes.has(id), 'unexpected element requested: ' + id);
      return nodes.get(id);
    },
    createElement: element
  });
  const window = events({});

  let monotonic = 0;
  // Deliberately years away from the provider's clock.
  let wall = Date.parse('2042-02-03T04:05:06.000Z');
  let timerId = 0;
  const timers = new Map();
  class ClockDate extends Date {
    constructor(...args) { super(...(args.length ? args : [wall])); }
    static now() { return wall; }
  }
  function setTimer(callback, delay) {
    const id = ++timerId;
    timers.set(id, {callback, at: monotonic + Math.max(0, Number(delay) || 0)});
    return id;
  }
  function advance(ms) {
    const target = monotonic + ms;
    let invocations = 0;
    while (true) {
      const next = [...timers.entries()].filter(([, timer]) => timer.at <= target)
        .sort((a, b) => a[1].at - b[1].at)[0];
      if (!next) break;
      assert.ok(++invocations < 10000, 'timer must not loop without advancing');
      const [id, timer] = next;
      timers.delete(id);
      wall += timer.at - monotonic;
      monotonic = timer.at;
      timer.callback();
    }
    wall += target - monotonic;
    monotonic = target;
  }

  const requests = [];
  function fetch(url, options) {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    requests.push({
      url: String(url), options,
      respond(body, status = 200) {
        const copied = structuredClone(body);
        resolve({ok: status >= 200 && status < 300, status, json: async () => copied});
      }
    });
    // Intentionally ignore abort: cancellation is best effort in real transports.
    // A stale successful response must remain harmless even when it still arrives.
    return promise;
  }
  vm.runInNewContext(assetSource, {
    document, window, fetch, AbortController,
    Date: ClockDate, performance: {now: () => monotonic},
    setTimeout: setTimer, clearTimeout: id => timers.delete(id)
  }, {filename: assetPath, timeout: 1000});

  const get = id => nodes.get(id);
  return {
    document, window, requests, advance, get,
    flush: () => new Promise(resolve => setImmediate(resolve)),
    detailText: () => get('tenderplan-detail').textContent,
    buttons: () => get('tenderplan-list').querySelectorAll('button'),
    clickReference(id) {
      const button = this.buttons().find(node => node.dataset.referenceId === id);
      assert.ok(button, 'reference button must exist: ' + id);
      button.click();
    },
    lastRequest() { return requests.at(-1); },
    assertCleared() {
      assert.equal(get('tenderplan-content').hidden, true);
      assert.equal(get('tenderplan-toggle').getAttribute('aria-expanded'), 'false');
      assert.equal(get('tenderplan-list').textContent, '');
      assert.doesNotMatch(this.detailText(), /PRIVATE-CARD|PRIVATE-CUSTOMER/);
    }
  };
}

function reference(id, overrides = {}) {
  return {
    item_id: 'item-' + id, reference_id: id,
    created_at_utc: SERVER_NOW, expires_at_utc: '2026-09-12T12:01:00.000Z',
    state: 'READY_FOR_REVIEW', content_state: 'AVAILABLE',
    semantic_status: SEMANTICS, ...overrides
  };
}

function listResponse(items, total = items.length) {
  return {version: VERSION, items, total};
}

function detailResponse(ref, {ttl = 60000, title = 'PRIVATE-CARD-' + ref.reference_id} = {}) {
  return {
    version: VERSION, server_now_utc: SERVER_NOW,
    reference: {...ref, expires_at_utc: new Date(Date.parse(SERVER_NOW) + ttl).toISOString()},
    card: {
      semantic_status: SEMANTICS, title,
      customer_legal_names: ['PRIVATE-CUSTOMER-' + ref.reference_id],
      tender_id: 'provider-' + ref.reference_id, number: '42', revision: '1',
      publication_datetime: 'provider date', submission_close_datetime: 'provider deadline',
      max_price: '3 000 000', currency: 'RUB', region: 'provider region', status: 'provider status'
    }
  };
}

async function enablePanel(h) {
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].url, '/api/session');
  h.requests[0].respond({tenderplan_review_enabled: true, token: 'local-test-session'});
  await h.flush();
  assert.equal(h.get('tenderplan-panel').hidden, false);
  assert.equal(h.get('tenderplan-content').hidden, true);
}

async function openList(h, items, total = items.length) {
  h.get('tenderplan-toggle').click();
  const request = h.lastRequest();
  assert.equal(request.url, '/api/tenderplan/reviews?limit=50&offset=0');
  request.respond(listResponse(items, total));
  await h.flush();
}

function assertOnlyReadRequests(h) {
  for (const request of h.requests) {
    assert.equal(request.options.method, 'GET');
    assert.equal(request.options.cache, 'no-store');
    assert.equal(request.options.credentials, 'same-origin');
    assert.match(request.url, /^\/api\/(?:session$|tenderplan\/reviews(?:\?|\/))/);
    assert.equal(request.options.body, undefined);
    if (request.url !== '/api/session') {
      assert.equal(request.options.headers['X-Workspace-Token'], 'local-test-session');
    }
  }
}

test('panel is disabled until the server explicitly enables it', async t => {
  for (const session of [{}, {tenderplan_review_enabled: false}, {tenderplan_review_enabled: 'true'}]) {
    await t.test(JSON.stringify(session), async () => {
      const h = createTenderplanPanelHarness();
      assert.equal(h.get('tenderplan-panel').hidden, true);
      h.get('tenderplan-toggle').click();
      assert.equal(h.requests.length, 1);
      h.requests[0].respond(session);
      await h.flush();
      h.get('tenderplan-toggle').click();
      assert.equal(h.get('tenderplan-panel').hidden, true);
      assert.equal(h.get('tenderplan-content').hidden, true);
      assert.equal(h.requests.length, 1, 'disabled panel must not fetch a list or detail');
    });
  }
});

test('list is metadata only; explicit selection renders provider strings as text', async () => {
  const h = createTenderplanPanelHarness();
  await enablePanel(h);
  const ref = reference('ref /?<A>');
  await openList(h, [ref, reference('expired', {content_state: 'EXPIRED'})]);
  assert.equal(h.requests.length, 2, 'listing must not auto-fetch/decrypt any detail');
  assert.equal(h.buttons().length, 2);
  h.clickReference('expired');
  assert.equal(h.requests.length, 2, 'expired reference must not fetch content');
  h.clickReference(ref.reference_id);
  assert.equal(h.lastRequest().url,
    '/api/tenderplan/reviews/' + encodeURIComponent(ref.item_id) +
    '?reference_id=' + encodeURIComponent(ref.reference_id));
  const attack = '<img src=x onerror="globalThis.providerExecuted=true"><script>bad()</script>';
  const body = detailResponse(ref, {title: attack});
  body.card.customer_legal_names = [attack];
  body.card.region = attack;
  h.lastRequest().respond(body);
  await h.flush();
  assert.ok(h.detailText().includes(attack), 'the exact provider string must remain text');
  assert.match(h.detailText(), /Сведения источника · требуют проверки/);
  const allTags = [];
  function visit(node) { allTags.push(node.tagName); node.children.forEach(visit); }
  visit(h.get('tenderplan-detail'));
  assert.equal(allTags.includes('IMG'), false);
  assert.equal(allTags.includes('SCRIPT'), false);
  assert.equal(h.buttons()[0].getAttribute('aria-pressed'), 'true');
  assertOnlyReadRequests(h);
});

test('late A response cannot restore plaintext after B is selected and expires', async () => {
  const h = createTenderplanPanelHarness();
  await enablePanel(h);
  const a = reference('A'), b = reference('B');
  await openList(h, [a, b]);
  h.clickReference('A');
  const slowA = h.lastRequest();
  h.clickReference('B');
  h.lastRequest().respond(detailResponse(b, {ttl: 1000}));
  await h.flush();
  assert.match(h.detailText(), /PRIVATE-CARD-B/);
  assert.doesNotMatch(h.detailText(), /PRIVATE-CARD-A/);
  h.advance(1000);
  assert.doesNotMatch(h.detailText(), /PRIVATE-CARD|PRIVATE-CUSTOMER/);
  slowA.respond(detailResponse(a));
  await h.flush();
  assert.doesNotMatch(h.detailText(), /PRIVATE-CARD|PRIVATE-CUSTOMER/);
  assert.ok(h.buttons().every(node => node.getAttribute('aria-pressed') === 'false'));
  assert.equal(h.requests.length, 4, 'expiry must not automatically reopen or fetch content');
});

test('TTL uses server time, includes request latency, and never auto-refetches', async () => {
  const h = createTenderplanPanelHarness();
  await enablePanel(h);
  const ref = reference('TTL');
  await openList(h, [ref]);
  h.clickReference('TTL');
  h.advance(2000);
  h.lastRequest().respond(detailResponse(ref, {ttl: 5000}));
  await h.flush();
  assert.match(h.detailText(), /PRIVATE-CARD-TTL/, 'local calendar skew must not prematurely expire it');
  h.advance(2999);
  assert.match(h.detailText(), /PRIVATE-CARD-TTL/);
  h.advance(1);
  assert.doesNotMatch(h.detailText(), /PRIVATE-CARD|PRIVATE-CUSTOMER/);
  assert.equal(h.requests.length, 3);
  h.advance(10000);
  assert.equal(h.requests.length, 3, 'timer must only clear, never fetch/decrypt again');
});

const clearBoundaries = [
  ['document hidden', h => { h.document.hidden = true; h.document.dispatchEvent({type: 'visibilitychange'}); }],
  ['pagehide', h => h.window.dispatchEvent({type: 'pagehide'})],
  ['canonical object selection', h => h.document.dispatchEvent({type: 'radar:object-selected'})],
  ['close button', h => h.get('tenderplan-toggle').click()]
];
for (const [name, clear] of clearBoundaries) {
  test(name + ' clears displayed text and rejects later responses', async () => {
    const h = createTenderplanPanelHarness();
    await enablePanel(h);
    const a = reference('A'), b = reference('B');
    await openList(h, [a, b]);
    h.clickReference('A');
    h.lastRequest().respond(detailResponse(a));
    await h.flush();
    assert.match(h.detailText(), /PRIVATE-CARD-A/);
    clear(h);
    h.assertCleared();
    h.document.hidden = false;
    h.document.dispatchEvent({type: 'visibilitychange'});
    assert.equal(h.requests.length, 3, 'returning to a visible page must not auto-fetch');
    await openList(h, [a, b]);
    h.clickReference('B');
    const late = h.lastRequest();
    clear(h);
    h.assertCleared();
    late.respond(detailResponse(b));
    await h.flush();
    h.assertCleared();
    assert.equal(h.requests.length, 5);
    assertOnlyReadRequests(h);
  });
}

test('a late list from a closed panel cannot replace the newly opened list', async () => {
  const h = createTenderplanPanelHarness();
  await enablePanel(h);
  h.get('tenderplan-toggle').click();
  const oldList = h.lastRequest();
  h.get('tenderplan-toggle').click();
  h.assertCleared();
  await openList(h, [reference('B')]);
  oldList.respond(listResponse([reference('A')]));
  await h.flush();
  assert.deepEqual(h.buttons().map(node => node.dataset.referenceId), ['B']);
  assert.equal(h.requests.length, 3, 'neither list response may fetch card content');
});

test('changing page clears detail and never fetches a detail automatically', async () => {
  const h = createTenderplanPanelHarness();
  await enablePanel(h);
  const a = reference('A');
  await openList(h, [a], 51);
  h.clickReference('A');
  h.lastRequest().respond(detailResponse(a));
  await h.flush();
  assert.match(h.detailText(), /PRIVATE-CARD-A/);
  h.get('tenderplan-next').click();
  assert.doesNotMatch(h.detailText(), /PRIVATE-CARD|PRIVATE-CUSTOMER/);
  assert.equal(h.lastRequest().url, '/api/tenderplan/reviews?limit=50&offset=50');
  h.lastRequest().respond(listResponse([reference('B')], 51));
  await h.flush();
  assert.deepEqual(h.buttons().map(node => node.dataset.referenceId), ['B']);
  assert.equal(h.requests.length, 4);
  assertOnlyReadRequests(h);
});
