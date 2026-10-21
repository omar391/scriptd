const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function browser({ offline = false, grant = 'browser-grant', claim = null, authorized = true } = {}) {
  const source = fs.readFileSync('assets/web/app.js', 'utf8')
    .replace(/^import .*;\n/gm, '')
    .replace(/connect\(\);\s*$/, 'renderApp = () => {}; persistDrafts = () => {}; connect();');
  const storage = values => ({
    getItem: key => values[key] ?? null,
    setItem: (key, value) => { values[key] = value; },
    removeItem: key => { delete values[key]; }
  });
  const server = { offline, grant, authorized, generation: 1, claim, logReads: 0 };
  const streams = [];
  const timers = new Map();
  let timerId = 0;
  const documentListeners = {};
const frames = [];
const documentStub = {
    visibilityState: 'visible',
    activeElement: null,
    title: '',
    addEventListener: (name, handler) => { (documentListeners[name] = documentListeners[name] || []).push(handler); },
    getElementById: () => null,
    querySelector: () => null
  };
  const context = vm.createContext({
    h: (type, props, ...children) => ({ type, props: props || {}, children }),
    render: () => {}, htm: { bind: () => () => {} },
    requestAnimationFrame: callback => { frames.push(callback); return frames.length; },
    crypto: { randomUUID: () => 'test-request-id' },
    location: { pathname: '/', origin: 'http://127.0.0.1:15921' },
    sessionStorage: storage(claim ? { 'scriptd-access-claim': claim } : {}),
    localStorage: storage({ 'scriptd-grant': grant, 'scriptd-drafts': '{"service":{"yaml":"unsaved draft"}}' }),
    document: documentStub,
    navigator: { userAgent: 'Test Browser' },
    window: { addEventListener() {}, matchMedia: () => ({ matches: false }) },
    AbortController,
    URLSearchParams,
    URL,
    TextDecoder,
    TextEncoder,
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout: id => timers.delete(id),
    fetch: async (path, options = {}) => {
      if (server.offline) throw new TypeError('Failed to fetch');
      const headers = options.headers || {};
      const authenticated = headers['x-scriptd-grant'] === server.grant;
      if (path === '/api/access') {
        return jsonResponse(authenticated && server.authorized
          ? { ok: true, state: 'authorized' }
          : { ok: true, state: 'unauthorized' });
      }
      if (path === '/api/access/poll' && options.method === 'POST') {
        const body = JSON.parse(options.body);
        if (body.claim === server.claim) {
          server.grant = 'recovered-grant';
          server.authorized = true;
        }
        return jsonResponse(body.claim === server.claim
          ? { ok: true, state: 'authorized', grant: 'recovered-grant' }
          : { ok: false, state: 'unauthorized' }, body.claim === server.claim ? 200 : 401);
      }
      if (!authenticated || !server.authorized) return jsonResponse({ ok: false, state: 'unauthorized' }, 401);
      if (path === '/api/snapshot') return jsonResponse({ ok: true, snapshot: { service: { running: true, pid: `generation-${server.generation}` } } });
      if (path === '/api/drafts') return jsonResponse({ ok: true, drafts: {} });
      if (path === '/api/access/list') return jsonResponse({ ok: true, profiles: [] });
      if (path.startsWith('/api/logs')) {
        server.logReads += 1;
        return jsonResponse({ ok: true, logs: 'log line' });
      }
      if (path === '/events') {
        const stream = makeStream(options.signal);
        streams.push(Object.assign(stream, { url: path, headers }));
        return { ok: true, status: 200, body: { getReader: () => stream.reader } };
      }
      return jsonResponse({ ok: true });
    }
  });
  vm.runInContext(source, context);
  return {
    server, streams, context,
    state: () => vm.runInContext('appState', context),
    document: documentStub,
    flushFrames: () => { while (frames.length) frames.shift()(); },
    setVisibility: state => {
      documentStub.visibilityState = state;
      for (const handler of documentListeners.visibilitychange || []) handler();
    },
    nextRetry: async () => {
      const entry = [...timers.entries()].find(([, timer]) => timer.delay >= 1000);
      assert.ok(entry, 'automatic retry is scheduled');
      timers.delete(entry[0]); entry[1].fn();
      await settle();
      return entry[1].delay;
    },
    retryCount: () => timers.size
  };
}

function jsonResponse(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function makeStream(signal) {
  let finish;
  const queued = [];
  const stream = {
    closed: false,
    reader: null,
    close: () => { stream.closed = true; if (finish) finish({ done: true, aborted: true }); }
  };
  stream.reader = {
    read: () => new Promise((resolve, reject) => {
      if (queued.length) return resolve(queued.shift());
      finish = value => (value.aborted ? reject(new Error('aborted')) : resolve(value));
    }),
    cancel: async () => { stream.closed = true; }
  };
  stream.closeGracefully = () => { if (finish) finish({ done: true }); };
  stream.sendFrame = (data, eventName) => {
    const header = eventName ? `event: ${eventName}\n` : '';
    const value = { done: false, value: new TextEncoder().encode(`${header}data: ${JSON.stringify(data)}\n\n`) };
    if (finish) { const resolve = finish; finish = null; resolve(value); }
    else queued.push(value);
  };
  signal.addEventListener('abort', stream.close, { once: true });
  return stream;
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('an approved tab heals across restarts and downtime without losing drafts', async () => {
  const tab = browser();
  await settle();
  assert.equal(tab.state().serviceOnline, true);
  const original = tab.streams[0];
  assert.equal(original.url, '/events', 'the grant is never put in the stream URL');
  assert.equal(original.headers['x-scriptd-grant'], 'browser-grant');

  tab.server.offline = true;
  original.closeGracefully();
  await settle();
  assert.equal(tab.retryCount(), 1, 'normal stream EOF triggers automatic recovery');
  assert.equal(await tab.nextRetry(), 1000);
  assert.equal(await tab.nextRetry(), 2000);

  tab.server.offline = false;
  tab.server.generation = 2;
  await tab.nextRetry();
  assert.equal(tab.state().snapshot.service.pid, 'generation-2');
  assert.equal(tab.state().error, '');
  assert.equal(tab.state().drafts.service.yaml, 'unsaved draft');

  original.closeGracefully();
  await settle();
  assert.equal(tab.state().snapshot.service.pid, 'generation-2', 'an obsolete stream cannot overwrite recovered state');
  assert.equal(tab.retryCount(), 0, 'an obsolete stream cannot schedule a duplicate reconnect');
  tab.streams.at(-1).closeGracefully();
  await settle();
  tab.server.generation = 3;
  assert.equal(await tab.nextRetry(), 1000, 'a successful recovery resets reconnect backoff');
  assert.equal(tab.state().snapshot.service.pid, 'generation-3');
});

test('an unauthorized browser does not report the service offline or open a stream', async () => {
  const tab = browser({ grant: 'revoked-grant' });
  tab.server.authorized = false;
  await settle();
  assert.equal(tab.state().accessState, 'unauthorized');
  assert.equal(tab.state().serviceOnline, false);
  assert.equal(tab.streams.length, 0);
  assert.equal(tab.retryCount(), 0);
});

test('a stored private claim recovers approval after reload when status is unauthorized', async () => {
  const tab = browser({ grant: 'old-grant', claim: 'private-claim', authorized: false });
  await settle();
  await settle();
  await settle();
  assert.equal(tab.state().accessState, 'authorized');
  assert.equal(tab.state().snapshot.service.pid, 'generation-1');
  assert.equal(tab.context.localStorage.getItem('scriptd-grant'), 'recovered-grant');
});

test('a recoverable stream error does not prevent a later healthy snapshot', async () => {
  const tab = browser();
  await settle();
  const stream = tab.streams[0];
  stream.sendFrame({ ok: false, message: 'temporary snapshot error' });
  await settle();
  assert.equal(tab.state().error, 'temporary snapshot error');
  stream.sendFrame({ service: { running: true, pid: 'recovered' } });
  await settle();
  assert.equal(tab.state().snapshot.service.pid, 'recovered');
  assert.equal(tab.state().error, '');
  assert.equal(tab.retryCount(), 0);
});

test('a delayed-observation notice preserves the snapshot and is exposed in page state', async () => {
  const tab = browser();
  await settle();
  const stream = tab.streams[0];
  assert.equal(tab.state().snapshot.service.pid, 'generation-1');

  stream.sendFrame({ ok: true, observation: 'delayed' }, 'observation');
  await settle();

  assert.equal(tab.state().snapshot.service.pid, 'generation-1', 'a notice cannot replace the current service snapshot');
  assert.equal(tab.state().observationDelayed, true, 'the delayed-update banner state is retained');

  stream.sendFrame({ ok: true, service: { running: true, pid: 'generation-2' }, observation: 'delayed' }, 'snapshot');
  await settle();
  assert.equal(tab.state().snapshot.service.pid, 'generation-2');
  assert.equal(tab.state().observationDelayed, true, 'real snapshots carry the delayed state too');
});


test('a hidden page suspends the stream and a visible page resumes it without losing drafts', async () => {
  const tab = browser();
  await settle();
  assert.equal(tab.streams.length, 1, 'the stream opens while the page is visible');

  tab.setVisibility('hidden');
  await settle();
  assert.equal(tab.streams[0].closed, true, 'a hidden page releases the stream');
  assert.equal(tab.retryCount(), 0, 'a hidden page schedules no reconnect');

  tab.setVisibility('visible');
  await settle();
  assert.equal(tab.streams.length, 2, 'a visible page opens a fresh stream');
  assert.equal(tab.state().drafts.service.yaml, 'unsaved draft', 'drafts survive the transition');
});

test('a hidden page performs no automatic log reads and a visible followed log reads once per notification', async () => {
  const tab = browser();
  await settle();
  tab.setVisibility('hidden');
  await settle();
  const readsWhileHidden = tab.server.logReads;
  assert.equal(readsWhileHidden, 0, 'a hidden page reads no logs');

  tab.setVisibility('visible');
  await settle();
  const readsAfterResume = tab.server.logReads;
  assert.equal(readsAfterResume, 0, 'resuming does not read logs until a notification arrives');

  const stream = tab.streams.at(-1);
  stream.sendFrame({ ok: true, module: 'service' }, 'logs_changed');
  await settle();
  assert.equal(tab.server.logReads, 1, 'one notification triggers exactly one log read');
});


test('confirmation dialogs restore the current opener after confirm, Cancel, Escape, and reopening', async () => {
  const tab = browser();
  await settle();

  const opener = name => ({ name, focusCount: 0, focus() { this.focusCount += 1; } });
  const mountConfirmation = active => {
    tab.document.activeElement = active;
    vm.runInContext("confirmRun('mbrew')", tab.context);
    const dialog = vm.runInContext('Dialog()', tab.context);
    dialog.props.ref({ open: false, showModal() { this.open = true; } });
    return dialog;
  };
  const findButton = (node, label) => {
    if (!node || typeof node !== 'object') return null;
    if (node.type === 'button' && node.children[0] === label) return node;
    for (const child of node.children || []) {
      const found = findButton(child, label);
      if (found) return found;
    }
    return null;
  };

  const confirmedOpener = opener('confirm opener');
  const confirmation = mountConfirmation(confirmedOpener);
  assert.equal(tab.state().dialogFocus, confirmedOpener);
  findButton(confirmation, 'Queue manual run').props.onClick();
  assert.equal(tab.state().dialogFocus, null, 'confirm clears the captured opener');
  tab.flushFrames();
  assert.equal(confirmedOpener.focusCount, 1, 'confirm returns focus to its opener');

  const cancelOpener = opener('cancel opener');
  const cancelDialog = mountConfirmation(cancelOpener);
  findButton(cancelDialog, 'Cancel').props.onClick();
  assert.equal(tab.state().dialogFocus, null, 'Cancel clears the captured opener');
  tab.flushFrames();
  assert.equal(cancelOpener.focusCount, 1, 'Cancel returns focus to its opener');

  const escapeOpener = opener('escape opener');
  const escapeDialog = mountConfirmation(escapeOpener);
  let prevented = false;
  escapeDialog.props.onCancel({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true, 'Escape is kept inside the modal close path');
  assert.equal(tab.state().dialogFocus, null, 'Escape clears the captured opener');
  tab.flushFrames();
  assert.equal(escapeOpener.focusCount, 1, 'Escape returns focus to its opener');

  const nextOpener = opener('next dialog opener');
  const nextDialog = mountConfirmation(nextOpener);
  assert.equal(tab.state().dialogFocus, nextOpener, 'a later dialog captures its own opener');
  nextDialog.props.onCancel({ preventDefault() {} });
  tab.flushFrames();
  assert.equal(nextOpener.focusCount, 1);
});

test('the stream asks for log notifications only while a module log tab is followed', async () => {
  const tab = browser();
  await settle();
  assert.equal(tab.streams[0].url, '/events', 'the default stream asks for no log module');
});

test('brew casks that need a decision are shown with actions and never retried blindly', async () => {
  const tab = browser();
  await settle();

  const packages = [
    { name: 'opaque-cask', state: 'attention', reason: 'no trustworthy application identity', attempts: 0, retry: false },
    { name: 'anydesk', state: 'deferred', reason: 'an application or helper is running', attempts: 0, retry: true },
    { name: 'ignored-cask', state: 'dismissed', reason: 'dismissed by the user', attempts: 0, retry: false, dismissed: true }
  ];
  const snapshot = {
    service: { running: true, pid: 'generation-1' },
    modules: [{
      id: 'mbrew', name: 'Brew Manager', enabled: true, valid: true,
      outcomes: { packages }
    }]
  };
  const before = JSON.stringify(snapshot);
  tab.streams[0].sendFrame(snapshot);
  await settle();

  const state = tab.state();
  assert.equal(state.snapshot.modules[0].id, 'mbrew');
  assert.equal(JSON.stringify(state.snapshot), before, 'rendering must not mutate the snapshot');

  const panel = vm.runInContext('CaskAttentionPanel(moduleInfo("mbrew"))', tab.context);
  assert.ok(panel, 'a cask needing a decision opens the attention panel');

  const rendered = JSON.stringify(panel);
  assert.ok(rendered.includes('opaque-cask'), 'the attention cask is listed');
  assert.ok(!rendered.includes('anydesk'), 'a merely retry-eligible cask is not an attention item');
  assert.ok(!rendered.includes('ignored-cask'), 'a dismissed cask is not re-prompted');
  assert.ok(rendered.includes('Approve'), 'the panel offers an approve action');
  assert.ok(rendered.includes('Dismiss'), 'the panel offers a dismiss action');
  assert.ok(rendered.includes('Retry pending casks'), 'the panel can request the existing retry action');

  vm.runInContext("appState.caskAttention[JSON.stringify(['opaque-cask', 'no trustworthy application identity'])] = 'allowed'", tab.context);
  const resolvedPanel = vm.runInContext('CaskAttentionPanel(moduleInfo("mbrew"))', tab.context);
  assert.ok(JSON.stringify(resolvedPanel).includes('disabled'), 'a resolved episode keeps its decision state while attention remains');

  tab.streams[0].sendFrame({ service: { running: true }, modules: [{ id: 'mbrew', outcomes: { packages: [] } }] });
  await settle();
  tab.streams[0].sendFrame(snapshot);
  await settle();
  const recurringPanel = vm.runInContext('CaskAttentionPanel(moduleInfo("mbrew"))', tab.context);
  assert.ok(!JSON.stringify(recurringPanel).includes('allowed'), 'a later attention episode starts without the old decision');
});
