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
  const server = { offline, grant, authorized, generation: 1, claim };
  const streams = [];
  const timers = new Map();
  let timerId = 0;
  const context = vm.createContext({
    h: () => {}, render: () => {}, htm: { bind: () => () => {} },
    location: { pathname: '/', origin: 'http://127.0.0.1:15921' },
    sessionStorage: storage(claim ? { 'scriptd-access-claim': claim } : {}),
    localStorage: storage({ 'scriptd-grant': grant, 'scriptd-drafts': '{"service":{"yaml":"unsaved draft"}}' }),
    navigator: { userAgent: 'Test Browser' },
    window: { addEventListener() {}, matchMedia: () => ({ matches: false }) },
    AbortController,
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
      if (path === '/events') {
        const stream = makeStream(options.signal);
        streams.push({ ...stream, url: path, headers });
        return { ok: true, status: 200, body: { getReader: () => stream.reader } };
      }
      return jsonResponse({ ok: true });
    }
  });
  vm.runInContext(source, context);
  return {
    server, streams, context,
    state: () => vm.runInContext('appState', context),
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
  stream.sendFrame = data => {
    const value = { done: false, value: new TextEncoder().encode(`data: ${JSON.stringify(data)}\n\n`) };
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
