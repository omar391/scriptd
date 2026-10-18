const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function browser({ stale = false, offline = false } = {}) {
  const source = fs.readFileSync('assets/web/app.js', 'utf8')
    .replace(/^import .*;\n/gm, '')
    .replace(/connect\(\);\s*$/, 'renderApp = () => {}; persistDrafts = () => {}; connect();');
  const storage = values => ({
    getItem: key => values[key] ?? null,
    setItem: (key, value) => { values[key] = value; },
    removeItem: key => { delete values[key]; }
  });
  const server = { token: stale ? 'new-token' : 'old-token', offline };
  const streams = [];
  const timers = new Map();
  let timerId = 0;
  const context = vm.createContext({
    h: () => {}, render: () => {}, htm: { bind: () => () => {} },
    URLSearchParams,
    location: { search: '', pathname: '/', origin: 'http://127.0.0.1:15921' },
    history: { replaceState() {} },
    sessionStorage: storage({ 'scriptd-session': 'old-token' }),
    localStorage: storage({ 'scriptd-recovery': 'durable-capability', 'scriptd-drafts': '{"service":{"yaml":"unsaved draft"}}' }),
    window: { addEventListener() {}, matchMedia: () => ({ matches: false }) },
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout: id => timers.delete(id),
    EventSource: class {
      constructor(url) { this.url = url; this.listeners = {}; streams.push(this); }
      addEventListener(type, callback) { this.listeners[type] = callback; }
      close() { this.closed = true; }
    },
    fetch: async (path, options = {}) => {
      if (server.offline) throw new TypeError('Failed to fetch');
      const headers = options.headers || {};
      const authenticated = headers['x-scriptd-session'] === server.token;
      let status = 200;
      let body;
      if (path === '/api/session' && headers['x-scriptd-recovery'] === 'durable-capability') body = { ok: true, session: server.token };
      else if (!authenticated) { status = 401; body = { ok: false, message: 'session was not accepted' }; }
      else if (path === '/api/session') body = { ok: true, recovery: 'durable-capability' };
      else if (path === '/api/snapshot') body = { ok: true, snapshot: { service: { running: true, pid: server.token } } };
      else body = { ok: true, drafts: {} };
      return { ok: status === 200, status, json: async () => body };
    }
  });
  vm.runInContext(source, context);
  return {
    server, streams, context,
    state: () => vm.runInContext('appState', context),
    nextRetry: async () => {
      const entry = [...timers.entries()][0];
      assert.ok(entry, 'automatic retry is scheduled');
      timers.delete(entry[0]); entry[1].fn();
      await settle();
      return entry[1].delay;
    },
    retryCount: () => timers.size
  };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('an open tab heals across restarts and downtime without reload or losing drafts', async () => {
  const tab = browser();
  await settle();
  assert.equal(tab.state().serviceOnline, true);
  const original = tab.streams[0];
  tab.server.offline = true;
  original.onerror(); original.onerror();
  assert.equal(tab.retryCount(), 1, 'duplicate SSE errors do not duplicate retries');
  assert.equal(original.closed, true);
  assert.equal(await tab.nextRetry(), 1000);
  assert.equal(await tab.nextRetry(), 2000);
  tab.server.offline = false;
  tab.server.token = 'second-generation';
  await tab.nextRetry();
  assert.equal(tab.state().snapshot.service.pid, 'second-generation');
  assert.equal(tab.state().error, '');
  assert.equal(tab.streams.at(-1).url, '/events?session=second-generation');
  assert.equal(tab.state().drafts.service.yaml, 'unsaved draft');
  original.listeners.snapshot({ data: '{"service":{"running":false}}' });
  assert.equal(tab.state().serviceOnline, true, 'obsolete stream cannot overwrite recovered state');
  tab.server.token = 'third-generation';
  tab.streams.at(-1).onerror();
  assert.equal(await tab.nextRetry(), 1000, 'successful recovery resets backoff');
  assert.equal(tab.state().snapshot.service.pid, 'third-generation');
});

test('a tab opened during downtime or reloaded with a stale token heals automatically', async () => {
  const tab = browser({ stale: true, offline: true });
  await settle();
  assert.equal(tab.streams.length, 0, 'no event stream opens before authentication');
  await tab.nextRetry();
  tab.server.offline = false;
  await tab.nextRetry();
  assert.equal(tab.state().serviceOnline, true);
  assert.equal(tab.streams.at(-1).url, '/events?session=new-token');
  assert.equal(tab.context.sessionStorage.getItem('scriptd-session'), 'new-token');
});
