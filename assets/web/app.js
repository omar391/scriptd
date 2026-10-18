import { h, render } from '/vendor/preact.module.js';
import htm from '/vendor/htm.module.js';
const html = htm.bind(h);
const BrandMark = html`<span class="brand-mark" aria-hidden="true">s</span>`;

const MODULES = [
  { id: 'mbrew', name: 'Brew Manager', icon: 'B' },
  { id: 'mcpu', name: 'CPU Monitor', icon: 'C' },
  { id: 'mwifi', name: 'Wi-Fi Monitor', icon: 'W' },
  { id: 'miwatch', name: 'Router Watch', icon: 'R' }
];
const SETTING_PROFILES = {
  service: { basic: ['watch', 'log_dir', 'self_update_check_hours'], advanced: ['label'] },
  mbrew: { basic: ['homebrew_bin', 'trusted_taps', 'sudo_timeout_hours'], advanced: ['askpass_path', 'sudoers_path', 'sudoers_timeout_path'] },
  mcpu: { basic: ['cpu_threshold', 'exclude_apps'], advanced: [] },
  mwifi: { basic: ['prefer_ssids', 'ssids', 'repeater_rules', 'min_dwell', 'ping_target', 'ping_count', 'ping_timeout', 'ping_high_latency_ms', 'health_failure_switch_runs'], advanced: ['band_bonus_2g', 'band_bonus_5g', 'band_bonus_6g', 'preference_top_bonus', 'preference_rank_decay', 'current_sticky_bonus', 'rssi_offset', 'min_switch_score_delta'] },
  miwatch: { basic: ['cooldown_seconds', 'verified_remote_api', 'state_file', 'token_file'], advanced: ['remote'] }
};
const SETTING_LABELS = {
  watch: ['Watch configuration files', 'Reload valid configuration changes while the service is running.'],
  log_dir: ['Log directory', 'Directory used for module and service logs.'],
  self_update_check_hours: ['Source update check interval (hours)', 'Hours between checks for newer source files.'],
  label: ['Service label', 'Launchd service identifier. Changing it requires a service restart.'],
  homebrew_bin: ['Homebrew executable', 'Path used by maintenance runs.'],
  trusted_taps: ['Trusted taps', 'Tap sources permitted during Homebrew maintenance.'],
  sudo_timeout_hours: ['Privilege timeout (hours)', 'Hours before the sudo credential expires.'],
  askpass_path: ['Privilege prompt helper', 'Existing native authentication helper path.'],
  sudoers_path: ['Privilege policy path', 'System sudoers file used by the existing setup flow.'],
  sudoers_timeout_path: ['Timeout policy path', 'System policy for the privilege timeout.'],
  cpu_threshold: ['CPU threshold (%)', 'Minimum CPU percentage that triggers a cleanup candidate.'],
  exclude_apps: ['Excluded apps', 'Applications that must not be considered for cleanup.'],
  prefer_ssids: ['Preferred networks', 'Ordered network preference list.'],
  ssids: ['Candidate networks', 'Networks that may be considered by the monitor.'],
  repeater_rules: ['Repeater rules', 'SSID pattern and parent network mappings.'],
  min_dwell: ['Minimum dwell (seconds)', 'Seconds to remain on a network before switching.'],
  ping_target: ['Health check target', 'Host used by the network health probe.'],
  ping_count: ['Health check probes (count)', 'Probe count for one health evaluation.'],
  ping_timeout: ['Probe timeout (seconds)', 'Seconds allowed for each health probe.'],
  ping_high_latency_ms: ['High latency limit (milliseconds)', 'Milliseconds above which a network is considered unhealthy.'],
  health_failure_switch_runs: ['Failure runs before switching (runs)', 'Consecutive unhealthy evaluations required.'],
  band_bonus_2g: ['2.4 GHz score bonus', 'Advanced network scoring adjustment.'],
  band_bonus_5g: ['5 GHz score bonus', 'Advanced network scoring adjustment.'],
  band_bonus_6g: ['6 GHz score bonus', 'Advanced network scoring adjustment.'],
  preference_top_bonus: ['Top preference bonus', 'Advanced network scoring adjustment.'],
  preference_rank_decay: ['Preference rank decay', 'Advanced network scoring adjustment.'],
  current_sticky_bonus: ['Current network bonus', 'Advanced network scoring adjustment.'],
  rssi_offset: ['Signal strength offset', 'Advanced network scoring adjustment.'],
  min_switch_score_delta: ['Minimum switch score difference', 'Advanced network scoring adjustment.'],
  cooldown_seconds: ['Reboot cooldown (seconds)', 'Minimum seconds between router reboot attempts.'],
  verified_remote_api: ['Verify remote API', 'Require the configured remote API verification.'],
  state_file: ['Session health state file', 'Local state used to track router session health.'],
  token_file: ['Session token file', 'Path used by the existing native session flow.'],
  remote: ['Remote router settings', 'API endpoint, client identity, HTTP status, and timeout settings.']
};
const tabs = ['Overview', 'Settings', 'Triggers', 'Logs'];
const query = new URLSearchParams(location.search);

// The bridge hands the token to the tab through the URL on first launch and
// through sessionStorage on reload. The authenticated browser context also
// retains an origin-scoped recovery capability in localStorage, so a reload
// after sessionStorage was cleared can re-acquire the token from /api/session.
// Keep the value mutable so the recovered credential reaches
// every request without a page reload, and read it through sessionToken() so
// no caller can capture a stale empty value.
let session = query.get('session') || sessionStorage.getItem('scriptd-session');
function sessionToken() { return session; }

// Repopulates a lost credential with the origin-scoped recovery capability.
async function restoreSession() {
  if (session) return session;
  try {
    const capability = localStorage.getItem('scriptd-recovery');
    if (!capability) return null;
    const recovered = await fetch('/api/session', {
      headers: { 'x-scriptd-recovery': capability }, cache: 'no-store'
    }).then(r => r.json());
    if (recovered && recovered.ok && recovered.session) {
      session = recovered.session;
      sessionStorage.setItem('scriptd-session', session);
      return session;
    }
  } catch (_) {}
  return null;
}
if (session) {
  sessionStorage.setItem('scriptd-session', session);
  history.replaceState(null, '', location.pathname);
  fetch('/api/session', {
    headers: { 'x-scriptd-session': session }, cache: 'no-store'
  }).then(r => r.json()).then(data => {
    if (data && data.ok && data.recovery) localStorage.setItem('scriptd-recovery', data.recovery);
  }).catch(() => {});
}

let appState = {
  section: 'overview', module: null, tab: 'Overview', collapsed: false, mobileNavOpen: false,
  snapshot: null, drafts: {}, logs: [], severity: 'all', search: '',
  follow: true, message: '', error: '', loading: true, dialog: null,
  saveDiff: null, serviceOnline: false, quitQueue: null, quitWorking: false
};
let eventSource;
let draftTimer;
let settingsParseTimer;
let logTimer;
let saveReviewToken = 0;
let quitOperationToken = 0;

function api(path, options) {
  const opts = options || {};
  opts.headers = Object.assign({}, opts.headers || {}, { 'x-scriptd-session': sessionToken() || '' });
  if (opts.body) {
    opts.headers['content-type'] = 'application/json';
    opts.headers.origin = location.origin;
  }
  return fetch(path, opts).then(async response => {
    const data = await response.json();
    if (!response.ok || data.ok === false) throw new Error(data.message || ('Request failed (' + response.status + ')'));
    return data;
  });
}

function setState(patch) {
  appState = Object.assign({}, appState, patch);
  renderApp();
}

function moduleInfo(id) {
  return (appState.snapshot && appState.snapshot.modules || []).find(item => item.id === id) || {};
}

function docKey(id) { return id ? 'module:' + id : 'service'; }
function sourceYaml(id) {
  const info = id ? moduleInfo(id) : {};
  return id ? (info.module_yaml || '') : ((appState.snapshot && appState.snapshot.service_yaml) || '');
}
function sourceDigest(id) {
  const info = id ? moduleInfo(id) : {};
  return id ? (info.module_digest || '') : ((appState.snapshot && appState.snapshot.config_digest) || '');
}
function draftYaml(id) {
  const entry = appState.drafts[docKey(id)];
  return entry ? entry.yaml : sourceYaml(id);
}
function isDirty(id) { return draftYaml(id) !== sourceYaml(id); }

function persistDrafts() {
  const recoverable = recoverableDrafts(appState.drafts);
  try { localStorage.setItem('scriptd-drafts', JSON.stringify(recoverable)); } catch (_) {}
  clearTimeout(draftTimer);
  draftTimer = setTimeout(() => api('/api/drafts', {
    method: 'POST', body: JSON.stringify(recoverable)
  }).catch(() => {}), 250);
}

function recoverableDrafts(drafts) {
  const recoverable = {};
  Object.keys(drafts).forEach(key => {
    if (drafts[key].yaml !== undefined || drafts[key].trigger_json !== undefined) recoverable[key] = drafts[key];
  });
  return recoverable;
}

function persistDraftsImmediately(drafts) {
  const recoverable = recoverableDrafts(drafts);
  clearTimeout(draftTimer);
  try { localStorage.setItem('scriptd-drafts', JSON.stringify(recoverable)); } catch (_) {}
  return api('/api/drafts', { method: 'POST', body: JSON.stringify(recoverable) });
}

function updateDraft(id, yaml) {
  const key = docKey(id);
  const previous = appState.drafts[key] || {};
  const nextDraft = Object.assign({}, previous, {
    yaml, settings_stale: true, base_digest: previous.base_digest || sourceDigest(id)
  });
  const drafts = Object.assign({}, appState.drafts, {
    [key]: nextDraft
  });
  appState = Object.assign({}, appState, { drafts });
  persistDrafts();
  renderApp();
  clearTimeout(settingsParseTimer);
  settingsParseTimer = setTimeout(() => parseDraftSettings(id, yaml), 150);
}

function parseDraftSettings(id, yaml) {
  api('/api/validate', { method: 'POST', body: JSON.stringify({
    document: id ? 'module' : 'service', module: id || undefined, yaml
  }) }).then(response => {
    const key = docKey(id);
    const entry = appState.drafts[key];
    if (!entry || entry.yaml !== yaml) return;
    const drafts = Object.assign({}, appState.drafts, {
      [key]: Object.assign({}, entry, { settings: response.snapshot && response.snapshot.settings || {}, settings_stale: false })
    });
    appState = Object.assign({}, appState, { drafts });
    persistDrafts();
    renderApp();
  }).catch(() => {});
}

function yamlScalar(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  return JSON.stringify(String(value));
}
function yamlBlock(value, indent) {
  const pad = ' '.repeat(indent);
  if (Array.isArray(value)) {
    if (!value.length) return [pad + '[]'];
    const lines = [];
    value.forEach(item => {
      if (item && typeof item === 'object') {
        const nested = yamlBlock(item, indent + 2);
        lines.push(pad + '- ' + nested[0].trimStart());
        lines.push(...nested.slice(1));
      } else lines.push(pad + '- ' + yamlScalar(item));
    });
    return lines;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (!entries.length) return [pad + '{}'];
    const lines = [];
    for (const [key, child] of entries) {
      const safeKey = /^[A-Za-z_][A-Za-z0-9_-]*$/.test(key) ? key : JSON.stringify(key);
      if (child && typeof child === 'object' && (Array.isArray(child) ? child.length : Object.keys(child).length)) {
        const nested = yamlBlock(child, indent + 2);
        lines.push(pad + safeKey + ':');
        lines.push(...nested);
      } else if (Array.isArray(child) && child.length === 0) lines.push(pad + safeKey + ': []');
      else if (child && typeof child === 'object' && !Array.isArray(child)) lines.push(pad + safeKey + ': {}');
      else lines.push(pad + safeKey + ': ' + yamlScalar(child));
    }
    return lines;
  }
  return [pad + yamlScalar(value)];
}
function yamlWithSettings(id, settings) {
  const source = draftYaml(id);
  if (!id) {
    const replacement = 'service:\n' + yamlBlock(settings || {}, 2).join('\n') + '\n';
    const start = source.search(/^service:\s*$/m);
    if (start < 0) return source.trimEnd() + '\n' + replacement;
    const modulesStart = source.indexOf('\nmodules:', start);
    const end = modulesStart >= 0 ? modulesStart + 1 : source.length;
    return source.slice(0, start) + replacement + (modulesStart >= 0 ? source.slice(end) : '');
  }
  const rendered = 'settings:\n' + yamlBlock(settings || {}, 2).join('\n') + '\n';
  return /^settings:\s*$/m.test(source) ? source.replace(/^settings:\s*\n[\s\S]*$/m, rendered) : source.trimEnd() + '\n\n' + rendered;
}
function setSetting(id, key, value) {
  const entry = appState.drafts[docKey(id)] || {};
  if (entry.settings_stale) return;
  const current = id ? moduleInfo(id).settings : ((appState.snapshot && appState.snapshot.service && appState.snapshot.service.settings) || {});
  const settings = JSON.parse(JSON.stringify(entry.settings || current || {}));
  const parts = key.split('.');
  let target = settings;
  for (const part of parts.slice(0, -1)) target = target[part] || (target[part] = {});
  target[parts[parts.length - 1]] = value;
  const yaml = yamlWithSettings(id, settings);
  const drafts = Object.assign({}, appState.drafts, { [docKey(id)]: Object.assign({}, entry, { yaml, settings, base_digest: entry.base_digest || sourceDigest(id) }) });
  appState = Object.assign({}, appState, { drafts });
  persistDrafts();
  renderApp();
}

function draftModuleEnabled(moduleId, enabled) {
  const source = draftYaml(null);
  const lines = source.split('\n');
  const modulesIndex = lines.findIndex(line => line.trim() === 'modules:');
  if (modulesIndex < 0) {
    setState({ error: 'The service document has no modules section. Add one in the YAML editor first.' });
    return;
  }
  const moduleIndex = lines.findIndex((line, index) => index > modulesIndex && /^  [A-Za-z0-9_-]+:\s*$/.test(line) && line.slice(2, -1) === moduleId);
  if (moduleIndex < 0) {
    lines.splice(modulesIndex + 1, 0, '  ' + moduleId + ':', '    enabled: ' + String(enabled));
  } else {
    const nextModule = lines.findIndex((line, index) => index > moduleIndex && /^  [A-Za-z0-9_-]+:\s*$/.test(line));
    const end = nextModule < 0 ? lines.length : nextModule;
    const enabledIndex = lines.findIndex((line, index) => index > moduleIndex && index < end && /^    enabled:\s*/.test(line));
    if (enabledIndex < 0) lines.splice(moduleIndex + 1, 0, '    enabled: ' + String(enabled));
    else lines[enabledIndex] = '    enabled: ' + String(enabled);
  }
  updateDraft(null, lines.join('\n'));
  appState = Object.assign({}, appState, { module: null, section: 'service', tab: 'Settings', message: (enabled ? 'Enable' : 'Disable') + ' ' + moduleId + ' in the shared service configuration, then review and save.' });
  renderApp();
}

function connect() {
  if (!session) {
    restoreSession().then(recovered => {
      if (recovered) connect();
      else setState({ loading: false, error: 'This browser session has no credential. Run scriptd again to open the control center.' });
    });
    return;
  }
  api('/api/snapshot').then(data => {
    const snapshot = data.snapshot || {};
    const drafts = Object.assign({}, JSON.parse(localStorage.getItem('scriptd-drafts') || '{}'), appState.drafts);
    appState = Object.assign({}, appState, { snapshot, drafts, serviceOnline: !!(snapshot.service && snapshot.service.running), loading: false, error: '' });
    renderApp();
    api('/api/drafts').then(saved => {
      appState = Object.assign({}, appState, { drafts: Object.assign({}, saved.drafts || {}, appState.drafts) });
      persistDrafts();
      renderApp();
      Object.keys(appState.drafts).forEach(key => {
        const entry = appState.drafts[key];
        if (entry.yaml !== undefined && (entry.settings_stale || !entry.settings)) {
          const id = key.startsWith('module:') ? key.slice('module:'.length) : null;
          parseDraftSettings(id, entry.yaml);
        }
      });
    }).catch(() => {});
  }).catch(error => setState({ loading: false, error: error.message }));
  if (eventSource) eventSource.close();
  eventSource = new EventSource('/events?session=' + encodeURIComponent(sessionToken()));
  eventSource.addEventListener('snapshot', event => {
    try {
      const data = JSON.parse(event.data);
      if (!data.ok && data.message) return setState({ error: data.message });
      appState = Object.assign({}, appState, { snapshot: data, serviceOnline: !!(data.service && data.service.running), error: '' });
      renderApp();
    } catch (_) {}
  });
  eventSource.onerror = () => setState({ error: 'Browser bridge disconnected. Refresh or run scriptd to reconnect.' });
}

function node(tag, props, children) { return h(tag, props || {}, ...(children || [])); }
function button(label, action, className, extra) {
  return h('button', Object.assign({ type: 'button', class: className || 'button', onClick: action }, extra || {}), label);
}
// A hidden visible label must not remove the button's accessible name, so mirror
// the label in a screen-reader-only element the compact rail keeps available.
function navName(label) {
  return [h('span', { class: 'nav-name', 'aria-hidden': 'true' }, label), h('span', { class: 'sr-only' }, label)];
}
function statusLabel(info) {
  if (!info.present) return 'Not installed';
  if (!info.valid) return 'Invalid configuration';
  if (info.enabled === false) return 'Disabled';
  const health = typeof info.health === 'string' ? info.health : (info.health && (info.health.status || info.health.state));
  if (info.health && info.health.ok === false) return info.health.message || info.message || 'Needs attention';
  if (health && health !== 'healthy') return String(health).replaceAll('_', ' ');
  if (info.status === 'failed' || info.status === 'error') return info.message || 'Needs attention';
  if (!info.status || info.status === 'unknown' || info.status === 'stopped') return 'Unknown';
  return 'Healthy';
}

// The control center can only report what it has actually observed. Before the
// first snapshot arrives the service state is unknown, not offline, and saying
// otherwise tells the user their service died when it never stopped.
function serviceStatusLabel() {
  const service = appState.snapshot && appState.snapshot.service || {};
  if (!appState.snapshot) return 'Service status unknown';
  return service.running ? 'Service running' : 'Service offline';
}
function serviceStatusTone() {
  const service = appState.snapshot && appState.snapshot.service || {};
  if (!appState.snapshot) return 'warn';
  return service.running ? 'good' : 'muted';
}
function badge(text, tone) { return h('span', { class: 'badge ' + (tone || '') }, text); }
function card(title, content, detail) {
  return h('section', { class: 'card' }, h('div', { class: 'card-heading' }, h('h2', null, title)),
    content, detail ? h('p', { class: 'muted' }, detail) : null);
}
function metric(label, value, note) {
  return h('article', { class: 'metric' }, h('span', { class: 'metric-label' }, label),
    h('strong', null, value || '—'), note ? h('small', null, note) : null);
}
function configurationApplicationState(snapshot) {
  const service = snapshot && snapshot.service || {};
  if (!snapshot) return 'Not observed yet';
  if (service.restart_required) return 'Restart required';
  if (!service.running) return 'Saved; service offline';
  if (service.reload_error) return 'Reload rejected';
  if (!service.loaded_digest) return 'Application unknown';
  if (service.loaded_digest === snapshot.config_digest) return 'Applied';
  return 'Saved; awaiting service reload';
}
function healthText(info) {
  const state = statusLabel(info);
  const tone = !info.present || !info.valid || (info.health && info.health.ok === false) || info.status === 'error' ? 'danger' :
    (info.enabled === false || !info.status || info.status === 'unknown' || info.status === 'stopped' ? 'muted' : 'good');
  return badge(state, tone);
}
function activeModule() { return appState.module ? moduleInfo(appState.module) : null; }
function sidebarToggleIcon(collapsed) {
  return h('svg', {
    class: 'icon-button-svg', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
    'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    'aria-hidden': 'true', focusable: 'false'
  },
  h('rect', { x: '3', y: '3', width: '18', height: '18', rx: '2' }),
  h('path', { d: 'M9 3v18' }),
  h('path', { d: collapsed ? 'm13 9 3 3-3 3' : 'm15 15-3-3 3-3' }));
}
function mobileNavigationIcon(open) {
  return h('svg', {
    class: 'icon-button-svg', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
    'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    'aria-hidden': 'true', focusable: 'false'
  }, h('path', { d: open ? 'm6 6 12 12M18 6 6 18' : 'M4 6h16M4 12h16M4 18h16' }));
}
function closeMobileNavigation(restoreFocus) {
  if (!appState.mobileNavOpen) return;
  appState = Object.assign({}, appState, { mobileNavOpen: false });
  renderApp();
  if (restoreFocus) {
    const toggle = document.getElementById('mobile-nav-toggle');
    if (toggle) toggle.focus();
  }
}
function focusMainContent() {
  const main = document.getElementById('content');
  if (main) main.focus();
}

function Sidebar() {
  const info = appState.snapshot || {};
  const service = info.service || {};
  const entries = [
    h('button', { type: 'button', class: 'nav-item ' + (appState.section === 'overview' ? 'selected' : ''), onClick: () => navigate(null) },
      h('span', { class: 'nav-icon' }, '⌂'), navName('Overview')),
    h('div', { class: 'nav-caption' }, 'MODULES'),
    ...MODULES.map(item => {
      const state = moduleInfo(item.id);
      return h('button', { type: 'button', class: 'nav-item ' + (appState.module === item.id ? 'selected' : ''), onClick: () => navigate(item.id) },
        h('span', { class: 'nav-icon' }, item.icon), navName(item.name),
        h('span', { class: 'nav-health' }, statusLabel(state)));
    }),
    h('div', { class: 'nav-caption service-caption' }, 'SERVICE'),
    h('button', { type: 'button', class: 'nav-item ' + (appState.section === 'service' ? 'selected' : ''), onClick: () => {
      const mobileNavigationWasOpen = appState.mobileNavOpen;
      appState = Object.assign({}, appState, { section: 'service', module: null, tab: 'Overview', mobileNavOpen: false });
      renderApp();
      if (mobileNavigationWasOpen) focusMainContent();
    } },
      h('span', { class: 'nav-icon' }, '◉'), navName('Service'), badge(service.running ? 'Running' : (appState.snapshot ? 'Offline' : 'Unknown'), service.running ? 'good' : (appState.snapshot ? 'muted' : 'warn')))
  ];
  return h('aside', { class: 'sidebar ' + (appState.collapsed ? 'collapsed ' : '') + (appState.mobileNavOpen ? 'mobile-nav-open' : ''), 'aria-label': 'Scriptd navigation' },
    h('div', { class: 'brand' }, BrandMark, h('strong', null, 'scriptd'),
      button(sidebarToggleIcon(appState.collapsed), () => setState({ collapsed: !appState.collapsed }), 'icon-button desktop-sidebar-toggle', { 'aria-expanded': String(!appState.collapsed), 'aria-label': appState.collapsed ? 'Expand navigation' : 'Collapse navigation', title: appState.collapsed ? 'Expand navigation' : 'Collapse navigation' }),
      button(mobileNavigationIcon(appState.mobileNavOpen), () => setState({ mobileNavOpen: !appState.mobileNavOpen }), 'icon-button mobile-nav-toggle', { id: 'mobile-nav-toggle', 'aria-expanded': String(appState.mobileNavOpen), 'aria-controls': 'primary-navigation', 'aria-label': appState.mobileNavOpen ? 'Close navigation' : 'Open navigation', title: appState.mobileNavOpen ? 'Close navigation' : 'Open navigation' })),
    h('nav', { id: 'primary-navigation', class: 'nav-list', 'aria-label': 'Main' }, entries),
    h('div', { class: 'sidebar-foot' }, h('span', { class: 'pulse ' + (serviceStatusTone() === 'good' ? 'on' : '') }),
      service.running ? 'Service connected' : (appState.snapshot ? 'Service unavailable' : 'Service status unknown'))
  );
}

function navigate(id) {
  const mobileNavigationWasOpen = appState.mobileNavOpen;
  appState = Object.assign({}, appState, { module: id, section: id ? 'module' : 'overview', tab: 'Overview', error: '', message: '', mobileNavOpen: false });
  renderApp();
  if (mobileNavigationWasOpen) focusMainContent();
  if (id && appState.tab === 'Logs') loadLogs();
}

function Header() {
  const info = activeModule();
  const service = appState.snapshot && appState.snapshot.service || {};
  const title = info ? (info.name || info.id) : (appState.section === 'service' ? 'Service' : 'Overview');
  return h('header', { class: 'topbar' },
    h('div', { class: 'breadcrumbs' }, h('span', null, 'SCRIPTD'), h('span', { class: 'slash' }, '/'), h('h1', null, title),
      info ? h('code', null, info.id) : null),
    h('div', { class: 'topbar-status' }, badge(serviceStatusLabel(), serviceStatusTone()),
      button('Refresh', refresh, 'button subtle'), button('Quit', requestQuit, 'button subtle'))
  );
}

function navigateTab(tab) {
  appState = Object.assign({}, appState, { tab, error: '' });
  renderApp();
  if (tab === 'Logs') loadLogs();
}

function tabsView() {
  return h('nav', { class: 'tabs', 'aria-label': 'Module sections' }, tabs.map(tab =>
    h('button', { type: 'button', class: 'tab ' + (appState.tab === tab ? 'active' : ''), 'aria-current': appState.tab === tab ? 'page' : null, onClick: () => navigateTab(tab) }, tab)
  ));
}

function Overview() {
  const info = activeModule();
  const service = appState.snapshot && appState.snapshot.service || {};
  if (!info) {
    const modules = appState.snapshot && appState.snapshot.modules || [];
    return h('div', { class: 'content-stack' },
      h('div', { class: 'welcome' }, h('p', { class: 'eyebrow' }, 'CONTROL CENTER'), h('h2', null, 'Your modules, one place.'),
        h('p', null, 'Review service health, module configuration, scheduled work, and recent outcomes. The service runs independently of this browser.')),
      h('div', { class: 'metric-grid' }, metric('Service', service.running ? 'Running' : (appState.snapshot ? 'Offline' : 'Unknown'), service.pid ? 'Process ' + service.pid : (appState.snapshot ? 'No active supervisor' : 'Not observed yet')),
        metric('Modules', modules.length, 'Configured and discovered modules'),
        metric('Configuration', configurationApplicationState(appState.snapshot), service.reload_error || 'Compared with the saved service document')),
      card('Modules', h('div', { class: 'module-cards' }, MODULES.map(item => {
        const module = moduleInfo(item.id);
        return h('button', { type: 'button', class: 'module-card', onClick: () => navigate(item.id) },
          h('span', { class: 'module-card-top' }, badge(item.id, 'module-id'), healthText(module)),
          h('strong', null, item.name), h('span', { class: 'muted' }, module.message || module.last_error || 'Open module details'));
      }))),
      card('Service status', h('div', { class: 'key-values' },
        row('Runtime', service.running ? 'Running' : (appState.snapshot ? 'Unavailable' : 'Not observed yet')),
        row('PID', service.pid || '—'),
        row('Loaded configuration', service.loaded_digest || 'Unknown'),
        row('Last reload error', service.reload_error || 'None')
      ), 'The browser reads observations from scriptd and never controls service lifetime.')
    );
  }
  return moduleOverview(info);
}

function row(label, value) {
  return h('div', { class: 'key-row' }, h('span', null, label), h('strong', null, value == null || value === '' ? '—' : String(value)));
}
function moduleOverview(info) {
  const outcomes = info.outcomes || [];
  const last = outcomes.length ? outcomes[outcomes.length - 1] : null;
  const jobs = ((appState.snapshot && appState.snapshot.jobs) || []).filter(job => job.module === info.id);
  const lastJob = jobs.length ? jobs[jobs.length - 1] : null;
  const brew = info.id === 'mbrew';
  const packages = brew && info.outcomes && Array.isArray(info.outcomes.packages) ? info.outcomes.packages : [];
  const pending = packages.filter(item => item.retry);
  return h('div', { class: 'content-stack' },
    h('div', { class: 'module-title-row' }, h('div', null, h('p', { class: 'eyebrow' }, info.id), h('h2', null, info.name || info.id)),
      h('div', { class: 'module-title-status' }, healthText(info), info.enabled ? badge('Enabled', 'good') : badge('Disabled', 'muted'))),
    h('div', { class: 'metric-grid' },
      metric('Last run', info.last_run_at || 'No run recorded', last && (last.state || last.outcome)),
      metric('Next evaluation', info.next_run_at || 'Not scheduled', info.trigger_state || 'From service scheduler'),
      metric('Pending work', brew ? (pending.length || 'None') : (lastJob && ['queued', 'running'].includes(lastJob.state) ? lastJob.state : '—'),
        brew ? 'Casks waiting for retry' : 'Manual request state')),
    info.last_error ? h('div', { class: 'alert danger', role: 'status' }, h('strong', null, 'Needs attention'), h('span', null, info.last_error)) : null,
    h('div', { class: 'two-col' },
      card('Module status', h('div', { class: 'key-values' },
        row('Health', statusLabel(info)), row('Configuration', info.valid ? 'Valid' : 'Invalid'),
        row('Runtime status', info.module_status && typeof info.module_status === 'object'
          ? Object.entries(info.module_status).map(([key, value]) => key + ': ' + (typeof value === 'object' ? JSON.stringify(value) : String(value))).join(' · ')
          : info.module_status || 'Not reported'), row('Last outcome', last && (last.message || last.state) || 'No recorded outcome')
      )),
      card(brew ? 'Homebrew maintenance' : 'Recent outcome', h('div', { class: 'key-values' },
        brew ? row('Privilege helper', info.privilege_helper || 'Not configured; privileged broker bridge is inactive') : row('Last successful action', last && last.action || '—'),
        row('Updated', info.updated || '—'), row('Deferred', info.deferred || '—'),
        row('Failed', info.failed || '—'),
        brew ? row('Formula maintenance', info.outcomes && info.outcomes.formula_error || 'No stage error') : null,
        brew ? row('Cask scan', info.outcomes && info.outcomes.cask_error || 'No stage error') : null,
        brew ? row('Cleanup', info.outcomes && info.outcomes.cleanup_error || 'No stage error') : null
      ))
    ),
    brew && packages.length ? card('Cask retry ledger', h('ul', { class: 'activity-list' }, packages.slice(-8).reverse().map(item =>
      h('li', null, badge(item.state || 'record', item.state === 'attention' ? 'danger' : item.retry ? 'warn' : 'good'),
        h('span', null, item.name + (item.reason ? ' · ' + item.reason : '')),
        h('time', null, item.retry ? 'Retry eligible' : (item.attempts || 0) + ' attempts'))))) : null,
    jobs.length ? card('Service requests', h('ul', { class: 'activity-list' }, jobs.slice(-6).reverse().map(job =>
      h('li', null, badge(job.state, job.state === 'failed' || job.state === 'interrupted' ? 'danger' : job.state === 'running' ? 'warn' : 'muted'),
        h('span', null, (job.action || 'manual run') + (job.message ? ' · ' + job.message : '')),
        h('time', null, job.id))))) : null,
    card('Recent activity', Array.isArray(outcomes) && outcomes.length ? h('ul', { class: 'activity-list' }, outcomes.slice(-6).reverse().map(item =>
      h('li', null, badge(item.state || item.outcome || 'record', item.state === 'failed' ? 'danger' : 'muted'),
        h('span', null, item.message || item.package || item.action || 'Maintenance event'),
        h('time', null, item.at || item.timestamp || '')))) : h('p', { class: 'empty-state' }, 'No recent module outcomes are available.'))
  );
}

function SettingsView() {
  const info = activeModule();
  const id = info && info.id;
  const current = draftYaml(id);
  const serviceSettings = appState.snapshot && appState.snapshot.service && appState.snapshot.service.settings;
  const settings = appState.drafts[docKey(id)] && appState.drafts[docKey(id)].settings || (id ? ((info && info.settings) || {}) : (serviceSettings || {}));
  const profile = SETTING_PROFILES[id || 'service'] || { basic: [], advanced: [] };
  return h('div', { class: 'content-stack' },
    h('div', { class: 'section-intro' }, h('div', null, h('h2', null, 'Configuration draft'),
      h('p', null, 'Changes stay in this draft until you review and save them. The service validates the document before applying it.')),
      isDirty(id) ? badge('Unsaved changes', 'warn') : badge('Saved', 'muted')),
    h('section', { class: 'card guided-settings' }, h('div', { class: 'card-heading' }, h('h2', null, 'Guided settings')),
      h('p', { class: 'muted' }, moduleGuide(id)),
      h('h3', null, 'Basic'), h('div', { class: 'settings-grid' }, profile.basic.map(key => settingField(id, key, settings))),
      profile.advanced.length ? h('details', { class: 'advanced-settings' }, h('summary', null, 'Advanced settings'),
        h('div', { class: 'settings-grid' }, profile.advanced.map(key => settingField(id, key, settings)))) : null),
    h('div', { class: 'editor-toolbar' }, h('span', null, id ? 'Module configuration · ' + id : 'Shared service configuration'),
    h('span', null, sourceDigest(id) ? 'Base ' + sourceDigest(id).slice(0, 19) + '…' : (appState.snapshot ? 'Service unavailable' : 'Not observed yet'))),
    h('label', { class: 'field-label', for: 'yaml-editor' }, 'YAML configuration'),
    h('textarea', { id: 'yaml-editor', class: 'yaml-editor', spellcheck: false, autocapitalize: 'off', autocorrect: 'off',
      value: current, onInput: event => updateDraft(id, event.currentTarget.value), 'aria-describedby': 'yaml-help' }),
    h('p', { id: 'yaml-help', class: 'muted' }, 'The editor preserves the existing Rust parser and atomic save path. Use the module’s configuration file format.'),
    h('div', { class: 'editor-actions' }, button('Review changes', () => reviewSave(id), 'button primary', { disabled: !isDirty(id) }),
      button('Reset draft', () => discardDraft(id), 'button subtle', { disabled: !isDirty(id) }))
  );
}

function moduleGuide(id) {
  const guides = {
    mbrew: 'Maintain trusted Homebrew sources and maintenance authentication settings. Pending packages and privilege readiness appear in Overview.',
    mcpu: 'Choose the CPU threshold and excluded applications. Native enrollment and approval remain controlled by the existing setup flow.',
    mwifi: 'Order preferred and candidate networks, define repeater rules, and tune connection health. Scoring controls are advanced.',
    miwatch: 'Set reboot cooldown and session files. Remote API values stay in the existing module configuration and setup flow.'
  };
  return guides[id] || 'Edit shared service settings. Service lifecycle remains an explicit CLI or launchd action.';
}
function nestedSetting(settings, key) {
  return key.split('.').reduce((value, part) => value && value[part], settings);
}
function settingField(id, key, settings) {
  const settingsStale = !!(appState.drafts[docKey(id)] && appState.drafts[docKey(id)].settings_stale);
  const value = nestedSetting(settings, key);
  const meta = SETTING_LABELS[key.split('.').pop()] || [key, 'Module setting.'];
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return h('fieldset', { class: 'nested-settings' }, h('legend', null, meta[0]),
      Object.entries(value).map(([child, childValue]) => settingField(id, key + '.' + child, settings)));
  }
  const idAttr = 'setting-' + id + '-' + key.replaceAll('.', '-');
  const label = h('label', { for: idAttr }, meta[0]);
  const description = h('span', { class: 'field-help' }, meta[1]);
  let input;
  if (typeof value === 'boolean') {
    input = h('input', { id: idAttr, type: 'checkbox', checked: value, disabled: settingsStale, onChange: event => setSetting(id, key, event.currentTarget.checked) });
  } else if (typeof value === 'number') {
    input = h('input', { id: idAttr, type: 'number', step: 'any', value, disabled: settingsStale, onChange: event => setSetting(id, key, Number(event.currentTarget.value)) });
  } else if (Array.isArray(value) && value.every(item => typeof item === 'string')) {
    input = h('textarea', { id: idAttr, class: 'array-input', value: value.join('\n'), rows: Math.max(3, Math.min(8, value.length + 1)), disabled: settingsStale, onBlur: event => setSetting(id, key, event.currentTarget.value.split('\n').map(item => item.trim()).filter(Boolean)) });
  } else if (Array.isArray(value)) {
    input = h('textarea', { id: idAttr, class: 'array-input', value: JSON.stringify(value, null, 2), rows: 6, spellcheck: false, disabled: settingsStale,
      onBlur: event => { try { setSetting(id, key, JSON.parse(event.currentTarget.value)); } catch (_) { setState({ error: meta[0] + ' must contain valid JSON.' }); } } });
  } else {
    input = h('input', { id: idAttr, type: 'text', value: value == null ? '' : String(value), disabled: settingsStale, onChange: event => setSetting(id, key, event.currentTarget.value) });
  }
  return h('div', { class: 'setting-field' }, label, input, description);
}

function TriggersView() {
  const info = activeModule();
  const moduleId = info && info.id;
  const triggers = info && info.triggers || {};
  const serviceName = moduleId ? 'modules.' + moduleId + '.triggers' : 'modules';
  return h('div', { class: 'content-stack' },
    h('div', { class: 'section-intro' }, h('div', null, h('h2', null, 'Trigger rules'),
      h('p', null, 'The supervisor owns evaluation. Edit the service YAML to change schedules, AND/OR conditions, fire policies, or reset rules.')),
      badge('Backend evaluated', 'muted')),
    card('Current evaluation', h('div', { class: 'key-values' },
      row('Scope', serviceName), row('Last result', info && JSON.stringify(info.trigger_state || {}) || 'No evaluation recorded'),
      row('Next scheduled time', info && info.next_run_at || 'Not scheduled'))),
    moduleId ? Object.entries(triggers).length ? Object.entries(triggers).map(([name, trigger]) =>
      card(name, h('div', { class: 'trigger-meta' }, badge(trigger.enabled === false ? 'Disabled' : 'Enabled', trigger.enabled === false ? 'muted' : 'good'),
        trigger.action ? badge('Action: ' + trigger.action, 'module-id') : null,
        badge('Fire: ' + ((trigger.fire && trigger.fire.mode) || 'every_match'), 'muted')),
        h('div', { class: 'condition-tree' }, renderCondition(trigger.when, 0)),
        trigger.fire && trigger.fire.mode === 'latched' ? h('pre', { class: 'trigger-policy' }, JSON.stringify(trigger.fire, null, 2)) : null))
      : card('No module triggers', h('p', { class: 'empty-state' }, 'No trigger definitions are configured for this module.')) : null,
    moduleId ? triggerEditor(moduleId, triggers) : null,
    h('div', { class: 'alert info' }, h('strong', null, 'Edit shared triggers'),
      h('span', null, 'Changes to this module’s trigger policy are part of service.yaml. Review and save from the shared configuration editor.')),
    button('Open service configuration', () => { appState = Object.assign({}, appState, { module: null, section: 'service', tab: 'Settings' }); renderApp(); }, 'button')
  );
}

function triggerEditor(moduleId, triggers) {
  const key = 'trigger-json:' + moduleId;
  const draft = appState.drafts[key];
  const value = draft && draft.trigger_json !== undefined ? draft.trigger_json : JSON.stringify(triggers || {}, null, 2);
  let tree;
  try { tree = JSON.parse(value); } catch (_) { tree = null; }
  return card('Edit trigger tree', h('div', { class: 'trigger-editor' },
    h('p', { class: 'muted' }, 'Edit the Boolean condition tree directly. Each leaf keeps its complete condition data; use Advanced trigger JSON for schedules, timezone, action, debounce, and fire/reset policies. The Rust service validates the whole map before staging.'),
    tree && typeof tree === 'object' ? Object.entries(tree).map(([name, trigger]) =>
      h('section', { class: 'trigger-builder' }, h('h3', null, name),
        trigger.when ? h(ConditionEditor, { moduleId, triggerName: name, path: ['when'], condition: trigger.when })
          : h('p', { class: 'alert danger' }, 'This trigger has no condition tree. Edit it in Advanced trigger JSON.')))
      : h('p', { class: 'alert danger' }, 'Trigger JSON is invalid. Correct it in Advanced trigger JSON before staging.'),
    h('details', { class: 'advanced-trigger-json' }, h('summary', null, 'Advanced trigger JSON'),
      h('label', { class: 'field-label', for: 'trigger-json-editor' }, 'Full trigger map'),
      h('textarea', { id: 'trigger-json-editor', class: 'yaml-editor', rows: 12, spellcheck: false, value,
        onInput: event => updateTriggerJsonDraft(moduleId, event.currentTarget.value) })),
    button('Validate and stage in service draft', () => stageTriggerDraft(moduleId), 'button primary', { disabled: isDirty(null) || !appState.snapshot })
  ), isDirty(null) ? 'Save or discard the existing service draft before staging trigger edits.' : 'Staging does not save or apply configuration; review the resulting diff in Service → Settings.');
}

const DEFAULT_CONDITIONS = {
  schedule: { schedule: { every_minutes: 60, timezone: 'Asia/Dhaka' } },
  time_window: { time_window: { timezone: 'Asia/Dhaka', start: '00:00', end: '01:00' } },
  wifi_power: { wifi_power: { state: 'on' } },
  wifi_ssid: { wifi_ssid: { ssid: 'Network name', state: 'connected' } },
  process_network: { process_network: { applications: ['com.example.App'], aggregation: 'sum', at_least_bytes_per_second: 1024 } }
};

function editCondition(moduleId, triggerName, path, change) {
  const key = 'trigger-json:' + moduleId;
  const draft = appState.drafts[key] || { trigger_json: JSON.stringify(moduleInfo(moduleId).triggers || {}, null, 2), base_digest: sourceDigest(null) };
  let triggers;
  try { triggers = JSON.parse(draft && draft.trigger_json || JSON.stringify(moduleInfo(moduleId).triggers || {})); }
  catch (_) { return; }
  let parent = triggers[triggerName];
  for (const segment of path.slice(0, -1)) parent = parent && parent[segment];
  if (!parent) return;
  change(parent, path[path.length - 1]);
  updateTriggerJsonDraft(moduleId, JSON.stringify(triggers, null, 2));
}

function ConditionEditor({ moduleId, triggerName, path, condition }) {
  if (!condition || typeof condition !== 'object') return h('p', { class: 'alert danger' }, 'Condition must be an object.');
  const groupKey = Array.isArray(condition.all) ? 'all' : Array.isArray(condition.any) ? 'any' : null;
  if (groupKey) return h('div', { class: 'condition-editor-group' },
    h('header', null, h('strong', null, groupKey === 'all' ? 'AND — all conditions must match' : 'OR — any condition may match'),
      button(groupKey === 'all' ? 'Change to OR' : 'Change to AND', () => editCondition(moduleId, triggerName, path, (parent, key) => {
        const children = parent[key][groupKey]; parent[key] = { [groupKey === 'all' ? 'any' : 'all']: children };
      }), 'button subtle')),
    h('ol', null, condition[groupKey].map((child, index) => h('li', null,
      h(ConditionEditor, { moduleId, triggerName, path: path.concat(groupKey, index), condition: child }),
      condition[groupKey].length > 1 ? button('Remove condition', () => editCondition(moduleId, triggerName, path.concat(groupKey), (parent, key) => parent[key].splice(index, 1)), 'text-button danger-text') : null))),
    h('div', { class: 'condition-add' },
      h('label', null, 'Add condition', h('select', { value: 'schedule', onChange: event => {
        const next = JSON.parse(JSON.stringify(DEFAULT_CONDITIONS[event.currentTarget.value]));
        editCondition(moduleId, triggerName, path.concat(groupKey), (parent, key) => parent[key].push(next));
      } }, Object.keys(DEFAULT_CONDITIONS).map(key => h('option', { value: key }, key.replace('_', ' ')))))));
  const leafKey = Object.keys(condition)[0];
  return h('section', { class: 'condition-editor-leaf' },
    h('strong', null, 'Condition: ' + (leafKey || 'unknown')),
    h('label', null, 'Condition data (JSON)', h('textarea', { rows: 4, spellcheck: false, value: JSON.stringify(condition, null, 2),
      onInput: event => {
        try {
          const next = JSON.parse(event.currentTarget.value);
          editCondition(moduleId, triggerName, path, (parent, key) => { parent[key] = next; });
        } catch (_) {}
      } })),
    h('div', { class: 'condition-add' },
      button('Add AND condition', () => editCondition(moduleId, triggerName, path, (parent, key) => {
        const current = parent[key];
        parent[key] = { all: [current, JSON.parse(JSON.stringify(DEFAULT_CONDITIONS.wifi_power))] };
      }), 'button subtle'),
      button('Add OR condition', () => editCondition(moduleId, triggerName, path, (parent, key) => {
        const current = parent[key];
        parent[key] = { any: [current, JSON.parse(JSON.stringify(DEFAULT_CONDITIONS.wifi_ssid))] };
      }), 'button subtle')));
}

function updateTriggerJsonDraft(moduleId, json) {
  const key = 'trigger-json:' + moduleId;
  const drafts = Object.assign({}, appState.drafts, {
    [key]: { trigger_json: json, base_digest: appState.drafts[key] && appState.drafts[key].base_digest || sourceDigest(null) }
  });
  appState = Object.assign({}, appState, { drafts });
  persistDrafts();
  renderApp();
}

function stageTriggerDraft(moduleId) {
  const key = 'trigger-json:' + moduleId;
  const draft = appState.drafts[key] || { trigger_json: JSON.stringify(moduleInfo(moduleId).triggers || {}, null, 2), base_digest: sourceDigest(null) };
  let triggers;
  try { triggers = JSON.parse(draft.trigger_json || '{}'); }
  catch (_) { return setState({ error: 'Trigger draft must be valid JSON.' }); }
  api('/api/trigger-draft', { method: 'POST', body: JSON.stringify({
    module: moduleId, triggers, base_digest: draft.base_digest || sourceDigest(null)
  }) }).then(response => {
    if (!response.draft_yaml) throw new Error('The service did not return a configuration draft.');
    const drafts = Object.assign({}, appState.drafts);
    delete drafts[key];
    appState = Object.assign({}, appState, { drafts });
    updateDraft(null, response.draft_yaml);
    appState = Object.assign({}, appState, { section: 'service', module: null, tab: 'Settings', message: 'Trigger tree validated and staged. Review the service configuration diff before saving.', error: '' });
    renderApp();
  }).catch(error => setState({ error: error.message }));
}

function renderCondition(condition, depth) {
  if (!condition || typeof condition !== 'object') return h('div', { class: 'condition-node' }, 'No condition defined');
  const group = condition.all || condition.any;
  if (Array.isArray(group)) {
    const op = condition.all ? 'ALL conditions' : 'ANY condition';
    return h('div', { class: 'condition-group', style: { '--depth': depth } },
      h('strong', null, op), h('div', { class: 'condition-children' }, group.map(child => renderCondition(child, depth + 1))));
  }
  const [kind, value] = Object.entries(condition)[0] || ['condition', condition];
  const title = kind.replaceAll('_', ' ');
  const summary = typeof value === 'object' ? JSON.stringify(value) : String(value);
  return h('div', { class: 'condition-node', style: { '--depth': depth } }, h('strong', null, title), h('code', null, summary));
}

function LogsView() {
  return h('div', { class: 'content-stack' },
    h('div', { class: 'section-intro' }, h('div', null, h('h2', null, 'Logs'), h('p', null, 'Search the bounded service log tail. Browser observations do not sample module sensors.')),
      h('label', { class: 'toggle' }, h('input', { type: 'checkbox', checked: appState.follow, onChange: event => setState({ follow: event.currentTarget.checked }) }), 'Follow')),
    h('div', { class: 'log-controls' },
      h('label', null, 'Severity', h('select', { value: appState.severity, onChange: event => { setState({ severity: event.currentTarget.value }); loadLogs(); } },
        ['all', 'error', 'warn', 'info'].map(level => h('option', { value: level }, level)))),
    h('label', { class: 'search-label' }, 'Search', h('input', { type: 'search', value: appState.search, onInput: event => setState({ search: event.currentTarget.value }), onKeyDown: event => { if (event.key === 'Enter') loadLogs(); }, placeholder: 'Filter log lines' })),
      button('Search', loadLogs, 'button'))
    ,
    h('pre', { class: 'log-view', 'aria-live': appState.follow ? 'polite' : 'off' }, appState.logs.length ? appState.logs.join('\n') : 'No log entries loaded.'),
    button('Load latest', loadLogs, 'button subtle')
  );
}

function ServiceView() {
  const service = appState.snapshot && appState.snapshot.service || {};
  return h('div', { class: 'content-stack' },
    h('div', { class: 'welcome compact' }, h('p', { class: 'eyebrow' }, 'RUNTIME'), h('h2', null, service.running ? 'The service is running.' : (appState.snapshot ? 'The service is not connected.' : 'The service has not been observed yet.')),
      h('p', null, 'This browser control center observes and sends explicit requests. It does not start, stop, or restart the service.')),
    h('div', { class: 'metric-grid' }, metric('Status', service.running ? 'Running' : (appState.snapshot ? 'Offline' : 'Unknown'), service.pid ? 'PID ' + service.pid : ''),
      metric('Loaded configuration', configurationApplicationState(appState.snapshot), service.loaded_digest || ''),
      metric('Last reload error', service.reload_error ? 'Needs attention' : 'None', service.reload_error || 'No error reported')),
    card('Service lifecycle', h('div', { class: 'key-values' }, row('Configuration saved', appState.snapshot && appState.snapshot.config_digest || 'Unknown'),
      row('Configuration applied', service.loaded_digest || 'Unknown'), row('Restart required', service.restart_required ? 'Yes' : 'No')),
      'Use the existing explicit CLI or launchd workflow to manage service lifecycle.')
  );
}

function renderContent() {
  if (appState.section === 'service') {
    if (appState.tab === 'Settings') return SettingsView();
    if (appState.tab === 'Triggers') return TriggersView();
    if (appState.tab === 'Logs') return LogsView();
    return ServiceView();
  }
  if (appState.tab === 'Settings') return SettingsView();
  if (appState.tab === 'Triggers') return TriggersView();
  if (appState.tab === 'Logs') return LogsView();
  return Overview();
}

function navigateActions() {
  const info = activeModule();
  if (!info) return;
  const action = info.enabled ? 'Disable module' : 'Enable module';
  const setupCommand = './scriptd.sh config ' + info.id;
  return h('details', { class: 'actions-menu' }, h('summary', null, 'Actions'),
    h('div', { class: 'actions-popover' }, info.id !== 'miwatch' ? button('Run now…', () => confirmRun(info.id), 'menu-action') : null,
      info.id === 'mbrew' ? button('Retry pending casks…', () => confirmRun(info.id, 'retry_pending'), 'menu-action') : null,
      button(action, () => draftModuleEnabled(info.id, !info.enabled), 'menu-action'),
      info.id === 'miwatch' ? button('Refresh router session', () => setState({ message: 'In Terminal, run ./scriptd.sh miwatch session refresh. Return here and choose Refresh to reload service status.' }), 'menu-action') :
        button('Setup or authentication', () => setState({ message: 'In Terminal, run ' + setupCommand + ' to use the existing setup and authentication flow. Return here and choose Refresh to reload service status.' }), 'menu-action'),
      info.id === 'miwatch' ? button('Import router session', () => setState({ message: 'In Terminal, run ./scriptd.sh miwatch session import. Return here and choose Refresh to reload service status.' }), 'menu-action') : null,
      info.id === 'miwatch' ? button('Verify router access', () => setState({ message: 'In Terminal, run ./scriptd.sh miwatch remote verify. Return here and choose Refresh to reload service status.' }), 'menu-action') : null,
      info.id === 'miwatch' ? button('Reboot router…', () => confirmReboot(info.id), 'menu-action danger-text') : null))
}

function Main() {
  const navigable = !!activeModule() || appState.section === 'service';
  return h('main', { id: 'content', class: 'main', tabIndex: -1 },
    h(Header),
    navigable ? h('div', { class: 'module-toolbar' }, tabsView(), navigateActions()) : null,
    appState.message ? h('div', { class: 'alert info', role: 'status' }, appState.message, button('Dismiss', () => setState({ message: '' }), 'text-button')) : null,
    appState.error ? h('div', { class: 'alert danger', role: 'alert' }, appState.error, button('Retry', refresh, 'text-button')) : null,
    appState.loading ? h('div', { class: 'loading' }, 'Connecting to scriptd…') : renderContent()
  );
}

function Dialog() {
  const modalProps = {
    class: 'dialog',
    ref: dialog => { if (dialog && !dialog.open) dialog.showModal(); }
  };
  if (appState.saveDiff) {
    const diff = appState.saveDiff;
    return h('dialog', Object.assign({}, modalProps, { 'aria-labelledby': 'dialog-title', onCancel: event => { event.preventDefault(); cancelSaveReview(); } }),
      h('h2', { id: 'dialog-title' }, 'Review configuration changes'),
      h('p', null, 'The server will validate this document and compare its original digest before saving.'),
      h('pre', { class: 'diff-view', tabIndex: 0 }, diff.text || 'No line-by-line difference available.'),
      diff.conflict ? h('div', { class: 'alert danger' }, 'The file changed since this draft began. Reload the latest version before saving.') : null,
      h('div', { class: 'dialog-actions' }, button('Cancel', cancelSaveReview, 'button subtle'),
        button(diff.conflict ? 'Reload current file' : 'Save configuration', diff.conflict ? () => reloadDocument(diff.id) : () => saveDocument(diff.id), 'button primary', { disabled: !!diff.conflict })));
  }
  if (appState.dialog && appState.dialog.type === 'quit') return h('dialog', Object.assign({}, modalProps, { 'aria-labelledby': 'quit-title', onCancel: event => { event.preventDefault(); stayInApp(); } }),
    h('h2', { id: 'quit-title' }, 'Leave scriptd?'),
    h('p', null, appState.dialog.count + (appState.dialog.count === 1 ? ' recoverable draft needs' : ' recoverable drafts need') + ' a choice. Saving reviews and validates every document before it is written.'),
    appState.quitWorking ? h('p', { role: 'status' }, 'Preparing recoverable drafts…') : null,
    h('div', { class: 'dialog-actions' },
      button('Stay', stayInApp, 'button subtle', { disabled: appState.quitWorking }),
      button('Discard drafts', discardAllAndQuit, 'button danger', { disabled: appState.quitWorking }),
      button('Save drafts', saveAllAndQuit, 'button primary', { disabled: appState.quitWorking })));
  if (appState.dialog) return h('dialog', Object.assign({}, modalProps, { 'aria-labelledby': 'confirm-title', onCancel: event => { event.preventDefault(); setState({ dialog: null }); } }),
    h('h2', { id: 'confirm-title' }, appState.dialog.title), h('p', null, appState.dialog.text),
    h('div', { class: 'dialog-actions' }, button('Cancel', () => setState({ dialog: null }), 'button subtle'),
      button(appState.dialog.confirmLabel, appState.dialog.onConfirm, 'button danger')));
  return null;
}

function App() {
  return h('div', { class: 'app-shell' + (appState.collapsed ? ' sidebar-collapsed' : '') }, h('a', { class: 'skip-link', href: '#content' }, 'Skip to main content'),
    h(Sidebar), h(Main), h(Dialog));
}

function renderApp() {
  const active = activeModule();
  document.title = (active ? active.name : appState.section === 'service' ? 'Service' : 'Overview') + ' | scriptd';
  render(h(App), document.getElementById('app'));
  const shouldFollowLogs = appState.tab === 'Logs' && appState.follow;
  if (shouldFollowLogs && !logTimer) logTimer = setInterval(loadLogs, 3000);
  if (!shouldFollowLogs && logTimer) { clearInterval(logTimer); logTimer = null; }
}
function refresh() { appState = Object.assign({}, appState, { loading: true }); renderApp(); connect(); }
function loadLogs() {
  const info = activeModule();
  const module = info ? info.id : 'service';
  const params = new URLSearchParams({ module, severity: appState.severity, query: appState.search });
  api('/api/logs?' + params.toString()).then(data => {
    const logText = data.logs || '';
    setState({ logs: logText.split('\n').filter(Boolean), error: '' });
    if (appState.follow) {
      const view = document.querySelector('.log-view');
      if (view) view.scrollTop = view.scrollHeight;
    }
  }).catch(error => setState({ error: error.message }));
}
function reviewSave(id) {
  const token = ++saveReviewToken;
  const key = docKey(id);
  const base = appState.drafts[key] && appState.drafts[key].base_digest || sourceDigest(id);
  const currentDigest = sourceDigest(id);
  if (base && currentDigest && base !== currentDigest) {
    return setState({ saveDiff: { id, text: makeDiff(sourceYaml(id), draftYaml(id)), conflict: true } });
  }
  api('/api/validate', { method: 'POST', body: JSON.stringify({
    document: id ? 'module' : 'service', module: id || undefined,
    yaml: draftYaml(id), base_digest: base || currentDigest || ''
  }) }).then(() => {
    if (token !== saveReviewToken) return;
    setState({ saveDiff: { id, text: makeDiff(sourceYaml(id), draftYaml(id)), conflict: false }, error: '' });
  }).catch(error => {
    if (token !== saveReviewToken) return;
    if (appState.quitQueue) appState = Object.assign({}, appState, { quitQueue: null, quitWorking: false });
    setState({ error: 'Configuration validation failed: ' + error.message });
  });
}
function makeDiff(before, after) {
  const a = before.split('\n'), b = after.split('\n');
  const out = ['--- current', '+++ draft'];
  const max = Math.max(a.length, b.length);
  for (let i = 0; i < max; i++) {
    if (a[i] === b[i]) continue;
    if (a[i] !== undefined) out.push('- ' + a[i]);
    if (b[i] !== undefined) out.push('+ ' + b[i]);
  }
  return out.join('\n');
}
function saveDocument(id) {
  const key = docKey(id);
  const draft = appState.drafts[key];
  if (!draft) return;
  api('/api/save', { method: 'POST', body: JSON.stringify({
    document: id ? 'module' : 'service', module: id || undefined,
    yaml: draft.yaml, base_digest: draft.base_digest || sourceDigest(id)
  }) }).then(response => {
    const drafts = Object.assign({}, appState.drafts);
    delete drafts[key];
    appState = Object.assign({}, appState, { drafts, saveDiff: null,
      message: 'Saved. Application state: ' + (response.apply || response.state || 'pending') + '.' +
        (response.reload_error ? ' ' + response.reload_error : ''),
      error: '' });
    if (appState.quitQueue) {
      const remaining = appState.quitQueue.slice(1);
      appState = Object.assign({}, appState, { quitQueue: remaining });
      if (remaining.length) {
        persistDrafts();
        reviewSave(remaining[0] ? remaining[0].slice('module:'.length) : null);
      } else {
        appState = Object.assign({}, appState, { quitQueue: null });
        persistDraftsImmediately(appState.drafts).then(closeControlCenter).catch(error => {
          setState({ quitWorking: false, error: 'Saved drafts, but could not clear their recovery copy: ' + error.message });
        });
      }
    } else {
      persistDrafts();
      refresh();
    }
  }).catch(error => {
    if (appState.quitQueue) appState = Object.assign({}, appState, { quitQueue: null, quitWorking: false });
    setState({ saveDiff: null, error: error.message });
  });
}
function discardDraft(id) {
  const drafts = Object.assign({}, appState.drafts);
  delete drafts[docKey(id)];
  setState({ drafts, message: 'Draft discarded.' });
  persistDrafts();
}
function reloadDocument(id) {
  const drafts = Object.assign({}, appState.drafts);
  delete drafts[docKey(id)];
  appState = Object.assign({}, appState, { drafts, saveDiff: null, quitQueue: null, quitWorking: false });
  persistDrafts();
  refresh();
}

function requestQuit() {
  const drafts = recoverableDrafts(appState.drafts);
  const count = Object.keys(drafts).length;
  if (!count) return closeControlCenter();
  setState({ dialog: { type: 'quit', count }, error: '' });
}

function stayInApp() {
  quitOperationToken++;
  saveReviewToken++;
  setState({ dialog: null, saveDiff: null, quitQueue: null, quitWorking: false });
}

function cancelSaveReview() {
  saveReviewToken++;
  if (appState.quitQueue) return stayInApp();
  setState({ saveDiff: null });
}

function closeControlCenter() {
  quitOperationToken++;
  setState({ dialog: null, quitQueue: null, quitWorking: false, message: 'The service continues independently. Close this browser tab to leave scriptd.' });
  window.close();
}

async function discardAllAndQuit() {
  const token = ++quitOperationToken;
  setState({ quitWorking: true, error: '' });
  try {
    await persistDraftsImmediately({});
    if (token !== quitOperationToken) return;
    appState = Object.assign({}, appState, { drafts: {}, dialog: null, quitQueue: null, quitWorking: false });
    closeControlCenter();
  } catch (error) {
    if (token !== quitOperationToken) return;
    setState({ quitWorking: false, error: 'Could not clear the recoverable drafts: ' + error.message });
  }
}

async function saveAllAndQuit() {
  const token = ++quitOperationToken;
  setState({ quitWorking: true, error: '' });
  try {
    const drafts = Object.assign({}, appState.drafts);
    let serviceYaml = drafts.service && drafts.service.yaml;
    const triggerKeys = Object.keys(drafts).filter(key => key.startsWith('trigger-json:')).sort();
    for (const key of triggerKeys) {
      const draft = drafts[key];
      const moduleId = key.slice('trigger-json:'.length);
      let triggers;
      try { triggers = JSON.parse(draft.trigger_json); }
      catch (_) { throw new Error(moduleId + ' trigger draft is not valid JSON.'); }
      const response = await api('/api/trigger-draft', { method: 'POST', body: JSON.stringify({
        module: moduleId, triggers, base_digest: draft.base_digest || sourceDigest(null), draft_yaml: serviceYaml
      }) });
      if (token !== quitOperationToken) return;
      if (!response.draft_yaml) throw new Error('The service did not return a staged configuration draft.');
      serviceYaml = response.draft_yaml;
      delete drafts[key];
    }
    if (serviceYaml !== undefined) {
      const previous = drafts.service || {};
      drafts.service = Object.assign({}, previous, {
        yaml: serviceYaml,
        settings_stale: true,
        base_digest: previous.base_digest || sourceDigest(null)
      });
    }
    if (token !== quitOperationToken) return;
    const queue = Object.keys(drafts).filter(key => drafts[key].yaml !== undefined).sort((a, b) => {
      if (a === 'service') return -1;
      if (b === 'service') return 1;
      return a.localeCompare(b);
    });
    appState = Object.assign({}, appState, { drafts, dialog: null, quitWorking: false, quitQueue: queue });
    persistDrafts();
    if (!queue.length) {
      await persistDraftsImmediately(appState.drafts);
      if (token !== quitOperationToken) return;
      closeControlCenter();
      return;
    }
    reviewSave(queue[0] === 'service' ? null : queue[0].slice('module:'.length));
  } catch (error) {
    if (token !== quitOperationToken) return;
    setState({ dialog: null, quitWorking: false, quitQueue: null, error: 'Could not prepare every draft for saving: ' + error.message });
  }
}
function confirmRun(id, action) {
  if (id === 'miwatch') return;
  const retry = action === 'retry_pending';
  setState({ dialog: { title: retry ? 'Retry pending casks?' : 'Run module now?', text: (retry ? 'This requests only eligible pending cask retries. ' : 'This manual run bypasses global trigger conditions. ') + 'The service must already be running; accepted work continues if this browser closes.', confirmLabel: retry ? 'Queue cask retry' : 'Queue manual run', onConfirm: () => runModule(id, action) } });
}
function confirmReboot(id) {
  setState({ dialog: { title: 'Reboot the router?', text: 'This sends an explicit reboot request to the configured router and may interrupt network access.', confirmLabel: 'Reboot router', onConfirm: () => execute(id, 'reboot', 'reboot-router') } });
}
function runModule(id, action) { execute(id, action || null, 'bypass-global-triggers'); }
function execute(id, action, confirm) {
  setState({ dialog: null, error: '' });
  const requestId = crypto.randomUUID();
  api('/api/run', { method: 'POST', body: JSON.stringify({ module: id, action, confirm, request_id: requestId }) })
    .then(response => setState({ message: 'Request ' + requestId + ' is ' + (response.state || 'accepted') + '.', error: '' }))
    .catch(error => setState({ error: error.message }));
}
window.addEventListener('beforeunload', event => {
  if (Object.keys(appState.drafts).some(key => appState.drafts[key].yaml !== undefined || appState.drafts[key].trigger_json !== undefined)) {
    event.preventDefault();
    event.returnValue = '';
  }
});
window.addEventListener('keydown', event => {
  if (event.key === 'Escape' && (appState.dialog || appState.saveDiff)) {
    if (appState.quitQueue) stayInApp();
    else if (appState.saveDiff) cancelSaveReview();
    else setState({ dialog: null });
  } else if (event.key === 'Escape' && appState.mobileNavOpen) {
    event.preventDefault();
    const navigation = document.getElementById('primary-navigation');
    const toggle = document.getElementById('mobile-nav-toggle');
    const focusWasInside =
      (navigation && navigation.contains(document.activeElement)) || toggle === document.activeElement;
    closeMobileNavigation(focusWasInside);
  }
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 's') {
    event.preventDefault();
    const id = activeModule() && appState.tab === 'Settings' ? activeModule().id : null;
    if (isDirty(id)) reviewSave(id);
  }
});
const mobileNavMedia = window.matchMedia('(max-width: 620px)');
window.addEventListener('resize', () => {
  if (!mobileNavMedia.matches) closeMobileNavigation(false);
});
connect();
