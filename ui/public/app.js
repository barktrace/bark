const state = {
  me: null,
  organizations: [],
  organizationId: '',
  projects: [],
  projectId: '',
  issues: [],
  releases: [],
  performance: { period: '24h', stats: {}, transactions: [] },
  logs: [],
  logLevel: 'all',
  monitors: [],
  monitorId: '',
  monitorDetails: { checks: [], incidents: [] },
  route: 'overview',
  query: '',
  issueStatus: 'all',
  providerName: 'OIDC',
};

const routeMeta = {
  overview: ['Overview', 'The health of your project at a glance.'],
  issues: ['Issues', 'Errors grouped by fingerprint and ordered by recent activity.'],
  releases: ['Releases', 'Versions observed in events for this project.'],
  projects: ['Projects', 'SDK entry points owned by this organization.'],
  setup: ['SDK setup', 'Connect any Sentry-compatible SDK.'],
  settings: ['Organization', 'Membership, identity, and workspace settings.'],
  performance: ['Performance', 'Transactions, traces, and latency.'],
  logs: ['Logs', 'Structured application logs in context.'],
  uptime: ['Uptime', 'Endpoint checks and incident history.'],
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHTML = (value = '') => String(value).replace(
  /[&<>'"]/g,
  (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character],
);
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const currentProject = () => state.projects.find((project) => project.id === state.projectId);
const currentOrganization = () => state.organizations.find((organization) => organization.organization_id === state.organizationId);

function relative(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'unknown';
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const absolute = Math.abs(seconds);
  const [amount, unit] = absolute < 60
    ? [seconds, 'second']
    : absolute < 3600
      ? [Math.round(seconds / 60), 'minute']
      : absolute < 86400
        ? [Math.round(seconds / 3600), 'hour']
        : [Math.round(seconds / 86400), 'day'];
  return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(amount, unit);
}

function formatMS(value) {
  const milliseconds = Number(value || 0);
  if (milliseconds >= 1000) return `${(milliseconds / 1000).toFixed(milliseconds >= 10000 ? 1 : 2)} s`;
  return `${milliseconds.toFixed(milliseconds >= 100 ? 0 : 1)} ms`;
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers ?? {}) },
  });
  if (response.status === 401) {
    location.href = '/ui/login/';
    throw new Error('Authentication required');
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error?.message || 'Request failed');
  }
  return response.status === 204 ? null : response.json();
}

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => { toast.hidden = true; }, 2400);
}

function routeFromPath() {
  return location.pathname.replace(/^\/ui\/?/, '').split('/')[0] || 'overview';
}

function setRoute(route, push = false) {
  if (!routeMeta[route]) route = 'overview';
  state.route = route;
  if (push) history.pushState({}, '', route === 'overview' ? '/ui/' : `/ui/${route}/`);
  $$('.primary-nav a').forEach((link) => link.classList.toggle('active', link.dataset.route === route));
  const [title, subtitle] = routeMeta[route];
  $('#page-title').textContent = title;
  $('#page-subtitle').textContent = subtitle;
  const organization = currentOrganization();
  const project = currentProject();
  $('#breadcrumb').textContent = [
    organization?.organization_name,
    route === 'projects' || route === 'settings' ? '' : project?.name,
  ].filter(Boolean).join(' / ');
  document.title = `${title} · Barktrace`;
  render();
}

function statCard(label, value, detail, tone = '') {
  return `<article class="stat-card ${tone}"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong><small>${escapeHTML(detail)}</small></article>`;
}

function filteredIssues(limit = 100) {
  const needle = state.query.toLowerCase();
  return state.issues.filter((issue) =>
    (state.issueStatus === 'all' || issue.status === state.issueStatus)
    && (!needle || `${issue.title} ${issue.level} ${issue.first_release} ${issue.last_release}`.toLowerCase().includes(needle)),
  ).slice(0, limit);
}

function issueRows(limit) {
  const rows = filteredIssues(limit);
  if (!rows.length) {
    return `<div class="empty-state">${icon('alert')}<h3>No matching issues</h3><p>New SDK events will be grouped here automatically.</p></div>`;
  }
  return `
    <div class="table-head issue-grid"><span>Issue</span><span>First release</span><span>Last seen</span><span>Events</span></div>
    ${rows.map((issue) => {
      const level = ['warning', 'info', 'debug'].includes(issue.level) ? issue.level : 'error';
      return `<div class="table-row issue-grid">
        <div class="issue-name"><i class="severity ${level}"></i><div><strong>${escapeHTML(issue.title)}</strong><small><span class="status ${escapeHTML(issue.status)}">${escapeHTML(issue.status)}</span> ${escapeHTML(issue.level)}</small></div></div>
        <span class="mono secondary-cell">${escapeHTML(issue.first_release || '—')}</span>
        <span class="secondary-cell">${escapeHTML(relative(issue.last_seen_at))}</span>
        <b class="numeric">${Number(issue.event_count).toLocaleString()}</b>
      </div>`;
    }).join('')}`;
}

function releaseRows(limit) {
  const needle = state.query.toLowerCase();
  const rows = state.releases.filter((release) => !needle || release.version.toLowerCase().includes(needle)).slice(0, limit);
  if (!rows.length) {
    return `<div class="empty-state">${icon('rocket')}<h3>No releases yet</h3><p>Set <code>release</code> in your SDK configuration to start tracking versions.</p></div>`;
  }
  return `
    <div class="table-head release-grid"><span>Version</span><span>First seen</span><span>Last seen</span><span>Events</span></div>
    ${rows.map((release) => `<div class="table-row release-grid">
      <div class="release-name">${icon('rocket')}<strong class="mono">${escapeHTML(release.version)}</strong></div>
      <span class="secondary-cell">${escapeHTML(relative(release.first_seen_at))}</span>
      <span class="secondary-cell">${escapeHTML(relative(release.last_seen_at))}</span>
      <b class="numeric">${Number(release.events).toLocaleString()}</b>
    </div>`).join('')}`;
}

function projectRows() {
  const needle = state.query.toLowerCase();
  const rows = state.projects.filter((project) => !needle || `${project.name} ${project.slug} ${project.platform}`.toLowerCase().includes(needle));
  if (!rows.length) {
    return `<div class="empty-state large">${icon('folder')}<h3>No projects yet</h3><p>Create a project to receive your first event.</p><button class="button" data-open-project>${icon('plus')} Create project</button></div>`;
  }
  return `<div class="project-list">${rows.map((project) => `<button class="project-row" data-project-id="${escapeHTML(project.id)}">
    <span class="platform-icon">${escapeHTML((project.platform || 'O').slice(0, 2).toUpperCase())}</span>
    <span><strong>${escapeHTML(project.name)}</strong><small class="mono">${escapeHTML(project.slug)}</small></span>
    <span class="project-platform">${escapeHTML(project.platform || 'generic')}</span>
    <span class="project-created">Created ${escapeHTML(relative(project.created_at))}</span>${icon('chevron')}
  </button>`).join('')}</div>`;
}

function renderOverview() {
  const project = currentProject();
  if (!project) return projectRows();
  const openIssues = state.issues.filter((issue) => issue.status === 'unresolved').length;
  const eventCount = state.issues.reduce((total, issue) => total + Number(issue.event_count || 0), 0);
  const latest = state.releases[0];
  const recentReleases = state.releases.slice(0, 5).map((release) => `<div><span class="release-dot"></span><p><strong class="mono">${escapeHTML(release.version)}</strong><small>${escapeHTML(relative(release.last_seen_at))} · ${release.events} events</small></p></div>`).join('');
  return `
    <section class="metric-grid">
      ${statCard('Open issues', openIssues, `${state.issues.length} visible groups`, openIssues ? 'bad' : 'good')}
      ${statCard('Events', eventCount.toLocaleString(), 'Across visible issue groups')}
      ${statCard('Releases', state.releases.length, latest ? `Latest ${latest.version}` : 'Waiting for release data')}
      ${statCard('Project', project.platform || 'Generic', project.slug || 'No project selected')}
    </section>
    <section class="dashboard-grid">
      <article class="card wide"><div class="card-heading"><div><p class="eyebrow">Attention</p><h2>Top issues</h2></div><a href="/ui/issues/" data-route="issues">View all ${icon('chevron')}</a></div><div class="data-table">${issueRows(5)}</div></article>
      <article class="card"><div class="card-heading"><div><p class="eyebrow">Deployments</p><h2>Recent releases</h2></div><a href="/ui/releases/" data-route="releases">View all ${icon('chevron')}</a></div><div class="compact-list">${recentReleases || '<p class="muted padded">No releases have been observed.</p>'}</div></article>
    </section>`;
}

function renderIssues() {
  return `<div class="toolbar"><div class="segmented" id="issue-filter">${['all', 'unresolved', 'resolved', 'ignored'].map((status) => `<button class="${state.issueStatus === status ? 'active' : ''}" data-status="${status}">${{ all: 'All', unresolved: 'Open', resolved: 'Resolved', ignored: 'Muted' }[status]}</button>`).join('')}</div><span class="result-count">${filteredIssues().length} issue groups</span></div><section class="card data-table" id="issues-table">${issueRows(100)}</section>`;
}

function renderReleases() {
  return `<div class="toolbar"><p class="muted">Releases are created automatically when an event contains a release identifier.</p><a class="button secondary small" href="/ui/setup/" data-route="setup">Configure SDK</a></div><section class="card data-table">${releaseRows(100)}</section>`;
}

function renderProjects() {
  return `<div class="toolbar"><p class="muted">${state.projects.length} project${state.projects.length === 1 ? '' : 's'} in ${escapeHTML(currentOrganization()?.organization_name || 'this organization')}</p><button class="button small" data-open-project>${icon('plus')} New project</button></div><section class="card">${projectRows()}</section>`;
}

function renderSetup() {
  const project = currentProject();
  if (!project) return projectRows();
  const snippet = `Sentry.init({\n  dsn: "${project.dsn}",\n  release: "${project.slug}@1.0.0",\n  environment: "production"\n});`;
  return `<div class="setup-grid">
    <section class="card setup-main"><p class="step">01 / Client key</p><h2>Connect ${escapeHTML(project.name)}</h2><p class="muted">This DSN is safe to expose in client applications. It can only submit telemetry.</p><div class="copy-field"><code>${escapeHTML(project.dsn)}</code><button data-copy="${escapeHTML(project.dsn)}">${icon('copy')} Copy</button></div><p class="step">02 / Initialize your SDK</p><div class="code-tabs"><button class="active" data-language="javascript">JavaScript</button><button data-language="go">Go</button><button data-language="python">Python</button></div><pre><code id="sdk-snippet">${escapeHTML(snippet)}</code><button id="copy-snippet" data-copy="${escapeHTML(snippet)}" aria-label="Copy snippet">${icon('copy')}</button></pre><p class="step">03 / Verify</p><p class="muted">Send a test exception. It will appear under Issues and its release will be linked automatically.</p></section>
    <aside class="card setup-side"><p class="eyebrow">Compatible SDKs</p><h3>Use the Sentry client you already know.</h3><ul><li>JavaScript and browser</li><li>Go services</li><li>Python applications</li><li>Rust and native clients</li><li>Any envelope-compatible SDK</li></ul><a href="https://docs.sentry.io/platforms/" target="_blank" rel="noreferrer">Browse SDK documentation ${icon('chevron')}</a></aside>
  </div>`;
}

function renderSettings() {
  const organization = currentOrganization();
  const membership = state.me?.memberships.find((item) => item.organization_id === state.organizationId);
  return `<div class="settings-grid">
    <section class="card settings-card"><p class="eyebrow">Workspace</p><h2>${escapeHTML(organization?.organization_name || 'Organization')}</h2><dl><div><dt>Slug</dt><dd class="mono">${escapeHTML(organization?.organization_slug || '')}</dd></div><div><dt>Your role</dt><dd><span class="status unresolved">${escapeHTML(membership?.role || '')}</span></dd></div><div><dt>Projects</dt><dd>${state.projects.length}</dd></div></dl></section>
    <section class="card settings-card"><p class="eyebrow">Identity</p><h2>Single sign-on</h2><p class="muted">Accounts are provisioned from your OIDC provider. Password authentication is disabled.</p><dl><div><dt>Signed in as</dt><dd>${escapeHTML(state.me?.email || '')}</dd></div><div><dt>Provider</dt><dd>${escapeHTML(state.providerName)}</dd></div></dl></section>
    <section class="card settings-card span-two"><div class="card-heading"><div><p class="eyebrow">Organizations</p><h2>Your workspaces</h2></div><button class="button secondary small" data-open-organization>${icon('plus')} New organization</button></div><div class="org-list">${state.organizations.map((item) => `<button data-org-id="${escapeHTML(item.organization_id)}"><span>${escapeHTML(item.organization_name)}</span><small class="mono">${escapeHTML(item.organization_slug)}</small><b>${escapeHTML(item.role)}</b></button>`).join('')}</div></section>
  </div>`;
}

function renderPerformance() {
  const { stats = {}, transactions = [], period = '24h' } = state.performance;
  const failureRate = Number(stats.count) ? (100 * Number(stats.failed || 0) / Number(stats.count)).toFixed(1) : '0.0';
  const rows = transactions.filter((item) => !state.query || `${item.name} ${item.operation}`.toLowerCase().includes(state.query.toLowerCase()));
  return `<div class="toolbar"><div class="segmented" id="performance-period">${['1h', '24h', '7d', '30d'].map((value) => `<button class="${period === value ? 'active' : ''}" data-period="${value}">${value}</button>`).join('')}</div><p class="muted">Sentry transaction envelopes · ${escapeHTML(period)} window</p></div>
    <section class="metric-grid">
      ${statCard('Transactions', Number(stats.count || 0).toLocaleString(), `${Number(stats.failed || 0)} failed`)}
      ${statCard('Average', formatMS(stats.average_ms), 'Mean transaction duration')}
      ${statCard('p95 latency', formatMS(stats.p95_ms), `p50 ${formatMS(stats.p50_ms)}`, Number(stats.p95_ms) > 1000 ? 'bad' : 'good')}
      ${statCard('Failure rate', `${failureRate}%`, `${Number(stats.failed || 0)} failed transactions`, Number(failureRate) ? 'bad' : 'good')}
    </section>
    <section class="card data-table observability-table"><div class="table-head performance-grid"><span>Transaction</span><span>Throughput</span><span>Average</span><span>Slowest</span><span>Failed</span></div>${rows.length ? rows.map((item) => `<div class="table-row performance-grid"><div class="telemetry-name">${icon('pulse')}<span><strong>${escapeHTML(item.name)}</strong><small>${escapeHTML(item.operation || 'transaction')} · last seen ${escapeHTML(relative(item.last_seen_at))}</small></span></div><b>${Number(item.count).toLocaleString()}</b><span>${formatMS(item.average_ms)}</span><span>${formatMS(item.max_ms)}</span><span class="${item.failed ? 'danger-text' : 'muted'}">${Number(item.failed).toLocaleString()}</span></div>`).join('') : `<div class="empty-state">${icon('pulse')}<h3>No transactions yet</h3><p>Enable tracing in a Sentry-compatible SDK and transactions will appear here.</p></div>`}</section>`;
}

function renderLogs() {
  const needle = state.query.toLowerCase();
  const rows = state.logs.filter((item) => (state.logLevel === 'all' || item.level === state.logLevel) && (!needle || `${item.message} ${item.environment} ${item.release} ${item.trace_id}`.toLowerCase().includes(needle)));
  const levels = ['all', 'debug', 'info', 'warning', 'error', 'fatal'];
  return `<div class="toolbar"><div class="segmented" id="log-filter">${levels.map((level) => `<button class="${state.logLevel === level ? 'active' : ''}" data-level="${level}">${level}</button>`).join('')}</div><span class="result-count">${rows.length} recent entries</span></div>
    <section class="card log-stream">${rows.length ? rows.map((entry) => `<details class="log-row"><summary><time>${escapeHTML(new Date(entry.timestamp).toLocaleTimeString())}</time><span class="log-level ${escapeHTML(entry.level)}">${escapeHTML(entry.level)}</span><strong>${escapeHTML(entry.message)}</strong><span class="secondary-cell">${escapeHTML(entry.environment || entry.release || '')}</span></summary><div class="log-context"><dl><div><dt>Timestamp</dt><dd class="mono">${escapeHTML(entry.timestamp)}</dd></div><div><dt>Trace</dt><dd class="mono">${escapeHTML(entry.trace_id || '—')}</dd></div><div><dt>Span</dt><dd class="mono">${escapeHTML(entry.span_id || '—')}</dd></div><div><dt>Release</dt><dd class="mono">${escapeHTML(entry.release || '—')}</dd></div></dl><pre>${escapeHTML(JSON.stringify(entry.attributes || {}, null, 2))}</pre></div></details>`).join('') : `<div class="empty-state">${icon('log')}<h3>No matching logs</h3><p>Send structured logs through the Sentry envelope or Barktrace logs endpoint.</p></div>`}</section>`;
}

function renderUptime() {
  const selected = state.monitors.find((monitor) => monitor.id === state.monitorId);
  const monitorRows = state.monitors.length ? state.monitors.map((monitor) => `<button class="monitor-row ${monitor.id === state.monitorId ? 'selected' : ''}" data-monitor-id="${escapeHTML(monitor.id)}"><i class="monitor-state ${escapeHTML(monitor.last_status)}"></i><span><strong>${escapeHTML(monitor.name)}</strong><small>${escapeHTML(monitor.url)}</small></span><span><b>${Number(monitor.availability_24h).toFixed(2)}%</b><small>last 24 hours</small></span><span><b>${escapeHTML(monitor.last_status)}</b><small>${monitor.last_checked_at ? escapeHTML(relative(monitor.last_checked_at)) : 'not checked yet'}</small></span>${icon('chevron')}</button>`).join('') : `<div class="empty-state">${icon('clock')}<h3>No uptime monitors</h3><p>Create an HTTP monitor to begin scheduled checks and incident tracking.</p><button class="button" data-open-monitor>${icon('plus')} Create monitor</button></div>`;
  const detail = selected ? `<section class="card monitor-detail"><div class="card-heading"><div><p class="eyebrow">Monitor detail</p><h2>${escapeHTML(selected.name)}</h2></div><div class="inline-actions"><button class="button secondary small" data-check-monitor="${escapeHTML(selected.id)}">Check now</button><button class="button danger small" data-delete-monitor="${escapeHTML(selected.id)}">Delete</button></div></div><div class="monitor-summary"><div><span>Status</span><strong class="${selected.last_status === 'down' ? 'danger-text' : ''}">${escapeHTML(selected.last_status)}</strong></div><div><span>Interval</span><strong>${Number(selected.interval_seconds) / 60} min</strong></div><div><span>Expected</span><strong>${selected.expected_status_min}–${selected.expected_status_max}</strong></div><div><span>Timeout</span><strong>${selected.timeout_seconds} s</strong></div></div><h3 class="section-title">Recent checks</h3><div class="check-list">${state.monitorDetails.checks.length ? state.monitorDetails.checks.slice(0, 20).map((check) => `<div><i class="monitor-state ${escapeHTML(check.status)}"></i><span><strong>${escapeHTML(check.status)}${check.status_code ? ` · HTTP ${check.status_code}` : ''}</strong><small>${escapeHTML(check.error || relative(check.checked_at))}</small></span><b>${formatMS(check.duration_ms)}</b></div>`).join('') : '<p class="muted padded">No checks recorded yet.</p>'}</div>${state.monitorDetails.incidents.length ? `<h3 class="section-title">Incidents</h3><div class="incident-list">${state.monitorDetails.incidents.map((incident) => `<div><span class="status ${incident.resolved_at ? 'resolved' : 'unresolved'}">${incident.resolved_at ? 'resolved' : 'open'}</span><p><strong>${escapeHTML(incident.cause || 'Monitor failed')}</strong><small>Started ${escapeHTML(relative(incident.started_at))}${incident.resolved_at ? ` · resolved ${escapeHTML(relative(incident.resolved_at))}` : ''}</small></p></div>`).join('')}</div>` : ''}</section>` : '';
  return `<div class="toolbar"><p class="muted">Checks run inside this Barktrace instance. Private network targets are blocked by default.</p><button class="button small" data-open-monitor>${icon('plus')} New monitor</button></div><div class="uptime-grid"><section class="card monitor-list">${monitorRows}</section>${detail}</div>`;
}

function render() {
  $('#page-actions').innerHTML = '';
  const renderers = {
    overview: renderOverview,
    issues: renderIssues,
    releases: renderReleases,
    projects: renderProjects,
    setup: renderSetup,
    settings: renderSettings,
    performance: renderPerformance,
    logs: renderLogs,
    uptime: renderUptime,
  };
  $('#view').innerHTML = (renderers[state.route] || renderOverview)();
  bindView();
}

function bindView() {
  $$('[data-route]').forEach((link) => link.addEventListener('click', (event) => {
    if (link.origin && link.origin !== location.origin) return;
    event.preventDefault();
    setRoute(link.dataset.route, true);
    $('#sidebar').classList.remove('open');
  }));
  $$('[data-open-project]').forEach((button) => button.addEventListener('click', () => $('#project-dialog').showModal()));
  $$('[data-open-organization]').forEach((button) => button.addEventListener('click', () => $('#organization-dialog').showModal()));
  $$('[data-copy]').forEach((button) => button.addEventListener('click', async () => {
    await navigator.clipboard.writeText(button.dataset.copy);
    showToast('Copied to clipboard');
  }));
  $$('[data-project-id]').forEach((button) => button.addEventListener('click', async () => {
    state.projectId = button.dataset.projectId;
    localStorage.setItem(`project:${state.organizationId}`, state.projectId);
    $('#project').value = state.projectId;
    await loadProjectData();
    setRoute('overview', true);
  }));
  $$('[data-org-id]').forEach((button) => button.addEventListener('click', async () => {
    state.organizationId = button.dataset.orgId;
    localStorage.setItem('organization', state.organizationId);
    $('#organization').value = state.organizationId;
    await loadProjects();
    setRoute('overview', true);
  }));
  $$('#issue-filter button').forEach((button) => button.addEventListener('click', () => {
    state.issueStatus = button.dataset.status;
    render();
  }));
  $$('#log-filter button').forEach((button) => button.addEventListener('click', () => {
    state.logLevel = button.dataset.level;
    render();
  }));
  $$('#performance-period button').forEach((button) => button.addEventListener('click', async () => {
    state.performance = await request(`/performance?project_id=${encodeURIComponent(state.projectId)}&period=${button.dataset.period}`);
    render();
  }));
  $$('[data-open-monitor]').forEach((button) => button.addEventListener('click', () => $('#monitor-dialog').showModal()));
  $$('[data-monitor-id]').forEach((button) => button.addEventListener('click', async () => {
    state.monitorId = button.dataset.monitorId;
    state.monitorDetails = await request(`/uptime/checks?monitor_id=${encodeURIComponent(state.monitorId)}`);
    render();
  }));
  $$('[data-check-monitor]').forEach((button) => button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      const result = await request(`/uptime/monitors/${encodeURIComponent(button.dataset.checkMonitor)}/check`, { method: 'POST' });
      showToast(`Monitor is ${result.status}`);
      await loadObservabilityData();
    } catch (error) { showToast(error.message); }
  }));
  $$('[data-delete-monitor]').forEach((button) => button.addEventListener('click', async () => {
    if (!confirm('Delete this monitor and its check history?')) return;
    await request(`/uptime/monitors/${encodeURIComponent(button.dataset.deleteMonitor)}`, { method: 'DELETE' });
    state.monitorId = '';
    state.monitorDetails = { checks: [], incidents: [] };
    await loadObservabilityData();
    showToast('Monitor deleted');
  }));
  $$('.code-tabs [data-language]').forEach((button) => button.addEventListener('click', () => {
    const project = currentProject();
    const snippets = {
      javascript: `Sentry.init({\n  dsn: "${project.dsn}",\n  release: "${project.slug}@1.0.0",\n  environment: "production"\n});`,
      go: `sentry.Init(sentry.ClientOptions{\n  Dsn: "${project.dsn}",\n  Release: "${project.slug}@1.0.0",\n  Environment: "production",\n})`,
      python: `sentry_sdk.init(\n    dsn="${project.dsn}",\n    release="${project.slug}@1.0.0",\n    environment="production",\n)`,
    };
    $$('.code-tabs button').forEach((item) => item.classList.toggle('active', item === button));
    $('#sdk-snippet').textContent = snippets[button.dataset.language];
    $('#copy-snippet').dataset.copy = snippets[button.dataset.language];
  }));
}

function populateSelectors() {
  $('#organization').innerHTML = state.organizations.map((organization) => `<option value="${escapeHTML(organization.organization_id)}">${escapeHTML(organization.organization_name)}</option>`).join('');
  $('#organization').value = state.organizationId;
  $('#project').innerHTML = state.projects.length
    ? state.projects.map((project) => `<option value="${escapeHTML(project.id)}">${escapeHTML(project.name)}</option>`).join('')
    : '<option value="">No projects</option>';
  $('#project').value = state.projectId;
  const project = currentProject();
  $('#project-slug').textContent = project?.slug || 'No project selected';
  $('#project-avatar').textContent = (project?.platform || project?.name || '–').slice(0, 2).toUpperCase();
}

async function loadProjectData() {
  populateSelectors();
  if (!state.projectId) {
    state.issues = [];
    state.releases = [];
    state.performance = { period: '24h', stats: {}, transactions: [] };
    state.logs = [];
    state.monitors = [];
    $('#issue-count').textContent = '0';
    render();
    return;
  }
  [state.issues, state.releases] = await Promise.all([
    request(`/issues?project_id=${encodeURIComponent(state.projectId)}`),
    request(`/releases?project_id=${encodeURIComponent(state.projectId)}`),
  ]);
  await loadObservabilityData();
  $('#issue-count').textContent = String(state.issues.filter((issue) => issue.status === 'unresolved').length);
  populateSelectors();
  render();
}

async function loadObservabilityData() {
  if (!state.projectId) return;
  const period = state.performance.period || '24h';
  [state.performance, state.logs, state.monitors] = await Promise.all([
    request(`/performance?project_id=${encodeURIComponent(state.projectId)}&period=${period}`),
    request(`/logs?project_id=${encodeURIComponent(state.projectId)}&limit=200`),
    request(`/uptime/monitors?project_id=${encodeURIComponent(state.projectId)}`),
  ]);
  if (state.monitorId && state.monitors.some((monitor) => monitor.id === state.monitorId)) {
    state.monitorDetails = await request(`/uptime/checks?monitor_id=${encodeURIComponent(state.monitorId)}`);
  } else {
    state.monitorId = '';
    state.monitorDetails = { checks: [], incidents: [] };
  }
  render();
}

async function loadProjects(preferredProject = '') {
  state.projects = state.organizationId
    ? await request(`/projects?organization_id=${encodeURIComponent(state.organizationId)}`)
    : [];
  const remembered = preferredProject || localStorage.getItem(`project:${state.organizationId}`);
  state.projectId = state.projects.some((project) => project.id === remembered)
    ? remembered
    : state.projects[0]?.id || '';
  await loadProjectData();
}

async function boot() {
  try {
    const [principal, authConfig] = await Promise.all([request('/auth/me'), request('/auth/config')]);
    state.me = principal;
    state.providerName = authConfig.provider_name || 'OIDC';
    state.organizations = state.me.memberships;
    const remembered = localStorage.getItem('organization');
    state.organizationId = state.organizations.some((organization) => organization.organization_id === remembered)
      ? remembered
      : state.organizations[0]?.organization_id || '';
    $('#account-name').textContent = state.me.name || 'Account';
    $('#account-email').textContent = state.me.email;
    $('#account-button').textContent = (state.me.name || state.me.email || '?').slice(0, 1).toUpperCase();
    await loadProjects();
    setRoute(routeFromPath());
    $('#loading-state').hidden = true;
    $('#page').hidden = false;
    $('#app').setAttribute('aria-busy', 'false');
  } catch (error) {
    $('#loading-state').innerHTML = `<div class="empty-state"><h3>Could not load the workspace</h3><p>${escapeHTML(error.message)}</p><button class="button" onclick="location.reload()">Try again</button></div>`;
  }
}

$('#organization').addEventListener('change', async (event) => {
  state.organizationId = event.target.value;
  localStorage.setItem('organization', state.organizationId);
  await loadProjects();
  setRoute(state.route);
});
$('#project').addEventListener('change', async (event) => {
  state.projectId = event.target.value;
  localStorage.setItem(`project:${state.organizationId}`, state.projectId);
  await loadProjectData();
  setRoute(state.route);
});
$('#global-search').addEventListener('input', (event) => {
  state.query = event.target.value.trim();
  render();
});
document.addEventListener('keydown', (event) => {
  if (event.key === '/' && document.activeElement?.tagName !== 'INPUT') {
    event.preventDefault();
    $('#global-search').focus();
  }
});
$('#mobile-menu').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
$('#account-button').addEventListener('click', () => { $('#account-menu').hidden = !$('#account-menu').hidden; });
$('#logout').addEventListener('click', async () => {
  await request('/auth/logout', { method: 'POST' });
  location.href = '/ui/login/';
});
const savedTheme = localStorage.getItem('theme');
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
$('#theme-toggle').addEventListener('click', () => {
  const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('theme', theme);
});
$$('[data-close]').forEach((button) => button.addEventListener('click', () => button.closest('dialog').close()));
$('#create-project').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = new FormData(form);
  const error = $('#project-error');
  error.hidden = true;
  try {
    const project = await request('/projects', {
      method: 'POST',
      body: JSON.stringify({ organization_id: state.organizationId, name: input.get('name'), platform: input.get('platform') }),
    });
    form.reset();
    $('#project-dialog').close();
    await loadProjects(project.id);
    setRoute('setup', true);
    showToast('Project created');
  } catch (reason) {
    error.textContent = reason.message;
    error.hidden = false;
  }
});
$('#create-organization').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = new FormData(form);
  const error = $('#organization-error');
  error.hidden = true;
  try {
    const organization = await request('/organizations', {
      method: 'POST',
      body: JSON.stringify({ name: input.get('name'), slug: input.get('slug') }),
    });
    form.reset();
    $('#organization-dialog').close();
    state.me = await request('/auth/me');
    state.organizations = state.me.memberships;
    state.organizationId = organization.id;
    await loadProjects();
    setRoute('projects', true);
    showToast('Organization created');
  } catch (reason) {
    error.textContent = reason.message;
    error.hidden = false;
  }
});
$('#create-monitor').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = new FormData(form);
  const error = $('#monitor-error');
  error.hidden = true;
  try {
    const monitor = await request('/uptime/monitors', {
      method: 'POST',
      body: JSON.stringify({ project_id: state.projectId, name: input.get('name'), url: input.get('url'), method: input.get('method'), interval_seconds: Number(input.get('interval_seconds')), timeout_seconds: Number(input.get('timeout_seconds')) }),
    });
    form.reset();
    $('#monitor-dialog').close();
    state.monitorId = monitor.id;
    await request(`/uptime/monitors/${encodeURIComponent(monitor.id)}/check`, { method: 'POST' });
    await loadObservabilityData();
    showToast('Monitor created');
  } catch (reason) {
    error.textContent = reason.message;
    error.hidden = false;
  }
});
addEventListener('popstate', () => setRoute(routeFromPath()));

boot();
