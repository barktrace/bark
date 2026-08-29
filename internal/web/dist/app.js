const state = {
  me: null,
  organizations: [],
  organizationId: '',
  projects: [],
  projectId: '',
  issues: [],
  issueId: '',
  issueDetail: null,
  eventId: '',
  releases: [],
  performance: { period: '24h', stats: {}, transactions: [] },
  transactionDetail: null,
  logs: [],
  logLevel: 'all',
  monitors: [],
  monitorId: '',
  monitorDetails: { checks: [], incidents: [] },
  route: 'overview',
  query: '',
  issueStatus: 'all',
  providerName: 'OIDC',
  members: { members: [], invitations: [] },
  tokens: [],
  storage: null,
  alerts: [],
  alertDeliveries: [],
  newToken: '',
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
const currentMembership = () => state.me?.memberships.find((item) => item.organization_id === state.organizationId);
const canAdminister = () => ['owner', 'admin'].includes(currentMembership()?.role);

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
      return `<button class="table-row issue-grid issue-row-button" data-issue-id="${escapeHTML(issue.id)}">
        <div class="issue-name"><i class="severity ${level}"></i><div><strong>${issue.bookmarked ? '★ ' : ''}${escapeHTML(issue.title)}</strong><small><span class="status ${escapeHTML(issue.status)}">${escapeHTML(issue.status)}</span> ${escapeHTML(issue.priority || 'medium')} priority · ${escapeHTML(issue.level)}${issue.assignee_name ? ` · ${escapeHTML(issue.assignee_name)}` : ''}</small></div></div>
        <span class="mono secondary-cell">${escapeHTML(issue.first_release || '—')}</span>
        <span class="secondary-cell">${escapeHTML(relative(issue.last_seen_at))}</span>
        <b class="numeric">${Number(issue.event_count).toLocaleString()}</b>
      </button>`;
    }).join('')}`;
}

function releaseRows(limit) {
  const needle = state.query.toLowerCase();
  const rows = state.releases.filter((release) => !needle || release.version.toLowerCase().includes(needle)).slice(0, limit);
  if (!rows.length) {
    return `<div class="empty-state">${icon('rocket')}<h3>No releases yet</h3><p>Set <code>release</code> in your SDK configuration to start tracking versions.</p></div>`;
  }
  return `
    <div class="table-head release-grid"><span>Version</span><span>Last seen</span><span>Events</span><span>Release health</span></div>
    ${rows.map((release) => `<div class="table-row release-grid">
      <div class="release-name">${icon('rocket')}<strong class="mono">${escapeHTML(release.version)}</strong></div>
      <span class="secondary-cell">${escapeHTML(relative(release.last_seen_at))}</span>
      <b class="numeric">${Number(release.events).toLocaleString()}</b>
      <span class="release-health"><b>${Number(release.crash_free_sessions ?? 100).toFixed(1)}%</b><small>${Number(release.sessions || 0).toLocaleString()} sessions · ${Number(release.users || 0).toLocaleString()} users</small></span>
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
  if (state.issueDetail) return renderIssueDetail();
  return `<div class="toolbar"><div class="segmented" id="issue-filter">${['all', 'unresolved', 'resolved', 'ignored'].map((status) => `<button class="${state.issueStatus === status ? 'active' : ''}" data-status="${status}">${{ all: 'All', unresolved: 'Open', resolved: 'Resolved', ignored: 'Muted' }[status]}</button>`).join('')}</div><span class="result-count">${filteredIssues().length} issue groups</span></div><section class="card data-table" id="issues-table">${issueRows(100)}</section>`;
}

function eventExceptions(payload = {}) {
  const exception = payload.exception;
  if (Array.isArray(exception)) return exception;
  return Array.isArray(exception?.values) ? exception.values : [];
}

function renderIssueDetail() {
  const detail = state.issueDetail;
  const issue = detail.issue;
  const selected = detail.events.find((event) => event.id === state.eventId) || detail.events[0];
  const payload = selected?.payload || {};
  const exceptions = eventExceptions(payload);
  const exception = exceptions.at(-1) || {};
  const frames = Array.isArray(exception.stacktrace?.frames) ? [...exception.stacktrace.frames].reverse() : [];
  const breadcrumbs = Array.isArray(payload.breadcrumbs?.values) ? payload.breadcrumbs.values : [];
  const activity = detail.activities.map((item) => `<div class="activity-item"><span class="activity-icon">${item.kind === 'comment' ? '”' : '•'}</span><p><strong>${escapeHTML(item.user_name || item.user_email || 'System')}</strong> ${item.kind === 'comment' ? escapeHTML(item.value) : `${escapeHTML(item.kind)} → ${escapeHTML(item.value || 'cleared')}`}<small>${escapeHTML(relative(item.created_at))}</small></p></div>`).join('');
  return `<div class="issue-detail-head"><button class="button secondary small" data-back-issues>← All issues</button><div class="inline-actions"><button class="icon-text-button ${issue.bookmarked ? 'active' : ''}" data-bookmark-issue>${issue.bookmarked ? '★ Bookmarked' : '☆ Bookmark'}</button><button class="button secondary small" data-snooze-issue>${issue.snoozed_until ? 'Unsnooze' : 'Snooze 24h'}</button><button class="button secondary small" data-issue-status="${issue.status === 'resolved' ? 'unresolved' : 'resolved'}">${issue.status === 'resolved' ? 'Reopen' : 'Resolve'}</button>${canAdminister() ? '<button class="button danger small" data-delete-issue>Delete</button>' : ''}</div></div>
    <section class="issue-hero card"><div><div class="issue-meta"><span class="severity ${escapeHTML(issue.level)}"></span><span class="status ${escapeHTML(issue.status)}">${escapeHTML(issue.status)}</span><span>${escapeHTML(issue.level)}</span><span>${Number(issue.event_count).toLocaleString()} events</span>${issue.snoozed_until ? `<span>Snoozed until ${escapeHTML(new Date(issue.snoozed_until).toLocaleString())}</span>` : ''}</div><h2>${escapeHTML(issue.title)}</h2><p class="muted">First seen ${escapeHTML(relative(issue.first_seen_at))} · Last seen ${escapeHTML(relative(issue.last_seen_at))}</p></div><div class="issue-controls"><label>Assignee<select id="issue-assignee"><option value="">Unassigned</option>${state.members.members.map((member) => `<option value="${escapeHTML(member.id)}" ${issue.assignee_user_id === member.id ? 'selected' : ''}>${escapeHTML(member.name || member.email)}</option>`).join('')}</select></label><label>Priority<select id="issue-priority">${['low', 'medium', 'high', 'critical'].map((value) => `<option value="${value}" ${issue.priority === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label><label>Status<select id="issue-status">${['unresolved', 'resolved', 'ignored'].map((value) => `<option value="${value}" ${issue.status === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label></div></section>
    <div class="issue-detail-grid"><section class="card event-detail"><div class="event-picker">${detail.events.map((event, index) => `<button class="${event.id === selected?.id ? 'active' : ''}" data-event-id="${escapeHTML(event.id)}"><strong>#${detail.events.length - index}</strong><span>${escapeHTML(event.environment || 'default')}</span><small>${escapeHTML(relative(event.timestamp))}</small></button>`).join('')}</div>${selected ? `<div class="event-content"><div class="event-facts"><span><small>Event ID</small><code>${escapeHTML(selected.event_id)}</code></span><span><small>Release</small><code>${escapeHTML(selected.release || '—')}</code></span><span><small>Platform</small><b>${escapeHTML(selected.platform || 'generic')}</b></span><span><small>Environment</small><b>${escapeHTML(selected.environment || 'default')}</b></span></div>${exception.type || exception.value ? `<div class="exception-block"><p class="eyebrow">Exception</p><h3>${escapeHTML(exception.type || 'Error')}</h3><p>${escapeHTML(exception.value || payload.message || '')}</p></div>` : ''}<div class="detail-section"><h3>Stack trace</h3>${frames.length ? `<div class="stacktrace">${frames.map((frame) => `<div class="frame ${frame.in_app ? 'in-app' : ''}"><div><strong class="mono">${escapeHTML(frame.function || '<unknown>')}</strong><span class="mono">${escapeHTML(frame.filename || frame.abs_path || '')}:${escapeHTML(frame.lineno || '')}</span></div>${frame.context_line ? `<pre>${escapeHTML(frame.context_line)}</pre>` : ''}</div>`).join('')}</div>` : '<p class="muted">No stack frames were included in this event.</p>'}</div>${breadcrumbs.length ? `<div class="detail-section"><h3>Breadcrumbs</h3><div class="breadcrumb-list">${breadcrumbs.slice(-30).reverse().map((crumb) => `<div><time>${escapeHTML(crumb.timestamp || '')}</time><span class="log-level ${escapeHTML(crumb.level || 'info')}">${escapeHTML(crumb.category || crumb.type || 'log')}</span><strong>${escapeHTML(crumb.message || JSON.stringify(crumb.data || {}))}</strong></div>`).join('')}</div></div>` : ''}<details class="raw-event"><summary>Raw event JSON</summary><pre>${escapeHTML(JSON.stringify(payload, null, 2))}</pre></details></div>` : '<div class="empty-state"><h3>No retained events</h3></div>'}</section>
    <aside class="card activity-panel"><div class="card-heading"><div><p class="eyebrow">Collaboration</p><h2>Activity</h2></div></div><form id="issue-comment"><textarea name="body" maxlength="4000" placeholder="Leave a note for your team…" required></textarea><button class="button small">Comment</button></form><div class="activity-list">${activity || '<p class="muted padded">No activity yet.</p>'}</div></aside></div>`;
}

function renderReleases() {
  return `<div class="toolbar"><p class="muted">Releases are created automatically when an event contains a release identifier.</p><a class="button secondary small" href="/ui/setup/" data-route="setup">Configure SDK</a></div><section class="card data-table">${releaseRows(100)}</section>`;
}

function renderProjects() {
  const project = currentProject();
  const manage = project ? `<section class="card project-admin"><div class="card-heading"><div><p class="eyebrow">Selected project</p><h2>Project configuration</h2></div></div><form id="edit-project" class="settings-form"><label>Name<input name="name" value="${escapeHTML(project.name)}" required /></label><label>Slug<input name="slug" value="${escapeHTML(project.slug)}" required pattern="[a-z0-9-]+" /></label><label>Platform<input name="platform" value="${escapeHTML(project.platform || '')}" placeholder="generic" /></label><button class="button small">Save changes</button></form><div class="danger-zone"><div><strong>Client key</strong><p class="muted">Rotating immediately invalidates the current DSN.</p></div><button class="button secondary small" data-rotate-key>Rotate key</button><button class="button danger small" data-delete-project>Delete project</button></div></section>` : '';
  return `<div class="toolbar"><p class="muted">${state.projects.length} project${state.projects.length === 1 ? '' : 's'} in ${escapeHTML(currentOrganization()?.organization_name || 'this organization')}</p><button class="button small" data-open-project>${icon('plus')} New project</button></div><section class="card">${projectRows()}</section>${manage}`;
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
  const membership = currentMembership();
  const admin = canAdminister();
  const members = state.members.members.map((item) => `<div class="management-row"><span class="avatar small-avatar">${escapeHTML((item.name || item.email).slice(0, 1).toUpperCase())}</span><span><strong>${escapeHTML(item.name || item.email)}</strong><small>${escapeHTML(item.email)}</small></span>${admin && item.id !== state.me.id ? `<select data-member-role="${escapeHTML(item.id)}">${['viewer', 'member', 'admin', ...(membership?.role === 'owner' ? ['owner'] : [])].map((role) => `<option ${item.role === role ? 'selected' : ''}>${role}</option>`).join('')}</select><button class="icon-text-button danger-text" data-remove-member="${escapeHTML(item.id)}">Remove</button>` : `<b>${escapeHTML(item.role)}</b>`}</div>`).join('');
  const invitations = state.members.invitations.map((item) => `<div class="management-row"><span class="avatar small-avatar">?</span><span><strong>${escapeHTML(item.email)}</strong><small>Expires ${escapeHTML(relative(item.expires_at))}</small></span><b>${escapeHTML(item.role)}</b>${admin ? `<button class="icon-text-button danger-text" data-revoke-invite="${escapeHTML(item.id)}">Revoke</button>` : ''}</div>`).join('');
  const tokens = state.tokens.map((item) => `<div class="management-row"><span class="platform-icon">API</span><span><strong>${escapeHTML(item.name)}</strong><small class="mono">${escapeHTML(item.prefix)}… · ${item.last_used_at ? `used ${escapeHTML(relative(item.last_used_at))}` : 'never used'}</small></span><small>${item.expires_at ? `expires ${escapeHTML(relative(item.expires_at))}` : 'no expiry'}</small><button class="icon-text-button danger-text" data-delete-token="${escapeHTML(item.id)}">Revoke</button></div>`).join('');
  const totals = state.storage?.totals || {};
  const alerts = state.alerts.map((item) => `<div class="management-row"><i class="monitor-state ${item.enabled ? 'up' : 'pending'}"></i><span><strong>${escapeHTML(item.name)}</strong><small>${escapeHTML(item.trigger.replaceAll('_', ' '))} · ${escapeHTML(item.destination_type)} · ${escapeHTML(item.destination_host)}</small></span><button class="button secondary small" data-toggle-alert="${escapeHTML(item.id)}" data-enabled="${item.enabled}">${item.enabled ? 'Disable' : 'Enable'}</button><button class="button secondary small" data-test-alert="${escapeHTML(item.id)}">Test</button><button class="icon-text-button danger-text" data-delete-alert="${escapeHTML(item.id)}">Delete</button></div>`).join('');
  const deliveries = state.alertDeliveries.slice(0, 5).map((item) => `<div class="delivery-row"><span class="status ${item.status === 'sent' ? 'resolved' : 'unresolved'}">${escapeHTML(item.status)}</span><strong>${escapeHTML(item.rule_name)}</strong><small>${escapeHTML(item.event_type)} · ${escapeHTML(relative(item.created_at))}${item.last_error ? ` · ${escapeHTML(item.last_error)}` : ''}</small></div>`).join('');
  return `<div class="settings-grid">
    <section class="card settings-card"><p class="eyebrow">Workspace</p><h2>${escapeHTML(organization?.organization_name || 'Organization')}</h2><dl><div><dt>Slug</dt><dd class="mono">${escapeHTML(organization?.organization_slug || '')}</dd></div><div><dt>Your role</dt><dd><span class="status unresolved">${escapeHTML(membership?.role || '')}</span></dd></div><div><dt>Projects</dt><dd>${state.projects.length}</dd></div></dl></section>
    <section class="card settings-card"><p class="eyebrow">Identity</p><h2>Single sign-on</h2><p class="muted">Accounts are provisioned from your OIDC provider. Password authentication is disabled.</p><dl><div><dt>Signed in as</dt><dd>${escapeHTML(state.me?.email || '')}</dd></div><div><dt>Provider</dt><dd>${escapeHTML(state.providerName)}</dd></div></dl></section>
    <section class="card settings-card span-two"><div class="card-heading"><div><p class="eyebrow">Team</p><h2>Members and invitations</h2></div>${admin ? `<form id="invite-member" class="inline-form"><input name="email" type="email" required placeholder="teammate@example.com" /><select name="role"><option>member</option><option>viewer</option><option>admin</option></select><button class="button small">Invite</button></form>` : ''}</div><div class="management-list">${members || '<p class="muted padded">No members.</p>'}${invitations}</div></section>
    <section class="card settings-card span-two"><div class="card-heading"><div><p class="eyebrow">Automation</p><h2>API tokens</h2></div><form id="create-token" class="inline-form"><input name="name" required placeholder="CI deployment" /><select name="expires_in_days"><option value="0">No expiry</option><option value="30">30 days</option><option value="90">90 days</option><option value="365">1 year</option></select><button class="button small">Create</button></form></div>${state.newToken ? `<div class="token-secret"><strong>Copy this token now — it will not be shown again.</strong><div class="copy-field"><code>${escapeHTML(state.newToken)}</code><button data-copy="${escapeHTML(state.newToken)}">${icon('copy')} Copy</button></div></div>` : ''}<div class="management-list">${tokens || '<p class="muted padded">No personal API tokens.</p>'}</div></section>
    <section class="card settings-card"><p class="eyebrow">Data lifecycle</p><h2>Storage</h2><div class="storage-stats"><div><strong>${Number(state.storage?.database_bytes || 0).toLocaleString()}</strong><small>database bytes</small></div><div><strong>${Number(totals.events || 0).toLocaleString()}</strong><small>events</small></div><div><strong>${Number(totals.spans || 0).toLocaleString()}</strong><small>spans</small></div></div>${admin ? `<form id="retention-form" class="inline-form"><label>Retention days<input name="days" type="number" min="1" max="3650" value="${Number(state.storage?.retention_days || 30)}" /></label><button class="button small">Save</button></form><div class="inline-actions"><button class="button secondary small" data-cleanup="dry">Preview cleanup</button><button class="button danger small" data-cleanup="apply">Delete expired data</button></div>` : ''}</section>
    <section class="card settings-card"><p class="eyebrow">Notifications</p><h2>Project alerts</h2>${currentProject() && admin ? `<form id="create-alert" class="stack-form"><input name="name" required placeholder="Production errors" /><div class="form-grid"><select name="trigger"><option value="new_issue">New issue</option><option value="regression">Regression</option><option value="uptime_down">Uptime down</option></select><select name="destination_type"><option value="webhook">Webhook</option><option value="slack">Slack</option></select></div><input name="destination_url" type="url" required placeholder="https://hooks.example.com/…" /><button class="button small">Add alert</button></form>` : '<p class="muted">Select a project to configure alerts.</p>'}<div class="management-list compact-management">${alerts || '<p class="muted padded">No alert rules for this project.</p>'}</div>${deliveries ? `<h3 class="section-title">Recent deliveries</h3><div class="delivery-list">${deliveries}</div>` : ''}</section>
    <section class="card settings-card span-two"><div class="card-heading"><div><p class="eyebrow">Organizations</p><h2>Your workspaces</h2></div><button class="button secondary small" data-open-organization>${icon('plus')} New organization</button></div><div class="org-list">${state.organizations.map((item) => `<button data-org-id="${escapeHTML(item.organization_id)}"><span>${escapeHTML(item.organization_name)}</span><small class="mono">${escapeHTML(item.organization_slug)}</small><b>${escapeHTML(item.role)}</b></button>`).join('')}</div></section>
  </div>`;
}

function renderPerformance() {
  if (state.transactionDetail) return renderTransactionDetail();
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
    <section class="card data-table observability-table"><div class="table-head performance-grid"><span>Transaction</span><span>Throughput</span><span>Average</span><span>Slowest</span><span>Failed</span></div>${rows.length ? rows.map((item) => `<button class="table-row performance-grid transaction-row" data-transaction-id="${escapeHTML(item.sample_id)}"><div class="telemetry-name">${icon('pulse')}<span><strong>${escapeHTML(item.name)}</strong><small>${escapeHTML(item.operation || 'transaction')} · last seen ${escapeHTML(relative(item.last_seen_at))}</small></span></div><b>${Number(item.count).toLocaleString()}</b><span>${formatMS(item.average_ms)}</span><span>${formatMS(item.max_ms)}</span><span class="${item.failed ? 'danger-text' : 'muted'}">${Number(item.failed).toLocaleString()}</span></button>`).join('') : `<div class="empty-state">${icon('pulse')}<h3>No transactions yet</h3><p>Enable tracing in a Sentry-compatible SDK and transactions will appear here.</p></div>`}</section>`;
}

function renderTransactionDetail() {
  const item = state.transactionDetail;
  const start = new Date(item.started_at).getTime();
  const total = Math.max(Number(item.duration_ms), 0.01);
  const spans = item.spans.map((span) => {
    const offset = Math.max(0, new Date(span.started_at).getTime() - start);
    const left = Math.min(100, 100 * offset / total);
    const width = Math.max(0.8, Math.min(100 - left, 100 * Number(span.duration_ms) / total));
    return `<div class="span-row"><span><strong>${escapeHTML(span.operation || 'span')}</strong><small>${escapeHTML(span.description || span.span_id)}</small></span><div class="span-track"><i style="left:${left}%;width:${width}%"></i></div><b>${formatMS(span.duration_ms)}</b></div>`;
  }).join('');
  return `<button class="button secondary small" data-back-performance>← All transactions</button><section class="card transaction-hero"><p class="eyebrow">${escapeHTML(item.operation || 'transaction')}</p><h2>${escapeHTML(item.name)}</h2><div class="event-facts"><span><small>Duration</small><b>${formatMS(item.duration_ms)}</b></span><span><small>Status</small><b>${escapeHTML(item.status || 'unknown')}</b></span><span><small>Release</small><code>${escapeHTML(item.release || '—')}</code></span><span><small>Trace ID</small><code>${escapeHTML(item.trace_id || '—')}</code></span></div></section><section class="card trace-waterfall"><div class="card-heading"><div><p class="eyebrow">Trace</p><h2>Span waterfall</h2></div><span>${item.spans.length} normalized spans</span></div>${spans || '<div class="empty-state"><h3>No child spans</h3><p>The transaction was received without span details.</p></div>'}</section>`;
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
  $$('[data-issue-id]').forEach((button) => button.addEventListener('click', async () => {
    state.issueId = button.dataset.issueId;
    state.issueDetail = await request(`/issues/${encodeURIComponent(state.issueId)}`);
    state.eventId = state.issueDetail.events[0]?.id || '';
    render();
  }));
  $$('[data-back-issues]').forEach((button) => button.addEventListener('click', () => {
    state.issueId = '';
    state.issueDetail = null;
    state.eventId = '';
    render();
  }));
  $$('[data-event-id]').forEach((button) => button.addEventListener('click', () => {
    state.eventId = button.dataset.eventId;
    render();
  }));
  $$('[data-issue-status]').forEach((button) => button.addEventListener('click', async () => {
    await updateSelectedIssue({ status: button.dataset.issueStatus });
  }));
  $('#issue-status')?.addEventListener('change', async (event) => updateSelectedIssue({ status: event.target.value }));
  $('#issue-priority')?.addEventListener('change', async (event) => updateSelectedIssue({ priority: event.target.value }));
  $('#issue-assignee')?.addEventListener('change', async (event) => updateSelectedIssue({ assignee_user_id: event.target.value }));
  $$('[data-bookmark-issue]').forEach((button) => button.addEventListener('click', async () => {
    await updateSelectedIssue({ bookmarked: !state.issueDetail.issue.bookmarked });
  }));
  $$('[data-snooze-issue]').forEach((button) => button.addEventListener('click', async () => {
    const value = state.issueDetail.issue.snoozed_until ? '' : new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    await updateSelectedIssue({ snoozed_until: value });
  }));
  $$('[data-delete-issue]').forEach((button) => button.addEventListener('click', async () => {
    if (!confirm('Permanently delete this issue and its retained events?')) return;
    await request(`/issues/${encodeURIComponent(state.issueId)}`, { method: 'DELETE' });
    state.issueId = '';
    state.issueDetail = null;
    state.issues = await request(`/issues?project_id=${encodeURIComponent(state.projectId)}`);
    render();
    showToast('Issue deleted');
  }));
  $('#issue-comment')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const body = new FormData(form).get('body');
    await request(`/issues/${encodeURIComponent(state.issueId)}/comments`, { method: 'POST', body: JSON.stringify({ body }) });
    form.reset();
    await reloadSelectedIssue();
    showToast('Comment added');
  });
  $$('[data-transaction-id]').forEach((button) => button.addEventListener('click', async () => {
    state.transactionDetail = await request(`/transactions/${encodeURIComponent(button.dataset.transactionId)}`);
    render();
  }));
  $$('[data-back-performance]').forEach((button) => button.addEventListener('click', () => {
    state.transactionDetail = null;
    render();
  }));
  $('#edit-project')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = new FormData(event.currentTarget);
    await request(`/projects/${encodeURIComponent(state.projectId)}`, { method: 'PATCH', body: JSON.stringify({ name: input.get('name'), slug: input.get('slug'), platform: input.get('platform') }) });
    await loadProjects(state.projectId);
    setRoute('projects');
    showToast('Project updated');
  });
  $$('[data-rotate-key]').forEach((button) => button.addEventListener('click', async () => {
    if (!confirm('Rotate this project key? Existing DSNs will stop sending data.')) return;
    const result = await request(`/projects/${encodeURIComponent(state.projectId)}/rotate-key`, { method: 'POST' });
    await loadProjects(state.projectId);
    await navigator.clipboard.writeText(result.dsn);
    showToast('Key rotated; new DSN copied');
  }));
  $$('[data-delete-project]').forEach((button) => button.addEventListener('click', async () => {
    const project = currentProject();
    if (!confirm(`Delete ${project?.name || 'this project'} and all of its telemetry?`)) return;
    await request(`/projects/${encodeURIComponent(state.projectId)}`, { method: 'DELETE' });
    localStorage.removeItem(`project:${state.organizationId}`);
    await loadProjects();
    setRoute('projects');
    showToast('Project deleted');
  }));
  $('#invite-member')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const input = new FormData(form);
    await request(`/organizations/${encodeURIComponent(state.organizationId)}/invitations`, { method: 'POST', body: JSON.stringify({ email: input.get('email'), role: input.get('role') }) });
    form.reset();
    await loadManagementData();
    showToast('Invitation saved');
  });
  $$('[data-member-role]').forEach((select) => select.addEventListener('change', async () => {
    await request(`/organizations/${encodeURIComponent(state.organizationId)}/members/${encodeURIComponent(select.dataset.memberRole)}`, { method: 'PATCH', body: JSON.stringify({ role: select.value }) });
    await loadManagementData();
    showToast('Member role updated');
  }));
  $$('[data-remove-member]').forEach((button) => button.addEventListener('click', async () => {
    if (!confirm('Remove this member from the organization?')) return;
    await request(`/organizations/${encodeURIComponent(state.organizationId)}/members/${encodeURIComponent(button.dataset.removeMember)}`, { method: 'DELETE' });
    await loadManagementData();
    showToast('Member removed');
  }));
  $$('[data-revoke-invite]').forEach((button) => button.addEventListener('click', async () => {
    await request(`/organizations/${encodeURIComponent(state.organizationId)}/invitations/${encodeURIComponent(button.dataset.revokeInvite)}`, { method: 'DELETE' });
    await loadManagementData();
    showToast('Invitation revoked');
  }));
  $('#create-token')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const input = new FormData(form);
    const token = await request('/api-tokens', { method: 'POST', body: JSON.stringify({ organization_id: state.organizationId, name: input.get('name'), expires_in_days: Number(input.get('expires_in_days')) }) });
    state.newToken = token.token;
    form.reset();
    await loadManagementData();
    showToast('API token created');
  });
  $$('[data-delete-token]').forEach((button) => button.addEventListener('click', async () => {
    if (!confirm('Revoke this API token?')) return;
    await request(`/api-tokens/${encodeURIComponent(button.dataset.deleteToken)}`, { method: 'DELETE' });
    await loadManagementData();
    showToast('API token revoked');
  }));
  $('#retention-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const days = Number(new FormData(event.currentTarget).get('days'));
    await request('/storage/retention', { method: 'PATCH', body: JSON.stringify({ organization_id: state.organizationId, days }) });
    await loadManagementData();
    showToast('Retention updated');
  });
  $$('[data-cleanup]').forEach((button) => button.addEventListener('click', async () => {
    const dryRun = button.dataset.cleanup === 'dry';
    const days = Number(state.storage?.retention_days || 30);
    if (!dryRun && !confirm(`Permanently delete telemetry older than ${days} days?`)) return;
    const result = await request('/storage/cleanup', { method: 'POST', body: JSON.stringify({ organization_id: state.organizationId, older_than_days: days, dry_run: dryRun }) });
    const total = Object.values(result.deleted || {}).reduce((sum, value) => sum + Number(value), 0);
    if (!dryRun) await loadManagementData();
    showToast(`${dryRun ? 'Would delete' : 'Deleted'} ${total.toLocaleString()} records`);
  }));
  $('#create-alert')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const input = new FormData(form);
    await request('/alerts', { method: 'POST', body: JSON.stringify({ project_id: state.projectId, name: input.get('name'), trigger: input.get('trigger'), destination_type: input.get('destination_type'), destination_url: input.get('destination_url') }) });
    form.reset();
    await loadManagementData();
    showToast('Alert rule created');
  });
  $$('[data-test-alert]').forEach((button) => button.addEventListener('click', async () => {
    await request(`/alerts/${encodeURIComponent(button.dataset.testAlert)}/test`, { method: 'POST' });
    showToast('Test alert queued');
  }));
  $$('[data-toggle-alert]').forEach((button) => button.addEventListener('click', async () => {
    await request(`/alerts/${encodeURIComponent(button.dataset.toggleAlert)}`, { method: 'PATCH', body: JSON.stringify({ enabled: button.dataset.enabled !== 'true' }) });
    await loadManagementData();
    showToast('Alert rule updated');
  }));
  $$('[data-delete-alert]').forEach((button) => button.addEventListener('click', async () => {
    if (!confirm('Delete this alert rule and its delivery history?')) return;
    await request(`/alerts/${encodeURIComponent(button.dataset.deleteAlert)}`, { method: 'DELETE' });
    await loadManagementData();
    showToast('Alert rule deleted');
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
  state.transactionDetail = null;
  if (!state.projectId) {
    state.issues = [];
    state.issueId = '';
    state.issueDetail = null;
    state.releases = [];
    state.performance = { period: '24h', stats: {}, transactions: [] };
    state.logs = [];
    state.monitors = [];
    await loadManagementData();
    $('#issue-count').textContent = '0';
    render();
    return;
  }
  [state.issues, state.releases] = await Promise.all([
    request(`/issues?project_id=${encodeURIComponent(state.projectId)}`),
    request(`/releases?project_id=${encodeURIComponent(state.projectId)}`),
  ]);
  await loadObservabilityData();
  await loadManagementData();
  $('#issue-count').textContent = String(state.issues.filter((issue) => issue.status === 'unresolved').length);
  populateSelectors();
  render();
}

async function loadManagementData() {
  if (!state.organizationId) {
    state.members = { members: [], invitations: [] };
    state.tokens = [];
    state.storage = null;
    state.alerts = [];
    state.alertDeliveries = [];
    return;
  }
  const requests = [
    request(`/organizations/${encodeURIComponent(state.organizationId)}/members`),
    request('/api-tokens'),
    request(`/storage?organization_id=${encodeURIComponent(state.organizationId)}`),
  ];
  if (state.projectId) {
    requests.push(request(`/alerts?project_id=${encodeURIComponent(state.projectId)}`));
    requests.push(request(`/alert-deliveries?project_id=${encodeURIComponent(state.projectId)}`));
  }
  const [members, tokens, storage, alerts = [], deliveries = []] = await Promise.all(requests);
  state.members = members;
  state.tokens = tokens;
  state.storage = storage;
  state.alerts = alerts;
  state.alertDeliveries = deliveries;
  render();
}

async function reloadSelectedIssue() {
  if (!state.issueId) return;
  state.issueDetail = await request(`/issues/${encodeURIComponent(state.issueId)}`);
  render();
}

async function updateSelectedIssue(changes) {
  await request(`/issues/${encodeURIComponent(state.issueId)}`, { method: 'PATCH', body: JSON.stringify(changes) });
  state.issues = await request(`/issues?project_id=${encodeURIComponent(state.projectId)}`);
  await reloadSelectedIssue();
  showToast('Issue updated');
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
