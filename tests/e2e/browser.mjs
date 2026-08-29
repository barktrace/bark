import { chromium } from 'playwright';

const baseURL = process.env.BARKTRACE_E2E_URL || 'http://127.0.0.1:18080';
const mcpToken = process.env.BARKTRACE_E2E_MCP_TOKEN || '';
const configuredChromium = process.env.CHROME_BIN || '';
const browser = await chromium.launch({
  headless: true,
  executablePath: configuredChromium
    ? (configuredChromium.startsWith('/') ? configuredChromium : `/usr/bin/${configuredChromium}`)
    : undefined,
  args: ['--no-sandbox'],
});
const context = await browser.newContext({ baseURL });
const page = await context.newPage();
const browserErrors = [];
page.on('pageerror', (error) => browserErrors.push(`page error: ${error.message}`));
page.on('console', (message) => {
  if (message.type() === 'error' && !message.text().includes('favicon')) browserErrors.push(`console error: ${message.text()}`);
});

try {
  await page.goto('/ui/login/');
  await page.getByRole('link', { name: 'Continue with Test SSO' }).click();
  await page.waitForURL(`${baseURL}/ui/`);
  try {
    await page.locator('#page:not([hidden])').waitFor();
  } catch (error) {
    const loading = await page.locator('#loading-state').textContent().catch(() => '');
    throw new Error(`${error.message}; loading state: ${loading || 'none'}; ${browserErrors.join('; ')}`);
  }
  const accountEmail = await page.locator('#account-email').textContent();
  if (accountEmail !== 'e2e@barktrace.test') throw new Error(`unexpected auto-provisioned account: ${accountEmail}`);

  await page.getByRole('button', { name: 'Create project' }).click();
  await page.locator('#create-project input[name="name"]').fill('Checkout E2E');
  await page.locator('#create-project select[name="platform"]').selectOption('javascript');
  await page.locator('#create-project').getByRole('button', { name: 'Create project' }).click();
  try {
    await page.waitForURL(`${baseURL}/ui/setup/`);
  } catch (error) {
    const formError = await page.locator('#project-error').textContent().catch(() => '');
    throw new Error(`${error.message}; current URL: ${page.url()}; project error: ${formError || 'none'}; ${browserErrors.join('; ')}`);
  }
  const dsn = await page.locator('.setup-main .copy-field code').textContent();
  if (!dsn) throw new Error('project setup did not expose a DSN');

  const parsed = new URL(dsn);
  const projectID = parsed.pathname.slice(1);
  const organizationsResponse = await page.request.get('/organizations');
  const organizations = await organizationsResponse.json();
  const nativeOrganization = organizations.find((item) => item.organization_slug === 'e2e');
  if (!organizationsResponse.ok() || !nativeOrganization) throw new Error('native organization discovery failed');
  const nativeProjectsResponse = await page.request.get(`/projects?organization_id=${encodeURIComponent(nativeOrganization.organization_id)}`);
  const nativeProjects = await nativeProjectsResponse.json();
  const nativeProject = nativeProjects.find((item) => item.sentry_id === projectID);
  if (!nativeProjectsResponse.ok() || !nativeProject) throw new Error('native project discovery failed');

  const sourceMapDebugID = '12345678-1234-1234-1234-123456789abc';
  const sourceMapUpload = await page.request.post(`/artifacts?project_id=${encodeURIComponent(nativeProject.id)}&release=${encodeURIComponent('checkout@1.0.0')}`, {
    multipart: {
      name: '~/unrelated-checkout-bundle.js.map',
      artifact_type: 'sourcemap',
      debug_id: sourceMapDebugID,
      dist: 'e2e-web',
      file: {
        name: 'checkout.js.map',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify({
          version: 3,
          sections: [{
            offset: { line: 0, column: 10 },
            map: {
              version: 3,
              sourceRoot: 'webpack:///',
              sources: ['src/checkout.ts'],
              sourcesContent: ['export function submitOrder() {}'],
              names: ['submitOrder'],
              mappings: 'AAAAA',
            },
          }],
        })),
      },
    },
  });
  if (!sourceMapUpload.ok()) throw new Error(`source-map upload failed: ${sourceMapUpload.status()} ${await sourceMapUpload.text()}`);

  const ingestEnvelope = async (header, type, payload) => {
    const body = `${JSON.stringify(header)}\n${JSON.stringify({ type, length: Buffer.byteLength(payload) })}\n${payload}\n`;
    const envelopeResponse = await fetch(`${baseURL}/api/${projectID}/envelope/?sentry_key=${encodeURIComponent(parsed.username)}&sentry_version=7`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-sentry-envelope' },
      body,
    });
    if (!envelopeResponse.ok) throw new Error(`${type} ingestion returned ${envelopeResponse.status}: ${await envelopeResponse.text()}`);
  };
  const eventID = '0123456789abcdef0123456789abcdef';
  const response = await fetch(`${baseURL}/api/${projectID}/store/?sentry_key=${encodeURIComponent(parsed.username)}&sentry_version=7`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      event_id: eventID,
      timestamp: new Date().toISOString(),
      platform: 'javascript',
      environment: 'e2e',
      release: 'checkout@1.0.0',
      dist: 'e2e-web',
      level: 'error',
      debug_meta: { images: [{ type: 'sourcemap', code_file: 'https://cdn.example/assets/checkout.js', debug_id: sourceMapDebugID }] },
      exception: { values: [{ type: 'E2EError', value: 'Browser workflow failed', stacktrace: { frames: [{ filename: 'https://cdn.example/assets/checkout.js', abs_path: 'https://cdn.example/assets/checkout.js', function: 'a', lineno: 1, colno: 10, in_app: true }] } }] },
    }),
  });
  if (!response.ok) throw new Error(`Sentry ingestion returned ${response.status}: ${await response.text()}`);

  const replayID = '12121212121212121212121212121212';
  await ingestEnvelope({ replay_id: replayID }, 'replay_event', JSON.stringify({
    replay_id: replayID,
    segment_id: 0,
    timestamp: '2026-08-29T10:00:01Z',
    replay_start_timestamp: '2026-08-29T10:00:00Z',
    environment: 'e2e',
    release: 'checkout@1.0.0',
    urls: ['https://shop.example/checkout'],
  }));
  await ingestEnvelope({ replay_id: replayID }, 'replay_recording', JSON.stringify([
    { type: 4, timestamp: 1787997600000, data: { href: 'https://shop.example/checkout', width: 800, height: 600 } },
    {
      type: 2,
      timestamp: 1787997600010,
      data: {
        node: {
          type: 0,
          id: 1,
          childNodes: [{
            type: 2,
            id: 2,
            tagName: 'html',
            attributes: {},
            childNodes: [
              { type: 2, id: 3, tagName: 'head', attributes: {}, childNodes: [] },
              {
                type: 2,
                id: 4,
                tagName: 'body',
                attributes: { style: 'font-family: sans-serif; padding: 32px' },
                childNodes: [{
                  type: 2,
                  id: 5,
                  tagName: 'button',
                  attributes: { type: 'button' },
                  childNodes: [{ type: 3, id: 6, textContent: 'Place order' }],
                }],
              },
            ],
          }],
        },
        initialOffset: { top: 0, left: 0 },
      },
    },
    { type: 3, timestamp: 1787997600200, data: { source: 2, type: 2, id: 5, x: 20, y: 12 } },
  ]));
  await ingestEnvelope({}, 'profile', JSON.stringify({
    profile_id: 'profile-e2e',
    platform: 'javascript',
    duration_ns: 200000000,
    profile: {
      frames: [{ function: 'checkout' }, { function: 'submitOrder', filename: 'checkout.js', lineno: 42 }],
      stacks: [[0, 1]],
      samples: [{ stack_id: 0, thread_id: 'main' }, { stack_id: 0, thread_id: 'main' }],
      thread_metadata: { main: { name: 'Main thread' } },
    },
  }));

  for (let attempt = 0; attempt < 20; attempt += 1) {
    await page.goto('/ui/issues/');
    await page.locator('#page:not([hidden])').waitFor();
    if (await page.getByText('E2EError: Browser workflow failed', { exact: true }).count()) break;
    await page.waitForTimeout(250);
  }
  await page.getByText('E2EError: Browser workflow failed', { exact: true }).click();
  await page.getByRole('heading', { name: 'E2EError', exact: true }).waitFor();
  await page.getByText('checkout@1.0.0', { exact: true }).waitFor();

  const organizationDetail = await page.request.get('/api/0/organizations/e2e/');
  if (!organizationDetail.ok() || (await organizationDetail.json()).slug !== 'e2e') throw new Error('Sentry organization detail endpoint failed');
  const projectListResponse = await page.request.get('/api/0/organizations/e2e/projects/');
  const sentryProjects = await projectListResponse.json();
  const sentryProject = sentryProjects.find((item) => item.id === projectID);
  if (!projectListResponse.ok() || !sentryProject) throw new Error('Sentry project discovery failed');
  const projectDetail = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/`);
  if (!projectDetail.ok() || (await projectDetail.json()).id !== projectID) throw new Error('Sentry project detail endpoint failed');
  const projectKeys = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/keys/`);
  const keys = await projectKeys.json();
  if (!projectKeys.ok() || keys[0]?.public !== parsed.username) throw new Error('Sentry project key endpoint failed');
  const issueList = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/issues/`);
  const sentryIssues = await issueList.json();
  if (!issueList.ok() || !sentryIssues[0]?.id) throw new Error('Sentry issue discovery failed');
  const issueDetail = await page.request.get(`/api/0/issues/${encodeURIComponent(sentryIssues[0].id)}/`);
  if (!issueDetail.ok() || (await issueDetail.json()).shortId !== sentryIssues[0].shortId) throw new Error('Sentry issue detail endpoint failed');
  const latestEvent = await page.request.get(`/api/0/issues/${encodeURIComponent(sentryIssues[0].id)}/events/latest/`);
  if (!latestEvent.ok() || (await latestEvent.json()).eventID !== eventID) throw new Error('Sentry latest issue event endpoint failed');
  const eventDetail = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/events/${eventID}/`);
  if (!eventDetail.ok() || (await eventDetail.json()).groupID !== sentryIssues[0].id) throw new Error('Sentry event detail endpoint failed');

  await page.getByRole('link', { name: 'Discover' }).click();
  await page.locator('#discover-form input[name="query"]').fill('environment:e2e');
  await page.locator('#discover-form').getByRole('button', { name: 'Run query' }).click();
  await page.getByText('E2EError: Browser workflow failed', { exact: true }).waitFor();

  await page.getByRole('link', { name: 'Dashboards' }).click();
  await page.locator('#create-dashboard input[name="title"]').fill('E2E health');
  await page.locator('#create-dashboard').getByRole('button', { name: 'Create dashboard' }).click();
  await page.getByRole('heading', { name: 'E2E health', exact: true }).waitFor();
  await page.locator('#add-widget input[name="title"]').fill('Error volume');
  await page.locator('#add-widget select[name="display_type"]').selectOption('number');
  await page.locator('#add-widget').getByRole('button', { name: 'Add widget' }).click();
  await page.getByRole('heading', { name: 'Error volume', exact: true }).waitFor();
  await page.locator('.widget-number').waitFor();
  const widgetValue = await page.locator('.widget-number').textContent();
  if (!widgetValue?.trim().startsWith('1')) throw new Error(`unexpected dashboard widget value: ${widgetValue}`);

  await page.getByRole('link', { name: 'Telemetry' }).click();
  await page.getByRole('heading', { name: 'Cron monitors' }).waitFor();
  await page.getByRole('button', { name: 'Replays' }).click();
  const replayRow = page.locator('.management-row', { hasText: replayID });
  await replayRow.getByRole('button', { name: 'Analyze' }).click();
  await page.getByRole('heading', { name: 'https://shop.example/checkout' }).waitFor();
  await page.locator('#replay-player[data-mounted="true"] .rr-controller').waitFor();
  await page.locator('#replay-player iframe').waitFor();
  await page.locator('.timeline-list strong').getByText('click', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Profiles' }).click();
  const profileRow = page.locator('.management-row', { hasText: 'profile-e2e' });
  await profileRow.getByRole('button', { name: 'Analyze' }).click();
  await page.locator('.profile-analysis').getByText('submitOrder', { exact: true }).first().waitFor();
  await page.locator('.profile-analysis').getByText('Main thread', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Artifacts' }).click();
  await page.getByRole('heading', { name: 'Source maps and debug files' }).waitFor();

  const nativeIssuesResponse = await page.request.get(`/issues?project_id=${encodeURIComponent(nativeProject.id)}`);
  const nativeIssues = await nativeIssuesResponse.json();
  if (!nativeIssuesResponse.ok() || !nativeIssues[0]?.id) throw new Error('native issue discovery failed');
  const nativeIssueDetailResponse = await page.request.get(`/issues/${encodeURIComponent(nativeIssues[0].id)}`);
  const nativeIssueDetail = await nativeIssueDetailResponse.json();
  const symbolicatedEvent = nativeIssueDetail.events?.find((item) => item.event_id === eventID);
  const symbolicatedFrame = symbolicatedEvent?.payload?.exception?.values?.[0]?.stacktrace?.frames?.[0];
  if (!nativeIssueDetailResponse.ok() || symbolicatedFrame?.filename !== 'webpack:///src/checkout.ts' || symbolicatedFrame?.function !== 'submitOrder' || symbolicatedFrame?.lineno !== 1 || symbolicatedFrame?.original_function !== 'a') {
    throw new Error(`production source-map symbolication failed: ${JSON.stringify(symbolicatedFrame)}`);
  }

  const mcpCall = async (id, name, args) => {
    const result = await fetch(`${baseURL}/mcp`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${mcpToken}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }),
    });
    const payload = await result.json();
    if (!result.ok || payload.result?.isError) throw new Error(`MCP ${name} failed: ${JSON.stringify(payload)}`);
    return payload.result.structuredContent;
  };
  const mcpMembers = await mcpCall(1, 'list_organization_members', { organization_id: nativeOrganization.organization_id });
  if (!mcpMembers.some((member) => member.email === 'e2e@barktrace.test')) throw new Error('MCP organization member listing failed');
  const mcpPermissions = await mcpCall(2, 'list_project_permissions', { project_id: nativeProject.id });
  if (!mcpPermissions.some((permission) => permission.email === 'e2e@barktrace.test' && permission.effective_role === 'admin')) throw new Error('MCP project permission listing failed');
  const mcpIssue = await mcpCall(3, 'update_issue', { issue_id: nativeIssues[0].id, priority: 'critical', bookmarked: true });
  if (mcpIssue.priority !== 'critical' || !mcpIssue.bookmarked) throw new Error('MCP advanced issue update failed');
  const mcpQuota = await mcpCall(4, 'set_project_quota', { project_id: nativeProject.id, category: 'error', per_minute: 120, per_day: 5000, max_item_bytes: 1048576 });
  if (!mcpQuota.configured || mcpQuota.per_minute !== 120) throw new Error('MCP quota update failed');
  const mcpRetention = await mcpCall(5, 'update_retention', { organization_id: nativeOrganization.organization_id, days: 45 });
  if (mcpRetention.retention_days !== 45) throw new Error('MCP retention update failed');
  const mcpComment = await mcpCall(6, 'add_issue_comment', { issue_id: nativeIssues[0].id, body: 'Verified by production MCP E2E' });
  if (mcpComment.body !== 'Verified by production MCP E2E') throw new Error('MCP issue comment failed');
  const mcpAlert = await mcpCall(7, 'create_alert_rule', {
    project_id: nativeProject.id,
    name: 'E2E errors',
    trigger: 'new_issue',
    destination_type: 'email',
    destination_email: 'alerts@example.com',
    conditions: { environment: 'e2e', levels: ['error'] },
    frequency_minutes: 15,
  });
  const mcpUpdatedAlert = await mcpCall(8, 'update_alert_rule', { project_id: nativeProject.id, rule_id: mcpAlert.id, enabled: false });
  if (mcpUpdatedAlert.enabled !== false) throw new Error('MCP alert update failed');
  await mcpCall(9, 'delete_alert_rule', { project_id: nativeProject.id, rule_id: mcpAlert.id });
  const mcpUptime = await mcpCall(10, 'create_uptime_monitor', {
    project_id: nativeProject.id,
    name: 'E2E public target',
    url: 'https://example.com/',
    method: 'HEAD',
    interval_seconds: 300,
    timeout_seconds: 5,
    expected_status_min: 200,
    expected_status_max: 399,
  });
  await mcpCall(11, 'delete_uptime_monitor', { project_id: nativeProject.id, monitor_id: mcpUptime.id });
  const mcpCron = await mcpCall(12, 'create_cron_monitor', {
    project_id: nativeProject.id,
    slug: 'e2e-nightly',
    name: 'E2E nightly',
    schedule_type: 'crontab',
    schedule_value: '0 2 * * *',
    timezone: 'UTC',
    checkin_margin: 10,
    max_runtime: 120,
  });
  await mcpCall(13, 'delete_cron_monitor', { project_id: nativeProject.id, monitor_id: mcpCron.id });
  const mcpTeam = await mcpCall(14, 'create_team', { organization_id: nativeOrganization.organization_id, name: 'E2E Responders', slug: 'e2e-responders' });
  await mcpCall(15, 'link_team_project', { team_id: mcpTeam.id, project_id: nativeProject.id, role: 'admin' });
  const mcpTeams = await mcpCall(16, 'list_teams', { organization_id: nativeOrganization.organization_id });
  if (!mcpTeams.some((team) => team.id === mcpTeam.id && team.project_count === 1)) throw new Error('MCP team lifecycle failed');
  const assignedIssue = await mcpCall(17, 'update_issue', { issue_id: nativeIssues[0].id, assignee_team_id: mcpTeam.id });
  if (assignedIssue.assignee_team_id !== mcpTeam.id || assignedIssue.assignee_user_id !== null) throw new Error('MCP team issue assignment failed');

  await page.reload();
  await page.locator('#page:not([hidden])').waitFor();
  await page.getByRole('link', { name: 'Organization' }).click();
  await page.getByRole('heading', { name: 'Teams' }).waitFor();
  await page.getByText('E2E Responders', { exact: true }).waitFor();

  await page.locator('#account-button').click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL(`${baseURL}/ui/login/`);
  const me = await page.request.get('/auth/me');
  if (me.status() !== 401) throw new Error(`logout left session active: /auth/me returned ${me.status()}`);

  if (browserErrors.length) throw new Error(browserErrors.join('\n'));
  console.log('browser E2E passed: OIDC, ingestion, debug-ID/indexed source-map symbolication, Sentry API details, Discover, dashboards, teams, interactive replay, profile analysis, telemetry, MCP operations, and logout');
} finally {
  await browser.close();
}
