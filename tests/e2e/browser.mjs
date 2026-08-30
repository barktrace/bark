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

  const ingestEnvelope = async (header, type, payload, item = {}) => {
    const body = `${JSON.stringify(header)}\n${JSON.stringify({ type, length: Buffer.byteLength(payload), ...item })}\n${payload}\n`;
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
      tags: { region: 'eu-west-1', checkout_flow: 'express' },
      debug_meta: { images: [{ type: 'sourcemap', code_file: 'https://cdn.example/assets/checkout.js', debug_id: sourceMapDebugID }] },
      exception: { values: [{ type: 'E2EError', value: 'Browser workflow failed', stacktrace: { frames: [{ filename: 'https://cdn.example/assets/checkout.js', abs_path: 'https://cdn.example/assets/checkout.js', function: 'a', lineno: 1, colno: 10, in_app: true }] } }] },
    }),
  });
  if (!response.ok) throw new Error(`Sentry ingestion returned ${response.status}: ${await response.text()}`);
  await ingestEnvelope({ event_id: eventID }, 'attachment', 'E2E diagnostic attachment', {
    filename: 'diagnostic.txt',
    content_type: 'text/plain',
    attachment_type: 'event.attachment',
  });
  await ingestEnvelope({}, 'user_report', JSON.stringify({
    event_id: eventID,
    name: 'E2E customer',
    email: 'customer@example.test',
    comments: 'The checkout button failed',
    url: 'https://shop.example/checkout',
  }));

  const replayID = '12121212121212121212121212121212';
  await ingestEnvelope({ replay_id: replayID }, 'replay_event', JSON.stringify({
    replay_id: replayID,
    segment_id: 0,
    timestamp: '2026-08-29T10:00:01Z',
    replay_start_timestamp: '2026-08-29T10:00:00Z',
    environment: 'e2e',
    release: 'checkout@1.0.0',
    urls: ['https://shop.example/checkout'],
    error_ids: [eventID],
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
                  attributes: { type: 'button', id: 'checkout', class: 'primary' },
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
    { type: 3, timestamp: 1787997600500, data: { source: 2, type: 2, id: 5, x: 20, y: 12 } },
    { type: 3, timestamp: 1787997600900, data: { source: 2, type: 2, id: 5, x: 20, y: 12 } },
    { type: 3, timestamp: 1787997601000, data: { source: 0, adds: [], removes: [], texts: [], attributes: [] } },
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
  const sessionTimestamp = new Date().toISOString();
  await ingestEnvelope({}, 'session', JSON.stringify({
    sid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    did: 'e2e-user-healthy',
    init: true,
    started: sessionTimestamp,
    timestamp: sessionTimestamp,
    status: 'ok',
    duration: 12,
    errors: 0,
    attrs: { release: 'checkout@1.0.0', environment: 'e2e' },
  }));
  await ingestEnvelope({}, 'session', JSON.stringify({
    sid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    did: 'e2e-user-crashed',
    init: true,
    started: sessionTimestamp,
    timestamp: sessionTimestamp,
    status: 'crashed',
    duration: 18,
    errors: 1,
    attrs: { release: 'checkout@1.0.0', environment: 'e2e' },
  }));

  for (let attempt = 0; attempt < 20; attempt += 1) {
    await page.goto('/ui/issues/');
    await page.locator('#page:not([hidden])').waitFor();
    if (await page.getByText('E2EError: Browser workflow failed', { exact: true }).count()) break;
    await page.waitForTimeout(250);
  }
  await page.getByText('Rage click on button#checkout.primary', { exact: true }).waitFor();
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
  const organizationEnvironmentsResponse = await page.request.get('/api/0/organizations/e2e/environments/');
  const organizationEnvironments = await organizationEnvironmentsResponse.json();
  if (!organizationEnvironmentsResponse.ok() || !organizationEnvironments.some((item) => item.name === 'e2e')) throw new Error(`Sentry organization environment discovery failed: ${JSON.stringify(organizationEnvironments)}`);
  const projectEnvironmentsPath = `/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/environments/`;
  const projectEnvironmentsResponse = await page.request.get(projectEnvironmentsPath);
  const projectEnvironments = await projectEnvironmentsResponse.json();
  if (!projectEnvironmentsResponse.ok() || !projectEnvironments.some((item) => item.name === 'e2e' && item.isHidden === false)) throw new Error(`Sentry project environment discovery failed: ${JSON.stringify(projectEnvironments)}`);
  const hideEnvironmentResponse = await page.request.put(projectEnvironmentsPath, { data: { environmentNames: ['e2e', 'e2e'], isHidden: true } });
  const hiddenEnvironments = await hideEnvironmentResponse.json();
  if (!hideEnvironmentResponse.ok() || hiddenEnvironments.length !== 1 || hiddenEnvironments[0]?.name !== 'e2e' || hiddenEnvironments[0]?.isHidden !== true) throw new Error(`Sentry environment bulk hide failed: ${JSON.stringify(hiddenEnvironments)}`);
  const visibleAfterHide = await (await page.request.get(projectEnvironmentsPath)).json();
  if (visibleAfterHide.some((item) => item.name === 'e2e')) throw new Error(`hidden Sentry environment remained visible: ${JSON.stringify(visibleAfterHide)}`);
  const hiddenOnlyResponse = await page.request.get(`${projectEnvironmentsPath}?visibility=hidden`);
  const hiddenOnly = await hiddenOnlyResponse.json();
  if (!hiddenOnlyResponse.ok() || !hiddenOnly.some((item) => item.name === 'e2e' && item.isHidden === true)) throw new Error(`Sentry hidden environment filter failed: ${JSON.stringify(hiddenOnly)}`);
  const restoreEnvironmentResponse = await page.request.put(`${projectEnvironmentsPath}${encodeURIComponent('e2e')}/`, { data: { isHidden: false } });
  if (!restoreEnvironmentResponse.ok() || (await restoreEnvironmentResponse.json()).isHidden !== false) throw new Error('Sentry environment restore failed');
  const sessionsQuery = new URLSearchParams({ statsPeriod: '24h', interval: '1h', project: sentryProject.id, environment: 'e2e' });
  sessionsQuery.append('field', 'sum(session)');
  sessionsQuery.append('field', 'count_unique(user)');
  sessionsQuery.append('field', 'crash_free_rate(session)');
  sessionsQuery.append('groupBy', 'release');
  const sessionsResponse = await page.request.get(`/api/0/organizations/e2e/sessions/?${sessionsQuery}`);
  const sessions = await sessionsResponse.json();
  const releaseHealth = sessions.groups?.find((group) => group.by?.release === 'checkout@1.0.0');
  if (!sessionsResponse.ok() || releaseHealth?.totals?.['sum(session)'] !== 2 || releaseHealth?.totals?.['count_unique(user)'] !== 2 || releaseHealth?.totals?.['crash_free_rate(session)'] !== 50) throw new Error(`Sentry release health failed: ${JSON.stringify(sessions)}`);
  const issueList = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/issues/`);
  const sentryIssues = await issueList.json();
  if (!issueList.ok() || !sentryIssues[0]?.id) throw new Error('Sentry issue discovery failed');
  const errorIssue = sentryIssues.find((item) => item.title === 'E2EError: Browser workflow failed');
  if (!errorIssue) throw new Error(`Sentry error issue discovery failed: ${JSON.stringify(sentryIssues)}`);
  const projectTagsResponse = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/tags/`);
  const projectTags = await projectTagsResponse.json();
  if (!projectTagsResponse.ok() || !projectTags.some((tag) => tag.key === 'region' && tag.totalValues === 1) || !projectTags.some((tag) => tag.key === 'sentry:environment')) throw new Error(`Sentry project tag summary failed: ${JSON.stringify(projectTags)}`);
  const issueTagValuesResponse = await page.request.get(`/api/0/issues/${encodeURIComponent(errorIssue.id)}/tags/region/values/`);
  const issueTagValues = await issueTagValuesResponse.json();
  if (!issueTagValuesResponse.ok() || issueTagValues[0]?.value !== 'eu-west-1' || issueTagValues[0]?.count !== 1) throw new Error(`Sentry issue tag values failed: ${JSON.stringify(issueTagValues)}`);
  const replayIssue = sentryIssues.find((item) => item.issueType === 'rage_click');
  if (!replayIssue || replayIssue.issueCategory !== 'replay') throw new Error(`Sentry Replay issue discovery failed: ${JSON.stringify(sentryIssues)}`);
  const replayIssueDetail = await page.request.get(`/api/0/issues/${encodeURIComponent(replayIssue.id)}/`);
  if (!replayIssueDetail.ok() || (await replayIssueDetail.json()).issueType !== 'rage_click') throw new Error('Sentry Replay issue detail failed');
  const replayIssueEvent = await page.request.get(`/api/0/issues/${encodeURIComponent(replayIssue.id)}/events/latest/`);
  const replayIssueEventBody = await replayIssueEvent.json();
  if (!replayIssueEvent.ok() || replayIssueEventBody.contexts?.replay?.replay_id !== replayID || replayIssueEventBody.contexts.replay.click_count !== 3) throw new Error(`Sentry Replay issue event failed: ${JSON.stringify(replayIssueEventBody)}`);
  const issueDetail = await page.request.get(`/api/0/issues/${encodeURIComponent(sentryIssues[0].id)}/`);
  if (!issueDetail.ok() || (await issueDetail.json()).shortId !== sentryIssues[0].shortId) throw new Error('Sentry issue detail endpoint failed');
  const createdCommentResponse = await page.request.post(`/api/0/issues/${encodeURIComponent(sentryIssues[0].id)}/comments/`, { data: { text: 'Investigating through the Sentry API' } });
  const createdComment = await createdCommentResponse.json();
  if (!createdCommentResponse.ok() || createdComment.type !== 'note' || createdComment.data?.text !== 'Investigating through the Sentry API') throw new Error(`Sentry issue comment creation failed: ${JSON.stringify(createdComment)}`);
  const issueActivitiesResponse = await page.request.get(`/api/0/organizations/e2e/issues/${encodeURIComponent(sentryIssues[0].id)}/activities/`);
  const issueActivities = await issueActivitiesResponse.json();
  if (!issueActivitiesResponse.ok() || !issueActivities.activity?.some((item) => item.id === createdComment.id) || !issueActivities.activity?.some((item) => item.type === 'first_seen')) throw new Error(`Sentry issue activities failed: ${JSON.stringify(issueActivities)}`);
  const updatedCommentResponse = await page.request.put(`/api/0/organizations/e2e/groups/${encodeURIComponent(sentryIssues[0].id)}/notes/${encodeURIComponent(createdComment.id)}/`, { data: { text: 'Resolved through the Sentry API' } });
  const updatedComment = await updatedCommentResponse.json();
  if (!updatedCommentResponse.ok() || updatedComment.data?.text !== 'Resolved through the Sentry API') throw new Error(`Sentry issue comment update failed: ${JSON.stringify(updatedComment)}`);
  const deletedCommentResponse = await page.request.delete(`/api/0/issues/${encodeURIComponent(sentryIssues[0].id)}/comments/${encodeURIComponent(createdComment.id)}/`);
  if (!deletedCommentResponse.ok()) throw new Error(`Sentry issue comment deletion failed: ${deletedCommentResponse.status()}`);
  const latestEvent = await page.request.get(`/api/0/issues/${encodeURIComponent(sentryIssues[0].id)}/events/latest/`);
  if (!latestEvent.ok() || (await latestEvent.json()).eventID !== eventID) throw new Error('Sentry latest issue event endpoint failed');
  const eventDetail = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/events/${eventID}/`);
  if (!eventDetail.ok() || (await eventDetail.json()).groupID !== sentryIssues[0].id) throw new Error('Sentry event detail endpoint failed');
  const resolvedEvent = await page.request.get(`/api/0/organizations/e2e/eventids/${eventID}/`);
  const resolvedEventBody = await resolvedEvent.json();
  if (!resolvedEvent.ok() || resolvedEventBody.event?.eventID !== eventID || resolvedEventBody.group?.id !== sentryIssues[0].id) throw new Error(`Sentry event ID resolution failed: ${JSON.stringify(resolvedEventBody)}`);
  const recommendedEvent = await page.request.get(`/api/0/organizations/e2e/groups/${encodeURIComponent(sentryIssues[0].id)}/events/recommended/`);
  if (!recommendedEvent.ok() || (await recommendedEvent.json()).eventID !== eventID) throw new Error('Sentry recommended issue event endpoint failed');
  const rawEvent = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/events/${eventID}/json/`);
  if (!rawEvent.ok() || (await rawEvent.json()).event_id !== eventID) throw new Error('Sentry raw event JSON endpoint failed');
  const attachmentList = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/events/${eventID}/attachments/?query=diagnostic`);
  const attachments = await attachmentList.json();
  if (!attachmentList.ok() || attachments[0]?.name !== 'diagnostic.txt' || attachments[0]?.event_id !== eventID) throw new Error(`Sentry attachment list failed: ${JSON.stringify(attachments)}`);
  const attachmentDownload = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/events/${eventID}/attachments/${encodeURIComponent(attachments[0].id)}/?download`);
  if (!attachmentDownload.ok() || (await attachmentDownload.text()) !== 'E2E diagnostic attachment') throw new Error('Sentry attachment download failed');
  const feedbackList = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/user-feedback/`);
  const feedback = await feedbackList.json();
  if (!feedbackList.ok() || feedback[0]?.eventID !== eventID || feedback[0]?.comments !== 'The checkout button failed') throw new Error(`Sentry user feedback list failed: ${JSON.stringify(feedback)}`);
  const replaySearch = await page.request.get(`/api/0/organizations/e2e/replays/?project=${encodeURIComponent(sentryProject.id)}&query=${encodeURIComponent(`environment:e2e issue:${sentryIssues[0].id}`)}`);
  const replaySearchBody = await replaySearch.json();
  if (!replaySearch.ok() || replaySearchBody.data?.[0]?.replayId !== replayID || replaySearchBody.data[0].issues?.[0]?.id !== sentryIssues[0].id) throw new Error(`Sentry replay search/correlation failed: ${JSON.stringify(replaySearchBody)}`);
  const replayDetail = await page.request.get(`/api/0/organizations/e2e/replays/${replayID}/`);
  const replayDetailBody = await replayDetail.json();
  if (!replayDetail.ok() || replayDetailBody.data?.count_rage_clicks !== 3 || !replayDetailBody.data?.has_viewed) throw new Error(`Sentry replay detail failed: ${JSON.stringify(replayDetailBody)}`);
  const replaySegments = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/replays/${replayID}/recording-segments/`);
  const replaySegmentBody = await replaySegments.json();
  if (!replaySegments.ok() || replaySegmentBody?.[0]?.[0]?.type !== 4) throw new Error(`Sentry replay segment listing failed: ${JSON.stringify(replaySegmentBody)}`);
  const replaySegment = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/replays/${replayID}/recording-segments/0/`);
  if (!replaySegment.ok() || (await replaySegment.json()).data?.segmentId !== 0) throw new Error('Sentry replay segment detail failed');
  const replayClicks = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/replays/${replayID}/clicks/`);
  if (!replayClicks.ok() || (await replayClicks.json()).data?.length !== 3) throw new Error('Sentry replay click listing failed');
  const replaySelectors = await page.request.get('/api/0/organizations/e2e/replay-selectors/?project=1&environment=e2e');
  const replaySelectorsBody = await replaySelectors.json();
  if (!replaySelectors.ok() || replaySelectorsBody.data?.[0]?.dom_element !== 'button#checkout.primary' || replaySelectorsBody.data[0].count_rage_clicks !== 3) throw new Error(`Sentry replay selectors failed: ${JSON.stringify(replaySelectorsBody)}`);
  const replayViewers = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/replays/${replayID}/viewed-by/`);
  if (!replayViewers.ok() || (await replayViewers.json()).data?.viewed_by?.[0]?.email !== 'e2e@barktrace.test') throw new Error('Sentry replay viewer history failed');

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
  if (!widgetValue?.trim().startsWith('2')) throw new Error(`unexpected dashboard widget value after Replay issue creation: ${widgetValue}`);

  await page.getByRole('link', { name: 'Telemetry' }).click();
  await page.getByRole('heading', { name: 'Cron monitors' }).waitFor();
  await page.getByRole('button', { name: 'Replays' }).click();
  await page.locator('#replay-search input[name="q"]').fill('checkout');
  await page.locator('#replay-search input[name="environment"]').fill('e2e');
  await page.locator('#replay-search input[name="release"]').fill('checkout@1.0.0');
  await page.locator('#replay-search input[name="has_error"]').check();
  await page.locator('#replay-search').getByRole('button', { name: 'Search' }).click();
  const replayRow = page.locator('.management-row', { hasText: replayID });
  await replayRow.getByRole('button', { name: 'Analyze' }).click();
  await page.getByRole('heading', { name: 'https://shop.example/checkout' }).waitFor();
  await page.locator('#replay-player[data-mounted="true"] .rr-controller').waitFor();
  await page.locator('#replay-player iframe').waitFor();
  await page.locator('.timeline-list strong').getByText('click', { exact: true }).first().waitFor();
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
  const mcpEnvironments = await mcpCall(21, 'list_environments', { project_id: nativeProject.id, visibility: 'all' });
  if (!mcpEnvironments.some((environment) => environment.name === 'e2e' && environment.is_hidden === false)) throw new Error(`MCP environment listing failed: ${JSON.stringify(mcpEnvironments)}`);
  const mcpTags = await mcpCall(22, 'list_event_tags', { project_id: nativeProject.id, tag_key: 'region' });
  if (mcpTags[0]?.value !== 'eu-west-1' || mcpTags[0]?.count !== 1) throw new Error(`MCP event tag values failed: ${JSON.stringify(mcpTags)}`);
  const mcpReleaseHealth = await mcpCall(23, 'query_release_health', { project_id: nativeProject.id, environment: 'e2e', stats_period: '24h', interval: '1h', fields: ['sum(session)', 'crash_free_rate(session)'], group_by: ['release'] });
  const mcpReleaseGroup = mcpReleaseHealth.groups?.find((group) => group.by?.release === 'checkout@1.0.0');
  if (mcpReleaseGroup?.totals?.['sum(session)'] !== 2 || mcpReleaseGroup?.totals?.['crash_free_rate(session)'] !== 50) throw new Error(`MCP release health failed: ${JSON.stringify(mcpReleaseHealth)}`);
  const mcpIssue = await mcpCall(3, 'update_issue', { issue_id: nativeIssues[0].id, priority: 'critical', bookmarked: true });
  if (mcpIssue.priority !== 'critical' || !mcpIssue.bookmarked) throw new Error('MCP advanced issue update failed');
  const mcpReplays = await mcpCall(18, 'list_replays', { project_id: nativeProject.id, query: 'checkout', environment: 'e2e', release: 'checkout@1.0.0', issue_id: nativeIssues[0].id, has_error: true });
  if (!mcpReplays.some((replay) => replay.replay_id === replayID)) throw new Error('MCP replay filtering failed');
  const mcpReplayClicks = await mcpCall(19, 'list_replay_clicks', { project_id: nativeProject.id, replay_id: replayID });
  if (mcpReplayClicks.length !== 3 || !mcpReplayClicks.every((click) => click.is_rage)) throw new Error('MCP replay click listing failed');
  const mcpReplaySelectors = await mcpCall(20, 'list_replay_selectors', { project_id: nativeProject.id });
  if (mcpReplaySelectors[0]?.dom_element !== 'button#checkout.primary') throw new Error('MCP replay selector listing failed');
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

  const deleteJobResponse = await page.request.post(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/replays/jobs/delete/`, { data: { data: { rangeStart: '2026-08-29T00:00:00Z', rangeEnd: '2026-08-30T00:00:00Z', environments: ['e2e'], query: 'checkout' } } });
  const deleteJob = await deleteJobResponse.json();
  if (!deleteJobResponse.ok() || !deleteJob.data?.id) throw new Error(`create Replay deletion job failed: ${JSON.stringify(deleteJob)}`);
  let deletionComplete = false;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const jobResponse = await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/replays/jobs/delete/${deleteJob.data.id}/`);
    const job = await jobResponse.json();
    if (job.data?.status === 'completed' && job.data?.countDeleted === 1) { deletionComplete = true; break; }
    if (job.data?.status === 'failed') throw new Error(`Replay deletion job failed: ${JSON.stringify(job)}`);
    await page.waitForTimeout(500);
  }
  if (!deletionComplete) throw new Error('Replay deletion job did not complete');
  const issuesAfterReplayDeletion = await (await page.request.get(`/api/0/projects/e2e/${encodeURIComponent(sentryProject.slug)}/issues/`)).json();
  if (issuesAfterReplayDeletion.some((item) => item.issueType === 'rage_click')) throw new Error('Replay deletion retained its synthetic issue');

  await page.locator('#account-button').click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL(`${baseURL}/ui/login/`);
  const me = await page.request.get('/auth/me');
  if (me.status() !== 401) throw new Error(`logout left session active: /auth/me returned ${me.status()}`);

  if (browserErrors.length) throw new Error(browserErrors.join('\n'));
  console.log('browser E2E passed: OIDC, ingestion, source-map symbolication, Sentry event resolution/environments/tags/release health, Replay issues/interactions/deletion, Discover, dashboards, teams, profiles, telemetry, MCP, and logout');
} finally {
  await browser.close();
}
