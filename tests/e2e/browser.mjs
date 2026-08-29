import { chromium } from 'playwright';

const baseURL = process.env.BARKTRACE_E2E_URL || 'http://127.0.0.1:18080';
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
      level: 'error',
      exception: { values: [{ type: 'E2EError', value: 'Browser workflow failed', stacktrace: { frames: [{ filename: 'checkout.js', function: 'submitOrder', lineno: 42, in_app: true }] } }] },
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

  await page.locator('#account-button').click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL(`${baseURL}/ui/login/`);
  const me = await page.request.get('/auth/me');
  if (me.status() !== 401) throw new Error(`logout left session active: /auth/me returned ${me.status()}`);

  if (browserErrors.length) throw new Error(browserErrors.join('\n'));
  console.log('browser E2E passed: OIDC, ingestion, issue detail, Discover, dashboards, interactive replay, profile analysis, telemetry, and logout');
} finally {
  await browser.close();
}
