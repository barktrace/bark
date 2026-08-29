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
  await page.locator('#page:not([hidden])').waitFor();
  const accountEmail = await page.locator('#account-email').textContent();
  if (accountEmail !== 'e2e@barktrace.test') throw new Error(`unexpected auto-provisioned account: ${accountEmail}`);

  await page.getByRole('button', { name: 'Create project' }).click();
  await page.locator('#create-project input[name="name"]').fill('Checkout E2E');
  await page.locator('#create-project select[name="platform"]').selectOption('javascript');
  await page.locator('#create-project').getByRole('button', { name: 'Create project' }).click();
  await page.waitForURL(`${baseURL}/ui/setup/`);
  const dsn = await page.locator('.setup-main .copy-field code').textContent();
  if (!dsn) throw new Error('project setup did not expose a DSN');

  const parsed = new URL(dsn);
  const projectID = parsed.pathname.slice(1);
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
  await page.getByRole('button', { name: 'Artifacts' }).click();
  await page.getByRole('heading', { name: 'Source maps and debug files' }).waitFor();

  await page.locator('#account-button').click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.waitForURL(`${baseURL}/ui/login/`);
  const me = await page.request.get('/auth/me');
  if (me.status() !== 401) throw new Error(`logout left session active: /auth/me returned ${me.status()}`);

  if (browserErrors.length) throw new Error(browserErrors.join('\n'));
  console.log('browser E2E passed: OIDC, ingestion, issue detail, Discover, dashboards, telemetry, and logout');
} finally {
  await browser.close();
}
