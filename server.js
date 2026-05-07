const express   = require('express');
const fetch     = require('node-fetch');
const puppeteer = require('puppeteer');
const cors      = require('cors');
const path      = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

const GREYTHR_BASE = 'https://hashconnect.greythr.com';
const BROWSER_UA   = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

async function loginWithPuppeteer(userName, password) {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  try {
    const page = await browser.newPage();
    await page.setUserAgent(BROWSER_UA);

    // Capture employee ID from latte API URLs like /latte/v3/attendance/info/472/...
    let employeeId = null;
    page.on('response', response => {
      if (employeeId) return;
      const m = response.url().match(/\/latte\/v3\/attendance\/info\/(\d+)\//);
      if (m) {
        employeeId = parseInt(m[1]);
        console.log(`[puppeteer] employeeId=${employeeId}`);
      }
    });

    console.log('[puppeteer] navigating to greytHR…');
    await page.goto(GREYTHR_BASE, { waitUntil: 'load', timeout: 30000 });
    console.log(`[puppeteer] landed at: ${page.url()}`);

    await page.waitForSelector('input', { visible: true, timeout: 20000 });

    const inputInfo = await page.$$eval(
      'input:not([type="hidden"])',
      els => els.map(e => ({ type: e.type, name: e.name, placeholder: e.placeholder }))
    );
    console.log('[puppeteer] inputs:', JSON.stringify(inputInfo));

    await page.type('input:not([type="hidden"]):not([type="password"])', userName, { delay: 30 });
    await page.type('input[type="password"]', password, { delay: 30 });

    console.log('[puppeteer] submitting…');
    const submitBtn = await page.$('button[type="submit"]') ?? await page.$('button.btn');
    if (!submitBtn) throw new Error('Submit button not found on login page');
    await submitBtn.click();

    // Wait for full OAuth chain: hashconnect /auth/login → goth-coral → idp-coral → hashconnect main app
    console.log('[puppeteer] waiting for full OAuth redirect chain to complete…');
    await page.waitForFunction(
      () => window.location.hostname === 'hashconnect.greythr.com' &&
            !window.location.pathname.includes('/auth/'),
      { timeout: 45000, polling: 500 }
    ).catch(async () => {
      const currentUrl = page.url();
      const errorText = await page.evaluate(() => {
        const el = document.querySelector('.error-message, .alert-danger, [class*="error"], [class*="Error"]');
        return el ? el.textContent.trim() : null;
      }).catch(() => null);
      throw new Error(
        errorText ? `Login failed: ${errorText}` : `Login timed out at ${currentUrl} — check credentials`
      );
    });

    await page.waitForNavigation({ waitUntil: 'load', timeout: 15000 }).catch(() => {});
    console.log(`[puppeteer] post-login URL: ${page.url()}`);

    // If the portal home page didn't trigger any latte calls, navigate to attendance-info to capture employee ID
    if (!employeeId) {
      console.log('[puppeteer] navigating to attendance-info to capture employee ID…');
      const waitForLatte = page.waitForResponse(
        r => /\/latte\/v3\/attendance\/info\/\d+\//.test(r.url()),
        { timeout: 15000 }
      ).catch(() => null);
      await page.goto(`${GREYTHR_BASE}/v3/portal/ess/attendance/attendance-info`, {
        waitUntil: 'load', timeout: 20000,
      });
      await waitForLatte;
    }

    if (!employeeId) throw new Error('Could not determine employee ID from latte API');

    const cookies = await page.cookies(GREYTHR_BASE);
    console.log(`[puppeteer] cookies: ${cookies.map(c => c.name).join(', ')}, employeeId=${employeeId}`);

    if (!cookies.some(c => c.name === 'access_token')) throw new Error('access_token cookie not found after login');

    return { sessionCookie: cookies.map(c => `${c.name}=${c.value}`).join('; '), employeeId };
  } finally {
    await browser.close();
  }
}

// ── POST /api/login ───────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { userName, password } = req.body;
  if (!userName || !password) return res.status(400).json({ error: 'userName and password required' });

  try {
    console.log(`\n[login] ── ${userName} ──`);
    const { sessionCookie, employeeId } = await loginWithPuppeteer(userName, password);
    res.json({ ok: true, sessionCookie, employeeId });
  } catch (err) {
    console.error('[login] error:', err.message);
    res.status(401).json({ error: err.message });
  }
});

// ── GET /api/attendance?date=YYYY-MM-DD&employeeId=472 ────────────────────────
app.get('/api/attendance', async (req, res) => {
  const { date, sessionCookie, employeeId } = req.query;
  if (!sessionCookie) return res.status(401).json({ error: 'sessionCookie required' });
  if (!employeeId)    return res.status(400).json({ error: 'employeeId required' });

  const today = date || new Date().toISOString().split('T')[0];

  try {
    const attRes = await fetch(
      `${GREYTHR_BASE}/latte/v3/attendance/info/${employeeId}/swipes?startDate=${today}&endDate=&systemSwipes=true&swipePairs=true`,
      {
        headers: {
          'accept':           'application/json',
          'api-scope':        'web',
          'cookie':           sessionCookie,
          'referer':          `${GREYTHR_BASE}/v3/portal/ess/attendance/attendance-info`,
          'user-agent':       BROWSER_UA,
          'x-requested-with': 'XMLHttpRequest',
        },
      }
    );

    const body = await attRes.text();
    let data;
    try { data = JSON.parse(body); } catch { data = body; }
    console.log(`[attendance] status=${attRes.status} body=`, JSON.stringify(data).substring(0, 300));
    res.json({ raw: data, status: attRes.status });

  } catch (err) {
    console.error('[attendance] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n  Swipe Logout — local server`);
  console.log(`  http://localhost:${PORT}\n`);
});
